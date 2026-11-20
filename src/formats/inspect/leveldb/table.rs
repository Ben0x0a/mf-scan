//! LevelDB tables (`*.ldb`, `*.sst`): a byte offset to its block and entry, so the
//! key, sequence number, operation and value of a data entry, an index entry's
//! separator key, a metaindex entry, or a filter block, footer or block trailer.
//!
//! Defines: `Table` (`read`, `locate_many`).
//! Used by: `leveldb` (the inspector).
//! Uses: `leveldb::{masked_crc, snappy, TABLE_MAGIC}`, `inspect::{leb128, quoted_bytes}`.
//!
//! ── Format (LevelDB's `table_format.md`, `format.cc`, `block_builder.cc`) ──
//! The footer, the last 48 bytes, holds two block handles (offset and size, as
//! varints), the metaindex's and the index's, then padding and the magic. A block is
//! its contents, a type byte (0 stored, 1 Snappy) and the masked CRC-32C of both.
//! Block contents are entries (shared key length, unshared length, value length as
//! varints, the unshared key bytes, the value) then the restart offsets (u32 each)
//! and their count (u32): an entry's key is its first `shared` bytes of the key
//! before it, then its own. The index maps each data block's last key, or a key
//! between it and the next block's, to its handle; the metaindex names the filter
//! block (`filter.<policy>`), a Bloom filter. Data and index keys are internal keys:
//! the user key, then 8 bytes (little-endian) of sequence number << 8 | type (1 put,
//! 0 delete).
//!
//! A block is decoded only when its CRC verifies and it parses exactly: its entries
//! end where its restart array begins, and each restart point is an entry that shares
//! nothing with the one before. Otherwise it is named, not decoded. A Snappy block is
//! decompressed: a match in a literal run (where the text a raw search finds lies)
//! maps to its entry, one in a tag or copy is named only. A match in no block the
//! index locates is named too: when the index does not decode, the data blocks
//! cannot be found (a block does not hold its own size; only the index does).
//!
//! Checked on every table of four test phones (510 tables, three Android, one
//! iPhone): each block's CRC verifies and each block but the filters decodes
//! exactly, 2,504 data blocks (2,096 Snappy), 510 indexes (167 Snappy) and 510
//! metaindexes, 168,420 entries.

use std::collections::HashMap;
use std::ops::Range;

use serde_json::{Map, Value, json};

use super::snappy::{self, Decompressed};
use super::{TABLE_MAGIC, masked_crc};
use crate::core::models::Inspection;
use crate::formats::inspect::{detail_bytes, leb128, quoted_bytes};

/// The footer: two block handles of at most 20 bytes each, padding, the magic.
const FOOTER: usize = 48;
/// A block's trailer: the compression type (u8), then the masked CRC-32C (u32).
const TRAILER: usize = 5;
/// The bytes after the user key in an internal key: sequence and type.
const TAG: usize = 8;

/// What a block holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    /// The n-th data block (1-based), in index order.
    Data(usize),
    Index,
    Metaindex,
    Filter,
}

impl Role {
    fn label(self) -> String {
        match self {
            Role::Data(n) => format!("data block {n}"),
            Role::Index => "index block".into(),
            Role::Metaindex => "metaindex block".into(),
            Role::Filter => "filter block".into(),
        }
    }

    fn kind(self) -> &'static str {
        match self {
            Role::Data(_) => "data",
            Role::Index => "index",
            Role::Metaindex => "metaindex",
            Role::Filter => "filter",
        }
    }
}

/// A block of the file: its contents' range (the trailer follows), and its check.
#[derive(Debug)]
struct Block {
    role: Role,
    contents: Range<usize>,
    compression: u8,
    crc_ok: bool,
}

impl Block {
    fn compression(&self) -> String {
        match self.compression {
            0 => "none".into(),
            1 => "snappy".into(),
            n => format!("type {n}"),
        }
    }
}

/// A table's blocks, sorted and not overlapping, and its footer.
#[derive(Debug)]
pub(super) struct Table {
    blocks: Vec<Block>,
    footer: Range<usize>,
    /// Whether the index decoded, so the data blocks were located.
    index_ok: bool,
}

/// A block's contents as stored, or decompressed.
enum Contents<'c> {
    Stored(&'c [u8]),
    Snappy(Decompressed),
}

impl Contents<'_> {
    fn bytes(&self) -> &[u8] {
        match self {
            Contents::Stored(b) => b,
            Contents::Snappy(d) => &d.bytes,
        }
    }

    /// Where byte `i` of the stored contents is in [`bytes`](Self::bytes).
    fn position(&self, i: usize) -> Option<usize> {
        match self {
            Contents::Stored(_) => Some(i),
            Contents::Snappy(d) => d.output_of(i),
        }
    }
}

/// One entry of a block, as ranges within its (decompressed) contents.
#[derive(Debug)]
struct Entry {
    range: Range<usize>,
    /// The whole key: the shared bytes of the key before, then `unshared`.
    key: Vec<u8>,
    unshared: Range<usize>,
    value: Range<usize>,
}

/// A decoded block.
struct Decoded<'c> {
    contents: Contents<'c>,
    entries: Vec<Entry>,
    /// The restart offsets and their count.
    restarts: Range<usize>,
}

impl Decoded<'_> {
    fn value(&self, entry: &Entry) -> &[u8] {
        &self.contents.bytes()[entry.value.clone()]
    }
}

/// A block handle at `i`: the range of the block's contents, and the position after.
fn handle(b: &[u8], i: usize) -> Option<(Range<usize>, usize)> {
    let (offset, at) = leb128(b, i, 10)?;
    let (size, at) = leb128(b, at, 10)?;
    let start = usize::try_from(offset).ok()?;
    Some((start..start.checked_add(usize::try_from(size).ok()?)?, at))
}

/// The block whose contents are `contents`, when it and its trailer end before `end`.
fn block_at(c: &[u8], contents: Range<usize>, role: Role, end: usize) -> Option<Block> {
    if contents.start > contents.end || contents.end.checked_add(TRAILER)? > end {
        return None;
    }
    let trailer = &c[contents.end..contents.end + TRAILER];
    let stored = u32::from_le_bytes(trailer[1..].try_into().ok()?);
    Some(Block {
        role,
        compression: trailer[0],
        crc_ok: masked_crc(&c[contents.start..=contents.end]) == stored,
        contents,
    })
}

impl Table {
    /// The blocks of the table `c`, from its footer, index and metaindex; `None`
    /// when it has no table footer.
    pub(super) fn read(c: &[u8]) -> Option<Table> {
        let footer_start = c.len().checked_sub(FOOTER)?;
        let footer = &c[footer_start..];
        if footer[FOOTER - TABLE_MAGIC.len()..] != TABLE_MAGIC {
            return None;
        }
        let (meta, at) = handle(footer, 0)?;
        let (index, _) = handle(footer, at)?;
        let mut blocks = Vec::new();
        let mut index_ok = false;
        for (contents, role) in [(index, Role::Index), (meta, Role::Metaindex)] {
            let Some(block) = block_at(c, contents, role, footer_start) else {
                continue;
            };
            if let Some(decoded) = decode(c, &block) {
                index_ok |= role == Role::Index;
                for (n, entry) in decoded.entries.iter().enumerate() {
                    let role = match role {
                        Role::Index => Role::Data(n + 1),
                        _ if entry.key.starts_with(b"filter.") => Role::Filter,
                        _ => continue,
                    };
                    if let Some((contents, _)) = handle(decoded.value(entry), 0)
                        && let Some(b) = block_at(c, contents, role, footer_start)
                    {
                        blocks.push(b);
                    }
                }
            }
            blocks.push(block);
        }
        // A corrupt handle can point into another block: the first by offset is kept.
        blocks.sort_by_key(|b| b.contents.start);
        let mut end = 0;
        blocks.retain(|b| {
            let keep = b.contents.start >= end;
            if keep {
                end = b.contents.end + TRAILER;
            }
            keep
        });
        Some(Table {
            blocks,
            footer: footer_start..c.len(),
            index_ok,
        })
    }

    /// What each of `offsets` falls in; each block is decoded once.
    pub(super) fn locate_many(&self, c: &[u8], offsets: &[usize]) -> Vec<Option<Inspection>> {
        let mut decoded: HashMap<usize, Option<Decoded>> = HashMap::new();
        offsets
            .iter()
            .map(|&offset| self.locate(c, offset, &mut decoded))
            .collect()
    }

    fn locate<'c>(
        &self,
        c: &'c [u8],
        offset: usize,
        cache: &mut HashMap<usize, Option<Decoded<'c>>>,
    ) -> Option<Inspection> {
        if self.footer.contains(&offset) {
            return Some(found("table footer".into(), json!({ "block": "footer" })));
        }
        let k = self.blocks.partition_point(|b| b.contents.start <= offset);
        let Some(block) = k
            .checked_sub(1)
            .map(|k| &self.blocks[k])
            .filter(|b| offset < b.contents.end + TRAILER)
        else {
            return Some(self.unlocated());
        };
        let k = k - 1;
        let label = block.role.label();
        let mut detail = Map::new();
        detail.insert("block".into(), block.role.kind().into());
        if let Role::Data(n) = block.role {
            detail.insert("block_number".into(), n.into());
        }
        detail.insert("compression".into(), block.compression().into());
        let named = |note: &str, part: &str, mut detail: Map<String, Value>| {
            detail.insert("part".into(), part.into());
            Some(found(format!("{label}  ({note})"), Value::Object(detail)))
        };
        if (block.contents.end..block.contents.end + TRAILER).contains(&offset) {
            return named("block trailer: compression type and CRC", "trailer", detail);
        }
        if block.role == Role::Filter {
            return named(
                "a Bloom filter of the keys: no keys or values",
                "filter",
                detail,
            );
        }
        if !block.crc_ok {
            return named("its CRC does not verify: not decoded", "contents", detail);
        }
        let Some(d) = cache.entry(k).or_insert_with(|| decode(c, block)) else {
            let why = match block.compression {
                0 | 1 => "does not parse as a block: not decoded".to_string(),
                n => format!("compression type {n}: not decoded"),
            };
            return named(&why, "contents", detail);
        };
        let Some(at) = d.contents.position(offset - block.contents.start) else {
            return named(
                "Snappy-compressed: in a tag or copy, not a literal run",
                "compressed",
                detail,
            );
        };
        if d.restarts.contains(&at) {
            return named("restart points", "restarts", detail);
        }
        let e = d
            .entries
            .partition_point(|e| e.range.start <= at)
            .checked_sub(1)?;
        let entry = &d.entries[e];
        if !entry.range.contains(&at) {
            return None;
        }
        let part = if entry.unshared.contains(&at) {
            "key"
        } else if entry.value.contains(&at) {
            "value"
        } else {
            "entry header"
        };
        detail.insert("entry".into(), (e + 1).into());
        detail.insert("part".into(), part.into());
        let value = d.value(entry);
        let summary = match block.role {
            Role::Data(_) => data_entry(&label, &entry.key, value, &mut detail),
            Role::Index => {
                let (user, _) = split_internal(&entry.key);
                detail.insert("key".into(), detail_bytes(user));
                detail.insert("data_block".into(), (e + 1).into());
                format!(
                    "{label}  key: {}  (data block {})",
                    quoted_bytes(user),
                    e + 1
                )
            }
            _ => {
                detail.insert("key".into(), detail_bytes(&entry.key));
                format!("{label}  {}", quoted_bytes(&entry.key))
            }
        };
        Some(found(
            format!("{summary}  (in the {part})"),
            Value::Object(detail),
        ))
    }
}

impl Table {
    /// A match in no block located: the data blocks when the index does not decode.
    fn unlocated(&self) -> Inspection {
        let (summary, block) = if self.index_ok {
            ("in no block the index names", "none")
        } else {
            (
                "data blocks, not located: the index block does not decode",
                "data",
            )
        };
        found(
            summary.into(),
            json!({ "block": block, "part": "unlocated", "index_decoded": self.index_ok }),
        )
    }
}

/// A data entry's summary, its fields added to `detail`: the user key, sequence and
/// operation from the internal key, and the value of a put.
fn data_entry(label: &str, key: &[u8], value: &[u8], detail: &mut Map<String, Value>) -> String {
    let (user, tag) = split_internal(key);
    detail.insert("key".into(), detail_bytes(user));
    let Some((sequence, kind)) = tag else {
        // Not an internal key: shown as stored.
        detail.insert("value".into(), detail_bytes(value));
        return format!(
            "{label}  key: {}  value: {}",
            quoted_bytes(user),
            quoted_bytes(value)
        );
    };
    let op = match kind {
        1 => "put".to_string(),
        0 => "delete".to_string(),
        n => format!("type {n}"),
    };
    detail.insert("sequence".into(), sequence.into());
    detail.insert("operation".into(), op.clone().into());
    let mut summary = format!(
        "{label}  sequence {sequence}  {op}  key: {}",
        quoted_bytes(user)
    );
    if kind != 0 {
        detail.insert("value".into(), detail_bytes(value));
        summary.push_str(&format!("  value: {}", quoted_bytes(value)));
    }
    summary
}

/// An internal key's user key, and its sequence number and type when it has them.
fn split_internal(key: &[u8]) -> (&[u8], Option<(u64, u8)>) {
    match key.len().checked_sub(TAG) {
        Some(at) => {
            let tag = u64::from_le_bytes(key[at..].try_into().unwrap_or_default());
            (&key[..at], Some((tag >> 8, tag as u8)))
        }
        None => (key, None),
    }
}

fn found(summary: String, detail: Value) -> Inspection {
    Inspection {
        format: "leveldb".into(),
        summary,
        detail,
    }
}

/// `block` decoded: its CRC verified, decompressed if Snappy, parsed exactly.
fn decode<'c>(c: &'c [u8], block: &Block) -> Option<Decoded<'c>> {
    if !block.crc_ok || block.role == Role::Filter {
        return None;
    }
    let stored = &c[block.contents.clone()];
    let contents = match block.compression {
        0 => Contents::Stored(stored),
        1 => Contents::Snappy(snappy::decompress(stored)?),
        _ => return None,
    };
    let (entries, restarts) = entries(contents.bytes())?;
    Some(Decoded {
        contents,
        entries,
        restarts,
    })
}

/// A block's entries and its restart array, when it parses exactly.
fn entries(b: &[u8]) -> Option<(Vec<Entry>, Range<usize>)> {
    let count_at = b.len().checked_sub(4)?;
    let count = u32::from_le_bytes(b[count_at..].try_into().ok()?);
    let restarts_at = count_at.checked_sub(usize::try_from(count).ok()?.checked_mul(4)?)?;
    let mut entries: Vec<Entry> = Vec::new();
    let mut key: Vec<u8> = Vec::new();
    let mut shared_of = Vec::new();
    let mut i = 0;
    while i < restarts_at {
        let start = i;
        let field = |at: usize| -> Option<(usize, usize)> {
            let (n, at) = leb128(b, at, 5)?;
            Some((usize::try_from(n).ok()?, at))
        };
        let (shared, at) = field(i)?;
        let (unshared, at) = field(at)?;
        let (value_len, at) = field(at)?;
        let unshared = at..at.checked_add(unshared)?;
        let value = unshared.end..unshared.end.checked_add(value_len)?;
        if shared > key.len() || value.end > restarts_at {
            return None;
        }
        key.truncate(shared);
        key.extend_from_slice(&b[unshared.clone()]);
        shared_of.push(shared);
        entries.push(Entry {
            range: start..value.end,
            key: key.clone(),
            unshared,
            value: value.clone(),
        });
        i = value.end;
    }
    // Each restart point is an entry that shares nothing (an empty block, such as a
    // metaindex without a filter, has the one restart 0).
    for r in b[restarts_at..count_at].as_chunks::<4>().0 {
        let at = usize::try_from(u32::from_le_bytes(*r)).ok()?;
        let ok = match entries.binary_search_by_key(&at, |e| e.range.start) {
            Ok(n) => shared_of[n] == 0,
            Err(_) => entries.is_empty() && at == 0,
        };
        if !ok {
            return None;
        }
    }
    Some((entries, restarts_at..b.len()))
}

#[cfg(test)]
mod tests {
    use super::super::Leveldb;
    use super::super::testing::{at, varint_bytes};
    use super::*;
    use crate::formats::inspect::Inspector;

    /// An internal key: `user`, then sequence << 8 | kind.
    fn ikey(user: &[u8], sequence: u64, kind: u8) -> Vec<u8> {
        let mut k = user.to_vec();
        k.extend_from_slice(&((sequence << 8) | u64::from(kind)).to_le_bytes());
        k
    }

    /// Block contents: `entries` prefix-compressed, a restart every 2 entries.
    fn contents(entries: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
        let mut b = Vec::new();
        let mut restarts = Vec::new();
        let mut last: &[u8] = &[];
        for (n, (key, value)) in entries.iter().enumerate() {
            let shared = if n % 2 == 0 {
                restarts.push(b.len() as u32);
                0
            } else {
                last.iter().zip(key).take_while(|(a, b)| a == b).count()
            };
            b.extend(varint_bytes(shared));
            b.extend(varint_bytes(key.len() - shared));
            b.extend(varint_bytes(value.len()));
            b.extend_from_slice(&key[shared..]);
            b.extend_from_slice(value);
            last = key;
        }
        if restarts.is_empty() {
            restarts.push(0);
        }
        for r in &restarts {
            b.extend_from_slice(&r.to_le_bytes());
        }
        b.extend_from_slice(&(restarts.len() as u32).to_le_bytes());
        b
    }

    /// Append a block (contents, type, CRC) to `f`; returns its handle.
    fn push_block(f: &mut Vec<u8>, stored: &[u8], kind: u8) -> Vec<u8> {
        let mut handle = varint_bytes(f.len());
        handle.extend(varint_bytes(stored.len()));
        f.extend_from_slice(stored);
        f.push(kind);
        let crc = masked_crc(&f[f.len() - stored.len() - 1..]);
        f.extend_from_slice(&crc.to_le_bytes());
        handle
    }

    /// Snappy for `b` as one literal run (valid, if not compressed).
    fn snappy_literal(b: &[u8]) -> Vec<u8> {
        let mut s = varint_bytes(b.len());
        let n = b.len() - 1;
        assert!(n < 1 << 16);
        s.extend_from_slice(&[61 << 2, n as u8, (n >> 8) as u8]);
        s.extend_from_slice(b);
        s
    }

    /// A table: one stored data block, one Snappy data block, an empty metaindex.
    fn table() -> Vec<u8> {
        let mut f = Vec::new();
        let first = contents(&[
            (ikey(b"user:1", 41, 1), b"alice@example.org".to_vec()),
            (ikey(b"user:2", 42, 1), b"bob".to_vec()),
            (ikey(b"user:3", 43, 0), Vec::new()),
        ]);
        let h1 = push_block(&mut f, &first, 0);
        let second = contents(&[(ikey(b"zeta", 50, 1), b"compressed carol".to_vec())]);
        let h2 = push_block(&mut f, &snappy_literal(&second), 1);
        let meta = push_block(&mut f, &contents(&[]), 0);
        let index = contents(&[(ikey(b"user:4", 43, 1), h1), (ikey(b"zz", 50, 1), h2)]);
        let ih = push_block(&mut f, &index, 0);
        let mut footer = meta;
        footer.extend(ih);
        footer.resize(FOOTER - TABLE_MAGIC.len(), 0);
        footer.extend_from_slice(&TABLE_MAGIC);
        f.extend(footer);
        f
    }

    #[test]
    fn data_entries_resolve_to_key_sequence_and_value() {
        let f = table();
        let alice = Leveldb.inspect(&f, at(&f, b"alice")).unwrap();
        assert_eq!(
            alice.summary,
            "data block 1  sequence 41  put  key: \"user:1\"  value: \"alice@example.org\"  (in the value)"
        );
        // The second key shares "user:" with the first: a match in its own byte
        // shows the whole key.
        let bob = Leveldb.inspect(&f, at(&f, b"2")).unwrap();
        assert_eq!(bob.detail["key"], "user:2");
        assert_eq!(bob.detail["part"], "key");
        let deleted = Leveldb.inspect(&f, at(&f, b"user:3")).unwrap();
        assert_eq!(deleted.detail["operation"], "delete");
        assert_eq!(deleted.detail["sequence"], 43);
    }

    #[test]
    fn a_snappy_block_maps_a_literal_to_its_entry() {
        let f = table();
        let carol = Leveldb.inspect(&f, at(&f, b"carol")).unwrap();
        assert_eq!(carol.detail["compression"], "snappy");
        assert_eq!(carol.detail["block_number"], 2);
        assert_eq!(carol.detail["value"], "compressed carol");
        // The literal's tag is not text.
        let tag = at(&f, &[61 << 2]);
        assert!(
            Leveldb
                .inspect(&f, tag)
                .unwrap()
                .summary
                .contains("not a literal run"),
            "{:?}",
            Leveldb.inspect(&f, tag)
        );
    }

    #[test]
    fn index_footer_and_trailers_are_named() {
        let f = table();
        let index = Leveldb.inspect(&f, at(&f, b"zz")).unwrap();
        assert_eq!(
            index.summary,
            "index block  key: \"zz\"  (data block 2)  (in the key)"
        );
        assert_eq!(
            Leveldb.inspect(&f, f.len() - 1).unwrap().summary,
            "table footer"
        );
        let t = Table::read(&f).unwrap();
        let first = &t.blocks[0];
        let found = Leveldb.inspect(&f, first.contents.end).unwrap();
        assert_eq!(found.detail["part"], "trailer");
    }

    #[test]
    fn a_block_whose_crc_fails_is_not_decoded() {
        let mut f = table();
        let a = at(&f, b"alice");
        f[a] = b'A';
        let found = Leveldb.inspect(&f, a + 1).unwrap();
        assert!(
            found.summary.contains("CRC does not verify"),
            "{}",
            found.summary
        );
        assert!(found.detail.get("key").is_none());
    }

    #[test]
    fn a_table_whose_index_fails_names_its_data_blocks() {
        let mut f = table();
        let zz = at(&f, b"zz");
        f[zz] = b'Z';
        let found = Leveldb.inspect(&f, at(&f, b"alice")).unwrap();
        assert_eq!(found.detail["part"], "unlocated");
        assert_eq!(found.detail["index_decoded"], false);
        assert!(found.summary.contains("not located"), "{}", found.summary);
    }

    #[test]
    fn a_long_value_is_cut_in_the_detail() {
        let mut f = Vec::new();
        let long = vec![b'v'; crate::formats::inspect::DETAIL_CHARS + 10];
        let data = contents(&[(ikey(b"k", 1, 1), long)]);
        let h = push_block(&mut f, &data, 0);
        let meta = push_block(&mut f, &contents(&[]), 0);
        let ih = push_block(&mut f, &contents(&[(ikey(b"l", 1, 1), h)]), 0);
        let mut footer = meta;
        footer.extend(ih);
        footer.resize(FOOTER - TABLE_MAGIC.len(), 0);
        footer.extend_from_slice(&TABLE_MAGIC);
        f.extend(footer);
        let found = Leveldb.inspect(&f, at(&f, b"vvvv")).unwrap();
        assert_eq!(found.detail["value"]["truncated"], true);
        assert_eq!(found.detail["key"], "k");
    }

    #[test]
    fn corrupt_tables_never_panic() {
        let f = table();
        for i in 0..f.len() {
            for b in [0x00, 0x7F, 0x80, 0xFF] {
                let mut g = f.clone();
                g[i] = b;
                let offsets: Vec<usize> = (0..g.len()).step_by(7).collect();
                let _ = Leveldb.inspect_many(&g, &offsets);
            }
        }
    }
}
