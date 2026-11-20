//! LevelDB logs (`*.log`: write batches) and manifests (`MANIFEST-*`: version
//! edits): a byte offset to its record and entry, the key and value of a put or
//! delete with its sequence number, or the version edit field.
//!
//! Defines: `read` (the records, reassembled and decoded) and `locate`.
//! Used by: `leveldb` (the inspector).
//! Uses: `leveldb::masked_crc`, `inspect::{leb128, quoted_bytes}`.
//!
//! ── Format (LevelDB's `log_format.md`, `write_batch.cc`, `version_edit.cc`) ──
//! The file is 32 KiB blocks of physical records: masked CRC-32C (u32), payload
//! length (u16), type (1 full, 2 first, 3 middle, 4 last) and the payload; fewer
//! than 7 bytes left in a block are padding. A logical record is one full record or a
//! first … last run. In a log it is a write batch: sequence (u64), count (u32), then
//! entries: 1 put (key, value) or 0 delete (key), lengths as varints. In a manifest
//! it is a version edit: tagged fields (1 comparator, 2 log number, 3 next file, 4
//! last sequence, 5 compact pointer, 6 deleted file, 7 new file, 9 previous log).
//!
//! A record is read only when its CRC verifies, as LevelDB's reader requires; the
//! first record that does not (or an unknown type) ends the reading, so bytes left
//! from an earlier use of the file are never shown as records. Checked on every log
//! and manifest of two Android test devices (1,029 files): each record that
//! verifies decodes exactly as a write batch or version edit.

use std::ops::Range;

use serde_json::json;

use super::masked_crc;
use crate::core::models::Inspection;
use crate::formats::inspect::{leb128, quoted_bytes};

pub(super) const BLOCK: usize = 32 * 1024;
pub(super) const RECORD_HEADER: usize = 7;

/// One logical record: its bytes reassembled, where each fragment's payload lies in
/// the file, and what it decodes to.
#[derive(Debug)]
struct Record {
    /// 1-based, in file order.
    number: usize,
    bytes: Vec<u8>,
    /// `(payload in the file, its start within `bytes`)`, in order.
    fragments: Vec<(Range<usize>, usize)>,
    items: Vec<Item>,
}

/// A decoded part of a record, as a range within the record's bytes.
#[derive(Debug)]
enum Item {
    /// A write batch's sequence and entry count.
    BatchHeader {
        range: Range<usize>,
        sequence: u64,
        count: u32,
    },
    /// A put (with its value) or a delete, and its sequence number.
    Entry {
        range: Range<usize>,
        sequence: u64,
        key: Range<usize>,
        value: Option<Range<usize>>,
    },
    /// A version edit field; `key` is a key it holds (comparator name, file bounds).
    Field {
        range: Range<usize>,
        name: &'static str,
        text: String,
        key: Option<Range<usize>>,
    },
}

impl Item {
    fn range(&self) -> &Range<usize> {
        match self {
            Item::BatchHeader { range, .. }
            | Item::Entry { range, .. }
            | Item::Field { range, .. } => range,
        }
    }
}

/// What a byte range of the file is.
#[derive(Debug)]
enum Part {
    /// A physical record's 7-byte header.
    Header(usize),
    /// Payload: the record (index into `Log::records`) and the start within it.
    Payload(usize, usize),
}

#[derive(Debug, Default)]
pub(super) struct Log {
    records: Vec<Record>,
    /// File ranges, sorted and not overlapping.
    parts: Vec<(Range<usize>, Part)>,
}

/// Read the physical records, reassemble the logical ones, and decode them.
pub(super) fn read(c: &[u8]) -> Log {
    // No up-front check: every record's CRC is verified below, so a table (or any
    // other file) stops at its first "record".
    let mut log = Log::default();
    let mut pending: Option<Record> = None;
    let mut pos = 0;
    while pos + RECORD_HEADER <= c.len() {
        let left = BLOCK - pos % BLOCK;
        if left < RECORD_HEADER {
            pos += left; // block trailer
            continue;
        }
        let len = usize::from(u16::from_le_bytes([c[pos + 4], c[pos + 5]]));
        let kind = c[pos + 6];
        if kind == 0 && len == 0 {
            pos += left; // zeroed (preallocated) space
            continue;
        }
        let payload = pos + RECORD_HEADER..pos + RECORD_HEADER + len;
        let Some(body) = c.get(payload.clone()) else {
            break;
        };
        let stored = u32::from_le_bytes([c[pos], c[pos + 1], c[pos + 2], c[pos + 3]]);
        if masked_crc(&c[pos + 6..payload.end]) != stored {
            break;
        }
        let number = log.records.len() + 1;
        let record = match (kind, pending.take()) {
            (1 | 2, None) => Record {
                number,
                bytes: Vec::new(),
                fragments: Vec::new(),
                items: Vec::new(),
            },
            (3 | 4, Some(r)) => r,
            _ => break, // a fragment out of sequence
        };
        let mut record = record;
        let index = log.records.len();
        log.parts.push((pos..payload.start, Part::Header(index)));
        log.parts
            .push((payload.clone(), Part::Payload(index, record.bytes.len())));
        record.fragments.push((payload.clone(), record.bytes.len()));
        record.bytes.extend_from_slice(body);
        if matches!(kind, 1 | 4) {
            log.records.push(record);
        } else {
            pending = Some(record);
        }
        pos = payload.end;
    }
    // A record still pending at the end is incomplete: its parts are dropped.
    let complete = log.records.len();
    log.parts
        .retain(|(_, p)| matches!(p, Part::Header(i) | Part::Payload(i, _) if *i < complete));
    // A log holds write batches, a manifest version edits: the first record decides.
    let batches = log
        .records
        .first()
        .is_some_and(|r| batch(&r.bytes).is_some());
    for record in &mut log.records {
        record.items = if batches {
            batch(&record.bytes)
        } else {
            edit(&record.bytes)
        }
        .unwrap_or_default();
    }
    log
}

/// A varint length and the bytes it counts, at `i`.
fn sized(b: &[u8], i: usize) -> Option<(Range<usize>, usize)> {
    let (n, at) = leb128(b, i, 10)?;
    let range = at..at.checked_add(usize::try_from(n).ok()?)?;
    (range.end <= b.len()).then(|| (range.clone(), range.end))
}

/// A write batch's items, when the record is exactly one.
fn batch(r: &[u8]) -> Option<Vec<Item>> {
    let sequence = u64::from_le_bytes(r.get(..8)?.try_into().ok()?);
    let count = u32::from_le_bytes(r.get(8..12)?.try_into().ok()?);
    let mut items = vec![Item::BatchHeader {
        range: 0..12,
        sequence,
        count,
    }];
    let mut i = 12;
    for n in 0..u64::from(count) {
        let start = i;
        let tag = *r.get(i)?;
        let (key, at) = sized(r, i + 1)?;
        let (value, at) = match tag {
            1 => {
                let (value, at) = sized(r, at)?;
                (Some(value), at)
            }
            0 => (None, at),
            _ => return None,
        };
        i = at;
        items.push(Item::Entry {
            range: start..i,
            sequence: sequence.wrapping_add(n),
            key,
            value,
        });
    }
    (i == r.len()).then_some(items)
}

/// A version edit's fields, when the record is exactly one.
fn edit(r: &[u8]) -> Option<Vec<Item>> {
    let mut items = Vec::new();
    let mut i = 0;
    while i < r.len() {
        let start = i;
        let (tag, at) = leb128(r, i, 10)?;
        let number = |at: usize| leb128(r, at, 10);
        let (name, text, key, end) = match tag {
            1 => {
                let (key, at) = sized(r, at)?;
                ("comparator", String::new(), Some(key), at)
            }
            2 | 3 | 4 | 9 => {
                let (n, at) = number(at)?;
                let name = match tag {
                    2 => "log number",
                    3 => "next file number",
                    4 => "last sequence",
                    _ => "previous log number",
                };
                (name, n.to_string(), None, at)
            }
            5 => {
                let (level, at) = number(at)?;
                let (key, at) = sized(r, at)?;
                ("compact pointer", format!("level {level}"), Some(key), at)
            }
            6 => {
                let (level, at) = number(at)?;
                let (file, at) = number(at)?;
                ("deleted file", format!("#{file} level {level}"), None, at)
            }
            7 => {
                let (level, at) = number(at)?;
                let (file, at) = number(at)?;
                let (size, at) = number(at)?;
                let (smallest, at) = sized(r, at)?;
                let (largest, at) = sized(r, at)?;
                // The key in the field is the one the match falls in, else the first.
                let text = format!("#{file} level {level} {size} bytes");
                items.push(Item::Field {
                    range: start..largest.start,
                    name: "new file (smallest key)",
                    text: text.clone(),
                    key: Some(smallest),
                });
                items.push(Item::Field {
                    range: largest.start..at,
                    name: "new file (largest key)",
                    text,
                    key: Some(largest),
                });
                i = at;
                continue;
            }
            _ => return None,
        };
        items.push(Item::Field {
            range: start..end,
            name,
            text,
            key,
        });
        i = end;
    }
    Some(items)
}

pub(super) fn locate(log: &Log, offset: usize) -> Option<Inspection> {
    let i = log.parts.partition_point(|(r, _)| r.start <= offset);
    let (range, part) = log.parts.get(i.checked_sub(1)?)?;
    if !range.contains(&offset) {
        return None;
    }
    let found = |summary: String, detail: serde_json::Value| Inspection {
        format: "leveldb".into(),
        summary,
        detail,
    };
    let (index, at) = match part {
        Part::Header(index) => {
            let n = log.records[*index].number;
            return Some(found(
                format!("record {n}  (record header)"),
                json!({ "record": n, "part": "header" }),
            ));
        }
        Part::Payload(index, start) => (*index, start + (offset - range.start)),
    };
    let record = &log.records[index];
    let n = record.number;
    let Some(item) = record.items.iter().find(|item| item.range().contains(&at)) else {
        return Some(found(
            format!("record {n}  (not decoded)"),
            json!({ "record": n }),
        ));
    };
    let bytes = &record.bytes;
    Some(match item {
        Item::BatchHeader {
            sequence, count, ..
        } => found(
            format!("record {n}  write batch: sequence {sequence}, {count} entries"),
            json!({ "record": n, "sequence": sequence, "count": count }),
        ),
        Item::Entry {
            sequence,
            key,
            value,
            ..
        } => {
            let part = if key.contains(&at) {
                "key"
            } else if value.as_ref().is_some_and(|v| v.contains(&at)) {
                "value"
            } else {
                "entry header"
            };
            let key_text = quoted_bytes(&bytes[key.clone()]);
            let (op, value_text) = match value {
                Some(v) => ("put", Some(quoted_bytes(&bytes[v.clone()]))),
                None => ("delete", None),
            };
            let mut summary = format!("record {n}  sequence {sequence}  {op}  key: {key_text}");
            if let Some(v) = &value_text {
                summary.push_str(&format!("  value: {v}"));
            }
            summary.push_str(&format!("  (in the {part})"));
            found(
                summary,
                json!({
                    "record": n, "sequence": sequence, "operation": op, "part": part,
                    "key": String::from_utf8_lossy(&bytes[key.clone()]),
                    "value": value.as_ref().map(|v| String::from_utf8_lossy(&bytes[v.clone()])),
                }),
            )
        }
        Item::Field {
            name, text, key, ..
        } => {
            let key_text = key.as_ref().map(|k| quoted_bytes(&bytes[k.clone()]));
            let mut summary = format!("record {n}  version edit: {name}");
            if !text.is_empty() {
                summary.push_str(&format!("  {text}"));
            }
            if let Some(k) = &key_text {
                summary.push_str(&format!("  {k}"));
            }
            found(
                summary,
                json!({ "record": n, "field": name, "value": text,
                        "key": key.as_ref().map(|k| String::from_utf8_lossy(&bytes[k.clone()])) }),
            )
        }
    })
}

#[cfg(test)]
mod tests {
    use super::super::Leveldb;
    use super::super::testing::{at, varint_bytes};
    use super::*;
    use crate::formats::inspect::Inspector;

    /// A physical record: header with a valid masked CRC, then the payload.
    fn physical(kind: u8, payload: &[u8]) -> Vec<u8> {
        let mut covered = vec![kind];
        covered.extend_from_slice(payload);
        let crc = masked_crc(&covered);
        let mut r = crc.to_le_bytes().to_vec();
        r.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        r.extend_from_slice(&covered);
        r
    }

    /// A write batch of `(key, Some(value))` puts and `(key, None)` deletes.
    fn write_batch(sequence: u64, entries: &[(&[u8], Option<&[u8]>)]) -> Vec<u8> {
        let mut b = sequence.to_le_bytes().to_vec();
        b.extend_from_slice(&(entries.len() as u32).to_le_bytes());
        for (key, value) in entries {
            b.push(u8::from(value.is_some()));
            b.push(key.len() as u8);
            b.extend_from_slice(key);
            if let Some(v) = value {
                b.push(v.len() as u8);
                b.extend_from_slice(v);
            }
        }
        b
    }

    #[test]
    fn log_entries_resolve_to_key_value_and_sequence() {
        let mut f = physical(
            1,
            &write_batch(41, &[(b"user:1", Some(b"alice@example.org"))]),
        );
        f.extend(physical(
            1,
            &write_batch(42, &[(b"user:2", Some(b"bob")), (b"user:1", None)]),
        ));
        assert!(Leveldb.detect(&f));

        let alice = Leveldb.inspect(&f, at(&f, b"alice")).unwrap();
        assert_eq!(
            alice.summary,
            "record 1  sequence 41  put  key: \"user:1\"  value: \"alice@example.org\"  (in the value)"
        );
        // The second entry of a batch has the batch's sequence plus one.
        let deleted = Leveldb.inspect(&f, f.len() - 2).unwrap();
        assert_eq!(deleted.detail["operation"], "delete");
        assert_eq!(deleted.detail["sequence"], 43);
        assert_eq!(
            Leveldb.inspect(&f, 2).unwrap().summary,
            "record 1  (record header)"
        );
    }

    #[test]
    fn a_record_split_across_blocks_is_reassembled() {
        // One put whose 40,000-byte value ends in "TAIL", too big for one block: its
        // first fragment fills block 0 but for a 3-byte trailer, its last starts block 1.
        let mut value = vec![b'x'; 39_996];
        value.extend_from_slice(b"TAIL");
        let mut batch = 7u64.to_le_bytes().to_vec();
        batch.extend_from_slice(&1u32.to_le_bytes());
        batch.extend_from_slice(&[1, 1, b'k']);
        batch.extend(varint_bytes(value.len()));
        batch.extend_from_slice(&value);
        let first = BLOCK - RECORD_HEADER - 3;
        let mut f = physical(2, &batch[..first]);
        f.resize(BLOCK, 0); // the trailer: under 7 bytes left in the block
        f.extend(physical(4, &batch[first..]));

        let tail = Leveldb.inspect(&f, at(&f, b"TAIL")).unwrap();
        assert_eq!(tail.detail["record"], 1);
        assert_eq!(tail.detail["part"], "value");
        assert_eq!(tail.detail["sequence"], 7);
        // A match in the first fragment maps to the same record.
        let head = Leveldb.inspect(&f, 100).unwrap();
        assert_eq!(head.detail["part"], "value");
    }

    #[test]
    fn manifest_fields_resolve() {
        // Comparator, then a new file: level 0, #5, 2048 bytes, smallest and largest
        // internal keys (user key + 8 bytes of sequence and type), each length-prefixed.
        let mut edit = vec![1, 26];
        edit.extend_from_slice(b"leveldb.BytewiseComparator");
        edit.extend_from_slice(&[7, 0, 5, 0x80, 0x10]);
        edit.push(11);
        edit.extend_from_slice(b"aaa\x01\x00\x00\x00\x00\x00\x00\x01");
        edit.push(11);
        edit.extend_from_slice(b"zzz\x01\x00\x00\x00\x00\x00\x00\x01");
        let f = physical(1, &edit);
        let cmp = Leveldb.inspect(&f, at(&f, b"Bytewise")).unwrap();
        assert_eq!(cmp.detail["field"], "comparator");
        let smallest = Leveldb.inspect(&f, at(&f, b"aaa")).unwrap();
        assert_eq!(smallest.detail["field"], "new file (smallest key)");
        let largest = Leveldb.inspect(&f, at(&f, b"zzz")).unwrap();
        assert_eq!(largest.detail["field"], "new file (largest key)");
        assert!(
            largest.summary.contains("#5 level 0 2048 bytes"),
            "{}",
            largest.summary
        );
    }

    #[test]
    fn a_bad_crc_ends_the_reading() {
        let mut f = physical(1, &write_batch(1, &[(b"good", Some(b"one"))]));
        let mut bad = physical(1, &write_batch(2, &[(b"stale", Some(b"two"))]));
        bad[0] ^= 1;
        f.extend(bad);
        assert!(Leveldb.inspect(&f, at(&f, b"good")).is_some());
        assert!(Leveldb.inspect(&f, at(&f, b"stale")).is_none());
    }

    #[test]
    fn corrupt_bytes_never_panic() {
        let f = physical(
            1,
            &write_batch(9, &[(b"key", Some(b"value")), (b"gone", None)]),
        );
        for i in 0..f.len() {
            for b in [0x00, 0x80, 0xFF] {
                let mut g = f.clone();
                g[i] = b;
                let _ = Leveldb.inspect_many(&g, &[0, i, g.len() - 1]);
            }
        }
    }
}
