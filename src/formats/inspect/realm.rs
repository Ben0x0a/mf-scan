//! Realm inspector: map a byte offset in a Realm database to the class (table),
//! object and property it belongs to, with the value for a string or binary property.
//!
//! Defines: [`Realm`] (the inspector).
//! Used by: `inspect::mod` (registered in `INSPECTORS`).
//! Uses: `crate::core::models::Inspection`, `serde_json`.
//!
//! ── Format ───────────────────────────────────────────────────────────────────
//! From Realm Core's sources (spec, keys, cluster, cluster_tree, array_string*,
//! array_blobs_*: github.com/realm/realm-core, Apache-2.0), as also implemented by the
//! crush-forensics `realm_parser.py` (Apache-2.0) that iLEAPP and ALEAPP use; read as
//! documentation, not run.
//!
//! - **Header** (24 bytes): two top refs (u64), "T-DB" at 16, a file format version
//!   per top ref (bytes 20, 21), flags at 23 (bit 0 selects the live top ref). A file
//!   written in "streaming form" has top ref 0 = all ones and its real top ref in a
//!   16-byte footer (ref, then the magic 0x3034125237E526C8).
//! - **Arrays**: everything is an 8-byte-aligned array: "AAAA", a flags byte (bit 7
//!   inner B+tree node, bit 6 holds refs, bit 5 context flag, bits 4-3 width scheme:
//!   0 bits / 1 bytes / 2 byte count, bits 2-0 width index into 0,1,2,4,8,16,32,64),
//!   a big-endian 24-bit element count, then the payload.
//! - **Group** (the top array): child 0 the table names, child 1 the table refs.
//!   **Table**: child 0 its spec, child 2 its cluster tree. **Spec**: child 1 the
//!   public property names (fixed-width slots), child 5 the column keys (index in
//!   bits 0-15, type in 16-21, attributes in 22-29: 0x20 list, 0x40 dictionary,
//!   0x80 set; type 14 is a hidden backlink).
//! - **Cluster tree**: a leaf's child 0 is the object keys (a tagged count `n<<1|1`
//!   for keys 0..n, or a ref to the keys), and column `i`'s values are at child
//!   `i + 1`. An inner node holds key offsets (or 0), the tagged depth and size, then
//!   its children; a child's keys are offset by its explicit offset, or by
//!   `index << (depth * 8)`.
//! - **String / binary leaves**: no refs → inline fixed-width slots whose last byte
//!   is the padding (equal to the width for null); refs, no context flag → offsets,
//!   blob and nulls (each value ends at its offset); refs and context flag → one blob
//!   ref per value.
//!
//! Only file format 10 and later (the cluster layout) is decoded: an older file is
//! named, with its version, but its objects are not mapped. Values are decoded for
//! string and binary properties; a match in another property's data resolves to
//! its class and property.
//!
//! What was checked: the only Realm files of the test file systems (two, from one
//! Android app, format 24). Every byte of both resolves: header, class and property
//! names, schema, cluster nodes, property data, other live structure, and the free
//! list (space an earlier version used, checked to hold every array the live tree no
//! longer reaches). Neither file holds an object with a string value, so the value
//! decoding is checked only on synthetic files built to the layouts above. Anything
//! that does not fit those layouts is left unresolved, never guessed.

use std::collections::HashSet;
use std::ops::Range;

use serde_json::json;

use crate::core::models::Inspection;

const MNEMONIC: &[u8; 4] = b"T-DB";
const HEADER: usize = 24;
const STREAMING_FOOTER_MAGIC: u64 = 0x3034_1252_37E5_26C8;
/// The first file format with the cluster layout decoded here.
const MIN_CLUSTER_FORMAT: u8 = 10;
const WIDTHS: [usize; 8] = [0, 1, 2, 4, 8, 16, 32, 64];
const MAX_TREE_DEPTH: usize = 32;
/// The most arrays walked in one file, against a corrupt or crafted ref web.
const MAX_ARRAYS: usize = 2_000_000;
/// Column type codes (low 6 bits of the type field of a column key).
const TYPE_STRING: u8 = 2;
const TYPE_BINARY: u8 = 4;
const TYPE_BACKLINK: u8 = 14;
/// Column key attribute bits that make a property a collection.
const ATTR_COLLECTION: u8 = 0x20 | 0x40 | 0x80;

/// Realm inspector — recognised by "T-DB" at offset 16.
pub struct Realm;

impl super::Inspector for Realm {
    fn name(&self) -> &'static str {
        "realm"
    }
    fn category(&self) -> &'static str {
        "database"
    }
    /// None: recognised by its header only (an encrypted Realm has no readable
    /// header, and its name would prove nothing).
    fn extensions(&self) -> &'static [&'static str] {
        &[]
    }
    fn detect(&self, content: &[u8]) -> bool {
        content.get(16..20) == Some(MNEMONIC)
    }
    fn inspect(&self, content: &[u8], offset: usize) -> Option<Inspection> {
        self.inspect_many(content, &[offset]).pop().flatten()
    }
    /// The file is walked once; each match is then a lookup.
    fn inspect_many(&self, content: &[u8], offsets: &[usize]) -> Vec<Option<Inspection>> {
        let layout = read(content);
        offsets
            .iter()
            .map(|&o| locate(content, layout.as_ref(), o))
            .collect()
    }
}

/// One array of the file, decoded from its header.
#[derive(Debug, Clone, Copy)]
struct Arr {
    start: usize,
    has_refs: bool,
    inner: bool,
    context: bool,
    scheme: u8,
    width: usize,
    size: usize,
    end: usize,
}

/// The array at `at`, when a valid header is there and its payload fits the file.
fn arr(c: &[u8], at: usize) -> Option<Arr> {
    if at < HEADER || !at.is_multiple_of(8) {
        return None;
    }
    let h = c.get(at..at + 8)?;
    if &h[..4] != b"AAAA" {
        return None;
    }
    let flags = h[4];
    let size = (usize::from(h[5]) << 16) | (usize::from(h[6]) << 8) | usize::from(h[7]);
    let width = WIDTHS[usize::from(flags & 7)];
    let scheme = (flags >> 3) & 3;
    let payload = match scheme {
        0 => (width * size).div_ceil(8),
        1 => width.checked_mul(size)?,
        _ => size,
    };
    let end = at.checked_add(8)?.checked_add(payload)?;
    (end <= c.len()).then_some(Arr {
        start: at,
        has_refs: flags & 0x40 != 0,
        inner: flags & 0x80 != 0,
        context: flags & 0x20 != 0,
        scheme,
        width,
        size,
        end,
    })
}

impl Arr {
    fn payload(&self) -> usize {
        self.start + 8
    }

    /// How many elements to walk: none when the width is 0 (the elements carry no
    /// bytes, so a corrupt count could be anything up to 2^24 at no cost to the file).
    fn len(&self) -> usize {
        if self.width == 0 { 0 } else { self.size }
    }

    /// Element `i` as an integer: bit-packed widths (0-4) are unsigned, byte widths
    /// (8-64 bits) little-endian signed, as Realm's integer arrays store them.
    fn get(&self, c: &[u8], i: usize) -> Option<i64> {
        if i >= self.size {
            return None;
        }
        match (self.scheme, self.width) {
            (0, 0) => Some(0),
            (0, w) if w < 8 => {
                let bit = i * w;
                let byte = *c.get(self.payload() + bit / 8)?;
                Some(i64::from((byte >> (bit % 8)) & ((1u8 << w) - 1)))
            }
            (0, w) => {
                let n = w / 8;
                let at = self.payload() + i * n;
                let b = c.get(at..at + n)?;
                let mut v = [0u8; 8];
                v[..n].copy_from_slice(b);
                // Sign-extend from the element's own width.
                let shift = 64 - w as u32;
                Some((i64::from_le_bytes(v) << shift) >> shift)
            }
            (1, n) => {
                let at = self.payload() + i * n;
                let b = c.get(at..at + n)?;
                let mut v = [0u8; 8];
                v[..n.min(8)].copy_from_slice(&b[..n.min(8)]);
                Some(i64::from_le_bytes(v))
            }
            _ => None,
        }
    }

    /// Element `i` as a ref: positive, even (an odd value is a tagged integer), and
    /// inside the file.
    fn child(&self, c: &[u8], i: usize) -> Option<usize> {
        let v = usize::try_from(self.get(c, i)?).ok()?;
        (v > 0 && v.is_multiple_of(2) && v < c.len()).then_some(v)
    }
}

/// A class (table) and its properties.
#[derive(Debug)]
struct Table {
    /// As stored, e.g. `class_Mailbox`.
    name: String,
    columns: Vec<Column>,
}

#[derive(Debug, Clone)]
struct Column {
    name: String,
    type_code: u8,
    attrs: u8,
    /// Position of the column's values in a cluster leaf, minus one.
    index: usize,
}

/// What a range of bytes is.
#[derive(Debug, Clone)]
enum What {
    /// Part of the file's structure (group, table list, cluster node, …).
    Structure(&'static str),
    /// The names of the classes.
    ClassNames,
    /// The schema of a table: its spec, property names, column keys.
    Schema(usize),
    /// The object keys of a table.
    Keys(usize),
    /// A property's values, not split by object (not a string or binary column).
    ColumnData(usize, usize),
    /// One object's value of a string or binary property.
    Value {
        table: usize,
        column: usize,
        /// `None` when the key could not be read (damaged key array or offsets).
        object: Option<i64>,
    },
}

/// A parsed Realm file: every array walked, and every string or binary value, as
/// byte ranges sorted by start (arrays never overlap one another, nor do values).
#[derive(Debug)]
struct Layout {
    format: u8,
    tables: Vec<Table>,
    arrays: Vec<(Range<usize>, What)>,
    values: Vec<(Range<usize>, What)>,
    /// The free list: space released by earlier versions (copy-on-write), sorted.
    free: Vec<Range<usize>>,
}

/// Walk the file from its live top ref. `None` when the header is not a Realm's.
fn read(c: &[u8]) -> Option<Layout> {
    if c.len() < HEADER || c.get(16..20) != Some(MNEMONIC) {
        return None;
    }
    let active = usize::from(c[23] & 1);
    let format = c[20 + active];
    let mut top = u64::from_le_bytes(c[8 * active..8 * active + 8].try_into().ok()?);
    if active == 0 && top == u64::MAX {
        // Streaming form: the real top ref is in the footer.
        let footer = c.get(c.len().checked_sub(16)?..)?;
        let magic = u64::from_le_bytes(footer[8..16].try_into().ok()?);
        if magic != STREAMING_FOOTER_MAGIC {
            return None;
        }
        top = u64::from_le_bytes(footer[..8].try_into().ok()?);
    }
    let mut walk = Walk {
        c,
        layout: Layout {
            format,
            tables: Vec::new(),
            arrays: Vec::new(),
            values: Vec::new(),
            free: Vec::new(),
        },
        seen: HashSet::new(),
    };
    if format >= MIN_CLUSTER_FORMAT
        && let Ok(top) = usize::try_from(top)
    {
        walk.group(top);
        walk.free_list(top);
        walk.rest(top);
    }
    let mut layout = walk.layout;
    layout.arrays.sort_by_key(|(r, _)| r.start);
    layout.values.sort_by_key(|(r, _)| r.start);
    Some(layout)
}

struct Walk<'c> {
    c: &'c [u8],
    layout: Layout,
    seen: HashSet<usize>,
}

impl Walk<'_> {
    /// The array at `at`, recorded as `what` — once: a ref seen before (a loop, or
    /// shared structure) is not walked again.
    fn visit(&mut self, at: usize, what: What) -> Option<Arr> {
        if self.seen.len() >= MAX_ARRAYS || !self.seen.insert(at) {
            return None;
        }
        let a = arr(self.c, at)?;
        self.layout
            .arrays
            .push((a.start..allocated_end(self.c, &a), what));
        Some(a)
    }

    fn group(&mut self, top: usize) {
        let Some(group) = self
            .visit(top, What::Structure("group"))
            .filter(|a| a.has_refs)
        else {
            return;
        };
        let names = group
            .child(self.c, 0)
            .map(|at| self.strings(at, What::ClassNames, |_| What::ClassNames))
            .unwrap_or_default();
        let Some(list) = group
            .child(self.c, 1)
            .and_then(|at| self.visit(at, What::Structure("table list")))
        else {
            return;
        };
        for t in 0..list.len() {
            let name = names
                .get(t)
                .cloned()
                .flatten()
                .unwrap_or_else(|| format!("table{t}"));
            self.layout.tables.push(Table {
                name,
                columns: Vec::new(),
            });
            if let Some(at) = list.child(self.c, t) {
                self.table(t, at);
            }
        }
    }

    /// The free list (group slots 3 and 4: positions and lengths). Realm writes copy
    /// on write, so these ranges hold earlier versions' arrays until reused.
    fn free_list(&mut self, top: usize) {
        let c = self.c;
        let Some(group) = arr(c, top) else {
            return;
        };
        let (Some(pos), Some(len)) = (
            group.child(c, 3).and_then(|at| arr(c, at)),
            group.child(c, 4).and_then(|at| arr(c, at)),
        ) else {
            return;
        };
        for i in 0..pos.len().min(len.len()) {
            let (Some(p), Some(l)) = (pos.get(c, i), len.get(c, i)) else {
                continue;
            };
            if let (Ok(p), Ok(l)) = (usize::try_from(p), usize::try_from(l)) {
                self.layout.free.push(p..p.saturating_add(l));
            }
        }
        self.layout.free.sort_by_key(|r| r.start);
    }

    /// Every other array reachable from the live top (free-list arrays, a spec's
    /// type and attribute arrays, history, …): live structure not decoded above.
    fn rest(&mut self, top: usize) {
        let mut stack = vec![top];
        let mut reached = HashSet::new();
        while let Some(at) = stack.pop() {
            if reached.len() >= MAX_ARRAYS || !reached.insert(at) {
                continue;
            }
            let Some(a) = arr(self.c, at) else {
                continue;
            };
            if !self.seen.contains(&at) {
                self.seen.insert(at);
                let range = a.start..allocated_end(self.c, &a);
                self.layout
                    .arrays
                    .push((range, What::Structure("other structure")));
            }
            if a.has_refs {
                stack.extend((0..a.len()).filter_map(|i| a.child(self.c, i)));
            }
        }
    }

    fn table(&mut self, t: usize, at: usize) {
        let Some(table) = self.visit(at, What::Schema(t)).filter(|a| a.has_refs) else {
            return;
        };
        if let Some(spec) = table.child(self.c, 0) {
            self.spec(t, spec);
        }
        if let Some(root) = table.child(self.c, 2) {
            self.cluster(t, root, Some(0), 0);
        }
    }

    /// Property names (public columns only) and column keys (all columns, hidden
    /// backlinks included): the visible columns pair up with the names in order.
    fn spec(&mut self, t: usize, at: usize) {
        let Some(spec) = self
            .visit(at, What::Schema(t))
            .filter(|a| a.has_refs && a.size >= 6)
        else {
            return;
        };
        let names = spec
            .child(self.c, 1)
            .map(|at| self.strings(at, What::Schema(t), |_| What::Schema(t)))
            .unwrap_or_default();
        let Some(keys) = spec
            .child(self.c, 5)
            .and_then(|at| self.visit(at, What::Schema(t)))
        else {
            return;
        };
        let mut public = 0;
        for i in 0..keys.len() {
            let Some(key) = keys.get(self.c, i) else {
                continue;
            };
            let type_code = ((key >> 16) & 0x3F) as u8;
            if type_code == TYPE_BACKLINK {
                continue;
            }
            let name = names
                .get(public)
                .cloned()
                .flatten()
                .unwrap_or_else(|| format!("column{public}"));
            self.layout.tables[t].columns.push(Column {
                name,
                type_code,
                attrs: ((key >> 22) & 0xFF) as u8,
                index: (key & 0xFFFF) as usize,
            });
            public += 1;
        }
    }

    /// A cluster tree node: an inner node's children, or a leaf's objects.
    /// `key_base` is the subtree's object-key offset; `None` when it could not be read,
    /// and then its objects' keys are unknown rather than guessed.
    fn cluster(&mut self, t: usize, at: usize, key_base: Option<i64>, depth: usize) {
        if depth > MAX_TREE_DEPTH {
            return;
        }
        let Some(node) = self
            .visit(at, What::Structure("cluster node"))
            .filter(|a| a.has_refs)
        else {
            return;
        };
        if node.inner {
            // Slot 0: 0 for children of a compact size (offset `index << depth*8`),
            // else a ref to their explicit offsets.
            let compact = node.get(self.c, 0) == Some(0);
            let offsets = node
                .child(self.c, 0)
                .and_then(|at| self.visit(at, What::Structure("cluster key offsets")));
            let tree_depth = node.get(self.c, 1).map_or(1, |v| v >> 1).clamp(0, 7);
            for i in 3..node.len() {
                let Some(child) = node.child(self.c, i) else {
                    continue;
                };
                let n = i - 3;
                let offset = if compact {
                    Some((n as i64) << (tree_depth * 8))
                } else {
                    offsets.and_then(|o| o.get(self.c, n))
                };
                let base = key_base.zip(offset).map(|(b, o)| b.saturating_add(o));
                self.cluster(t, child, base, depth + 1);
            }
            return;
        }
        // Object keys: a tagged count (keys are the row numbers) or an array of keys,
        // read per row — never materialised, as a corrupt count can be huge. A key the
        // array does not hold (or an unreadable array) is unknown, not the row number.
        let compact = node.get(self.c, 0).is_some_and(|raw| raw & 1 == 1);
        let explicit = if compact {
            None
        } else {
            node.child(self.c, 0)
                .and_then(|at| self.visit(at, What::Keys(t)))
        };
        let c = self.c;
        let key = |row: usize| {
            let local = if compact {
                Some(row as i64)
            } else {
                explicit.and_then(|k| k.get(c, row))
            };
            key_base.zip(local).map(|(b, l)| b.saturating_add(l))
        };
        let columns = self.layout.tables[t].columns.clone();
        for (col, column) in columns.iter().enumerate() {
            let Some(data) = node.child(self.c, column.index + 1) else {
                continue;
            };
            let textual = matches!(column.type_code, TYPE_STRING | TYPE_BINARY)
                && column.attrs & ATTR_COLLECTION == 0;
            if textual {
                self.strings(data, What::ColumnData(t, col), |row| What::Value {
                    table: t,
                    column: col,
                    object: key(row),
                });
            } else {
                self.visit(data, What::ColumnData(t, col));
            }
        }
    }

    /// A string (or binary) leaf in any of its three forms: records the array(s) as
    /// `array`, each value's bytes as `value(row)`, and returns the values as text.
    fn strings(
        &mut self,
        at: usize,
        array: What,
        value: impl Fn(usize) -> What,
    ) -> Vec<Option<String>> {
        let Some(a) = self.visit(at, array.clone()) else {
            return Vec::new();
        };
        let c = self.c;
        let mut out = Vec::with_capacity(a.len().min(4096));
        let mut push = |walk: &mut Self, row: usize, range: Range<usize>, text: Option<String>| {
            if !range.is_empty() {
                walk.layout.values.push((range, value(row)));
            }
            out.push(text);
        };
        if !a.has_refs {
            // Inline fixed-width slots; the last byte is the padding.
            let w = a.width;
            for row in 0..a.len() {
                let slot = a.payload() + row * w;
                let Some(&pad) = (w > 0).then(|| c.get(slot + w - 1)).flatten() else {
                    push(self, row, 0..0, None);
                    continue;
                };
                let pad = usize::from(pad);
                if pad >= w {
                    push(self, row, 0..0, None);
                    continue;
                }
                let range = slot..slot + (w - 1 - pad);
                push(self, row, range.clone(), Some(text_of(&c[range])));
            }
        } else if !a.context {
            // Offsets, blob, nulls.
            let (Some(offsets), Some(blob)) = (
                a.child(c, 0).and_then(|at| self.visit(at, array.clone())),
                a.child(c, 1).and_then(|at| self.visit(at, array.clone())),
            ) else {
                return out;
            };
            let nulls = a.child(c, 2).and_then(|at| self.visit(at, array.clone()));
            let mut begin = 0usize;
            for row in 0..offsets.len() {
                let end = offsets.get(c, row).and_then(|e| usize::try_from(e).ok());
                let Some(end) = end.filter(|&e| e >= begin && blob.payload() + e <= blob.end)
                else {
                    break;
                };
                let null = nulls.and_then(|n| n.get(c, row)).is_some_and(|v| v != 0);
                let range = blob.payload() + begin..blob.payload() + end;
                let text = (!null).then(|| text_of(&c[range.clone()]));
                push(self, row, if null { 0..0 } else { range }, text);
                begin = end;
            }
        } else {
            // One blob per value.
            for row in 0..a.len() {
                let blob = a.child(c, row).and_then(|at| self.visit(at, array.clone()));
                match blob {
                    Some(b) => {
                        let range = b.payload()..b.payload() + b.size.min(b.end - b.payload());
                        push(self, row, range.clone(), Some(text_of(&c[range])));
                    }
                    None => push(self, row, 0..0, None),
                }
            }
        }
        out
    }
}

/// Where an array's allocation ends: Realm allocates in 8-byte units, so the padding
/// after a payload belongs to its array.
fn allocated_end(c: &[u8], a: &Arr) -> usize {
    a.end.next_multiple_of(8).min(c.len())
}

/// A value's bytes as text: a string's trailing NUL dropped, invalid UTF-8 replaced.
fn text_of(bytes: &[u8]) -> String {
    let bytes = bytes.strip_suffix(b"\0").unwrap_or(bytes);
    String::from_utf8_lossy(bytes).into_owned()
}

/// The range in `ranges` (sorted by start, not overlapping) holding `offset`.
fn holder(ranges: &[(Range<usize>, What)], offset: usize) -> Option<(&Range<usize>, &What)> {
    let i = ranges.partition_point(|(r, _)| r.start <= offset);
    let (range, what) = ranges.get(i.checked_sub(1)?)?;
    range.contains(&offset).then_some((range, what))
}

fn type_name(type_code: u8) -> &'static str {
    match type_code {
        0 => "int",
        1 => "bool",
        2 => "string",
        4 => "data",
        6 => "mixed",
        8 => "date",
        9 => "float",
        10 => "double",
        11 => "decimal128",
        12 => "link",
        13 => "linklist",
        15 => "objectId",
        16 => "typedlink",
        17 => "uuid",
        _ => "unknown",
    }
}

/// A class's display name: the table name without Realm's `class_` prefix.
fn class_name(table: &str) -> &str {
    table.strip_prefix("class_").unwrap_or(table)
}

fn locate(c: &[u8], layout: Option<&Layout>, offset: usize) -> Option<Inspection> {
    let layout = layout?;
    if offset >= c.len() {
        return None;
    }
    let v = layout.format;
    let found = |summary: String, detail: serde_json::Value| Inspection {
        format: "realm".into(),
        summary,
        detail,
    };
    if layout.format < MIN_CLUSTER_FORMAT {
        return Some(found(
            format!("Realm file format {v}  (before format 10: objects not decoded)"),
            json!({ "file_format": v }),
        ));
    }
    if offset < HEADER {
        return Some(found(
            "Realm file header".into(),
            json!({ "file_format": v, "part": "header" }),
        ));
    }
    let property = |t: usize, col: usize| {
        let table = &layout.tables[t];
        let column = &table.columns[col];
        (table, column)
    };
    if let Some((range, what)) = holder(&layout.values, offset) {
        let text = text_of(&c[range.clone()]);
        let shown = super::one_line(&text);
        match what {
            What::Value {
                table,
                column,
                object,
            } => {
                let (t, col) = property(*table, *column);
                let object_shown = object.map_or_else(|| "unknown".to_string(), |k| k.to_string());
                let value = if col.type_code == TYPE_BINARY {
                    format!("<data {} bytes>", range.len())
                } else {
                    format!("\"{shown}\"")
                };
                return Some(found(
                    format!(
                        "class: {}  property: {} [{}]  object: {object_shown}  value: {value}",
                        class_name(&t.name),
                        col.name,
                        type_name(col.type_code)
                    ),
                    json!({
                        "file_format": v,
                        "table": t.name,
                        "class": class_name(&t.name),
                        "property": col.name,
                        "type": type_name(col.type_code),
                        "object": object,
                        "offset_in_value": offset - range.start,
                    }),
                ));
            }
            What::ClassNames => {
                return Some(found(
                    format!("class name: {}  (schema)", class_name(&text)),
                    json!({ "file_format": v, "part": "class names", "table": text }),
                ));
            }
            What::Schema(t) => {
                let t = &layout.tables[*t];
                return Some(found(
                    format!(
                        "class: {}  property name: {shown}  (schema)",
                        class_name(&t.name)
                    ),
                    json!({ "file_format": v, "part": "schema", "table": t.name,
                            "property": text }),
                ));
            }
            _ => {}
        }
    }
    let (summary, detail) = match holder(&layout.arrays, offset).map(|(_, what)| what) {
        Some(What::ColumnData(t, col)) => {
            let (t, col) = property(*t, *col);
            (
                format!(
                    "class: {}  property: {} [{}]  (property data)",
                    class_name(&t.name),
                    col.name,
                    type_name(col.type_code)
                ),
                json!({ "file_format": v, "table": t.name, "class": class_name(&t.name),
                        "property": col.name, "type": type_name(col.type_code) }),
            )
        }
        Some(What::Value { .. }) => unreachable!("values are kept apart from arrays"),
        Some(What::Keys(t)) => {
            let t = &layout.tables[*t];
            (
                format!("class: {}  (object keys)", class_name(&t.name)),
                json!({ "file_format": v, "table": t.name, "part": "object keys" }),
            )
        }
        Some(What::Schema(t)) => {
            let t = &layout.tables[*t];
            (
                format!(
                    "class: {}  (schema: property names and types)",
                    class_name(&t.name)
                ),
                json!({ "file_format": v, "table": t.name, "part": "schema" }),
            )
        }
        Some(What::ClassNames) => (
            "class names  (schema)".into(),
            json!({ "file_format": v, "part": "class names" }),
        ),
        Some(What::Structure(part)) => (
            format!("Realm structure: {part}"),
            json!({ "file_format": v, "part": part }),
        ),
        None if layout.free.iter().any(|r| r.contains(&offset)) => (
            "free space  (an earlier version's data, no longer live)".into(),
            json!({ "file_format": v, "part": "free" }),
        ),
        None => (
            "not in a live object  (unused space)".into(),
            json!({ "file_format": v, "part": "unused" }),
        ),
    };
    Some(found(summary, detail))
}

#[cfg(test)]
mod tests {
    use super::super::Inspector;
    use super::*;

    /// Builds a Realm file array by array, each at an 8-byte boundary.
    struct File(Vec<u8>);

    impl File {
        fn new() -> Self {
            // Header: top refs patched by `finish`, "T-DB", format 24 twice, flags.
            let mut h = vec![0u8; 24];
            h[16..20].copy_from_slice(MNEMONIC);
            h[20] = 24;
            h[21] = 24;
            Self(h)
        }
        fn put(&mut self, flags: u8, size: usize, payload: &[u8]) -> u64 {
            let at = self.0.len();
            self.0.extend_from_slice(b"AAAA");
            self.0.push(flags);
            self.0.extend_from_slice(&(size as u32).to_be_bytes()[1..]);
            self.0.extend_from_slice(payload);
            self.0.resize(self.0.len().next_multiple_of(8), 0);
            at as u64
        }
        /// 64-bit refs (or tagged integers).
        fn refs(&mut self, items: &[u64]) -> u64 {
            let p: Vec<u8> = items.iter().flat_map(|v| v.to_le_bytes()).collect();
            self.put(0x40 | 7, items.len(), &p)
        }
        fn ints(&mut self, items: &[i64]) -> u64 {
            let p: Vec<u8> = items.iter().flat_map(|v| v.to_le_bytes()).collect();
            self.put(7, items.len(), &p)
        }
        /// Inline strings in 16-byte slots (last byte = padding; 16 = null).
        fn short(&mut self, items: &[Option<&str>]) -> u64 {
            let mut p = Vec::new();
            for item in items {
                let mut slot = [0u8; 16];
                match item {
                    Some(s) => {
                        slot[..s.len()].copy_from_slice(s.as_bytes());
                        slot[15] = (15 - s.len()) as u8;
                    }
                    None => slot[15] = 16,
                }
                p.extend_from_slice(&slot);
            }
            self.put(0x08 | 5, items.len(), &p)
        }
        fn blob(&mut self, bytes: &[u8]) -> u64 {
            self.put(0x10, bytes.len(), bytes)
        }
        fn finish(mut self, top: u64) -> Vec<u8> {
            self.0[8..16].copy_from_slice(&top.to_le_bytes());
            self.0[23] = 1; // top ref 1 is live
            self.0
        }
    }

    /// A column key: index, type, attributes.
    fn colkey(index: i64, type_code: i64) -> i64 {
        index | (type_code << 16)
    }

    /// One class `Person` with `name` (inline strings) and `bio` (small blobs),
    /// objects in two cluster leaves under an inner node, and `note` (big blobs).
    fn sample() -> Vec<u8> {
        let mut f = File::new();
        let class_names = f.short(&[Some("class_Person")]);
        let prop_names = f.short(&[Some("name"), Some("bio"), Some("note")]);
        let colkeys = f.ints(&[colkey(0, 2), colkey(1, 2), colkey(2, 4)]);
        let spec = f.refs(&[0, prop_names, 0, 0, 0, colkeys]);

        // Leaf 1: objects 0 and 1.
        let names1 = f.short(&[Some("Alice"), None]);
        let blob = f.blob(b"likes tea\0builds boats\0");
        let offs = f.ints(&[10, 23]);
        let nulls = f.ints(&[0, 0]);
        let bios1 = f.refs(&[offs, blob, nulls]);
        let note_a = f.blob(b"\x01\x02secret\x03");
        let notes1 = f.put(
            0x40 | 0x20 | 7,
            2,
            &[note_a.to_le_bytes(), 0u64.to_le_bytes()].concat(),
        );
        let leaf1 = f.refs(&[(2 << 1) | 1, names1, bios1, notes1]);
        // Leaf 2: one object, key offset 256 (compact: index 1 << 8).
        let names2 = f.short(&[Some("Bob")]);
        let blob2 = f.blob(b"plays chess\0");
        let offs2 = f.ints(&[12]);
        let nulls2 = f.ints(&[0]);
        let bios2 = f.refs(&[offs2, blob2, nulls2]);
        let notes2 = f.put(0x40 | 0x20 | 7, 1, &0u64.to_le_bytes());
        let leaf2 = f.refs(&[(1 << 1) | 1, names2, bios2, notes2]);
        let inner = f.put(
            0x80 | 0x40 | 7,
            5,
            &[0u64, (1 << 1) | 1, (3 << 1) | 1, leaf1, leaf2]
                .iter()
                .flat_map(|v| v.to_le_bytes())
                .collect::<Vec<_>>(),
        );

        let table = f.refs(&[spec, 0, inner]);
        let tables = f.refs(&[table]);
        let top = f.refs(&[class_names, tables, (4096 << 1) | 1]);
        f.finish(top)
    }

    fn at(f: &[u8], needle: &[u8]) -> usize {
        f.windows(needle.len()).position(|w| w == needle).unwrap()
    }

    #[test]
    fn values_resolve_to_class_property_and_object() {
        let f = sample();
        assert!(Realm.detect(&f));
        let get = |needle: &[u8]| Realm.inspect(&f, at(&f, needle)).unwrap();

        let alice = get(b"Alice");
        assert_eq!(
            alice.summary,
            "class: Person  property: name [string]  object: 0  value: \"Alice\""
        );
        let boats = get(b"boats");
        assert_eq!(boats.detail["property"], "bio");
        assert_eq!(boats.detail["object"], 1);
        assert!(
            boats.summary.ends_with("value: \"builds boats\""),
            "{}",
            boats.summary
        );
        // The second leaf's keys are offset by its place in the inner node.
        let chess = get(b"chess");
        assert_eq!(chess.detail["object"], 256);
        assert_eq!(chess.detail["offset_in_value"], 6);
        // A binary property, in its own blob: its size, not its bytes.
        let secret = get(b"secret");
        assert!(
            secret.summary.ends_with("object: 0  value: <data 9 bytes>"),
            "{}",
            secret.summary
        );
    }

    #[test]
    fn schema_and_header_resolve_too() {
        let f = sample();
        let class = Realm.inspect(&f, at(&f, b"Person")).unwrap();
        assert_eq!(class.summary, "class name: Person  (schema)");
        let prop = Realm.inspect(&f, at(&f, b"bio\0")).unwrap();
        assert_eq!(prop.summary, "class: Person  property name: bio  (schema)");
        assert_eq!(Realm.inspect(&f, 17).unwrap().summary, "Realm file header");
    }

    #[test]
    fn an_old_format_is_named_but_not_decoded() {
        let mut f = sample();
        f[21] = 9;
        let found = Realm.inspect(&f, at(&f, b"Alice")).unwrap();
        assert!(
            found.summary.starts_with("Realm file format 9"),
            "{}",
            found.summary
        );
    }

    #[test]
    fn corrupt_bytes_never_panic() {
        let f = sample();
        for i in 0..f.len() {
            for b in [0x00, 0x41, 0xff] {
                let mut g = f.clone();
                g[i] = b;
                let _ = Realm.inspect_many(&g, &[0, i, g.len() - 1]);
            }
        }
    }
}
