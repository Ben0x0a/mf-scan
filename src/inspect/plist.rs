//! Property-list inspector: XML plists and binary plists (`bplist00`).
//!
//! Defines: `inspect`, which maps a match offset to a key path such as
//! `$.Account.Servers[1]`.
//! Used by: `inspect::inspect` (dispatch).
//! Uses: `quick_xml` (XML plists), `serde_json`, `crate::models::Inspection`,
//!   `inspect::nskeyed` (NSKeyedArchiver path resolution).
//!
//! Two on-disk encodings share one logical model (nested dicts/arrays), so both
//! resolve to the same dictionary-key / array-index path:
//!  - XML plists: walked as XML, tracking `<key>` names and array positions.
//!  - Binary plists: parsed via the trailer + offset table; the object whose
//!    byte span contains the offset is located, then a path to it is found by
//!    walking the object graph from the root.
//!
//! Binary plists that are NSKeyedArchiver archives (`$archiver ==
//! "NSKeyedArchiver"`) get a second treatment: `inspect::nskeyed` decodes the
//! flattened `$objects` + UID graph back to a logical path like
//! `$.root.nested.inner`.  Detection is header-first (structure, not filename).
//! On any failure the code falls back to the ordinary `path_to` walk.

use std::io::Cursor;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use quick_xml::Reader;
use quick_xml::events::Event;
use serde_json::{Value, json};

use crate::inspect::value_diff::diff_values;
use crate::models::{ContentDiff, Inspection};

/// plist inspector — Apple property lists, both binary (`bplist00`) and XML.
pub struct Plist;

impl super::Inspector for Plist {
    fn name(&self) -> &'static str {
        "plist"
    }
    fn category(&self) -> &'static str {
        "structured"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["plist"]
    }
    fn detect(&self, content: &[u8]) -> bool {
        if content.starts_with(b"bplist00") {
            return true;
        }
        // An XML plist: an XML declaration whose head names the plist DTD/root.
        // (Checked before the generic XML inspector in the registry.)
        if super::looks_like_xml(content) {
            let head = &content[..content.len().min(512)];
            return super::contains(head, b"<plist") || super::contains(head, b"DOCTYPE plist");
        }
        false
    }
    fn inspect(&self, content: &[u8], offset: usize) -> Option<Inspection> {
        resolve(content, offset)
    }
    /// Batch resolution for binary plists: parse (and sort the offset table)
    /// once per file instead of once per match. XML plists keep the default
    /// per-offset walk (their scan is already a single linear pass).
    fn inspect_many(&self, content: &[u8], offsets: &[usize]) -> Vec<Option<Inspection>> {
        if !content.starts_with(b"bplist00") {
            return offsets.iter().map(|&o| self.inspect(content, o)).collect();
        }
        match Bplist::parse(content) {
            Some(bp) => offsets
                .iter()
                .map(|&o| inspect_binary_with(&bp, o))
                .collect(),
            None => offsets.iter().map(|_| None).collect(),
        }
    }
    fn diff(&self, old: &[u8], new: &[u8]) -> Option<ContentDiff> {
        // Both encodings (XML/binary) parse to one logical tree; convert each to a
        // JSON value and reuse the shared structured diff (same as the JSON inspector).
        let old = plist_to_json(&plist::Value::from_reader(Cursor::new(old)).ok()?);
        let new = plist_to_json(&plist::Value::from_reader(Cursor::new(new)).ok()?);
        Some(diff_values("plist", &old, &new))
    }
}

/// Convert a parsed plist value into a JSON value for the structured diff.
///
/// Scalars map directly; `Data` is base64-encoded and `Date`/`Uid` are tagged
/// strings, so any change in those still surfaces as a value change while keeping
/// the tree comparable as plain JSON.
fn plist_to_json(v: &plist::Value) -> Value {
    match v {
        plist::Value::Array(a) => Value::Array(a.iter().map(plist_to_json).collect()),
        plist::Value::Dictionary(d) => Value::Object(
            d.iter()
                .map(|(k, val)| (k.clone(), plist_to_json(val)))
                .collect(),
        ),
        plist::Value::Boolean(b) => Value::Bool(*b),
        plist::Value::String(s) => Value::String(s.clone()),
        plist::Value::Integer(i) => i
            .as_signed()
            .map(Value::from)
            .or_else(|| i.as_unsigned().map(Value::from))
            .unwrap_or(Value::Null),
        plist::Value::Real(r) => {
            serde_json::Number::from_f64(*r).map_or(Value::Null, Value::Number)
        }
        plist::Value::Data(bytes) => Value::String(format!("data:{}", BASE64.encode(bytes))),
        plist::Value::Date(date) => Value::String(format!("date:{date:?}")),
        plist::Value::Uid(uid) => Value::String(format!("uid:{}", uid.get())),
        // `plist::Value` is non-exhaustive; an unknown kind compares as null.
        _ => Value::Null,
    }
}

/// Dispatch to the binary or XML plist parser by signature.
fn resolve(content: &[u8], offset: usize) -> Option<Inspection> {
    if content.starts_with(b"bplist00") {
        inspect_binary(content, offset)
    } else {
        inspect_xml(content, offset)
    }
}

/// Render a path of segments (`key` or `[i]`) as `$`-rooted text.
fn render(path: &[String]) -> String {
    let mut s = String::from("$");
    for seg in path {
        if seg.starts_with('[') {
            s.push_str(seg);
        } else {
            s.push('.');
            s.push_str(seg);
        }
    }
    s
}

// --- XML plist ---------------------------------------------------------------

/// A container frame while walking an XML plist.
struct Frame {
    is_dict: bool,
    array_index: usize,
    pending_key: Option<String>,
    path_pushed: bool,
}

/// Walk an XML plist, resolving the offset to a dict/array key path.
fn inspect_xml(content: &[u8], offset: usize) -> Option<Inspection> {
    let mut reader = Reader::from_reader(content);
    reader.config_mut().check_end_names = false;

    let mut buf = Vec::new();
    let mut stack: Vec<Frame> = Vec::new();
    let mut path: Vec<String> = Vec::new();
    let mut in_key = false;
    let mut key_buf = String::new();
    let mut value_seg: Option<String> = None;
    let mut last = 0usize;
    let mut hit: Option<String> = None;

    while let Ok(event) = reader.read_event_into(&mut buf) {
        let pos = reader.buffer_position() as usize;
        let covers = offset >= last && offset < pos;

        match event {
            Event::Eof => break,
            Event::Start(e) => {
                let name = e.name().as_ref().to_vec();
                match name.as_slice() {
                    b"plist" => {}
                    b"key" => {
                        in_key = true;
                        key_buf.clear();
                    }
                    b"dict" | b"array" => {
                        let seg = take_segment(&mut stack);
                        let pushed = seg.is_some();
                        if let Some(seg) = seg {
                            path.push(seg);
                        }
                        stack.push(Frame {
                            is_dict: name == b"dict",
                            array_index: 0,
                            pending_key: None,
                            path_pushed: pushed,
                        });
                    }
                    _ => {
                        // A scalar value element (string, integer, ...).
                        value_seg = Some(take_segment(&mut stack).unwrap_or_default());
                    }
                }
            }
            Event::Text(t) => {
                // Accumulate key text BEFORE the covers check, so when the
                // covering event is itself inside a <key> the full accumulated
                // key (not just this fragment) names the hit. One arm for both
                // concerns — two guard-ordered arms here once regressed silently
                // when reordered (review finding L6).
                if in_key {
                    key_buf.push_str(&String::from_utf8_lossy(t.as_ref()));
                }
                if covers {
                    if in_key {
                        let mut p = path.clone();
                        p.push(key_buf.clone());
                        hit = Some(render(&p));
                    } else if let Some(seg) = &value_seg {
                        let mut p = path.clone();
                        p.push(seg.clone());
                        hit = Some(render(&p));
                    }
                }
            }
            Event::End(e) => {
                let name = e.name().as_ref().to_vec();
                match name.as_slice() {
                    b"key" => {
                        in_key = false;
                        if let Some(frame) = stack.last_mut() {
                            frame.pending_key = Some(key_buf.clone());
                        }
                    }
                    b"dict" | b"array" => {
                        if let Some(frame) = stack.pop()
                            && frame.path_pushed
                        {
                            path.pop();
                        }
                    }
                    b"plist" => {}
                    _ => value_seg = None,
                }
            }
            _ => {}
        }

        buf.clear();
        last = pos;
        if hit.is_some() {
            break;
        }
    }

    let path = hit?;
    let line = super::line_at(content, offset);
    Some(Inspection {
        format: "plist".into(),
        summary: format!("key: {path}  line: {line}"),
        detail: json!({ "path": path, "line": line }),
    })
}

/// Determine the path segment for a value, consuming the parent's pending key
/// or advancing its array index.
fn take_segment(stack: &mut [Frame]) -> Option<String> {
    let frame = stack.last_mut()?;
    if frame.is_dict {
        Some(frame.pending_key.take().unwrap_or_else(|| "?".into()))
    } else {
        let seg = format!("[{}]", frame.array_index);
        frame.array_index += 1;
        Some(seg)
    }
}

// --- Binary plist ------------------------------------------------------------

/// Parsed structure of a binary plist sufficient to resolve offsets to paths.
///
/// Widened to `pub(super)` so `inspect::nskeyed` can receive a `&Bplist`
/// reference — visibility stops at the `inspect` module boundary.
pub(super) struct Bplist<'a> {
    content: &'a [u8],
    offset_size: usize,
    ref_size: usize,
    num_objects: usize,
    top: usize,
    offset_table: usize,
    /// `(object start offset, oid)` sorted by start, built once at parse time
    /// so per-match lookups are a binary search instead of an O(num_objects)
    /// scan (review finding P4).
    sorted_offsets: Vec<(usize, usize)>,
}

/// The structural children of one binary-plist object.
enum Children {
    Dict(Vec<(usize, usize)>), // (key object, value object)
    Array(Vec<usize>),
    Leaf,
}

fn inspect_binary(content: &[u8], offset: usize) -> Option<Inspection> {
    let bp = Bplist::parse(content)?;
    inspect_binary_with(&bp, offset)
}

/// [`inspect_binary`] against an already-parsed [`Bplist`] (the batch path
/// parses once and resolves every offset against it).
///
/// For NSKeyedArchiver archives the logical path is derived by
/// `nskeyed::nskeyed_path`; the summary and detail are labelled accordingly.
/// For ordinary binary plists the existing `path_to` walk is used unchanged.
fn inspect_binary_with(bp: &Bplist<'_>, offset: usize) -> Option<Inspection> {
    // A match in the offset table or trailer is structural, not a value.
    if offset >= bp.offset_table {
        return Some(Inspection {
            format: "bplist".into(),
            summary: "offset table / trailer".into(),
            detail: json!({ "region": "offset_table_or_trailer", "offset": offset }),
        });
    }

    // Try the NSKeyedArchiver resolver first (header-first detection inside
    // `nskeyed_path`).  On any failure it returns `None` and we fall through to
    // the ordinary walk — degrade, don't die.
    if let Some(nk_path) = super::nskeyed::nskeyed_path(bp, offset) {
        let rendered = render(&nk_path);
        return Some(Inspection {
            format: "bplist".into(),
            summary: format!("nskeyed key: {rendered}"),
            detail: json!({
                "path": rendered,
                "archiver": "NSKeyedArchiver",
            }),
        });
    }

    let oid = bp.object_at_offset(offset)?;
    let path = bp.path_to(oid).unwrap_or_default();
    let rendered = render(&path);
    Some(Inspection {
        format: "bplist".into(),
        summary: format!("key: {rendered}"),
        detail: json!({ "path": rendered, "object": oid }),
    })
}

impl<'a> Bplist<'a> {
    fn parse(content: &'a [u8]) -> Option<Self> {
        if !content.starts_with(b"bplist00") || content.len() < 8 + 32 {
            return None;
        }
        let trailer = content.len() - 32;
        let offset_size = content[trailer + 6] as usize;
        let ref_size = content[trailer + 7] as usize;
        let num_objects = read_be(content, trailer + 8, 8)? as usize;
        let top = read_be(content, trailer + 16, 8)? as usize;
        let offset_table = read_be(content, trailer + 24, 8)? as usize;
        // The trailer values are untrusted (crafted evidence): every later
        // lookup iterates `0..num_objects` or indexes the offset table, so a
        // trailer claiming 2^60 objects would spin effectively forever. The
        // table cannot hold more entries than the bytes available for it, and
        // the table itself (plus the root reference) must lie inside the file.
        if offset_size == 0
            || offset_size > 8
            || ref_size == 0
            || ref_size > 8
            || offset_table >= trailer
            || num_objects > (trailer - offset_table) / offset_size
            || top >= num_objects
        {
            return None;
        }
        // Sorted (start, oid) lookup table — see the field docs.
        let mut sorted_offsets: Vec<(usize, usize)> = (0..num_objects)
            .filter_map(|oid| {
                read_be(content, offset_table + oid * offset_size, offset_size)
                    .map(|start| (start as usize, oid))
            })
            .collect();
        sorted_offsets.sort_unstable();
        Some(Self {
            content,
            offset_size,
            ref_size,
            num_objects,
            top,
            offset_table,
            sorted_offsets,
        })
    }

    /// File offset where object `oid` begins (from the offset table).
    fn obj_offset(&self, oid: usize) -> Option<usize> {
        if oid >= self.num_objects {
            return None;
        }
        let entry = self.offset_table + oid * self.offset_size;
        Some(read_be(self.content, entry, self.offset_size)? as usize)
    }

    /// The object whose data region contains `target` (largest start ≤ target).
    /// Binary search over the sorted offset table built at parse time.
    pub(super) fn object_at_offset(&self, target: usize) -> Option<usize> {
        let idx = self
            .sorted_offsets
            .partition_point(|&(start, _)| start <= target);
        idx.checked_sub(1).map(|i| self.sorted_offsets[i].1)
    }

    // ── pub(super) accessors for inspect::nskeyed ─────────────────────────────

    /// The root object id — the entry point for the NSKeyedArchiver walk.
    pub(super) fn top_oid(&self) -> usize {
        self.top
    }

    /// Return the `(key_oid, value_oid)` pairs for a dict object, or `None`
    /// when `oid` is not a dict.
    ///
    /// WHY: NSKeyedArchiver's root dict and each encoded NSDictionary are raw
    /// bplist dicts; callers need the pairs without knowing `Children` internals.
    pub(super) fn dict_pairs(&self, oid: usize) -> Option<Vec<(usize, usize)>> {
        match self.children(oid) {
            Children::Dict(p) => Some(p),
            _ => None,
        }
    }

    /// Return the element oids for an array object, or `None` when `oid` is
    /// not an array.
    ///
    /// WHY: NS.keys and NS.objects in an encoded NSDictionary are raw bplist
    /// arrays; callers need the element list without exposing `Children`.
    pub(super) fn array_elements(&self, oid: usize) -> Option<Vec<usize>> {
        match self.children(oid) {
            Children::Array(e) => Some(e),
            _ => None,
        }
    }

    /// Decode a bplist UID scalar at `oid` and return its integer value, or
    /// `None` when `oid` is not a UID.
    ///
    /// WHY: A UID (marker high-nibble `0x8`) is how NSKeyedArchiver references
    /// another `$objects` entry.  The low nibble is `(byte_count - 1)`, giving
    /// the number of big-endian bytes that follow the marker byte.
    pub(super) fn uid_value(&self, oid: usize) -> Option<usize> {
        let off = self.obj_offset(oid)?;
        let marker = *self.content.get(off)?;
        let high = marker >> 4;
        if high != 0x8 {
            return None;
        }
        let low = (marker & 0x0f) as usize; // byte_count - 1
        Some(read_be(self.content, off + 1, low + 1)? as usize)
    }

    /// Decode an object's structural children (dict pairs / array elements).
    fn children(&self, oid: usize) -> Children {
        let Some(off) = self.obj_offset(oid) else {
            return Children::Leaf;
        };
        let Some(&marker) = self.content.get(off) else {
            return Children::Leaf;
        };
        let high = marker >> 4;
        let low = (marker & 0x0f) as usize;
        let Some((count, header)) = self.read_count(off, low) else {
            return Children::Leaf;
        };
        let base = off + 1 + header;

        match high {
            0xD => {
                let mut pairs = Vec::with_capacity(count);
                for i in 0..count {
                    let k = read_be(self.content, base + i * self.ref_size, self.ref_size);
                    let v = read_be(
                        self.content,
                        base + (count + i) * self.ref_size,
                        self.ref_size,
                    );
                    if let (Some(k), Some(v)) = (k, v) {
                        pairs.push((k as usize, v as usize));
                    }
                }
                Children::Dict(pairs)
            }
            0xA | 0xC => {
                let mut elems = Vec::with_capacity(count);
                for i in 0..count {
                    if let Some(e) = read_be(self.content, base + i * self.ref_size, self.ref_size)
                    {
                        elems.push(e as usize);
                    }
                }
                Children::Array(elems)
            }
            _ => Children::Leaf,
        }
    }

    /// Read the element count and the number of header bytes after the marker.
    ///
    /// A low nibble of 0xF means the count is an integer object that follows the
    /// marker; otherwise the nibble is the count itself.
    fn read_count(&self, off: usize, low: usize) -> Option<(usize, usize)> {
        if low != 0x0F {
            return Some((low, 0));
        }
        let int_marker = *self.content.get(off + 1)?;
        let int_size = 1usize << (int_marker & 0x0f);
        let count = read_be(self.content, off + 2, int_size)? as usize;
        Some((count, 1 + int_size))
    }

    /// Decode a string object (ASCII or UTF-16BE) for use as a key name.
    pub(super) fn string_value(&self, oid: usize) -> Option<String> {
        let off = self.obj_offset(oid)?;
        let marker = *self.content.get(off)?;
        let high = marker >> 4;
        let low = (marker & 0x0f) as usize;
        let (count, header) = self.read_count(off, low)?;
        let start = off + 1 + header;
        match high {
            0x5 => {
                Some(String::from_utf8_lossy(self.content.get(start..start + count)?).into_owned())
            }
            0x6 => {
                let bytes = self.content.get(start..start + count * 2)?;
                let units: Vec<u16> = bytes
                    .chunks_exact(2)
                    .map(|c| u16::from_be_bytes([c[0], c[1]]))
                    .collect();
                Some(String::from_utf16_lossy(&units))
            }
            _ => None,
        }
    }

    /// Find the dict/array key path from the root object to `target`.
    fn path_to(&self, target: usize) -> Option<Vec<String>> {
        let mut result = None;
        let mut visited = std::collections::HashSet::new();
        self.walk(
            self.top,
            target,
            &mut Vec::new(),
            &mut result,
            &mut visited,
            0,
        );
        result
    }

    /// Maximum nesting `walk` descends into. The visited set stops cycles but
    /// not a crafted *chain* of 100 000 nested containers, which would overflow
    /// the stack; past the cap the subtree is abandoned (degrade, don't die).
    const MAX_WALK_DEPTH: usize = 128;

    fn walk(
        &self,
        oid: usize,
        target: usize,
        path: &mut Vec<String>,
        result: &mut Option<Vec<String>>,
        visited: &mut std::collections::HashSet<usize>,
        depth: usize,
    ) {
        if result.is_some() || depth > Self::MAX_WALK_DEPTH {
            return;
        }
        if oid == target {
            *result = Some(path.clone());
            return;
        }
        if !visited.insert(oid) {
            return;
        }
        match self.children(oid) {
            Children::Dict(pairs) => {
                for (k, v) in pairs {
                    let key = self.string_value(k).unwrap_or_else(|| format!("#{k}"));
                    if k == target {
                        let mut p = path.clone();
                        p.push(key);
                        *result = Some(p);
                        return;
                    }
                    path.push(key);
                    self.walk(v, target, path, result, visited, depth + 1);
                    path.pop();
                    if result.is_some() {
                        return;
                    }
                }
            }
            Children::Array(elems) => {
                for (i, e) in elems.into_iter().enumerate() {
                    path.push(format!("[{i}]"));
                    self.walk(e, target, path, result, visited, depth + 1);
                    path.pop();
                    if result.is_some() {
                        return;
                    }
                }
            }
            Children::Leaf => {}
        }
    }
}

/// Read a big-endian unsigned integer of `size` bytes (1–8).
fn read_be(content: &[u8], off: usize, size: usize) -> Option<u64> {
    let bytes = content.get(off..off + size)?;
    let mut value = 0u64;
    for &b in bytes {
        value = (value << 8) | b as u64;
    }
    Some(value)
}
