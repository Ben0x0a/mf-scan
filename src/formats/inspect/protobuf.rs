//! Protobuf inspector: map a byte offset to a field path (e.g. `4.3.6.1`), with no
//! `.proto` schema.
//!
//! Defines: [`Protobuf`] (the inspector) and [`parses`] (is this a protobuf message).
//! Used by: `inspect::inspect` (as the structural fallback for a matched file)
//! and the SQLite inspector (a BLOB cell holding a message).
//! Uses: `crate::core::models::Inspection`, `serde_json` (structured detail).
//!
//! ── Detection: what makes bytes "protobuf" ───────────────────────────────────
//! Protobuf has no signature. The rule is `protoc --decode_raw`'s: the bytes parse
//! completely as a sequence of fields (a tag with a field number of at least 1 and a
//! wire type of varint, 64-bit, length-delimited, group start/end or 32-bit, then a
//! value that fits), with groups balanced. Only the specification's own limits apply
//! (a 32-bit tag, field numbers 1 to 2^29 - 1); proto2 groups are accepted, as `protoc`
//! accepts them.
//!
//! Short random byte runs sometimes satisfy that rule too (measured: about 1% of
//! random 16-byte values, 0.002% of 256-byte ones), so a match resolved through a
//! message found this way is reported as inferred from structure by the caller,
//! never as certain.
//!
//! ── Reading a length-delimited value ─────────────────────────────────────────
//! Without a schema, a length-delimited value is a string, raw bytes, or an embedded
//! message. `protoc` shows it as a message whenever it parses as one, which turns a
//! word like `Hahahaha` into number fields. Here a value that is also printable text
//! is a message only if that message has a length-delimited field of its own (see
//! `read_len`); otherwise it is a string. Anything that is neither text nor a message
//! is bytes. The same rule decides whether a whole file or BLOB is protobuf at all.
//!
//! That rule is a choice between two valid readings, not a proof: a value that reads
//! both ways is marked as such in the result (`ambiguous`), with the reading not
//! taken, so the examiner is never shown one reading as the only one.

use std::ops::Range;

use serde_json::json;

use super::leb128;
use crate::core::models::Inspection;

/// The deepest nesting followed, as `protoc` limits its recursion.
const RECURSION_LIMIT: usize = 100;
/// The largest field number the protobuf specification allows (2^29 - 1).
const MAX_FIELD_NUMBER: u64 = (1 << 29) - 1;

/// Protobuf inspector — recognised by structure only (see the module doc).
pub struct Protobuf;

impl super::Inspector for Protobuf {
    fn name(&self) -> &'static str {
        "protobuf"
    }
    fn category(&self) -> &'static str {
        "structured"
    }
    /// None: a file name proves nothing about protobuf, so a file is only ever read
    /// as protobuf when its whole content parses (the structure fallback).
    fn extensions(&self) -> &'static [&'static str] {
        &[]
    }
    fn detect(&self, _content: &[u8]) -> bool {
        false // no signature
    }
    /// Not a `--type`: files are never classified as protobuf (see `detect`).
    fn selectable_by_type(&self) -> bool {
        false
    }
    fn inspect(&self, content: &[u8], offset: usize) -> Option<Inspection> {
        let fields = parse_message(content, 0, content.len(), 0)?;
        locate(content, &fields, offset)
    }
    fn inspect_many(&self, content: &[u8], offsets: &[usize]) -> Vec<Option<Inspection>> {
        match parse_message(content, 0, content.len(), 0) {
            Some(fields) => offsets
                .iter()
                .map(|&o| locate(content, &fields, o))
                .collect(),
            None => offsets.iter().map(|_| None).collect(),
        }
    }
}

/// Whether `content` is a protobuf message: non-empty, parsing completely, and, by the
/// rule `read_len` applies to a nested value, not plain text that merely parses
/// (a word like `Hahahaha` is text, at the top level as inside a message).
pub(crate) fn parses(content: &[u8]) -> bool {
    !content.is_empty()
        && parse_message(content, 0, content.len(), 0)
            .is_some_and(|fields| fields.iter().any(|f| f.wire == Wire::Len) || !is_text(content))
}

/// How a field's value is encoded on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Wire {
    Varint,
    I64,
    Len,
    Group,
    I32,
}

impl Wire {
    fn name(self) -> &'static str {
        match self {
            Wire::Varint => "varint",
            Wire::I64 => "i64",
            Wire::Len => "len",
            Wire::Group => "group",
            Wire::I32 => "i32",
        }
    }
}

/// What a length-delimited value holds, as read without a schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reading {
    Text,
    Message,
    Bytes,
    /// A varint, fixed-width number or group: not length-delimited.
    Other,
}

/// One parsed field and where its bytes are.
///
/// WHY a length-delimited value is not parsed here: whether it is a nested message,
/// text or bytes never decides whether its parent is valid, so it is only read
/// ([`read_len`]) on the way to a match. A group is parsed, as it is part of its
/// parent's own encoding.
#[derive(Debug)]
struct Field {
    number: u64,
    wire: Wire,
    /// From the tag's first byte to the value's last byte.
    span: Range<usize>,
    /// The value itself (for a group, its contents between the two tags).
    value: Range<usize>,
    /// A group's own fields (empty for every other wire type).
    children: Vec<Field>,
}

/// Parse the fields in `bytes[start..end]`; `None` unless they fill it exactly.
fn parse_message(bytes: &[u8], start: usize, end: usize, depth: usize) -> Option<Vec<Field>> {
    let (fields, at, _) = parse_fields(bytes, start, end, depth, None)?;
    (at == end).then_some(fields)
}

/// Parse fields from `start` up to `end`, or up to the end tag of `group` when
/// parsing a group's contents. Returns the fields, the position after them (after the
/// group's end tag, for a group), and where the contents end (where the group's end
/// tag starts, which a non-minimal tag encoding makes longer than one byte).
fn parse_fields(
    bytes: &[u8],
    start: usize,
    end: usize,
    depth: usize,
    group: Option<u64>,
) -> Option<(Vec<Field>, usize, usize)> {
    let mut fields = Vec::new();
    let mut at = start;
    while at < end {
        let tag_start = at;
        let (tag, used) = leb128(&bytes[at..end], 0, 10)?;
        at += used;
        // A tag is a 32-bit varint, and field numbers run from 1 to 2^29 - 1: the
        // limits the protobuf specification sets and `protoc` enforces.
        let number = tag >> 3;
        if tag > u64::from(u32::MAX) || number == 0 || number > MAX_FIELD_NUMBER {
            return None;
        }
        let (wire, value) = match tag & 7 {
            0 => {
                let (_, used) = leb128(&bytes[at..end], 0, 10)?;
                (Wire::Varint, at..at + used)
            }
            1 => (Wire::I64, at..at.checked_add(8)?),
            2 => {
                let (len, used) = leb128(&bytes[at..end], 0, 10)?;
                let from = at + used;
                (
                    Wire::Len,
                    from..from.checked_add(usize::try_from(len).ok()?)?,
                )
            }
            3 => {
                if depth >= RECURSION_LIMIT {
                    return None;
                }
                let (children, after, contents_end) =
                    parse_fields(bytes, at, end, depth + 1, Some(number))?;
                fields.push(Field {
                    number,
                    wire: Wire::Group,
                    span: tag_start..after,
                    value: at..contents_end,
                    children,
                });
                at = after;
                continue;
            }
            4 => {
                // The end tag closes the group being parsed, and nothing else.
                return (group == Some(number)).then_some((fields, at, tag_start));
            }
            5 => (Wire::I32, at..at.checked_add(4)?),
            _ => return None,
        };
        if value.end > end {
            return None;
        }
        at = value.end;
        fields.push(Field {
            number,
            wire,
            span: tag_start..at,
            value,
            children: Vec::new(),
        });
    }
    // Running out of bytes inside a group means its end tag is missing.
    group.is_none().then_some((fields, at, at))
}

/// Read a length-delimited value as an embedded message, text, or bytes, and say
/// whether it was ambiguous (both printable text and a valid message).
///
/// A value that parses as a message is one, unless it is also printable text and the
/// message has no length-delimited field of its own. WHY that test (structural, not
/// proof): letters read as tags make varint and fixed fields, whereas a length prefix
/// that frames the rest exactly is rare by chance and is what a real nested message
/// has. On Snapchat's `arroyo.db` it split 32 such values as expected (29 messages
/// holding the chat text, 3 words such as `Hahahaha`), but it can be wrong either
/// way, hence the `ambiguous` flag.
fn read_len(bytes: &[u8], value: Range<usize>, depth: usize) -> (Reading, Vec<Field>, bool) {
    // A length-delimited child is checked before the text test: it is the cheap
    // decider, and a full UTF-8 scan is needed only when there is none.
    let data = &bytes[value.clone()];
    let message = (!data.is_empty() && depth < RECURSION_LIMIT)
        .then(|| parse_message(bytes, value.start, value.end, depth + 1))
        .flatten();
    match message {
        Some(children) if children.iter().any(|f| f.wire == Wire::Len) => {
            let ambiguous = is_text(data);
            (Reading::Message, children, ambiguous)
        }
        Some(children) => {
            if is_text(data) {
                (Reading::Text, Vec::new(), true)
            } else {
                (Reading::Message, children, false)
            }
        }
        None if is_text(data) => (Reading::Text, Vec::new(), false),
        None => (Reading::Bytes, Vec::new(), false),
    }
}

/// Printable UTF-8 text: valid UTF-8 with no control characters but tab and newlines.
fn is_text(data: &[u8]) -> bool {
    !data.is_empty()
        && std::str::from_utf8(data).is_ok_and(|s| {
            s.chars()
                .all(|c| !c.is_control() || matches!(c, '\t' | '\n' | '\r'))
        })
}

/// Describe the deepest field whose bytes contain `offset`.
fn locate(content: &[u8], fields: &[Field], offset: usize) -> Option<Inspection> {
    let mut path = Vec::new();
    let mut ambiguous = Vec::new();
    descend(content, fields, offset, 0, &mut path, &mut ambiguous)
}

/// Find the field of `level` holding `offset` and go down into it, reading each
/// length-delimited value on the way (only those: the rest of the message is never
/// read past its first level). `path` and `ambiguous` grow as it descends.
fn descend(
    content: &[u8],
    level: &[Field],
    offset: usize,
    depth: usize,
    path: &mut Vec<String>,
    ambiguous: &mut Vec<(String, Reading)>,
) -> Option<Inspection> {
    // Fields are in byte order: the first that ends after `offset` is the only one
    // that can hold it.
    let field = level
        .get(level.partition_point(|f| f.span.end <= offset))
        .filter(|f| f.span.start <= offset)?;
    path.push(field.number.to_string());
    if !field.value.contains(&offset) {
        let path = path.join(".");
        return Some(Inspection {
            format: "protobuf".into(),
            summary: format!("field: {path}  (in the field's tag or length)"),
            detail: json!({ "path": path, "wire_type": field.wire.name(), "in_header": true }),
        });
    }
    let reading = match field.wire {
        Wire::Group => {
            if let Some(found) =
                descend(content, &field.children, offset, depth + 1, path, ambiguous)
            {
                return Some(found);
            }
            Reading::Other
        }
        Wire::Len => {
            let (reading, children, both) = read_len(content, field.value.clone(), depth);
            if both {
                ambiguous.push((path.join("."), reading));
            }
            if reading == Reading::Message
                && let Some(found) = descend(content, &children, offset, depth + 1, path, ambiguous)
            {
                return Some(found);
            }
            reading
        }
        _ => Reading::Other,
    };
    Some(describe_match(
        content, field, reading, path, ambiguous, offset,
    ))
}

/// The result for a match in the value of `field`, read as `reading`.
fn describe_match(
    content: &[u8],
    field: &Field,
    reading: Reading,
    path: &[String],
    ambiguous: &[(String, Reading)],
    offset: usize,
) -> Inspection {
    let path = path.join(".");
    let data = &content[field.value.clone()];
    let (kind, shown, value) = describe(field.wire, reading, data);
    let mut summary = format!("field: {path}  [{}]  {shown}", field.wire.name());
    let mut detail = json!({
        "path": path,
        "wire_type": field.wire.name(),
        "kind": kind,
        "value": value,
        "offset_in_value": offset - field.value.start,
    });
    if !ambiguous.is_empty() {
        let mut notes = Vec::new();
        let mut list = Vec::new();
        for (at, read) in ambiguous {
            let (read_as, other) = if *read == Reading::Message {
                ("message", "also valid as text")
            } else {
                ("string", "also parses as a message")
            };
            notes.push(format!("field {at} {other}"));
            list.push(json!({ "path": at, "read_as": read_as }));
        }
        summary.push_str(&format!("  ({})", notes.join("; ")));
        if let Some(obj) = detail.as_object_mut() {
            obj.insert("ambiguous".into(), json!(list));
        }
    }
    Inspection {
        format: "protobuf".into(),
        summary,
        detail,
    }
}

/// A field's value: its kind, the summary text, and the JSON value.
fn describe(
    wire: Wire,
    reading: Reading,
    data: &[u8],
) -> (&'static str, String, serde_json::Value) {
    let fixed = |n: usize| {
        let mut b = [0u8; 8];
        b[..n].copy_from_slice(&data[..n]);
        u64::from_le_bytes(b)
    };
    match (wire, reading) {
        (Wire::Varint, _) => {
            let v = leb128(data, 0, 10).map_or(0, |(v, _)| v);
            ("varint", format!("value: {v}"), json!(v))
        }
        (Wire::I64, _) => {
            let v = fixed(8);
            ("fixed64", format!("value: {v}"), json!(v))
        }
        (Wire::I32, _) => {
            let v = fixed(4);
            ("fixed32", format!("value: {v}"), json!(v))
        }
        (Wire::Len, Reading::Text) => {
            let text = String::from_utf8_lossy(data);
            // Control characters (a newline in a chat message) become spaces in the
            // one-line summary; the JSON value keeps the exact text, up to
            // DETAIL_CHARS (a multi-megabyte string is not copied whole per match).
            let shown = super::one_line(&text);
            let value = super::detail_text(&text);
            ("string", format!("string: \"{shown}\""), value)
        }
        (Wire::Len, Reading::Message) | (Wire::Group, _) => (
            "message",
            format!("message: {} bytes", data.len()),
            json!(data.len()),
        ),
        (Wire::Len, _) => (
            "bytes",
            format!("bytes: {} bytes", data.len()),
            json!(data.len()),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::super::Inspector;
    use super::*;

    /// A message: field 1 varint 150; field 2 = { field 1 "hello world" }; field 3
    /// bytes that are neither text nor a message.
    fn sample() -> Vec<u8> {
        let mut inner = vec![0x0a, 11];
        inner.extend_from_slice(b"hello world");
        let mut m = vec![0x08, 0x96, 0x01, 0x12, inner.len() as u8];
        m.extend_from_slice(&inner);
        m.extend_from_slice(&[0x1a, 3, 0xff, 0xff, 0xff]);
        m
    }

    #[test]
    fn a_match_resolves_to_its_field_path() {
        let m = sample();
        let at = m.windows(5).position(|w| w == b"world").unwrap();
        let found = Protobuf.inspect(&m, at).unwrap();
        assert_eq!(found.detail["path"], "2.1");
        assert_eq!(found.detail["kind"], "string");
        assert_eq!(found.detail["value"], "hello world");
        assert_eq!(found.detail["offset_in_value"], 6);

        let varint = Protobuf.inspect(&m, 1).unwrap();
        assert_eq!(varint.detail["path"], "1");
        assert_eq!(varint.detail["value"], 150);

        let bytes = Protobuf.inspect(&m, m.len() - 1).unwrap();
        assert_eq!(bytes.detail["kind"], "bytes");
    }

    #[test]
    fn text_that_also_parses_is_read_by_its_structure() {
        // Real Snapchat values: a message holding the text in field 1 (tag 0x0a then
        // the length), and a plain word that only parses as number fields.
        let mut wrapped = vec![0x0a, 9];
        wrapped.extend_from_slice(b"And you ?");
        let mut m = vec![0x12, wrapped.len() as u8];
        m.extend_from_slice(&wrapped);
        m.extend_from_slice(&[0x1a, 8]);
        m.extend_from_slice(b"Hahahaha");

        let at = m.windows(3).position(|w| w == b"you").unwrap();
        let inner = Protobuf.inspect(&m, at).unwrap();
        assert_eq!(inner.detail["path"], "2.1", "the message holds the text");
        assert_eq!(inner.detail["value"], "And you ?");

        let at = m.windows(4).position(|w| w == b"haha").unwrap();
        let word = Protobuf.inspect(&m, at).unwrap();
        assert_eq!(word.detail["path"], "3", "a word, not number fields");
        assert_eq!(word.detail["value"], "Hahahaha");

        // Both values read both ways: each result says so, with the reading taken.
        // ("And you ?" itself parses too: 'A' is a 64-bit field and 8 bytes follow.)
        assert_eq!(
            inner.detail["ambiguous"],
            json!([
                { "path": "2", "read_as": "message" },
                { "path": "2.1", "read_as": "string" }
            ])
        );
        assert!(
            inner
                .summary
                .ends_with("(field 2 also valid as text; field 2.1 also parses as a message)"),
            "{}",
            inner.summary
        );
        assert_eq!(word.detail["ambiguous"][0]["read_as"], "string");
        assert!(word.summary.ends_with("(field 3 also parses as a message)"));
        // An unambiguous value carries no flag.
        let plain = Protobuf.inspect(&sample(), 1).unwrap();
        assert!(plain.detail.get("ambiguous").is_none());
    }

    #[test]
    fn a_long_string_is_capped_in_the_detail() {
        // Field 1, a 5000-byte string (length varint 0x88 0x27), then field 2 varint.
        let mut m = vec![0x0a, 0x88, 0x27];
        m.extend(std::iter::repeat_n(b'x', 4999));
        m.push(b'.');
        m.extend_from_slice(&[0x10, 0x01]);
        let found = Protobuf.inspect(&m, 10).unwrap();
        assert_eq!(found.detail["kind"], "string");
        assert_eq!(found.detail["value"]["truncated"], true);
        assert_eq!(
            found.detail["value"]["text"].as_str().unwrap().len(),
            crate::formats::inspect::DETAIL_CHARS
        );
        // ("xxx…" also parses as varint fields: 'x' is field 15, varint.)
        assert!(found.summary.contains("…\""), "{}", found.summary);
    }

    #[test]
    fn plain_text_is_not_protobuf_at_the_top_level_either() {
        // Parses as number fields, but it is a word: same rule as for a nested value.
        assert!(parse_message(b"Hahahaha", 0, 8, 0).is_some());
        assert!(!parses(b"Hahahaha"));
        // Text whose structure holds a length-delimited field stays protobuf.
        let mut m = vec![0x0a, 9];
        m.extend_from_slice(b"And you ?");
        assert!(parses(&m));
    }

    #[test]
    fn groups_and_large_field_numbers_are_accepted() {
        // Field 536870911 (the largest) as a varint, then group 5 holding field 1.
        let mut m = vec![0xf8, 0xff, 0xff, 0xff, 0x0f, 0x01];
        m.extend_from_slice(&[0x2b, 0x08, 0x07, 0x2c]);
        assert!(parses(&m));
        let in_group = Protobuf.inspect(&m, 8).unwrap();
        assert_eq!(in_group.detail["path"], "5.1");
        assert_eq!(in_group.detail["value"], 7);
    }

    #[test]
    fn the_specification_limits_are_enforced() {
        // Field 2^29 - 1 is the largest allowed; 2^29 is not (its tag still fits 32
        // bits); a tag beyond 32 bits is refused as protoc refuses it.
        assert!(parses(&[0xf8, 0xff, 0xff, 0xff, 0x0f, 0x01]));
        assert!(!parses(&[0x80, 0x80, 0x80, 0x80, 0x10, 0x01]));
        assert!(!parses(&[0xff, 0xff, 0xff, 0xff, 0xff, 0x01, 0x01]));
    }

    #[test]
    fn a_non_minimal_group_end_tag_is_not_in_the_group() {
        // Group 1 holding field 1 = 7, closed by `8c 00`: the end tag of group 1
        // written in two bytes.
        let m = [0x0b, 0x08, 0x07, 0x8c, 0x00];
        assert!(parses(&m));
        let on_end_tag = Protobuf.inspect(&m, 3).unwrap();
        assert_eq!(on_end_tag.detail["in_header"], true);
    }

    #[test]
    fn a_newline_in_a_string_stays_on_one_summary_line() {
        let mut m = vec![0x0a, 9];
        m.extend_from_slice(b"one\ntwo !");
        let found = Protobuf.inspect(&m, 3).unwrap();
        assert!(!found.summary.contains('\n'), "{}", found.summary);
        assert_eq!(found.detail["value"], "one\ntwo !");
    }

    #[test]
    fn invalid_wire_format_is_refused() {
        assert!(!parses(b""));
        assert!(!parses(&[0x00, 0x01])); // field number 0
        assert!(!parses(&[0x12, 0x05, b'a'])); // length runs past the end
        assert!(!parses(&[0x2b, 0x08, 0x07])); // group never closed
        assert!(!parses(&[0x0c])); // end tag with no group open
        assert!(!parses(&[0x0e])); // wire type 6
        assert!(Protobuf.inspect(&[0x0e], 0).is_none());
    }
}
