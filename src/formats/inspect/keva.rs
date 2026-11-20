//! Keva inspector: ByteDance's key-value store (TikTok, Lemon8), an undocumented
//! format. Its files are named by their magic; a match in a single-value file
//! (`.sgv`) resolves to its value, the others are identified only.
//!
//! Defines: [`Keva`] (the inspector).
//! Used by: `inspect::mod` (registered in `INSPECTORS`).
//! Uses: `crate::core::models::Inspection`, `inspect::quoted_bytes`.
//!
//! ── What is known, from the files of one Android phone (TikTok and Lemon8) ──
//! Each store (`files/keva/repo/<name>/`) has a `<name>.blk` and a `<name>.chk`,
//! whole 4 KiB pages, and may have `.lxi`, `.mmb` and `.sgv` files; `keva/global/`
//! has a `keva.gxi`. Every file starts with `keva-` and three letters naming its kind,
//! then a version (u32, 1). The app's `libkeva.so` names `KevaBlockFile`,
//! `KevaChunkFile`, `KevaSingleValueFile`, `KevaMultiValueFile` and
//! `KevaGlobalExtraInfoFile` (C++ symbols).
//!
//! A single-value file (`.sgv`, 248 files): the 12-byte magic and version, 12 zero
//! bytes, then a u32 whose top byte is the type and low 24 bits the length of what
//! follows, which fills the rest of the file. Type 1 is a UTF-8 string (243 files),
//! type 3 a string array (5): a u32 count, then each string as a u32 length and its
//! bytes. The key is the file's name: 222 of the 248 names are a key record in their
//! store's `.blk` (the 26 others are in none). A file shorter than its declared
//! length (cut short, or carved) shows what it holds, said truncated.
//!
//! WHY the other kinds are identified only: the `.blk` holds the store's keys and
//! string values and the `.chk` the typed entries that point at them, but how an
//! entry's index maps to a block is not worked out for every store; a value shown
//! under the wrong key would mislead.

use serde_json::json;

use crate::core::models::Inspection;
use crate::formats::inspect::quoted_bytes;

/// The kinds of keva file, by the three letters after `keva-`.
const KINDS: [&[u8; 3]; 6] = [b"blk", b"chk", b"gxi", b"lxi", b"mmb", b"sgv"];
/// Where a single-value file's type and length are, and its value starts.
const SGV_HEADER: usize = 0x18;
const SGV_VALUE: usize = SGV_HEADER + 4;
/// The longest value given whole in the JSON detail, in bytes; a longer one is
/// pointed to by `offset_in_value`.
const DETAIL_VALUE: usize = 4096;

/// Keva inspector (see the module doc).
pub struct Keva;

impl super::Inspector for Keva {
    fn name(&self) -> &'static str {
        "keva"
    }
    fn category(&self) -> &'static str {
        "database"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &[]
    }
    fn detect(&self, content: &[u8]) -> bool {
        kind(content).is_some()
    }
    fn inspect(&self, content: &[u8], offset: usize) -> Option<Inspection> {
        let kind = kind(content)?;
        if kind != b"sgv" {
            let name = String::from_utf8_lossy(kind);
            return Some(found(
                format!("keva-{name}  (not decoded)"),
                json!({ "file": format!("keva-{name}"), "decoded": false }),
            ));
        }
        single_value(content, offset)
    }
}

/// The kind of keva file `c` is: `keva-`, a known kind, version 1.
fn kind(c: &[u8]) -> Option<&[u8; 3]> {
    let kind: &[u8; 3] = c.get(5..8)?.try_into().ok()?;
    (c.starts_with(b"keva-") && c.get(8..12)? == [1, 0, 0, 0] && KINDS.contains(&kind))
        .then_some(kind)
}

/// Where a match is in a string array.
enum InArray {
    /// In the element count (the count).
    Count(usize),
    /// In element n's length (n, the count).
    Length(usize, usize),
    /// In element n (n, the count, the element's range).
    Element(usize, usize, std::ops::Range<usize>),
}

/// A match in a single-value file: its value, or the element of a string array. A
/// file shorter than its declared length (cut short, or carved) shows what it holds,
/// said truncated; an array whose elements do not parse shows its bytes.
fn single_value(c: &[u8], offset: usize) -> Option<Inspection> {
    let base = json!({ "file": "keva-sgv", "key_from": "file name" });
    let mut detail = base.as_object()?.clone();
    let mut named = |summary: &str, part: &str| {
        detail.insert("part".into(), part.into());
        Some(found(
            format!("single value (key: the file name)  {summary}"),
            detail.clone().into(),
        ))
    };
    if offset < SGV_VALUE {
        return named("(in the header)", "header");
    }
    let head = u32::from_le_bytes(c.get(SGV_HEADER..SGV_VALUE)?.try_into().ok()?);
    let (kind, len) = (head >> 24, usize::try_from(head & 0x00FF_FFFF).ok()?);
    let declared_end = SGV_VALUE.checked_add(len)?;
    let value = c.get(SGV_VALUE..declared_end.min(c.len()))?;
    let at = offset - SGV_VALUE;
    if at >= value.len() {
        return (offset < c.len()).then(|| named("(after its value)", "after the value"))?;
    }
    let mut detail = detail.clone();
    let truncated = declared_end > c.len();
    let note = if truncated {
        detail.insert("truncated".into(), true.into());
        detail.insert("declared_length".into(), len.into());
        "  (truncated: the file ends before its declared length)"
    } else {
        ""
    };
    let mut named = |summary: String, part: &str| {
        detail.insert("part".into(), part.into());
        Some(found(
            format!("single value (key: the file name)  {summary}{note}"),
            detail.clone().into(),
        ))
    };
    let (text, at, summary, kind_name) = match kind {
        1 => (
            value,
            at,
            format!("string, {len} bytes"),
            "string".to_string(),
        ),
        3 => {
            let kind_name = "string array".to_string();
            match element(value, at) {
                Some(InArray::Count(of)) => {
                    return named(
                        format!("string array of {of}  (in its count)"),
                        "element count",
                    );
                }
                Some(InArray::Length(n, of)) => {
                    return named(
                        format!("string array: element {n} of {of}  (in its length)"),
                        "element length",
                    );
                }
                Some(InArray::Element(n, of, range)) => {
                    detail.insert("element".into(), n.into());
                    detail.insert("elements".into(), of.into());
                    let summary = format!("string array: element {n} of {of}");
                    (&value[range.clone()], at - range.start, summary, kind_name)
                }
                None => {
                    detail.insert("elements_decoded".into(), false.into());
                    let summary = "string array (its elements do not parse: the bytes as stored)";
                    (value, at, summary.to_string(), kind_name)
                }
            }
        }
        n => (
            value,
            at,
            format!("type {n}, {len} bytes"),
            format!("type {n}"),
        ),
    };
    detail.insert("type".into(), kind_name.into());
    detail.insert("part".into(), "value".into());
    detail.insert("offset_in_value".into(), at.into());
    if text.len() <= DETAIL_VALUE {
        detail.insert("value".into(), String::from_utf8_lossy(text).into());
    }
    Some(found(
        format!(
            "single value (key: the file name)  {summary}  value: {}{note}",
            quoted_bytes(around(text, at))
        ),
        detail.into(),
    ))
}

/// Where byte `at` of the string array `a` is; `None` when the array does not parse
/// up to it.
fn element(a: &[u8], at: usize) -> Option<InArray> {
    let u32_at = |i: usize| -> Option<usize> {
        usize::try_from(u32::from_le_bytes(
            a.get(i..i.checked_add(4)?)?.try_into().ok()?,
        ))
        .ok()
    };
    let count = u32_at(0)?;
    if at < 4 {
        return Some(InArray::Count(count));
    }
    let mut i = 4;
    for n in 1..=count {
        let len = u32_at(i)?;
        let range = i + 4..(i + 4).checked_add(len)?;
        if range.end > a.len() {
            return None;
        }
        if at < range.start {
            return Some(InArray::Length(n, count));
        }
        if at < range.end {
            return Some(InArray::Element(n, count, range));
        }
        i = range.end;
    }
    None
}

/// The part of `text` around byte `at` shown in a summary: from up to 40 bytes
/// before it (the summary shortens what follows).
fn around(text: &[u8], at: usize) -> &[u8] {
    &text[at.saturating_sub(40)..]
}

fn found(summary: String, detail: serde_json::Value) -> Inspection {
    Inspection {
        format: "keva".into(),
        summary,
        detail,
    }
}

#[cfg(test)]
mod tests {
    use super::super::Inspector;
    use super::*;

    fn sgv(kind: u8, value: &[u8]) -> Vec<u8> {
        let mut f = b"keva-sgv\x01\x00\x00\x00".to_vec();
        f.extend_from_slice(&[0; 12]);
        f.extend_from_slice(&(value.len() as u32 | u32::from(kind) << 24).to_le_bytes());
        f.extend_from_slice(value);
        f
    }

    fn at(f: &[u8], needle: &[u8]) -> usize {
        f.windows(needle.len()).position(|w| w == needle).unwrap()
    }

    #[test]
    fn every_kind_is_named_by_its_magic() {
        for kind in KINDS {
            let mut f = b"keva-".to_vec();
            f.extend_from_slice(kind);
            f.extend_from_slice(&[1, 0, 0, 0, 0, 0]);
            assert!(Keva.detect(&f), "{kind:?}");
        }
        assert!(!Keva.detect(b"keva-xyz\x01\x00\x00\x00"));
        assert!(!Keva.detect(b"keva-blk\x02\x00\x00\x00"));
        let blk = b"keva-blk\x01\x00\x00\x00\x00\x00";
        assert_eq!(
            Keva.inspect(blk, 9).unwrap().summary,
            "keva-blk  (not decoded)"
        );
    }

    #[test]
    fn a_string_value_resolves() {
        let f = sgv(1, br#"{"data":{"category_list":[1]}}"#);
        let found = Keva.inspect(&f, at(&f, b"category")).unwrap();
        assert_eq!(
            found.summary,
            r#"single value (key: the file name)  string, 30 bytes  value: "{"data":{"category_list":[1]}}""#
        );
        assert_eq!(found.detail["offset_in_value"], 10);
        assert_eq!(found.detail["part"], "value");
        assert_eq!(Keva.inspect(&f, 3).unwrap().detail["part"], "header");
        assert!(Keva.inspect(&f, f.len()).is_none());
    }

    #[test]
    fn a_string_array_resolves_to_its_element() {
        let mut a = 2u32.to_le_bytes().to_vec();
        for s in [&b"https://a.example/"[..], b"https://b.example/"] {
            a.extend_from_slice(&(s.len() as u32).to_le_bytes());
            a.extend_from_slice(s);
        }
        let f = sgv(3, &a);
        let b = Keva.inspect(&f, at(&f, b"b.example")).unwrap();
        assert_eq!(b.detail["element"], 2);
        assert_eq!(b.detail["elements"], 2);
        assert_eq!(b.detail["value"], "https://b.example/");
        assert_eq!(b.detail["offset_in_value"], 8);
        let length = at(&f, b"https://b") - 2;
        assert_eq!(
            Keva.inspect(&f, length).unwrap().detail["part"],
            "element length"
        );
    }

    #[test]
    fn a_truncated_or_unparsed_value_is_shown_and_said() {
        // Declared 30 bytes, 20 present: what is there is shown, said truncated.
        let full = sgv(1, br#"{"data":{"category_list":[1]}}"#);
        let cut = &full[..SGV_VALUE + 20];
        let found = Keva.inspect(cut, at(cut, b"category")).unwrap();
        assert_eq!(found.detail["truncated"], true);
        assert_eq!(found.detail["declared_length"], 30);
        assert!(found.summary.contains("truncated"), "{}", found.summary);
        assert_eq!(
            Keva.inspect(&cut[..16], 14).unwrap().detail["part"],
            "header"
        );
        // An array: a match in its count; an element length past the end: its bytes.
        let mut a = 2u32.to_le_bytes().to_vec();
        a.extend_from_slice(&[3, 0, 0, 0, b'a', b'b', b'c', 99, 0, 0, 0, b'x', b'y']);
        let f = sgv(3, &a);
        assert_eq!(
            Keva.inspect(&f, SGV_VALUE + 1).unwrap().detail["part"],
            "element count"
        );
        let xy = Keva.inspect(&f, at(&f, b"xy")).unwrap();
        assert_eq!(xy.detail["elements_decoded"], false);
        assert_eq!(xy.detail["type"], "string array");
        assert_eq!(xy.detail["part"], "value");
    }

    #[test]
    fn corrupt_files_never_panic() {
        let mut a = 2u32.to_le_bytes().to_vec();
        a.extend_from_slice(&[3, 0, 0, 0, b'a', b'b', b'c', 9, 0, 0, 0, b'x']);
        let f = sgv(3, &a);
        for i in 0..f.len() {
            for b in [0x00, 0x7F, 0xFF] {
                let mut g = f.clone();
                g[i] = b;
                for o in 0..g.len() + 2 {
                    let _ = Keva.inspect(&g, o);
                }
            }
        }
    }
}
