//! MMKV inspector: map a byte offset in an MMKV store (Tencent's key-value store,
//! used by apps on Android and iOS) to its entry's key and value.
//!
//! Defines: [`Mmkv`] (the inspector) and [`parses`] (is this an MMKV store).
//! Used by: `inspect::detect` (the structure fallback for a matched file).
//! Uses: `crate::core::models::Inspection`, `serde_json`.
//!
//! ── Format ───────────────────────────────────────────────────────────────────
//! From Tencent's MMKV sources (BSD-3-Clause), as also read by the `mmkv-parser`
//! that iLEAPP vendors (MIT): the data size (u32 little-endian), then the data: a
//! varint (the items' total size), then entries end to end, each a varint key
//! length, the key (UTF-8), a varint value length and the value. The rest of the
//! file is padding. The value's type is not stored: a value that is exactly a
//! varint length and that many bytes is a string, anything else a varint number.
//! Writes append, so a key may appear more than once: the last entry is current,
//! the earlier ones are superseded values still in the file.
//!
//! ── Detection ────────────────────────────────────────────────────────────────
//! No signature: a file is MMKV when its entries frame the data exactly to the
//! declared size, every key valid UTF-8 without control characters. Checked on the
//! Pixel 9a and Daphne iPhone file systems: 8 stores found, all in MMKV folders, no
//! other file passing. Still a structural reading, so a result is marked "(by
//! structure)" (by the fallback), and an encrypted store (AES-CFB) is not recognised.

use std::ops::Range;

use serde_json::json;

use super::leb128;
use crate::core::models::Inspection;

/// MMKV inspector — recognised by structure only (see the module doc).
pub struct Mmkv;

impl super::Inspector for Mmkv {
    fn name(&self) -> &'static str {
        "mmkv"
    }
    fn category(&self) -> &'static str {
        "database"
    }
    /// None: MMKV stores have no extension (`mmkv.default`, `redux-persist`, …).
    fn extensions(&self) -> &'static [&'static str] {
        &[]
    }
    fn detect(&self, _content: &[u8]) -> bool {
        false // no signature
    }
    /// Not a `--type`: files are never classified as MMKV (see `detect`).
    fn selectable_by_type(&self) -> bool {
        false
    }
    fn inspect(&self, content: &[u8], offset: usize) -> Option<Inspection> {
        self.inspect_many(content, &[offset]).pop().flatten()
    }
    fn inspect_many(&self, content: &[u8], offsets: &[usize]) -> Vec<Option<Inspection>> {
        let entries = entries(content);
        offsets
            .iter()
            .map(|&o| locate(content, entries.as_deref()?, o))
            .collect()
    }
}

/// Whether `content` is an MMKV store (see the module doc).
pub(crate) fn parses(content: &[u8]) -> bool {
    entries(content).is_some_and(|e| !e.is_empty())
}

/// One entry: where its key and value are.
#[derive(Debug)]
struct Entry {
    key: Range<usize>,
    value: Range<usize>,
}

/// The entries, when they frame the data exactly; `None` otherwise.
fn entries(c: &[u8]) -> Option<Vec<Entry>> {
    let size = usize::try_from(u32::from_le_bytes(c.get(..4)?.try_into().ok()?)).ok()?;
    let end = 4usize.checked_add(size)?;
    if size < 2 || end > c.len() {
        return None;
    }
    let (_, mut i) = leb128(c, 4, 5)?;
    let mut out = Vec::new();
    while i < end {
        let (key_len, at) = leb128(c, i, 5)?;
        let key = at..at.checked_add(usize::try_from(key_len).ok()?)?;
        if key.is_empty() || key.end > end {
            return None;
        }
        let text = std::str::from_utf8(&c[key.clone()]).ok()?;
        if text.chars().any(char::is_control) {
            return None;
        }
        let (value_len, at) = leb128(c, key.end, 5)?;
        let value = at..at.checked_add(usize::try_from(value_len).ok()?)?;
        if value.end > end {
            return None;
        }
        i = value.end;
        out.push(Entry { key, value });
    }
    (i == end).then_some(out)
}

/// A value as shown: a string when it is exactly a varint length and that many
/// bytes, else a varint number, else its size.
///
/// The store records no type, so this is a reading of the bytes' shape, named so in
/// the detail (`reading`). A single 0 byte fits both: the number 0 and an empty string.
fn value_text(c: &[u8], value: &Range<usize>) -> (&'static str, String) {
    let bytes = &c[value.clone()];
    if bytes == [0] {
        return ("number 0 or empty string", "0 (or \"\")".to_string());
    }
    if let Some((n, at)) = leb128(bytes, 0, 5)
        && usize::try_from(n).ok() == Some(bytes.len() - at)
    {
        return ("string", super::quoted_bytes(&bytes[at..]));
    }
    match leb128(bytes, 0, 5) {
        Some((n, at)) if at == bytes.len() => ("number", n.to_string()),
        _ => ("bytes", format!("<{} bytes>", bytes.len())),
    }
}

fn locate(c: &[u8], entries: &[Entry], offset: usize) -> Option<Inspection> {
    let i = entries.partition_point(|e| e.key.start <= offset);
    let (n, entry) = (i.checked_sub(1)?, entries.get(i.checked_sub(1)?)?);
    if offset >= entry.value.end {
        return None;
    }
    let key = String::from_utf8_lossy(&c[entry.key.clone()]).into_owned();
    // A later entry for the same key replaced this one's value.
    let superseded_by = entries[n + 1..]
        .iter()
        .position(|e| c[e.key.clone()] == c[entry.key.clone()])
        .map(|p| n + 1 + p + 1);
    let (kind, value) = value_text(c, &entry.value);
    let part = if entry.key.contains(&offset) {
        "key"
    } else {
        "value"
    };
    let mut summary = format!(
        "key: \"{key}\"  value: {value}  (entry {} of {})",
        n + 1,
        entries.len()
    );
    if let Some(later) = superseded_by {
        summary.push_str(&format!("  superseded by entry {later}"));
    }
    Some(Inspection {
        format: "mmkv".into(),
        summary,
        detail: json!({
            "key": key,
            "part": part,
            "reading": kind,
            "value": value,
            "entry": n + 1,
            "entries": entries.len(),
            "superseded_by": superseded_by,
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::super::Inspector;
    use super::*;

    /// An MMKV store from `(key, value container)` entries, padded to 4 KiB.
    fn store(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut items = Vec::new();
        for (k, v) in entries {
            items.push(k.len() as u8);
            items.extend_from_slice(k.as_bytes());
            items.push(v.len() as u8);
            items.extend_from_slice(v);
        }
        let mut data = vec![items.len() as u8];
        data.extend_from_slice(&items);
        let mut f = (data.len() as u32).to_le_bytes().to_vec();
        f.extend_from_slice(&data);
        f.resize(4096, 0);
        f
    }

    /// A string value: its varint length, then the bytes.
    fn s(text: &str) -> Vec<u8> {
        let mut v = vec![text.len() as u8];
        v.extend_from_slice(text.as_bytes());
        v
    }

    fn at(f: &[u8], needle: &[u8]) -> usize {
        f.windows(needle.len()).position(|w| w == needle).unwrap()
    }

    #[test]
    fn keys_values_and_superseded_entries_resolve() {
        let (old, new) = (s("old@mail.example"), s("new@mail.example"));
        let f = store(&[("email", &old), ("count", &[42]), ("email", &new)]);
        assert!(parses(&f));
        let first = Mmkv.inspect(&f, at(&f, b"old@")).unwrap();
        assert_eq!(
            first.summary,
            "key: \"email\"  value: \"old@mail.example\"  (entry 1 of 3)  superseded by entry 3"
        );
        let count = Mmkv.inspect(&f, at(&f, b"count")).unwrap();
        assert_eq!(count.detail["part"], "key");
        assert_eq!(count.detail["value"], "42");
        let last = Mmkv.inspect(&f, at(&f, b"new@")).unwrap();
        assert!(last.detail["superseded_by"].is_null());
        // A single 0 byte is both the number 0 and an empty string.
        let g = store(&[("flag", &[0])]);
        let flag = Mmkv.inspect(&g, at(&g, b"flag")).unwrap();
        assert_eq!(flag.detail["value"], "0 (or \"\")");
    }

    #[test]
    fn data_that_does_not_frame_exactly_is_not_mmkv() {
        let mut f = store(&[("k", &s("v"))]);
        assert!(parses(&f));
        f[0] += 1; // the declared size no longer matches the entries
        assert!(!parses(&f));
        assert!(!parses(b"plain text, nothing like a store at all"));
        // A key with a control character is not a key.
        assert!(!parses(&store(&[("a\x01b", &s("v"))])));
    }
}
