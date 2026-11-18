//! uuidtext inspector: map a byte offset in an Apple unified log `uuidtext` file
//! (`/private/var/db/uuidtext/XX/<uuid>`) to the format string holding it and the
//! binary that logs it.
//!
//! Defines: [`Uuidtext`] (the inspector).
//! Used by: `inspect::mod` (registered in `INSPECTORS`).
//! Uses: `crate::core::models::Inspection`, `serde_json`.
//!
//! ── Format ───────────────────────────────────────────────────────────────────
//! As documented by Mandiant's `macos-UnifiedLogs` and libyal's notes: a header
//! (magic 0x66778899, major and minor version, entry count; u32 little-endian),
//! one descriptor per entry (the entry's offset in the binary's string space, its
//! size), the entries' bytes (NUL-terminated format strings) one after another, then
//! the path of the binary. A `.tracev3` entry refers to its format string by that
//! string-space offset, given here as `string_offset`.
//!
//! Checked on the 1,165 `uuidtext` files of an iPhone: 1,163 lay out exactly so,
//! their footer a path; the other two still parse, their footer not a plain path.

use std::ops::Range;

use serde_json::json;

use super::quoted_bytes;
use crate::core::models::Inspection;

const MAGIC: [u8; 4] = [0x99, 0x88, 0x77, 0x66];
const HEADER: usize = 16;

/// uuidtext inspector — recognised by its magic and version 2.
pub struct Uuidtext;

impl super::Inspector for Uuidtext {
    fn name(&self) -> &'static str {
        "uuidtext"
    }
    fn category(&self) -> &'static str {
        "log"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &[]
    }
    fn detect(&self, content: &[u8]) -> bool {
        content.starts_with(&MAGIC) && content.get(4..8) == Some(&[2, 0, 0, 0])
    }
    fn inspect(&self, content: &[u8], offset: usize) -> Option<Inspection> {
        self.inspect_many(content, &[offset]).pop().flatten()
    }
    fn inspect_many(&self, content: &[u8], offsets: &[usize]) -> Vec<Option<Inspection>> {
        let layout = read(content);
        offsets
            .iter()
            .map(|&o| locate(content, layout.as_ref()?, o))
            .collect()
    }
}

/// One entry: where its bytes are, and their offset in the binary's string space.
struct Entry {
    range: Range<usize>,
    string_offset: u32,
}

struct Layout {
    entries: Vec<Entry>,
    /// The binary's path, after the entries.
    footer: Range<usize>,
}

fn u32_at(c: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(c.get(at..at + 4)?.try_into().ok()?))
}

/// The header, descriptors and entries, when they fit the file.
fn read(c: &[u8]) -> Option<Layout> {
    if !c.starts_with(&MAGIC) {
        return None;
    }
    let count = usize::try_from(u32_at(c, 12)?).ok()?;
    let mut at = HEADER.checked_add(count.checked_mul(8)?)?;
    if at > c.len() {
        return None;
    }
    let mut entries = Vec::with_capacity(count);
    for i in 0..count {
        let string_offset = u32_at(c, HEADER + 8 * i)?;
        let size = usize::try_from(u32_at(c, HEADER + 8 * i + 4)?).ok()?;
        let range = at..at.checked_add(size)?;
        if range.end > c.len() {
            return None;
        }
        at = range.end;
        entries.push(Entry {
            range,
            string_offset,
        });
    }
    Some(Layout {
        entries,
        footer: at..c.len(),
    })
}

/// The NUL-delimited string of `c[range]` holding `offset`, as its range.
fn string_at(c: &[u8], range: &Range<usize>, offset: usize) -> Range<usize> {
    let start = c[range.start..offset]
        .iter()
        .rposition(|&b| b == 0)
        .map_or(range.start, |p| range.start + p + 1);
    let end = c[offset..range.end]
        .iter()
        .position(|&b| b == 0)
        .map_or(range.end, |p| offset + p);
    start..end
}

fn locate(c: &[u8], layout: &Layout, offset: usize) -> Option<Inspection> {
    if offset >= c.len() {
        return None;
    }
    let path = String::from_utf8_lossy(&c[layout.footer.clone()])
        .trim_end_matches('\0')
        .to_string();
    let found = |summary: String, detail: serde_json::Value| Inspection {
        format: "uuidtext".into(),
        summary,
        detail,
    };
    if layout.footer.contains(&offset) {
        return Some(found(
            format!("binary path: \"{path}\""),
            json!({ "part": "binary path", "binary": path }),
        ));
    }
    let i = layout.entries.partition_point(|e| e.range.start <= offset);
    let Some((n, entry)) = i
        .checked_sub(1)
        .and_then(|n| Some((n, layout.entries.get(n)?)))
        .filter(|(_, e)| e.range.contains(&offset))
    else {
        return Some(found(
            "uuidtext header".into(),
            json!({ "part": "header", "binary": path }),
        ));
    };
    let string = string_at(c, &entry.range, offset);
    let string_offset = u64::from(entry.string_offset) + (string.start - entry.range.start) as u64;
    Some(found(
        format!(
            "format string: {}  (binary: {path})",
            quoted_bytes(&c[string.clone()])
        ),
        json!({
            "entry": n + 1,
            "string_offset": string_offset,
            "format_string": String::from_utf8_lossy(&c[string]),
            "binary": path,
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::super::Inspector;
    use super::*;

    /// A uuidtext file with two entries (string-space offsets 0x100 and 0x900).
    fn sample() -> Vec<u8> {
        let first = b"v8@?0\0started agent %{public}s\0";
        let second = b"connection lost: %d\0";
        let mut f = MAGIC.to_vec();
        for v in [2u32, 1, 2] {
            f.extend_from_slice(&v.to_le_bytes());
        }
        for (off, len) in [(0x100u32, first.len()), (0x900, second.len())] {
            f.extend_from_slice(&off.to_le_bytes());
            f.extend_from_slice(&(len as u32).to_le_bytes());
        }
        f.extend_from_slice(first);
        f.extend_from_slice(second);
        f.extend_from_slice(b"/usr/libexec/exampled\0");
        f
    }

    fn at(f: &[u8], needle: &[u8]) -> usize {
        f.windows(needle.len()).position(|w| w == needle).unwrap()
    }

    #[test]
    fn a_match_resolves_to_its_format_string_and_binary() {
        let f = sample();
        assert!(Uuidtext.detect(&f));
        let agent = Uuidtext.inspect(&f, at(&f, b"agent")).unwrap();
        assert_eq!(
            agent.summary,
            "format string: \"started agent %{public}s\"  (binary: /usr/libexec/exampled)"
        );
        // The second string of entry 1 starts 6 bytes into it.
        assert_eq!(agent.detail["string_offset"], 0x106);
        let lost = Uuidtext.inspect(&f, at(&f, b"lost")).unwrap();
        assert_eq!(lost.detail["entry"], 2);
        let path = Uuidtext.inspect(&f, at(&f, b"exampled")).unwrap();
        assert_eq!(path.summary, "binary path: \"/usr/libexec/exampled\"");
    }

    #[test]
    fn corrupt_bytes_never_panic() {
        let f = sample();
        for i in 0..f.len() {
            for b in [0x00, 0x7F, 0xFF] {
                let mut g = f.clone();
                g[i] = b;
                let _ = Uuidtext.inspect_many(&g, &[0, i, g.len() - 1]);
            }
        }
    }
}
