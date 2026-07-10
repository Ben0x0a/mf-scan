//! TXT inspector: map a byte offset to a line and column.
//!
//! Defines: `inspect`, returning the 1-based line and (byte) column of a match
//! within a text file.
//! Used by: `inspect::inspect` (dispatch).
//! Uses: `crate::core::models::Inspection`, `serde_json` (structured detail).
//!
//! Column is counted in bytes, not Unicode scalar values — forensic text may
//! not be valid UTF-8, and a byte column stays meaningful regardless.

use std::collections::HashMap;

use serde_json::json;

use crate::core::models::{ContentDiff, Inspection};

/// TXT inspector — plain text / log files (no header; detected by extension).
pub struct Txt;

impl super::Inspector for Txt {
    fn name(&self) -> &'static str {
        "txt"
    }
    fn category(&self) -> &'static str {
        "text"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["txt", "log", "text"]
    }
    fn detect(&self, _content: &[u8]) -> bool {
        false // no signature
    }
    fn inspect(&self, content: &[u8], offset: usize) -> Option<Inspection> {
        resolve(content, offset)
    }
    fn diff(&self, old: &[u8], new: &[u8]) -> Option<ContentDiff> {
        Some(line_diff(old, new))
    }
}

/// Report the 1-based line and byte-column of `offset` within `content`.
fn resolve(content: &[u8], offset: usize) -> Option<Inspection> {
    // An offset past the end means the caller passed a position from a
    // different buffer; refuse rather than report a bogus location.
    if offset > content.len() {
        return None;
    }

    let mut line = 1usize;
    let mut col = 1usize;
    for &b in &content[..offset] {
        if b == b'\n' {
            line += 1;
            col = 1;
        } else {
            col += 1;
        }
    }

    Some(Inspection {
        format: "txt".into(),
        summary: format!("line: {line}  col: {col}"),
        detail: json!({ "line": line, "col": col }),
    })
}

/// Diff two text blobs by line multiset: how many lines were added/removed.
///
/// HOW: count each distinct line in `old`, then walk `new` consuming those counts —
/// a `new` line with no remaining `old` match is an addition; `old` lines left over
/// are removals. This is a set-level summary, not a positional diff, so it ignores
/// pure reordering (reported as "no line additions or removals") and stays cheap on
/// large logs. Lines are split on `\n` with any trailing `\r` trimmed.
fn line_diff(old: &[u8], new: &[u8]) -> ContentDiff {
    let mut counts: HashMap<&[u8], i64> = HashMap::new();
    for line in lines(old) {
        *counts.entry(line).or_default() += 1;
    }
    let mut added = 0u64;
    for line in lines(new) {
        let slot = counts.entry(line).or_default();
        if *slot > 0 {
            *slot -= 1;
        } else {
            added += 1;
        }
    }
    let removed: u64 = counts.values().filter(|&&c| c > 0).map(|&c| c as u64).sum();

    let summary = if added == 0 && removed == 0 {
        "no line additions or removals (lines reordered or whitespace only)".to_string()
    } else {
        format!("+{added} / -{removed} lines")
    };
    ContentDiff {
        format: "txt".into(),
        summary,
        detail: json!({ "lines_added": added, "lines_removed": removed }),
    }
}

/// Split `content` into lines on `\n`, trimming a trailing `\r` (CRLF-safe).
fn lines(content: &[u8]) -> impl Iterator<Item = &[u8]> {
    content
        .split(|&b| b == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l))
}

#[cfg(test)]
mod tests {
    use super::line_diff;

    #[test]
    fn counts_added_and_removed_lines() {
        let d = line_diff(b"a\nb\nc\n", b"a\nc\nd\n");
        assert_eq!(d.format, "txt");
        assert_eq!(d.detail["lines_added"], 1); // d
        assert_eq!(d.detail["lines_removed"], 1); // b
        assert_eq!(d.summary, "+1 / -1 lines");
    }

    #[test]
    fn reordering_is_not_a_line_change() {
        // Same multiset of lines, different order — no additions or removals.
        let d = line_diff(b"one\ntwo\nthree", b"three\ntwo\none");
        assert_eq!(d.detail["lines_added"], 0);
        assert_eq!(d.detail["lines_removed"], 0);
        assert!(d.summary.contains("reordered"));
    }

    #[test]
    fn crlf_and_lf_lines_compare_equal() {
        // The trailing \r is trimmed, so CRLF vs LF is not a spurious change.
        let d = line_diff(b"x\r\ny\r\n", b"x\ny\n");
        assert_eq!(d.detail["lines_added"], 0);
        assert_eq!(d.detail["lines_removed"], 0);
    }
}
