//! Inspector template — a copy-paste starting point for a new format.
//!
//! To add an inspector:
//!   1. Copy this file to `src/formats/inspect/<format>.rs` and `mod <format>;` it in
//!      `src/formats/inspect/mod.rs`.
//!   2. Rename `Foo`, fill in the methods below.
//!   3. Register it: add `&<format>::Foo` to `INSPECTORS` in `src/formats/inspect/mod.rs`
//!      (list more specific formats first — header `detect` checks run in order).
//!   4. Add a test, ideally against a committed fixture in `tests/fixtures/`.
//!
//! An inspector turns a byte `offset` (where a match landed) into a meaningful
//! location inside a recognised format. It is a zero-sized type implementing the
//! `Inspector` trait, so all the shared plumbing (detection order, dispatch,
//! output) lives in `mod.rs` — you only supply the format specifics. If several
//! inspectors need the same logic, add a documented helper to `mod.rs` (see the
//! existing `line_at`, `looks_like_xml`, `contains`) rather than duplicating it.

use serde_json::json;

use crate::core::models::Inspection;

/// One-line description of the format this inspector handles.
pub struct Foo;

impl super::Inspector for Foo {
    /// Short format tag — the `--type` value for this exact format and the
    /// `format` shown in output (e.g. `"foo"`).
    fn name(&self) -> &'static str {
        "foo"
    }

    /// Coarse group for `--type` family selection, e.g. `"media"`, `"database"`,
    /// `"structured"`, `"text"`.
    fn category(&self) -> &'static str {
        "structured"
    }

    /// File-name extensions (lowercase, no dot) for fallback detection when the
    /// content has no recognisable header.
    fn extensions(&self) -> &'static [&'static str] {
        &["foo"]
    }

    /// Recognise the format from its header/magic — preferred over the
    /// extension. Return `false` for formats with no signature (the extension
    /// list then drives detection).
    fn detect(&self, content: &[u8]) -> bool {
        content.starts_with(b"FOO\0")
    }

    /// Resolve a match at `offset` to a meaningful location, or `None` when it
    /// cannot be placed (the caller then emits a plain match record).
    ///
    /// Conventions:
    /// - `format` is the short tag shown in output (e.g. `"foo"`).
    /// - `summary` is the labelled, human one-liner (the txt tag and csv
    ///   `context`), e.g. `key: $.a.b  line: 12`.
    /// - `detail` is the structured form (json `context`); use the same keys.
    /// - For binary formats, decode and length-cap any value you include — never
    ///   put raw bytes in the output.
    fn inspect(&self, content: &[u8], offset: usize) -> Option<Inspection> {
        if offset >= content.len() {
            return None;
        }

        // ... parse `content` and locate `offset` within it ...
        let location = "example";

        Some(Inspection {
            format: "foo".into(),
            summary: format!("location: {location}"),
            detail: json!({ "location": location }),
        })
    }

    /// Optional: sidecar files exported alongside a matched file of this format
    /// (suffixes appended to the file name, e.g. SQLite's `-wal`). Delete this
    /// method if the format has none — the default returns an empty list.
    fn sidecars(&self) -> &'static [&'static str] {
        &["-journal"]
    }
}
