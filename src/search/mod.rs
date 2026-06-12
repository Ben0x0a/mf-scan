//! Per-entry byte search: scan a regex over content read from a source.
//!
//! Defines: the search module surface — [`search_bytes`] (run the regex, with line
//! previews), [`search_entry`] (read a ZIP entry's bytes and scan them), and the
//! [`base64`] submodule (alignment fragments for `--base64`).
//! Used by: `engine` (orchestration) and the tests.
//! Uses: `scan` (regex + preview) and `crate::source::zip` (entry byte access).
//!
//! Why split: content acquisition (mmap borrow vs DEFLATE inflate, now owned by the
//! `source` containers) and match scanning (regex, line bounds, preview windowing)
//! are independent concerns; this module owns the scanning half.

pub mod base64;
mod scan;

pub use scan::{MAX_HITS_PER_FILE, SearchHits, search_bytes, search_bytes_capped};

use anyhow::Result;
use regex::bytes::Regex;

use crate::models::{Entry, SearchHit};
use crate::source::zip;

/// Search one ZIP entry for every (non-overlapping) match of `re`.
///
/// A convenience for callers (and tests) that hold the raw archive bytes; the
/// engine reads through a [`crate::source::Source`] instead.
pub fn search_entry(archive: &[u8], entry: &Entry, re: &Regex) -> Result<Vec<SearchHit>> {
    let content = zip::content(archive, entry)?;
    Ok(search_bytes(&content, re))
}
