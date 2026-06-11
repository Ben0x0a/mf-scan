//! File comparison: decide whether two located files are the same or changed.
//!
//! Defines: [`CompareMode`] (the fast metadata compare vs the exact content hash)
//! and [`differs`] (apply it to a pair of entries).
//! Used by: `diff` (the pairing engine).
//! Uses: `crate::models::Entry`, `crate::source::Source`, `sha2` (content hashing).

use anyhow::Result;
use sha2::{Digest, Sha256};

use crate::models::Entry;
use crate::source::Source;

/// How two files are compared to decide whether one was modified.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CompareMode {
    /// Fast (default): equal size *and* last-modified time means unchanged. Misses a
    /// content edit that preserves both — use [`CompareMode::Hash`] when that matters.
    Meta,
    /// Exact: equal SHA-256 of the content means unchanged. Reads both files.
    Hash,
}

/// True when the entry `ea` (in source `a`) differs from `eb` (in source `b`) under
/// `mode`. In [`CompareMode::Hash`] the content of both is read and hashed.
pub fn differs(
    mode: CompareMode,
    a: &dyn Source,
    ea: &Entry,
    b: &dyn Source,
    eb: &Entry,
) -> Result<bool> {
    match mode {
        CompareMode::Meta => {
            Ok(ea.uncompressed_size != eb.uncompressed_size || ea.mtime != eb.mtime)
        }
        CompareMode::Hash => Ok(sha256(&a.content(ea)?) != sha256(&b.content(eb)?)),
    }
}

/// SHA-256 digest of `bytes`.
fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
