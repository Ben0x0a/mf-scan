//! Nested-archive expansion for folder scans (`--archive-depth`).
//!
//! Defines: [`expand`], which opens a `.zip` found inside a scanned folder, lists
//! its files as [`crate::core::models::Location::Nested`] entries, and recurses into
//! further nested `.zip` files up to the requested depth.
//! Used by: `crate::core::source::folder` (when `--archive-depth >= 1`).
//! Uses: `crate::core::source::zip` (parse + read), `crate::core::models`.
//!
//! Each opened archive's bytes are kept in the [`FolderSource`](crate::core::source::folder)'s
//! `blobs` arena and referenced by index; the arena only grows, so the indices the
//! entries carry stay valid as deeper archives are appended. A `.zip` that cannot be
//! parsed (or read) is kept as a single opaque file rather than dropped — forensic
//! archives are frequently partial.

use std::fmt;

use anyhow::Result;

use crate::core::models::{Entry, Location, Method};
use crate::core::source::zip;

/// Cumulative cap on bytes held in the nested-archive arena.
///
/// Depth is operator-bounded (`--archive-depth`) but breadth is not: one folder
/// of many nested archives (or a crafted archive-of-archives) could exceed RAM
/// at depth 1. Exhausting the budget fails loudly (see [`ArenaBudgetExceeded`])
/// instead of OOM-killing the process.
pub(crate) const NESTED_ARENA_BUDGET: u64 = 4 * 1024 * 1024 * 1024;

/// Marker error: opening one more nested archive would exceed the arena budget.
///
/// Callers degrade a *parse* failure to an opaque entry, but must propagate
/// THIS error: degrading would silently cut coverage short, and continuing to
/// inflate would exhaust memory on crafted input.
#[derive(Debug)]
pub(crate) struct ArenaBudgetExceeded {
    pub(crate) budget: u64,
}

impl fmt::Display for ArenaBudgetExceeded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "nested archives exceed the {} bytes in-memory budget; \
             lower --archive-depth or scan the inner archives individually",
            self.budget
        )
    }
}

impl std::error::Error for ArenaBudgetExceeded {}

/// Expand a nested-archive `blob` into `entries`, prefixing each internal path with
/// `prefix` (which ends in `/`). `remaining` is how many *further* levels of nested
/// `.zip` may be opened below this one (0 = treat any inner `.zip` as opaque).
/// `budget` is the remaining arena allowance, decremented per opened blob.
///
/// Returns `Err` when `blob` itself is not a parseable ZIP — the caller can fall
/// back to treating it as an opaque file — or when the arena budget is exhausted
/// (an [`ArenaBudgetExceeded`], which the caller must propagate, not degrade);
/// other per-entry problems degrade to opaque entries in place.
pub(crate) fn expand(
    blob: Vec<u8>,
    prefix: &str,
    remaining: u32,
    entries: &mut Vec<Entry>,
    blobs: &mut Vec<Vec<u8>>,
    budget: &mut u64,
) -> Result<()> {
    // Parse before taking an arena slot, so a malformed blob errors without leaving
    // a dangling index behind.
    let zentries = zip::parse_entries(&blob)?;
    let blob_len = blob.len() as u64;
    if blob_len > *budget {
        return Err(anyhow::Error::new(ArenaBudgetExceeded {
            budget: NESTED_ARENA_BUDGET,
        }));
    }
    *budget -= blob_len;
    let blob_idx = blobs.len();
    blobs.push(blob);

    // Inner `.zip` files to expand after the loop — we cannot recurse (which mutably
    // borrows the arena) while still borrowing this blob to read them. We record only
    // the lightweight *coordinates* of each inner zip, NOT its bytes: materialising
    // every inner buffer up front would hold them all resident at once, so peak RAM
    // could exceed the budget by their sum. Re-extracting one at a time below keeps at
    // most ONE transient inner buffer resident, and it is charged only if/when the
    // recursion commits it to the arena.
    let mut pending: Vec<Pending> = Vec::new();

    for ze in &zentries {
        if ze.is_dir() {
            continue;
        }
        // `parse_entries` only ever yields `Zip` locations.
        let Location::Zip {
            method,
            data_offset,
            data_len,
        } = &ze.location
        else {
            continue;
        };
        let (method, data_offset, data_len) = (*method, *data_offset, *data_len);
        let name = format!("{prefix}{}", ze.name);

        // An inner `.zip` is a candidate for expansion when the depth budget allows;
        // anything else is a single opaque entry. We defer the extraction itself (and
        // its read errors) to the loop below, so coordinate-gathering touches no bytes.
        let is_zip = ze.name.to_ascii_lowercase().ends_with(".zip");
        if is_zip && remaining >= 1 {
            pending.push(Pending {
                name,
                method,
                data_offset,
                data_len,
                uncompressed_size: ze.uncompressed_size,
                mtime: ze.mtime,
            });
            continue;
        }
        entries.push(nested_entry(
            name,
            ze.uncompressed_size,
            ze.mtime,
            blob_idx,
            method,
            data_offset,
            data_len,
        ));
    }

    for p in pending {
        // Re-borrow the parent blob to extract just this one inner archive's bytes, then
        // drop the borrow before recursing (which mutably borrows the arena). At most one
        // such transient buffer is resident at a time. An unreadable inner zip degrades to
        // a single opaque entry — its (never materialised) bytes still live as a stored
        // entry in the parent blob, and no budget was ever charged for it.
        let content = match zip::read_range(
            &blobs[blob_idx],
            p.method,
            p.data_offset,
            p.data_len,
            p.uncompressed_size,
            &p.name,
        ) {
            Ok(c) => c.into_owned(),
            Err(_) => {
                entries.push(nested_entry(
                    p.name,
                    p.uncompressed_size,
                    p.mtime,
                    blob_idx,
                    p.method,
                    p.data_offset,
                    p.data_len,
                ));
                continue;
            }
        };

        // Recurse into the inner archive; if it will not parse, keep it as one opaque
        // file (the just-extracted buffer is dropped, so it consumes no budget — the
        // recursion only charges blobs it actually commits to the arena). A budget
        // exhaustion is NOT a parse problem and must abort the whole expansion.
        match expand(
            content,
            &format!("{}/", p.name),
            remaining - 1,
            entries,
            blobs,
            budget,
        ) {
            Ok(()) => {}
            Err(e) if e.is::<ArenaBudgetExceeded>() => return Err(e),
            Err(_) => entries.push(nested_entry(
                p.name,
                p.uncompressed_size,
                p.mtime,
                blob_idx,
                p.method,
                p.data_offset,
                p.data_len,
            )),
        }
    }
    Ok(())
}

/// The lightweight coordinates of an inner `.zip` queued for expansion after the
/// parent blob's borrow is released. Holds NO bytes — the buffer is re-extracted
/// from the parent blob one at a time in the expansion loop, so peak resident
/// memory stays bounded by the arena budget.
struct Pending {
    name: String,
    method: Method,
    data_offset: u64,
    data_len: u64,
    uncompressed_size: u64,
    mtime: Option<u64>,
}

/// Build an [`Entry`] for a file located inside the arena blob `archive`.
#[allow(clippy::too_many_arguments)]
fn nested_entry(
    name: String,
    uncompressed_size: u64,
    mtime: Option<u64>,
    archive: usize,
    method: Method,
    data_offset: u64,
    data_len: u64,
) -> Entry {
    Entry {
        name,
        uncompressed_size,
        mtime,
        location: Location::Nested {
            archive,
            method,
            data_offset,
            data_len,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // The single canonical STORED-zip builder for the crate's unit tests; the
    // integration tests use their own richer `tests/common::build_zip`.
    use crate::testutil::stored_zip as build_stored_zip;

    /// Expand with a generous budget, returning the entry names produced.
    fn expand_ok(blob: Vec<u8>, depth: u32) -> Vec<String> {
        let mut entries = Vec::new();
        let mut blobs = Vec::new();
        let mut budget = NESTED_ARENA_BUDGET;
        expand(blob, "", depth, &mut entries, &mut blobs, &mut budget).expect("expansion failed");
        entries.into_iter().map(|e| e.name).collect()
    }

    /// Several inner `.zip`s, each individually fitting a small budget but together
    /// exceeding it, must be rejected with `ArenaBudgetExceeded` rather than OOMing.
    ///
    /// WHY this guards the peak-memory fix: the inner buffers are charged exactly
    /// once each as the recursion commits them; the second one tips the running
    /// total past the budget and the error must propagate, not degrade.
    #[test]
    fn combined_inner_zips_exceed_small_budget() {
        // Two inner zips, each ~ one payload; pick a budget that fits the outer blob
        // plus one inner but not both.
        let payload_a = vec![b'A'; 256];
        let payload_b = vec![b'B'; 256];
        let inner_a = build_stored_zip(&[("a.txt", &payload_a)]);
        let inner_b = build_stored_zip(&[("b.txt", &payload_b)]);
        let outer = build_stored_zip(&[("a.zip", &inner_a), ("b.zip", &inner_b)]);

        // Budget: outer blob + the first inner blob fit; the second does not.
        let mut budget = outer.len() as u64 + inner_a.len() as u64 + (inner_b.len() as u64 - 1);
        let mut entries = Vec::new();
        let mut blobs = Vec::new();
        let err = expand(outer, "", 1, &mut entries, &mut blobs, &mut budget)
            .expect_err("combined inner zips should exceed the budget");
        assert!(
            err.is::<ArenaBudgetExceeded>(),
            "expected ArenaBudgetExceeded, got: {err}"
        );
    }

    /// An inner ".zip" that is actually un-parseable garbage degrades to an opaque
    /// entry WITHOUT consuming budget, so a subsequent legitimate inner zip still
    /// fits and expands — proving the budget is not leaked on the fallback path.
    #[test]
    fn unparseable_inner_zip_does_not_leak_budget() {
        // A garbage "zip" (no EOCD) that will fail to parse, plus a real inner zip.
        let garbage = b"PK-not-a-real-zip-at-all".to_vec();
        let real_payload = vec![b'R'; 256];
        let inner_real = build_stored_zip(&[("real.txt", &real_payload)]);
        let outer = build_stored_zip(&[("bad.zip", &garbage), ("good.zip", &inner_real)]);

        // Budget: outer blob + exactly the ONE legitimate inner blob. If the garbage
        // entry leaked budget (charged but never refunded), the good zip would no
        // longer fit and expansion would wrongly fail.
        let mut budget = outer.len() as u64 + inner_real.len() as u64;
        let mut entries = Vec::new();
        let mut blobs = Vec::new();
        expand(outer, "", 1, &mut entries, &mut blobs, &mut budget)
            .expect("garbage inner zip must degrade without leaking budget");

        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        // The garbage stays a single opaque entry; the good zip is expanded inwards.
        assert!(names.contains(&"bad.zip"), "names: {names:?}");
        assert!(names.contains(&"good.zip/real.txt"), "names: {names:?}");
    }

    /// A well-formed nest within budget expands inner contents with prefixed paths.
    #[test]
    fn nested_zip_expands_within_budget() {
        let inner = build_stored_zip(&[("note.txt", b"hello")]);
        let outer = build_stored_zip(&[("inner.zip", &inner), ("top.txt", b"top")]);
        let names = expand_ok(outer, 1);
        assert!(
            names.contains(&"inner.zip/note.txt".to_string()),
            "{names:?}"
        );
        assert!(names.contains(&"top.txt".to_string()), "{names:?}");
    }
}
