//! Nested-archive expansion for folder scans (`--archive-depth`).
//!
//! Defines: [`expand`], which opens a `.zip` found inside a scanned folder, lists
//! its files as [`crate::models::Location::Nested`] entries, and recurses into
//! further nested `.zip` files up to the requested depth.
//! Used by: `crate::source::folder` (when `--archive-depth >= 1`).
//! Uses: `crate::source::zip` (parse + read), `crate::models`.
//!
//! Each opened archive's bytes are kept in the [`FolderSource`](crate::source::folder)'s
//! `blobs` arena and referenced by index; the arena only grows, so the indices the
//! entries carry stay valid as deeper archives are appended. A `.zip` that cannot be
//! parsed (or read) is kept as a single opaque file rather than dropped — forensic
//! archives are frequently partial.

use anyhow::Result;

use crate::models::{Entry, Location, Method};
use crate::source::zip;

/// Expand a nested-archive `blob` into `entries`, prefixing each internal path with
/// `prefix` (which ends in `/`). `remaining` is how many *further* levels of nested
/// `.zip` may be opened below this one (0 = treat any inner `.zip` as opaque).
///
/// Returns `Err` only when `blob` itself is not a parseable ZIP, so the caller can
/// fall back to treating it as an opaque file; per-entry problems degrade to opaque
/// entries in place.
pub(crate) fn expand(
    blob: Vec<u8>,
    prefix: &str,
    remaining: u32,
    entries: &mut Vec<Entry>,
    blobs: &mut Vec<Vec<u8>>,
) -> Result<()> {
    // Parse before taking an arena slot, so a malformed blob errors without leaving
    // a dangling index behind.
    let zentries = zip::parse_entries(&blob)?;
    let blob_idx = blobs.len();
    blobs.push(blob);

    // Inner `.zip` files to open after the loop — we cannot recurse (which mutably
    // borrows the arena) while still borrowing this blob to read them.
    let mut pending: Vec<Pending> = Vec::new();

    {
        let blob_ref: &[u8] = &blobs[blob_idx];
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

            // Expand an inner `.zip` when the depth budget allows and it reads; an
            // unreadable one falls through to a single opaque entry.
            let is_zip = ze.name.to_ascii_lowercase().ends_with(".zip");
            if is_zip
                && remaining >= 1
                && let Ok(content) = zip::content(blob_ref, ze)
            {
                pending.push(Pending {
                    name,
                    content: content.into_owned(),
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
    }

    for p in pending {
        // Recurse into the inner archive; if it will not parse, keep it as one opaque
        // file (its bytes still live as a stored entry in the parent blob).
        if expand(
            p.content,
            &format!("{}/", p.name),
            remaining - 1,
            entries,
            blobs,
        )
        .is_err()
        {
            entries.push(nested_entry(
                p.name,
                p.uncompressed_size,
                p.mtime,
                blob_idx,
                p.method,
                p.data_offset,
                p.data_len,
            ));
        }
    }
    Ok(())
}

/// An inner `.zip` queued for expansion after the parent blob's borrow is released.
struct Pending {
    name: String,
    content: Vec<u8>,
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
