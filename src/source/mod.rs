//! Sources: the container abstraction the search and diff engines read through.
//!
//! Defines: the [`Source`] trait — enumerate a container's files ([`Source::entries`])
//! and read any file's logical bytes ([`Source::content`]) — plus the concrete
//! containers. A `Source` is whatever yields located files with bytes: a ZIP archive
//! ([`zip::ZipSource`]) or a directory of loose files ([`folder::FolderSource`]).
//! Opening nested archives found inside a folder (`--archive-depth`) is a later
//! addition.
//! Used by: `engine` (search), `report::export` and (later) `diff`. Built by the
//! binary's `support::sources`.
//! Uses: `crate::models::Entry`, `anyhow`, `std::borrow::Cow`.
//!
//! Why a trait rather than passing `&[u8]` around: the engine used to assume every
//! source was a memory-mapped ZIP addressed by byte offsets. Reading bytes through
//! one method lets a folder of loose files (no offsets, read from disk) flow through
//! the exact same search/inspect/export pipeline, with the offset model
//! (`MatchRecord::archive_offset`) becoming `None` where there is no archive.

use std::borrow::Cow;

use anyhow::Result;

use crate::models::Entry;

pub mod folder;
mod nested;
pub mod zip;

/// A container of located files: enumerate them, and read any one's bytes.
///
/// `Sync` because the engine searches entries in parallel (rayon) and calls
/// [`Source::content`] from worker threads. Implementors return each entry's
/// *logical* content — uncompressed, but still encrypted: decryption is the
/// engine's concern, applied after the bytes are read.
pub trait Source: Sync {
    /// The files this source exposes, in a stable order (directory placeholders
    /// included, so callers can report and skip them uniformly).
    fn entries(&self) -> &[Entry];

    /// The logical bytes of `entry`: borrowed from the backing store when possible
    /// (a STORED ZIP entry over the mmap), otherwise owned (DEFLATE inflate, or a
    /// loose file read from disk).
    fn content(&self, entry: &Entry) -> Result<Cow<'_, [u8]>>;

    /// The source's physical size in bytes — the archive file size for a ZIP, the
    /// summed file sizes for a folder. Used only for the coverage report; the
    /// default sums the entries' logical sizes, which a backing store can override
    /// with its true on-disk size.
    fn byte_size(&self) -> u64 {
        self.entries().iter().map(|e| e.uncompressed_size).sum()
    }
}
