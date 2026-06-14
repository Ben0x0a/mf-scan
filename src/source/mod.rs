//! Sources: the container abstraction the search and diff engines read through.
//!
//! Defines: the [`Source`] trait — enumerate a container's files ([`Source::entries`])
//! and read any file's logical bytes ([`Source::content`]) — plus [`Content`]
//! (the borrowed/owned/mapped byte carrier) and the concrete containers. A
//! `Source` is whatever yields located files with bytes: a ZIP archive
//! ([`zip::ZipSource`]) or a directory of loose files ([`folder::FolderSource`]).
//! Used by: `engine` (search), `report::export` and `diff`. Built by the
//! binary's `support::sources`.
//! Uses: `crate::models::Entry`, `anyhow`, `memmap2` (large loose files).
//!
//! Why a trait rather than passing `&[u8]` around: the engine used to assume every
//! source was a memory-mapped ZIP addressed by byte offsets. Reading bytes through
//! one method lets a folder of loose files (no offsets, read from disk) flow through
//! the exact same search/inspect/export pipeline, with the offset model
//! (`MatchRecord::archive_offset`) becoming `None` where there is no archive.

use std::ops::Deref;

use anyhow::Result;

use crate::models::Entry;

pub mod folder;
mod nested;
pub mod ranged;
pub mod zip;

/// One entry's logical bytes, however the source backs them.
///
/// Like `Cow<'a, [u8]>` with a third, self-owning variant: a memory map. The
/// map is what lets [`folder::FolderSource`] serve a multi-GB loose file
/// without materialising it on the heap — a `Cow` could only *borrow* a map
/// owned by `&self`, but the map is created per call — mirroring the zero-copy
/// path the top-level ZIP mmap already has.
pub enum Content<'a> {
    /// Borrowed from the source's backing store (a STORED ZIP entry over the mmap).
    Borrowed(&'a [u8]),
    /// Owned heap bytes (DEFLATE inflate, decrypted plaintext, small loose file).
    Owned(Vec<u8>),
    /// A read-only memory map of a large loose file.
    Mapped(memmap2::Mmap),
}

impl Deref for Content<'_> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        match self {
            Content::Borrowed(b) => b,
            Content::Owned(v) => v,
            Content::Mapped(m) => m,
        }
    }
}

impl AsRef<[u8]> for Content<'_> {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

impl Content<'_> {
    /// The bytes as an owned `Vec`, copying only when not already owned.
    pub fn into_owned(self) -> Vec<u8> {
        match self {
            Content::Borrowed(b) => b.to_vec(),
            Content::Owned(v) => v,
            Content::Mapped(m) => m.to_vec(),
        }
    }
}

/// Outcome of checking an entry's *stored* bytes against a digest the source
/// itself records — independent provenance metadata, not a hash this tool
/// computed. The only source that carries one today is an encrypted iOS backup,
/// whose `Manifest.db` records the SHA-1 of each file's encrypted on-disk blob.
///
/// Used by the export path to attest that the original evidence (the stored
/// ciphertext) was read intact, *before* any decryption — a stronger guarantee
/// than hashing only the bytes we wrote out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntegrityCheck {
    /// The source records a digest for this entry and the stored bytes matched.
    Verified { algorithm: &'static str },
    /// The source records a digest and the stored bytes did NOT match it —
    /// the original evidence is corrupt or was read wrong. Surfaced loudly.
    Mismatch {
        algorithm: &'static str,
        expected: String,
        actual: String,
    },
    /// The source records no digest for this entry (the common case).
    Unrecorded,
}

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
    /// (a STORED ZIP entry over the mmap), owned otherwise (DEFLATE inflate, a
    /// small loose file), or a fresh memory map (a large loose file).
    fn content(&self, entry: &Entry) -> Result<Content<'_>>;

    /// The source's physical size in bytes — the archive file size for a ZIP, the
    /// summed file sizes for a folder. Used only for the coverage report; the
    /// default sums the entries' logical sizes, which a backing store can override
    /// with its true on-disk size.
    fn byte_size(&self) -> u64 {
        self.entries().iter().map(|e| e.uncompressed_size).sum()
    }

    /// Check `entry`'s stored bytes against a digest the source records about
    /// them, if any. The default — for sources with no independent integrity
    /// metadata (folders, plain ZIPs) — is [`IntegrityCheck::Unrecorded`]. The
    /// encrypted-backup source overrides this to verify each file's encrypted
    /// blob against the SHA-1 in `Manifest.db`.
    fn integrity_check(&self, _entry: &Entry) -> IntegrityCheck {
        IntegrityCheck::Unrecorded
    }

    /// Whether classifying an entry's type from a cheap header *prefix* (rather
    /// than its full content) is worth it for this source.
    ///
    /// `false` by default: for an mmap or folder source [`Source::content`] is
    /// already lazy (the OS faults only the pages actually touched), so reading a
    /// prefix first would be pure overhead. The positioned-read
    /// [`ranged::RangedZipSource`] overrides it to `true` — over a network mount,
    /// fetching a whole media file only to skip it by `--type`/`--exclude-media`
    /// is exactly the cost to avoid, so the engine classifies from a small header
    /// read first (see [`Source::content_prefix`]).
    fn prefers_prefix_classification(&self) -> bool {
        false
    }

    /// Read up to `max` bytes of `entry`'s logical content, for type
    /// classification before committing to the full read.
    ///
    /// The default returns the whole content (correct everywhere — the caller
    /// only looks at the header); the ranged source overrides it to fetch just a
    /// small header range over the network. Only consulted when
    /// [`Source::prefers_prefix_classification`] is `true`.
    fn content_prefix(&self, entry: &Entry, _max: usize) -> Result<Content<'_>> {
        self.content(entry)
    }
}
