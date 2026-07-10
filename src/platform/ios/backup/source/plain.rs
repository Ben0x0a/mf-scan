//! `PlainBackupSource`: present an UNENCRYPTED iOS backup by logical paths.
//!
//! Defines: [`PlainBackupSource`], a [`Source`] decorator that wraps the inner
//! folder/zip an *unencrypted* iOS backup lives in and presents each backed-up
//! file at its logical `domain/relativePath` — reading the on-disk blob straight
//! through (no decryption) and attesting it against the SHA-1 `Digest` recorded
//! in `Manifest.db`.
//! Used by: `support::sources` (wraps the inner source when the profiler reports
//! an UNENCRYPTED backup) and, through the [`Source`] trait, the search/diff
//! engines.
//! Uses: `super::common` for all the structural work it shares with the encrypted
//! [`super::EncryptedBackupSource`] — the `Manifest.db` `Files` walk, blob
//! locating, logical-entry building and the SHA-1 digest check.
//!
//! ── Why a sibling of [`super::EncryptedBackupSource`] and not a flag on it ────
//! The encrypted source's distinctive body is crypto — recover class keys, unwrap
//! each file key, AES-CBC-decrypt. None of that applies here: `Manifest.db` and
//! every file are already plaintext, so the only per-file work is reading the
//! blob. Everything the two genuinely share lives in `super::common`; this source
//! is what remains once the crypto is removed.
//!
//! ── Build / Read ─────────────────────────────────────────────────────────────
//! Build reads `Manifest.db` (a plain SQLite file) and, via
//! `common::read_present_files`, the regular files present on disk — keyed by
//! `domain/relativePath`. [`Source::content`] reads the on-disk blob (already
//! plaintext) for the entry's `fileID`; [`Source::integrity_check`] hashes that
//! same blob with SHA-1 and compares it to the recorded `Digest` (for an
//! unencrypted backup the Digest is the SHA-1 of the file content itself).

use anyhow::Result;

use crate::core::models::Entry;
use crate::core::source::{Content, IntegrityCheck, Source};
use crate::platform::ios::backup::common::{
    self, check_blob_digest, logical_entry, meta_index, read_backup_blob, read_present_files,
};
use crate::platform::ios::backup::profile::BackupProfile;

/// Per-file metadata recovered from `Manifest.db`, kept beside each public
/// [`Entry`] (by index) so [`Source::content`] and [`Source::integrity_check`]
/// can find and attest the on-disk blob without re-reading the manifest.
struct PlainEntry {
    /// The 40-hex `fileID` naming the on-disk blob.
    file_id: String,
    /// The SHA-1 of the file content recorded in `Manifest.db`, when present.
    digest: Option<Vec<u8>>,
}

/// A [`Source`] presenting an unencrypted iOS backup by logical paths.
pub struct PlainBackupSource<'a> {
    inner: &'a dyn Source,
    /// The backup root prefix within the inner source's namespace (`""` or
    /// `"<udid>/"`).
    root_prefix: String,
    /// Public logical entries (sorted by name), parallel to `meta`.
    entries: Vec<Entry>,
    /// Per-entry metadata, indexed parallel to `entries`.
    meta: Vec<PlainEntry>,
    /// Files `Manifest.db` lists as regular files but whose blob is absent on
    /// disk — surfaced (never dropped silently) as a sign of an incomplete or
    /// modified acquisition.
    missing_files: usize,
}

impl<'a> PlainBackupSource<'a> {
    /// Build a logical view over `inner` for the unencrypted backup at `profile`.
    ///
    /// Errors only when `Manifest.db` cannot be read; a malformed individual
    /// record is skipped (degrade, don't die), and a file listed in the manifest
    /// but absent on disk is counted (see [`PlainBackupSource::missing_count`]).
    pub fn build(inner: &'a dyn Source, profile: &BackupProfile) -> Result<Self> {
        let root_prefix = profile.root_prefix.clone();

        // Manifest.db is a plain SQLite file for an unencrypted backup.
        let manifest_db = common::read_entry(inner, &format!("{root_prefix}Manifest.db"))?;

        let (records, missing_files) = read_present_files(&manifest_db, inner, &root_prefix);
        let mut entries = Vec::with_capacity(records.len());
        let mut meta = Vec::with_capacity(records.len());
        for r in records {
            entries.push(logical_entry(&r.name, r.mb.size));
            meta.push(PlainEntry {
                file_id: r.file_id,
                digest: r.mb.digest,
            });
        }

        Ok(Self {
            inner,
            root_prefix,
            entries,
            meta,
            missing_files,
        })
    }

    /// The number of logical files this view exposes (provenance reporting).
    pub fn file_count(&self) -> usize {
        self.entries.len()
    }

    /// The number of files `Manifest.db` listed whose blob was absent on disk —
    /// reported as a sign of an incomplete or modified acquisition.
    pub fn missing_count(&self) -> usize {
        self.missing_files
    }
}

impl Source for PlainBackupSource<'_> {
    fn entries(&self) -> &[Entry] {
        &self.entries
    }

    fn content(&self, entry: &Entry) -> Result<Content<'_>> {
        let idx = meta_index(&self.entries, &entry.name)?;
        let blob = read_backup_blob(self.inner, &self.root_prefix, &self.meta[idx].file_id)?;
        Ok(Content::Owned(blob))
    }

    fn byte_size(&self) -> u64 {
        self.entries.iter().map(|e| e.uncompressed_size).sum()
    }

    /// Verify the file's on-disk blob against the SHA-1 `Digest` in `Manifest.db`.
    /// For an unencrypted backup the recorded Digest is the SHA-1 of the file
    /// content itself, so this attests the stored evidence was read intact.
    fn integrity_check(&self, entry: &Entry) -> IntegrityCheck {
        let Ok(idx) = meta_index(&self.entries, &entry.name) else {
            return IntegrityCheck::Unrecorded;
        };
        let meta = &self.meta[idx];
        check_blob_digest(
            self.inner,
            &self.root_prefix,
            &meta.file_id,
            meta.digest.as_deref(),
        )
    }
}
