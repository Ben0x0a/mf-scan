//! `BackupSource`: the iOS-backup [`Source`], in its encrypted or plain form.
//!
//! Defines: [`BackupSource`], the one type callers use for an iOS iTunes/Finder
//! backup. Rust has no class inheritance, so the "a backup is either encrypted or
//! unencrypted" relationship is modelled the idiomatic way — an `enum` over the
//! two concrete implementations ([`EncryptedBackupSource`], [`PlainBackupSource`])
//! that implements [`Source`] by dispatching to whichever it holds. [`build`]
//! picks the variant from the recognised [`BackupProfile`]; [`record`] produces
//! the provenance [`BackupRecord`]. The variants share their structure through
//! `super::common`.
//! Used by: `support::sources` (the single open/dispatch point) — it builds a
//! `BackupSource` and hands the `&dyn Source` to the search/diff engines.
//!
//! [`build`]: BackupSource::build
//! [`record`]: BackupSource::record

pub mod encrypted;
pub mod plain;

pub use encrypted::EncryptedBackupSource;
pub use plain::PlainBackupSource;

use anyhow::Result;

use crate::core::models::Entry;
use crate::core::source::{Content, IntegrityCheck, Source};
use crate::platform::ios::backup::password::BackupRecord;
use crate::platform::ios::backup::profile::BackupProfile;

/// An iOS backup presented as a [`Source`] of logically-named files — either an
/// [`EncryptedBackupSource`] (decrypts each file lazily) or a
/// [`PlainBackupSource`] (an unencrypted backup, read straight through). Both
/// present files at their logical `domain/relativePath` and attest each against
/// the SHA-1 `Digest` in `Manifest.db`.
pub enum BackupSource<'a> {
    /// An encrypted backup, unlocked with a password.
    Encrypted(EncryptedBackupSource<'a>),
    /// An unencrypted backup, presented by logical path with no decryption.
    Plain(PlainBackupSource<'a>),
}

impl<'a> BackupSource<'a> {
    /// Build the right backup source for the recognised `profile`: an
    /// [`EncryptedBackupSource`] when the payload is encrypted (using
    /// `password`, or the acquisition defaults when `None`), else a
    /// [`PlainBackupSource`]. Errors when the manifest is unreadable or — for an
    /// encrypted backup — no password candidate unlocks the keybag.
    pub fn build(
        inner: &'a dyn Source,
        profile: &BackupProfile,
        password: Option<&str>,
    ) -> Result<Self> {
        if profile.encrypted {
            Ok(Self::Encrypted(EncryptedBackupSource::build(
                inner, profile, password,
            )?))
        } else {
            Ok(Self::Plain(PlainBackupSource::build(inner, profile)?))
        }
    }

    /// The provenance/audit record for this backup (encrypted vs not, how the
    /// password resolved, files mapped, and any listed-but-missing-on-disk count),
    /// for the stderr line and the scan report.
    pub fn record(&self, profile: &BackupProfile) -> BackupRecord {
        match self {
            BackupSource::Encrypted(s) => BackupRecord::new(
                profile.udid.clone(),
                profile.product_version.clone(),
                s.provenance(),
                s.entries().len(),
                s.missing_count(),
            ),
            BackupSource::Plain(s) => BackupRecord::new_unencrypted(
                profile.udid.clone(),
                profile.product_version.clone(),
                s.file_count(),
                s.missing_count(),
            ),
        }
    }
}

impl Source for BackupSource<'_> {
    fn entries(&self) -> &[Entry] {
        match self {
            BackupSource::Encrypted(s) => s.entries(),
            BackupSource::Plain(s) => s.entries(),
        }
    }

    fn content(&self, entry: &Entry) -> Result<Content<'_>> {
        match self {
            BackupSource::Encrypted(s) => s.content(entry),
            BackupSource::Plain(s) => s.content(entry),
        }
    }

    fn byte_size(&self) -> u64 {
        match self {
            BackupSource::Encrypted(s) => s.byte_size(),
            BackupSource::Plain(s) => s.byte_size(),
        }
    }

    fn integrity_check(&self, entry: &Entry) -> IntegrityCheck {
        match self {
            BackupSource::Encrypted(s) => s.integrity_check(entry),
            BackupSource::Plain(s) => s.integrity_check(entry),
        }
    }
}
