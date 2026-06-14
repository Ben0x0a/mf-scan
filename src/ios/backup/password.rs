//! Backup password candidates and unlock provenance.
//!
//! Defines: `candidates` (the ordered passwords to try, from a supplied value
//! or the acquisition defaults), [`UnlockProvenance`] (how the backup was
//! unlocked — supplied vs which default — for the audit record), and
//! `try_unlock`, which finds the first candidate that recovers the class keys.
//! Used by: `ios::backup::source` (build a `BackupSource`) and `support::sources`
//! (emit the stderr provenance line and the scan-report record).
//! Uses: `ios::backup::{keybag, keys}` (the 4a crypto layer).
//!
//! ── Candidate order (forensic defaults) ─────────────────────────────────────
//! If a password is supplied (the `--backup-password` flag or the
//! `MFSCAN_BACKUP_PASSWORD` env var), ONLY that one is tried — an examiner who
//! names a password means it. If none is supplied, the common acquisition
//! defaults are tried in order: `"1234"`, `"12345"`, `"123456"`, `"password"`. These are
//! the passcodes acquisition tooling (e.g. `idevicebackup2`) commonly sets when
//! it enables backup encryption to obtain a fuller backup; trying them lets a
//! routine search "just work" on such acquisitions. WHICH default unlocked the
//! backup is recorded loudly so an examiner is never misled into thinking the
//! owner chose it.

use std::collections::BTreeMap;

use anyhow::{Result, bail};
use serde::Serialize;

use crate::ios::backup::keybag::Keybag;
use crate::ios::backup::keys::unwrap_class_keys;

/// The acquisition-default passwords, in the order they are tried when none is
/// supplied. Documented as the single source of truth for the default list.
pub(crate) const DEFAULT_PASSWORDS: &[&str] = &["1234", "12345", "123456", "password"];

/// How the backup was unlocked — carried into stderr and the scan report so the
/// use of a default password is unmistakable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnlockProvenance {
    /// The operator supplied the password (flag or env). The value is NOT stored.
    Supplied,
    /// A built-in default unlocked it; the exact value is recorded (an examiner
    /// must know a weak default was assumed, and which one).
    Default(String),
}

/// The backup-decryption audit record, written to the scan report.
///
/// A parallel record to [`crate::decrypt::DecryptionRecord`] (which covers
/// per-database keychain decryption), clearly named so an examiner sees at a
/// glance that the *whole backup* was encrypted and how it was unlocked. A
/// supplied password's value is never recorded; a default's value is, because
/// the use of a weak default must be unmistakable.
#[derive(Debug, Clone, Serialize)]
pub struct BackupRecord {
    /// Whether the backup payload was encrypted. `false` records that an
    /// *unencrypted* backup was recognised and presented by logical path.
    pub encrypted: bool,
    /// The backup root within the source (the UDID directory, or "" at root).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udid: Option<String>,
    /// The iOS/product version, when readable (provenance only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product_version: Option<String>,
    /// Whether the password was operator-supplied or a built-in default. `None`
    /// for an unencrypted backup (no password was involved).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_source: Option<PasswordSource>,
    /// The default value that worked — present ONLY when a default unlocked it,
    /// so the examiner knows exactly which weak password was assumed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_password_used: Option<String>,
    /// Number of regular files the backup view exposes.
    pub files: usize,
    /// Files that `Manifest.db` lists but whose blob is absent on disk — a sign of
    /// an incomplete or modified acquisition, so it is reported, never dropped
    /// silently. `0` (and omitted from the report) for an intact backup.
    #[serde(skip_serializing_if = "is_zero")]
    pub missing_files: usize,
}

/// Serde predicate: skip a `0` count in the JSON report.
fn is_zero(n: &usize) -> bool {
    *n == 0
}

/// Where the unlocking password came from, for the report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PasswordSource {
    /// The operator supplied it (`--backup-password`/env); value not recorded.
    Supplied,
    /// A built-in acquisition default unlocked it (value in `default_password_used`).
    Default,
}

impl BackupRecord {
    /// Assemble the audit record from the unlock provenance and backup facts.
    /// `missing_files` is how many files `Manifest.db` listed but were absent on
    /// disk (an incomplete/modified acquisition).
    pub fn new(
        udid: Option<String>,
        product_version: Option<String>,
        provenance: &UnlockProvenance,
        files: usize,
        missing_files: usize,
    ) -> Self {
        let (password_source, default_password_used) = match provenance {
            UnlockProvenance::Supplied => (PasswordSource::Supplied, None),
            UnlockProvenance::Default(v) => (PasswordSource::Default, Some(v.clone())),
        };
        Self {
            encrypted: true,
            udid,
            product_version,
            password_source: Some(password_source),
            default_password_used,
            files,
            missing_files,
        }
    }

    /// Assemble the audit record for an UNENCRYPTED backup presented by logical
    /// path. No password is involved; `files` is the number of logical files the
    /// view exposes and `missing_files` how many `Manifest.db` listed but were
    /// absent on disk.
    pub fn new_unencrypted(
        udid: Option<String>,
        product_version: Option<String>,
        files: usize,
        missing_files: usize,
    ) -> Self {
        Self {
            encrypted: false,
            udid,
            product_version,
            password_source: None,
            default_password_used: None,
            files,
            missing_files,
        }
    }

    /// The one-line stderr provenance string an examiner sees at run time. A
    /// non-zero `missing_files` is appended as a loud warning so an incomplete or
    /// modified acquisition is never passed over in silence.
    pub fn stderr_line(&self) -> String {
        let base = if !self.encrypted {
            format!(
                "backup: unencrypted; {} file(s) mapped to logical paths via Manifest.db",
                self.files
            )
        } else {
            match &self.default_password_used {
                Some(v) => format!(
                    "backup: encrypted; decrypted with DEFAULT password \"{v}\" ({} file(s))",
                    self.files
                ),
                None => format!(
                    "backup: encrypted; decrypted with the supplied password ({} file(s))",
                    self.files
                ),
            }
        };
        if self.missing_files > 0 {
            format!(
                "{base}\n⚠ backup: {} file(s) listed in Manifest.db are MISSING on disk \
                 (incomplete or modified acquisition)",
                self.missing_files
            )
        } else {
            base
        }
    }
}

/// The ordered password candidates to try.
///
/// A supplied password (already resolved from the flag-or-env by the caller)
/// yields a single-element list; absence yields the defaults. Returned as owned
/// strings so the caller need not juggle the flag/env/default lifetimes.
pub(crate) fn candidates(supplied: Option<&str>) -> Vec<String> {
    match supplied {
        Some(pw) => vec![pw.to_string()],
        None => DEFAULT_PASSWORDS.iter().map(|s| s.to_string()).collect(),
    }
}

/// Try each candidate against the keybag; return the unwrapped class keys and the
/// provenance of the password that worked.
///
/// `supplied` is the resolved flag-or-env password, or `None` to try the
/// defaults. Errors (with a message naming `--backup-password`) when no candidate
/// recovers any class key — the single clear failure an examiner sees.
pub(crate) fn try_unlock(
    keybag: &Keybag,
    supplied: Option<&str>,
) -> Result<(BTreeMap<u32, [u8; 32]>, UnlockProvenance)> {
    let supplied_given = supplied.is_some();
    for candidate in candidates(supplied) {
        // unwrap_class_keys errors when the password is wrong; try the next one.
        if let Ok(keys) = unwrap_class_keys(candidate.as_bytes(), keybag)
            && !keys.is_empty()
        {
            let provenance = if supplied_given {
                UnlockProvenance::Supplied
            } else {
                UnlockProvenance::Default(candidate)
            };
            return Ok((keys, provenance));
        }
    }

    if supplied_given {
        bail!("the supplied --backup-password did not unlock the encrypted backup");
    }
    bail!(
        "encrypted backup: none of the default passwords ({}) unlocked it — pass the correct \
         one with --backup-password (or the MFSCAN_BACKUP_PASSWORD environment variable)",
        DEFAULT_PASSWORDS.join(", ")
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supplied_password_yields_single_candidate() {
        assert_eq!(candidates(Some("hunter2")), vec!["hunter2".to_string()]);
    }

    #[test]
    fn no_password_yields_defaults_in_order() {
        assert_eq!(
            candidates(None),
            vec!["1234", "12345", "123456", "password"]
        );
    }
}
