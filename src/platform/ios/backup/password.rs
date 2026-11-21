//! Backup password candidates and unlock provenance.
//!
//! Defines: [`PasswordInput`] (where a password comes from beyond the defaults),
//! `unlock_with` (try the defaults, then that password, with any unlock test),
//! [`UnlockProvenance`] (how the backup was unlocked — supplied vs which default —
//! for the audit record), and `try_unlock`, which finds the password that recovers
//! an iOS keybag's class keys.
//! Used by: `ios::backup::source` (build a `BackupSource`), `android::backup` (the
//! same order for an `.ab`) and `support::sources` (the prompt, the stderr
//! provenance line and the scan-report record).
//! Uses: `ios::backup::{keybag, keys}` (the 4a crypto layer).
//!
//! ── Candidate order (forensic defaults) ─────────────────────────────────────
//! The common acquisition defaults are always tried first, in order: `"1234"`,
//! `"12345"`, `"123456"`, `"password"`, `"Password"`. These are the passwords
//! acquisition tools commonly set when they turn backup encryption on to obtain a
//! fuller backup; trying them lets a routine search "just work". Then the password
//! supplied (`MFSCAN_BACKUP_PASSWORD`), or the one asked for on the terminal
//! (`--backup-password`), asked only when no default worked, so an examiner is not
//! asked for what a default opens. WHICH default unlocked the backup is recorded
//! loudly so an examiner is never misled into thinking the owner chose it; a
//! supplied password equal to a default is recorded as supplied.

use std::collections::BTreeMap;

use anyhow::Result;
use serde::Serialize;

use crate::platform::ios::backup::keybag::Keybag;
use crate::platform::ios::backup::keys::unwrap_class_keys;

/// The acquisition-default passwords, in the order they are tried, before any
/// supplied one. Documented as the single source of truth for the default list.
pub(crate) const DEFAULT_PASSWORDS: &[&str] = &["1234", "12345", "123456", "password", "Password"];

/// Where a backup's password comes from, beyond the defaults (always tried first).
#[derive(Clone, Copy)]
pub enum PasswordInput<'a> {
    /// None: the defaults only.
    None,
    /// Supplied up front (the environment variable).
    Given(&'a str),
    /// Asked for (on the terminal), only once the defaults have failed.
    Ask(&'a dyn Fn() -> Result<String>),
}

impl PasswordInput<'_> {
    /// Whether a password beyond the defaults will be tried.
    pub fn supplies(&self) -> bool {
        !matches!(self, PasswordInput::None)
    }
}

/// The first password `try_one` accepts, the defaults first, then the supplied or
/// asked-for one, with its provenance; `None` when none is accepted.
///
/// `try_one` returns what the password unlocked (keys), or `None` for a wrong one.
/// A supplied password equal to a default is skipped among the defaults and tried
/// as supplied, so its provenance says supplied.
pub(crate) fn unlock_with<T>(
    source: PasswordInput,
    mut try_one: impl FnMut(&str) -> Option<T>,
) -> Result<Option<(T, UnlockProvenance)>> {
    let given = match source {
        PasswordInput::Given(password) => Some(password),
        _ => None,
    };
    for default in DEFAULT_PASSWORDS {
        if given == Some(*default) {
            continue;
        }
        if let Some(found) = try_one(default) {
            return Ok(Some((
                found,
                UnlockProvenance::Default(default.to_string()),
            )));
        }
    }
    let supplied = match source {
        PasswordInput::None => return Ok(None),
        PasswordInput::Given(password) => password.to_string(),
        PasswordInput::Ask(ask) => ask()?,
    };
    Ok(try_one(&supplied).map(|found| (found, UnlockProvenance::Supplied)))
}

/// The error when no password unlocked a backup, for both backup kinds: whether a
/// password beyond the defaults was tried decides what it suggests.
pub(crate) fn no_unlock_error(what: &str, supplied: bool) -> anyhow::Error {
    if supplied {
        anyhow::anyhow!(
            "{what}: neither the default passwords ({}) nor the password supplied unlocked it",
            DEFAULT_PASSWORDS.join(", ")
        )
    } else {
        anyhow::anyhow!(
            "{what}: none of the default passwords ({}) unlocked it — pass --backup-password \
             to be asked for the right one (or set MFSCAN_BACKUP_PASSWORD)",
            DEFAULT_PASSWORDS.join(", ")
        )
    }
}

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
    /// What an Android backup's header recorded; omitted for an iOS backup.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub android: Option<crate::platform::android::backup::AndroidFacts>,
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
            android: None,
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
            android: None,
        }
    }

    /// Assemble the audit record for an Android backup.
    pub fn new_android(
        provenance: Option<&UnlockProvenance>,
        files: usize,
        facts: crate::platform::android::backup::AndroidFacts,
    ) -> Self {
        let mut record = match provenance {
            Some(provenance) => Self::new(None, None, provenance, files, 0),
            None => Self::new_unencrypted(None, None, files, 0),
        };
        record.android = Some(facts);
        record
    }

    /// The one-line stderr provenance string an examiner sees at run time. A
    /// non-zero `missing_files` is appended as a loud warning so an incomplete or
    /// modified acquisition is never passed over in silence.
    pub fn stderr_line(&self) -> String {
        let base = if self.android.is_some() && !self.encrypted {
            format!("backup: Android (.ab), unencrypted; {} file(s)", self.files)
        } else if !self.encrypted {
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

/// Try the defaults, then `source`, against the keybag; return the unwrapped class
/// keys and the provenance of the password that worked. Errors, naming what was
/// tried, when none recovers any class key — the single clear failure an examiner
/// sees.
pub(crate) fn try_unlock(
    keybag: &Keybag,
    source: PasswordInput,
) -> Result<(BTreeMap<u32, [u8; 32]>, UnlockProvenance)> {
    // unwrap_class_keys errors when the password is wrong: the next one is tried.
    let unlocked = unlock_with(source, |candidate| {
        unwrap_class_keys(candidate.as_bytes(), keybag)
            .ok()
            .filter(|keys| !keys.is_empty())
    })?;
    match unlocked {
        Some(found) => Ok(found),
        None => Err(no_unlock_error("encrypted backup", source.supplies())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every password `unlock_with` tries, in order, when none unlocks.
    fn tried(source: PasswordInput) -> Vec<String> {
        let mut tried = Vec::new();
        let found = unlock_with(source, |p| {
            tried.push(p.to_string());
            None::<()>
        })
        .unwrap();
        assert!(found.is_none());
        tried
    }

    #[test]
    fn the_defaults_come_first_then_the_supplied_password() {
        let defaults = ["1234", "12345", "123456", "password", "Password"];
        assert_eq!(tried(PasswordInput::None), defaults);
        let mut with = defaults.to_vec();
        with.push("hunter2");
        assert_eq!(tried(PasswordInput::Given("hunter2")), with);
        // A supplied default is tried once, as supplied.
        assert_eq!(
            tried(PasswordInput::Given("123456")),
            ["1234", "12345", "password", "Password", "123456"]
        );
    }

    #[test]
    fn the_prompt_is_reached_only_when_no_default_unlocks() {
        let asked = std::cell::Cell::new(0);
        let ask = || {
            asked.set(asked.get() + 1);
            Ok("hunter2".to_string())
        };
        // "12345" unlocks: never asked, and recorded as that default.
        let found = unlock_with(PasswordInput::Ask(&ask), |p| (p == "12345").then_some(()));
        let (_, provenance) = found.unwrap().unwrap();
        assert_eq!(provenance, UnlockProvenance::Default("12345".into()));
        assert_eq!(asked.get(), 0);
        // Only the asked one unlocks: asked once, recorded as supplied.
        let found = unlock_with(PasswordInput::Ask(&ask), |p| (p == "hunter2").then_some(()));
        assert_eq!(found.unwrap().unwrap().1, UnlockProvenance::Supplied);
        assert_eq!(asked.get(), 1);
    }
}
