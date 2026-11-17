//! What an export records: each written file with its hashes, and the report.
//!
//! Defines: [`ExportedFile`], [`SkippedFile`], [`StoredIntegrity`],
//! [`IntegritySummary`], and [`write_export_report`] (`export-report.json`).
//! Used by: `report::export::write` (fills the records), `report::rebuild_zip` and
//! `report::decrypted_zip`, and the binary (prints and writes the report).
//! Uses: `core::models::RunInfo`, `core::source::IntegrityCheck`, `serde`.

use std::io::Write;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::plan::Renamed;
use crate::core::models::RunInfo;

/// A file that was NOT written because its destination path would exceed the
/// length guard — recorded (rather than silently dropped or truncated) so the
/// analyst can re-export to a shorter root or raise `--max-path-len`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkippedFile {
    /// Path inside the source that was skipped.
    pub internal_path: String,
    /// The destination path that would have been written, relative to the dir.
    pub output_path: String,
    /// Why it was skipped (which limit it hit), for the operator and the report.
    pub reason: String,
}

/// One exported file recorded with its integrity hashes, for the export report.
///
/// Two independent SHA-256 hashes are recorded so a silent copy error (a bad
/// disk write, a truncated copy) is caught: `source_sha256` is the bytes read
/// out of the source, `sha256` is the bytes read back from the written file. The
/// export attests `copy_verified` (they match) — and, for an encrypted backup,
/// `stored_integrity` (the encrypted blob matched the SHA-1 in `Manifest.db`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedFile {
    /// Path inside the source archive.
    pub internal_path: String,
    /// Path written, relative to the export destination directory.
    pub output_path: String,
    pub size: u64,
    /// SHA-256 of the written bytes (read back from disk), lowercase hex.
    pub sha256: String,
    /// SHA-256 of the source bytes (as read out of the source), lowercase hex.
    pub source_sha256: String,
    /// Whether `source_sha256 == sha256` — the source-vs-copy attestation. A
    /// `false` here means the bytes on disk differ from what was read (a silent
    /// copy error) and is surfaced loudly.
    pub copy_verified: bool,
    /// Source-recorded stored-bytes integrity, when the source carries one (an
    /// encrypted backup's per-file SHA-1). `Unrecorded` for plain sources.
    pub stored_integrity: StoredIntegrity,
    /// The file's modification time as the source recorded it, in UTC. Written by a
    /// backup rebuild, so the report states the time each archive member must carry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtime_utc: Option<String>,
    /// Set on a file the export derived from `internal_path` rather than copied,
    /// such as a decrypted database: how it was produced. Its hashes are of the
    /// derived bytes, so the copy check still attests what landed on disk.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derived: Option<String>,
}

/// The serialisable form of [`crate::core::source::IntegrityCheck`] for the report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum StoredIntegrity {
    /// The source records no digest for this file.
    Unrecorded,
    /// The source's recorded digest matched the stored bytes.
    Verified { algorithm: String },
    /// The source's recorded digest did NOT match — corrupt original evidence.
    Mismatch {
        algorithm: String,
        expected: String,
        actual: String,
    },
}

impl From<crate::core::source::IntegrityCheck> for StoredIntegrity {
    fn from(check: crate::core::source::IntegrityCheck) -> Self {
        use crate::core::source::IntegrityCheck as I;
        match check {
            I::Unrecorded => StoredIntegrity::Unrecorded,
            I::Verified { algorithm } => StoredIntegrity::Verified {
                algorithm: algorithm.to_string(),
            },
            I::Mismatch {
                algorithm,
                expected,
                actual,
            } => StoredIntegrity::Mismatch {
                algorithm: algorithm.to_string(),
                expected,
                actual,
            },
        }
    }
}

impl ExportedFile {
    /// Whether this file's export is fully attested: the on-disk copy matches the
    /// source bytes AND any source-recorded stored digest matched. A `false` is
    /// reported loudly to the operator.
    pub fn is_intact(&self) -> bool {
        self.copy_verified && !matches!(self.stored_integrity, StoredIntegrity::Mismatch { .. })
    }
}

/// The export report: run metadata, an integrity summary, every written file with
/// its hashes, and any files skipped for an over-length destination path.
#[derive(Serialize)]
struct ExportReport<'a> {
    run: &'a RunInfo,
    file_count: usize,
    integrity: IntegritySummary,
    files: &'a [ExportedFile],
    #[serde(flatten)]
    notes: &'a ExportNotes,
}

/// What an export has to report besides the files it wrote. Each list is omitted
/// from the JSON when empty, so a clean export's report stays short.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExportNotes {
    /// Files not written because their path could not exist on this platform.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skipped_too_long: Vec<SkippedFile>,
    /// Files written but whose path is too long to move to Windows.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub portability_warnings: Vec<SkippedFile>,
    /// Files whose decrypted copy could not be made (the original was exported).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub undecrypted: Vec<SkippedFile>,
    /// Files written under another name because theirs was taken on disk: by a file
    /// of an earlier export, or by one this file system treats as the same name.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub renamed: Vec<Renamed>,
}

/// Aggregate integrity outcome over all exported files, surfaced at the head of
/// the report so an operator sees at a glance whether every copy is attested.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegritySummary {
    /// Files whose on-disk copy matched the source bytes AND any stored digest.
    pub intact: usize,
    /// Files whose written copy did NOT match the source bytes read.
    pub copy_mismatches: usize,
    /// Files whose source-recorded stored digest did NOT match (corrupt original).
    pub stored_digest_mismatches: usize,
    /// Files carrying a source-recorded stored digest that was verified.
    pub stored_digest_verified: usize,
}

impl IntegritySummary {
    /// Tally the per-file outcomes into the aggregate.
    pub fn of(files: &[ExportedFile]) -> Self {
        let mut s = IntegritySummary {
            intact: 0,
            copy_mismatches: 0,
            stored_digest_mismatches: 0,
            stored_digest_verified: 0,
        };
        for f in files {
            if f.is_intact() {
                s.intact += 1;
            }
            if !f.copy_verified {
                s.copy_mismatches += 1;
            }
            match f.stored_integrity {
                StoredIntegrity::Verified { .. } => s.stored_digest_verified += 1,
                StoredIntegrity::Mismatch { .. } => s.stored_digest_mismatches += 1,
                StoredIntegrity::Unrecorded => {}
            }
        }
        s
    }

    /// Whether any file failed either integrity check.
    pub fn has_failures(&self) -> bool {
        self.copy_mismatches > 0 || self.stored_digest_mismatches > 0
    }
}

/// Write the export report (run metadata + integrity summary + per-file hashes,
/// plus any files skipped for an over-length path).
pub fn write_export_report(
    run: &RunInfo,
    files: &[ExportedFile],
    notes: &ExportNotes,
    w: &mut dyn Write,
) -> Result<()> {
    let report = ExportReport {
        run,
        file_count: files.len(),
        integrity: IntegritySummary::of(files),
        files,
        notes,
    };
    serde_json::to_writer_pretty(&mut *w, &report).context("failed writing export report")?;
    writeln!(w).context("failed writing export report")?;
    Ok(())
}
