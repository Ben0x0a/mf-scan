//! Export machinery shared by the commands: write a manifest and/or an export archive,
//! name the archive, and announce what was written.
//!
//! Defines: [`run_export_sink`] (the one manifest/export/status pipeline),
//! [`export_if_requested`] (the search-time wrapper over it), [`export_subject`] and
//! [`export_archive_path`] (what an export is named, where it goes), and
//! [`report_outcome`] (what it says on stderr).
//! Used by: `run::grep` (`export_if_requested`), `run::diff`/`run::find`
//! (`run_export_sink`), and `run::export`/`run::app` (the naming and the outcome).
//! Uses: `mf_scan::report::export` (the library export engine) and `crate::cmd::cli`.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use mf_scan::core::models::RunInfo;
use mf_scan::core::source::Source;
use mf_scan::core::util::{UtcTime, now_unix};
use mf_scan::decrypt::DecryptionContext;
use mf_scan::ops::decrypting::{DerivedCopy, SourceDecryptor};
use mf_scan::ops::search::{Findings, MatchedFile};
use mf_scan::report::export::{
    self, ExportArchive, ExportOutcome, ExportedFile, FileNote, IntegritySummary, Renamed,
    StoredIntegrity,
};

use crate::cmd::cli::ExportSink;

/// The longest subject kept in an archive's name, in characters.
const SUBJECT_LEN: usize = 40;

/// Write a manifest and/or export matched files, if requested.
///
/// Status goes to stderr so it never pollutes the match results on stdout.
pub(crate) fn export_if_requested(
    sink: &ExportSink,
    source: &dyn Source,
    findings: &Findings,
    run: &RunInfo,
    decrypt: Option<&DecryptionContext>,
) -> Result<()> {
    run_export_sink(
        sink,
        source,
        &findings.files,
        run,
        "matched",
        &run.pattern,
        decrypt,
    )
}

/// Honour an export sink (`--manifest`/`--export`) for a list of files.
///
/// The single pipeline behind `grep` (matched files), `find` (found files) and
/// `diff` (changed files): write the manifest, write the archive into the
/// `--export` folder (honouring the size cap), and announce each step on stderr.
/// `what` qualifies the files in the status lines ("matched" / "changed"), and the
/// archive is named by [`export_subject`] (`fallback`: when the run has no app or
/// patterns).
///
/// With `decrypt`, each exported database that decrypts also gets its decrypted copy
/// written beside it (`name.decrypted.ext`).
pub(crate) fn run_export_sink(
    sink: &ExportSink,
    source: &dyn Source,
    files: &[MatchedFile],
    run: &RunInfo,
    what: &str,
    fallback: &str,
    decrypt: Option<&DecryptionContext>,
) -> Result<()> {
    if sink.manifest.is_none() && sink.export.is_none() {
        return Ok(());
    }

    let plan = export::plan(files);

    if let Some(path) = &sink.manifest {
        // Never over an earlier manifest: it may be the record an export was made from.
        let file = File::options()
            .write(true)
            .create_new(true)
            .open(path)
            .with_context(|| {
                format!(
                    "cannot create {} (an existing manifest is never replaced)",
                    path.display()
                )
            })?;
        let mut w = BufWriter::new(file);
        export::write_manifest(&plan, run, &mut w)?;
        w.flush().context("failed flushing manifest")?;
        eprintln!(
            "manifest: {} {what} file(s), {} bytes total -> {}",
            plan.items.len(),
            plan.total_size,
            path.display()
        );
    }

    if let Some(dir) = &sink.export {
        let decryptor = decrypt.map(|ctx| SourceDecryptor::new(ctx, source));
        let archive = export_archive_path(dir, &export_subject(run, fallback))?;
        let outcome = export::export_files(
            &plan,
            source,
            files,
            &archive,
            run,
            Some(sink.max_size),
            decryptor.as_ref().map(|d| d as &dyn DerivedCopy),
        )?;
        report_outcome(&outcome, what);
    }

    Ok(())
}

/// What an export archive is named after: the run's apps (`--app`, `app export`),
/// else its search patterns, else `fallback`.
///
/// WHY one rule: exports of one app accumulate in one case folder; named by the app
/// whichever command made them, they sort together.
pub(crate) fn export_subject(run: &RunInfo, fallback: &str) -> String {
    if let Some(app) = &run.app {
        return app.replace(", ", "+");
    }
    if !run.patterns.is_empty() {
        return run.patterns.join("+");
    }
    fallback.to_string()
}

/// Announce an export's outcome on stderr: the archive written and all it has to
/// report, or why nothing was written. The same lines for every command.
pub(crate) fn report_outcome(outcome: &ExportOutcome, what: &str) {
    match outcome {
        ExportOutcome::Exported(done) => {
            let missing = if done.skipped > 0 {
                format!("; {} listed file(s) not found in the source", done.skipped)
            } else {
                String::new()
            };
            eprintln!(
                "exported {} {what} file(s) ({} bytes) -> {}{missing}",
                done.files,
                done.bytes,
                done.archive.display()
            );
            report_export(done);
        }
        ExportOutcome::Refused { total_size, cap } => eprintln!(
            "refusing to export: {what} files, {total_size} bytes or more (with sidecars), \
             exceed --max-size {cap}; nothing written"
        ),
    }
}

/// Where a new export archive goes: `DIR/mf-scan-<UTC stamp>-export-<subject>.zip`,
/// with `-2`, `-3`, … after the stamp when that name is taken. `DIR` is created.
///
/// WHY the stamp and subject: exports of one case accumulate in one folder, and each
/// must say when it was made and what for without opening it. The subject is the app
/// id or the search, cut to its file-name-safe characters.
pub(crate) fn export_archive_path(dir: &Path, subject: &str) -> Result<PathBuf> {
    std::fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    let stamp = UtcTime::from_unix(now_unix()).compact();
    let subject = safe_subject(subject);
    for attempt in 1u32.. {
        let stamp = if attempt > 1 {
            format!("{stamp}-{attempt}")
        } else {
            stamp.clone()
        };
        let name = if subject.is_empty() {
            format!("mf-scan-{stamp}-export.zip")
        } else {
            format!("mf-scan-{stamp}-export-{subject}.zip")
        };
        // A name is taken by its archive or by its sidecar alone (an archive moved
        // away): the export claims both, so it would be refused at the start.
        let sidecar = dir.join(format!("{name}.sha256"));
        let path = dir.join(name);
        if !path.exists() && !sidecar.exists() {
            return Ok(path);
        }
    }
    unreachable!("the attempt counter is unbounded, so the loop only exits by returning")
}

/// `subject` cut to letters, digits, `.`, `-` and `_` (anything else becomes one `_`),
/// trimmed of separators at either end, at most [`SUBJECT_LEN`] characters.
fn safe_subject(subject: &str) -> String {
    let mut out = String::new();
    for c in subject.chars() {
        let c = if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
            c
        } else {
            '_'
        };
        if !(c == '_' && out.ends_with('_')) {
            out.push(c);
        }
    }
    let cut: String = out
        .trim_matches(['_', '.', '-'])
        .chars()
        .take(SUBJECT_LEN)
        .collect();
    cut.trim_end_matches(['_', '.', '-']).to_string()
}

/// Announce what a finished export has to report: the archive's hash, decrypted
/// copies, integrity, and the files renamed or too long to extract on Windows.
fn report_export(done: &ExportArchive) {
    eprintln!(
        "sha256 {} -> {} (export-report.json inside)",
        done.archive_sha256,
        done.sidecar.display()
    );
    report_decrypted_copies(&done.report, &done.notes.undecrypted);
    report_integrity(&done.report);
    report_portability_warnings(&done.notes.portability_warnings);
    report_renamed(&done.notes.renamed);
}

/// Announce the decrypted copies an export wrote beside their originals, and loudly
/// the databases that should have had one but did not decrypt.
fn report_decrypted_copies(report: &[ExportedFile], undecrypted: &[FileNote]) {
    let copies: Vec<&ExportedFile> = report.iter().filter(|f| f.derived.is_some()).collect();
    if !copies.is_empty() {
        eprintln!(
            "decrypted copies written beside their originals: {}",
            copies.len()
        );
        for f in copies {
            eprintln!("    {}", f.output_path);
        }
    }
    if !undecrypted.is_empty() {
        eprintln!(
            "⚠ {} database(s) exported encrypted only (no decrypted copy):",
            undecrypted.len()
        );
        for f in undecrypted {
            eprintln!("    {}: {}", f.output_path, f.reason);
        }
    }
}

/// Announce the export's integrity outcome on stderr.
///
/// The common case (every copy attested, any backup digests verified) gets a
/// single reassuring line. Any failure — a written copy that differs from the
/// source bytes, or an encrypted blob that didn't match its `Manifest.db` SHA-1
/// — is printed loudly, one line per offending file, so it can't be missed.
pub(crate) fn report_integrity(report: &[ExportedFile]) {
    let summary = IntegritySummary::of(report);
    if summary.stored_digest_verified > 0 {
        // Name the algorithm(s) that attested the stored bytes (a backup's SHA-1
        // from Manifest.db, or a ZIP's CRC-32 from the central directory).
        let algos = stored_algorithms(report);
        eprintln!(
            "integrity: {} copy-verified, {} stored-digest verified ({algos})",
            summary.intact, summary.stored_digest_verified
        );
    } else {
        eprintln!("integrity: {} file(s) copy-verified", summary.intact);
    }
    if !summary.has_failures() {
        return;
    }
    eprintln!(
        "⚠ INTEGRITY FAILURE: {} copy mismatch(es), {} stored-digest mismatch(es)",
        summary.copy_mismatches, summary.stored_digest_mismatches
    );
    for f in report {
        if !f.copy_verified {
            eprintln!(
                "  ⚠ copy mismatch: {} (source {} != written {})",
                f.internal_path, f.source_sha256, f.sha256
            );
        }
        if let StoredIntegrity::Mismatch {
            algorithm,
            expected,
            actual,
        } = &f.stored_integrity
        {
            eprintln!(
                "  ⚠ {algorithm} mismatch on stored evidence: {} (expected {expected}, got {actual})",
                f.internal_path
            );
        }
    }
}

/// Announce files written under another name because theirs was taken in the archive.
fn report_renamed(renamed: &[Renamed]) {
    if renamed.is_empty() {
        return;
    }
    eprintln!(
        "⚠ {} file(s) written under another name: a name differing only in case or \
         accent form would be the same file once extracted on Windows or macOS:",
        renamed.len()
    );
    for r in renamed {
        eprintln!("    {} -> {}", r.wanted, r.used);
    }
}

/// Announce files whose name in the archive is too long to extract on Windows — all
/// exported, so an analyst who hands the archive to a Windows examiner knows which
/// files need a long-path-aware extractor.
fn report_portability_warnings(warnings: &[FileNote]) {
    if warnings.is_empty() {
        return;
    }
    eprintln!(
        "⚠ {} file(s) in the archive have a path too long to extract on Windows \
         (all exported; listed in the report):",
        warnings.len()
    );
    for f in warnings {
        eprintln!("    {} ({})", f.output_path, f.reason);
    }
}

/// The distinct stored-digest algorithm names seen among verified files, joined
/// for the integrity summary line (e.g. `"sha1"`, `"crc32"`, or `"sha1, crc32"`
/// if a run mixed sources).
fn stored_algorithms(report: &[ExportedFile]) -> String {
    let mut algos: Vec<&str> = report
        .iter()
        .filter_map(|f| match &f.stored_integrity {
            StoredIntegrity::Verified { algorithm } => Some(algorithm.as_str()),
            _ => None,
        })
        .collect();
    algos.sort_unstable();
    algos.dedup();
    algos.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subjects_keep_only_file_name_safe_characters() {
        assert_eq!(safe_subject("com.whatsapp"), "com.whatsapp");
        assert_eq!(safe_subject("+41 79 123/45*"), "41_79_123_45");
        assert_eq!(safe_subject("café"), "caf");
        assert_eq!(safe_subject("***"), "");
        assert_eq!(safe_subject(&"a".repeat(80)).len(), SUBJECT_LEN);
    }

    #[test]
    fn archive_names_never_take_an_existing_one() {
        let dir = tempfile::tempdir().unwrap();
        let first = export_archive_path(dir.path(), "com.x").unwrap();
        let name = first.file_name().unwrap().to_string_lossy().into_owned();
        assert!(name.starts_with("mf-scan-") && name.ends_with("-export-com.x.zip"));
        std::fs::write(&first, b"").unwrap();
        let second = export_archive_path(dir.path(), "com.x").unwrap();
        assert_ne!(first, second);
    }
}
