//! Export-during-search machinery: write a manifest and/or export matched files.
//!
//! Defines: [`run_export_sink`] (the one manifest/export/status pipeline),
//! [`export_if_requested`] (the search-time wrapper over it), and
//! [`write_export_report_file`] (the per-export SHA-256 integrity report).
//! Used by: `run::grep` (`export_if_requested`), `run::diff` (`run_export_sink`),
//! and `run::export` (`write_export_report_file`).
//! Uses: `mf_scan::report::export` (the library export engine) and `crate::cmd::cli`.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

use anyhow::{Context, Result};

use mf_scan::core::models::RunInfo;
use mf_scan::core::source::Source;
use mf_scan::ops::search::{Findings, MatchedFile};
use mf_scan::report::export::{
    self, ExportOutcome, ExportedFile, IntegritySummary, SkippedFile, StoredIntegrity,
};

use crate::cmd::cli::ExportSink;

/// Write a manifest and/or export matched files, if requested.
///
/// Status goes to stderr so it never pollutes the match results on stdout.
pub(crate) fn export_if_requested(
    sink: &ExportSink,
    source: &dyn Source,
    findings: &Findings,
    run: &RunInfo,
) -> Result<()> {
    run_export_sink(sink, source, &findings.files, run, "matched")
}

/// Honour an export sink (`--manifest`/`--export`) for a list of files.
///
/// The single pipeline behind both `grep` (matched files) and `diff` (changed
/// files): write the manifest, copy the files (honouring the size cap), write
/// the export report, and announce each step on stderr. `what` qualifies the
/// files in the status lines ("matched" / "changed") so the cap/refusal
/// behaviour can evolve in one place without the wordings drifting.
pub(crate) fn run_export_sink(
    sink: &ExportSink,
    source: &dyn Source,
    files: &[MatchedFile],
    run: &RunInfo,
    what: &str,
) -> Result<()> {
    if sink.manifest.is_none() && sink.export.is_none() {
        return Ok(());
    }

    let plan = export::plan(files);

    if let Some(path) = &sink.manifest {
        let file =
            File::create(path).with_context(|| format!("cannot create {}", path.display()))?;
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
        match export::export_files(
            &plan,
            source,
            files,
            dir,
            Some(sink.max_size),
            sink.max_path_len,
        )? {
            ExportOutcome::Exported {
                files: n,
                bytes,
                report,
                skipped_too_long,
                portability_warnings,
                ..
            } => {
                write_export_report_file(
                    dir,
                    run,
                    &report,
                    &skipped_too_long,
                    &portability_warnings,
                )?;
                eprintln!(
                    "exported {n} {what} file(s) ({bytes} bytes) to {}",
                    dir.display()
                );
                report_integrity(&report);
                report_skipped_too_long(&skipped_too_long);
                report_portability_warnings(&portability_warnings);
            }
            ExportOutcome::Refused { total_size, cap } => {
                eprintln!(
                    "refusing to export: {what} total {total_size} bytes exceeds --max-size {cap}; \
                     nothing written (use the manifest to review)"
                );
            }
        }
    }

    Ok(())
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

/// Announce, loudly, any files that were not written because their destination
/// path exceeded the length guard — one line per file, so a portability problem
/// (typically Windows `MAX_PATH`) cannot pass unnoticed. The files are also listed
/// in `export-report.json`.
pub(crate) fn report_skipped_too_long(skipped: &[SkippedFile]) {
    if skipped.is_empty() {
        return;
    }
    eprintln!(
        "⚠ {} file(s) NOT exported — destination path too long (raise --max-path-len, or export to a shorter directory):",
        skipped.len()
    );
    for f in skipped {
        eprintln!("  ⚠ skipped: {} ({})", f.internal_path, f.reason);
    }
}

/// Announce files that were exported but whose path is too long to survive a move
/// to Windows — a warning (the files ARE on disk here), so an analyst who will hand
/// the export to a Windows examiner knows which files would be unreachable there.
pub(crate) fn report_portability_warnings(warnings: &[SkippedFile]) {
    if warnings.is_empty() {
        return;
    }
    eprintln!(
        "⚠ {} file(s) exported but NOT Windows-portable (path too long for MAX_PATH); \
         they are present here but would be unreachable on Windows:",
        warnings.len()
    );
    for f in warnings {
        eprintln!("  ⚠ not portable: {} ({})", f.internal_path, f.reason);
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

/// Write `export-report.json` (run metadata + per-file SHA-256) into the export
/// destination directory, beside the exported artefacts.
pub(crate) fn write_export_report_file(
    dir: &Path,
    run: &RunInfo,
    report: &[export::ExportedFile],
    skipped_too_long: &[SkippedFile],
    portability_warnings: &[SkippedFile],
) -> Result<()> {
    let path = dir.join("export-report.json");
    let file = File::create(&path).with_context(|| format!("cannot create {}", path.display()))?;
    let mut w = BufWriter::new(file);
    export::write_export_report(run, report, skipped_too_long, portability_warnings, &mut w)?;
    w.flush().context("failed flushing export report")?;
    eprintln!(
        "export report: {} files -> {}",
        report.len(),
        path.display()
    );
    Ok(())
}
