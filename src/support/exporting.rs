//! Export-during-search machinery: write a manifest and/or export matched files.
//!
//! Defines: [`run_export_sink`] (the one manifest/export/status pipeline),
//! [`export_if_requested`] (the search-time wrapper over it), and
//! [`write_export_report_file`] (the per-export SHA-256 integrity report).
//! Used by: `run::grep` (`export_if_requested`), `run::diff` (`run_export_sink`),
//! and `run::export` (`write_export_report_file`).
//! Uses: `mf_scan::report::export` (the library export engine) and `crate::cli`.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

use anyhow::{Context, Result};

use mf_scan::engine::{Findings, MatchedFile};
use mf_scan::models::RunInfo;
use mf_scan::report::export::{self, ExportOutcome};
use mf_scan::source::Source;

use crate::cli::ExportSink;

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
        match export::export_files(&plan, source, files, dir, Some(sink.max_size))? {
            ExportOutcome::Exported {
                files: n,
                bytes,
                report,
                ..
            } => {
                write_export_report_file(dir, run, &report)?;
                eprintln!(
                    "exported {n} {what} file(s) ({bytes} bytes) to {}",
                    dir.display()
                );
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

/// Write `export-report.json` (run metadata + per-file SHA-256) into the export
/// destination directory, beside the exported artefacts.
pub(crate) fn write_export_report_file(
    dir: &Path,
    run: &RunInfo,
    report: &[export::ExportedFile],
) -> Result<()> {
    let path = dir.join("export-report.json");
    let file = File::create(&path).with_context(|| format!("cannot create {}", path.display()))?;
    let mut w = BufWriter::new(file);
    export::write_export_report(run, report, &mut w)?;
    w.flush().context("failed flushing export report")?;
    eprintln!(
        "export report: {} files -> {}",
        report.len(),
        path.display()
    );
    Ok(())
}
