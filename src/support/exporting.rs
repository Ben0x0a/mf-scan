//! Export-during-search machinery: write a manifest and/or export matched files.
//!
//! Defines: [`export_if_requested`] (honour `--manifest`/`--export` after a
//! search) and [`write_export_report_file`] (the per-export SHA-256 integrity
//! report).
//! Used by: `run::grep`/`run::diff` (`export_if_requested`) and `run::export`
//! (`write_export_report_file`).
//! Uses: `mf_scan::report::export` (the library export engine) and `crate::cli`.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

use anyhow::{Context, Result};

use mf_scan::engine::Findings;
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
    if sink.manifest.is_none() && sink.export.is_none() {
        return Ok(());
    }

    let plan = export::plan(&findings.files);

    if let Some(path) = &sink.manifest {
        let file =
            File::create(path).with_context(|| format!("cannot create {}", path.display()))?;
        let mut w = BufWriter::new(file);
        export::write_manifest(&plan, run, &mut w)?;
        w.flush().context("failed flushing manifest")?;
        eprintln!(
            "manifest: {} files, {} bytes total -> {}",
            plan.items.len(),
            plan.total_size,
            path.display()
        );
    }

    if let Some(dir) = &sink.export {
        match export::export_files(&plan, source, &findings.files, dir, Some(sink.max_size))? {
            ExportOutcome::Exported {
                files,
                bytes,
                report,
                ..
            } => {
                write_export_report_file(dir, run, &report)?;
                eprintln!(
                    "exported {files} files ({bytes} bytes) to {}",
                    dir.display()
                );
            }
            ExportOutcome::Refused { total_size, cap } => {
                eprintln!(
                    "refusing to export: matched total {total_size} bytes exceeds --max-size {cap}; \
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
