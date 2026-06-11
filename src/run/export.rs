//! The `export` subcommand: re-ingest files listed in a manifest (no search).
//!
//! Defines: [`run_export`], one of the binary's two core operations.
//! Used by: `run` (dispatched from `main`).
//! Uses: `mf_scan::report::export` (the library export engine) and the `crate::support`
//! support modules (`sources`, `report`, `exporting`).

use std::fs::File;
use std::io::BufReader;

use anyhow::{Context, Result};

use mf_scan::report::export::{self, ExportOutcome};
use mf_scan::source::zip::ZipSource;

use crate::cli::ExportArgs;
use crate::support::exporting::write_export_report_file;
use crate::support::reporting::{report_verify, sha256_hex};
use crate::support::sources::open_archive;

/// Run the `export` subcommand: re-ingest files listed in a manifest.
pub(crate) fn run_export(args: ExportArgs) -> Result<()> {
    let mmap = open_archive(&args.archive)?;
    let verify_before = args.verify.then(|| sha256_hex(&mmap));
    let source = ZipSource::open(&mmap)?;

    let manifest_file = File::open(&args.from_manifest)
        .with_context(|| format!("cannot open manifest {}", args.from_manifest.display()))?;
    let manifest = export::read_manifest(BufReader::new(manifest_file))?;

    match export::export_from_manifest(&manifest, &source, &args.to, Some(args.max_size))? {
        ExportOutcome::Exported {
            files,
            bytes,
            skipped,
            report,
        } => {
            let note = if skipped > 0 {
                format!("; {skipped} listed file(s) not found in archive")
            } else {
                String::new()
            };
            // Per-file integrity record beside the exported artefacts. Reuses the
            // manifest's run metadata so the report says what produced it.
            write_export_report_file(&args.to, &manifest.run, &report)?;
            eprintln!(
                "exported {files} files ({bytes} bytes) to {}{note}",
                args.to.display()
            );
        }
        ExportOutcome::Refused { total_size, cap } => {
            eprintln!(
                "refusing to export: manifest total {total_size} bytes exceeds --max-size {cap}; nothing written"
            );
        }
    }

    if let Some(before) = verify_before {
        report_verify(&before, &sha256_hex(&mmap));
    }
    Ok(())
}
