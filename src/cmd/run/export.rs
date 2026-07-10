//! The `export` subcommand: re-ingest files listed in a manifest (no search).
//!
//! Defines: [`run_export`], one of the binary's two core operations.
//! Used by: `run` (dispatched from `main`).
//! Uses: `mf_scan::report::export` (the library export engine) and the `crate::cmd::support`
//! support modules (`sources`, `report`, `exporting`).

use std::fs::File;
use std::io::BufReader;

use anyhow::{Context, Result};

use mf_scan::core::source::Source;
use mf_scan::core::source::tar::TarSource;
use mf_scan::core::source::zip::ZipSource;
use mf_scan::report::export::{self, ExportOutcome};

use crate::cmd::cli::ExportArgs;
use crate::cmd::support::exporting::{
    report_portability_warnings, report_skipped_too_long, write_export_report_file,
};
use crate::cmd::support::reporting::{report_verify, sha256_hex};
use crate::cmd::support::sources::{is_tar_path, open_archive};

/// Run the `export` subcommand: re-ingest files listed in a manifest.
pub(crate) fn run_export(args: ExportArgs) -> Result<()> {
    let manifest_file = File::open(&args.from_manifest)
        .with_context(|| format!("cannot open manifest {}", args.from_manifest.display()))?;
    let manifest = export::read_manifest(BufReader::new(manifest_file))?;

    // The archive is a tar (plain or `.tar.gz`) or a ZIP, decided by name — the same
    // routing the search/diff paths use. A tar owns its backing buffer, so it opens
    // in its own branch; only the ZIP path exposes the raw bytes `--verify` hashes.
    if is_tar_path(&args.archive) {
        if args.verify {
            eprintln!(
                "note: --verify (whole-archive hash) is not supported for tar sources; skipping it"
            );
        }
        let source = TarSource::open(&args.archive)?;
        run_manifest_export(&args, &manifest, &source)?;
    } else {
        let mmap = open_archive(&args.archive)?;
        let verify_before = args.verify.then(|| sha256_hex(&mmap));
        let source = ZipSource::open(&mmap)?;
        run_manifest_export(&args, &manifest, &source)?;
        if let Some(before) = verify_before {
            report_verify(&before, &sha256_hex(&mmap));
        }
    }
    Ok(())
}

/// Export the manifest's files out of `source` and write the integrity report —
/// source-agnostic, so the ZIP and tar branches share it.
fn run_manifest_export(
    args: &ExportArgs,
    manifest: &export::Manifest,
    source: &dyn Source,
) -> Result<()> {
    match export::export_from_manifest(
        manifest,
        source,
        &args.to,
        Some(args.max_size),
        args.max_path_len,
    )? {
        ExportOutcome::Exported {
            files,
            bytes,
            skipped,
            report,
            skipped_too_long,
            portability_warnings,
        } => {
            let note = if skipped > 0 {
                format!("; {skipped} listed file(s) not found in archive")
            } else {
                String::new()
            };
            // Per-file integrity record beside the exported artefacts. Reuses the
            // manifest's run metadata so the report says what produced it.
            write_export_report_file(
                &args.to,
                &manifest.run,
                &report,
                &skipped_too_long,
                &portability_warnings,
            )?;
            eprintln!(
                "exported {files} files ({bytes} bytes) to {}{note}",
                args.to.display()
            );
            report_skipped_too_long(&skipped_too_long);
            report_portability_warnings(&portability_warnings);
        }
        ExportOutcome::Refused { total_size, cap } => {
            eprintln!(
                "refusing to export: manifest total {total_size} bytes exceeds --max-size {cap}; nothing written"
            );
        }
    }
    Ok(())
}
