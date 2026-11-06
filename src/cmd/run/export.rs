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
use mf_scan::report::export::{self, ExportOutcome};

use crate::cmd::cli::ExportArgs;
use crate::cmd::support::exporting::{
    report_portability_warnings, report_skipped_too_long, write_export_report_file,
};
use crate::cmd::support::reporting::{report_verify, sha256_hex};
use crate::cmd::support::sources::{
    BackupOptions, BackupProvenance, IoMode, resolve_file, with_operand_source,
};

/// Run the `export` subcommand: re-ingest files listed in a manifest.
pub(crate) fn run_export(args: ExportArgs) -> Result<()> {
    let manifest_file = File::open(&args.from_manifest)
        .with_context(|| format!("cannot open manifest {}", args.from_manifest.display()))?;
    let manifest = export::read_manifest(BufReader::new(manifest_file))?;

    let resolved = resolve_file(&args.archive)?;
    let backup_opts = BackupOptions::resolve(None);
    let prov = BackupProvenance::new();
    with_operand_source(
        resolved.operand(0),
        &backup_opts,
        IoMode::Auto,
        prov.sink(),
        |source, raw| {
            let verify_before = args.verify.then(|| raw.map(sha256_hex)).flatten();
            run_manifest_export(&args, &manifest, source)?;
            match (verify_before, raw) {
                (Some(before), Some(bytes)) => report_verify(&before, &sha256_hex(bytes)),
                _ if args.verify => {
                    eprintln!("verify: skipped (this source has no single archive file to hash)")
                }
                _ => {}
            }
            Ok(())
        },
    )?;
    prov.report();
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
            // A manifest re-ingestion writes no decrypted copies.
            undecrypted: _,
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
                &[],
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
