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
use mf_scan::report::export;

use crate::cmd::cli::ExportArgs;
use crate::cmd::support::exporting::{export_archive_path, export_subject, report_outcome};
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
    let backup_opts = BackupOptions::resolve(None, None);
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
    // Named after the manifest, whose run record the report inside reuses.
    // Named as the export the manifest's run would have made, else after the manifest.
    let stem = args
        .from_manifest
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let archive = export_archive_path(&args.to, &export_subject(&manifest.run, &stem))?;
    let outcome = export::export_from_manifest(manifest, source, &archive, Some(args.max_size))?;
    report_outcome(&outcome, "listed");
    Ok(())
}
