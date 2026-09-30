//! Orchestrates the `ios-backup` subcommand: `info` and `rebuild`.
//!
//! Defines: [`run_ios_backup`] and one private orchestrator per verb.
//! Used by: `main` (the `IosBackup` dispatch arm).
//! Uses: `cmd::support::{sources, exporting, reporting}` for opening a source and
//! writing output, `mf_scan::ops::rebuild` for the plan, and
//! `mf_scan::report::export` for the copying, digesting and manifest.
//!
//! WHY the rebuild does not reuse `support::exporting::run_export_sink`: that path
//! plans with the flat `<basename>_<hash>` layout, which is the opposite of what a
//! rebuild wants. It uses `export::plan_tree` with one root per domain instead,
//! which is the same engine the `app export` verb drives.

use anyhow::{Result, anyhow, bail};

use crate::cmd::cli::{
    IosBackupCommand, IosBackupInfoArgs, IosBackupRebuildArgs, IosBackupSourceArgs,
};
use crate::cmd::support::exporting::write_export_report_file;
use crate::cmd::support::reporting::{report_verify, sha256_hex};
use crate::cmd::support::sources::{
    BackupOptions, BackupProvenance, resolve_sources, with_operand_source,
};
use mf_scan::core::models::RunInfo;
use mf_scan::core::source::Source;
use mf_scan::ops::rebuild;
use mf_scan::ops::search::MatchedFile;
use mf_scan::platform::ios::backup::common::BackupStructure;
use mf_scan::report::export::{self, ExportOutcome};

/// Dispatch an `ios-backup` verb.
pub(crate) fn run_ios_backup(args: crate::cmd::cli::IosBackupArgs) -> Result<()> {
    match args.command {
        IosBackupCommand::Info(a) => run_info(a),
        IosBackupCommand::Rebuild(a) => run_rebuild(a),
    }
}

/// Open the backup described by `src`, erroring clearly when the source is not a
/// backup at all.
///
/// WHY it checks rather than sniffing path shapes: `support::sources` already
/// recognises a backup and wraps it in a `BackupSource` when it builds the source,
/// so the fact is available without re-deriving it from entry names (which
/// `ops::apps::detect` does, and which under-reports a backup holding no
/// third-party apps).
fn open_backup<R>(
    src: &IosBackupSourceArgs,
    f: impl FnOnce(&dyn Source, &BackupStructure, Option<&[u8]>, &str) -> Result<R>,
) -> Result<R> {
    let resolved = resolve_sources(std::slice::from_ref(&src.source), src.dir_mode, false)?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("no source to read"))?;

    let backup_opts = BackupOptions::resolve(src.backup_password.as_deref());
    let prov = BackupProvenance::new();
    let path_str = resolved.path.display().to_string();
    let operand = resolved.operand(src.archive_depth);

    let out = with_operand_source(
        operand,
        &backup_opts,
        src.io_mode.to_io_mode(),
        prov.sink(),
        |source, raw| {
            // The sink is filled when the BackupSource is built, which happens
            // before this closure runs. `None` means the source was not recognised
            // as a backup at all — fail loudly rather than rebuild nothing.
            let structure = prov.structure().ok_or_else(|| {
                anyhow!(
                    "{path_str} is not an iOS backup (no Manifest.plist/Manifest.db recognised)"
                )
            })?;
            f(source, &structure, raw, &path_str)
        },
    )?;

    prov.report();
    Ok(out)
}

fn run_info(args: IosBackupInfoArgs) -> Result<()> {
    open_backup(&args.source, |_source, _structure, _raw, path| {
        // The provenance line printed by `open_backup` already carries the
        // encryption state, file counts and how the backup was unlocked.
        eprintln!("source: {path}");
        Ok(())
    })
}

fn run_rebuild(args: IosBackupRebuildArgs) -> Result<()> {
    open_backup(&args.source, |source, structure, raw, path| {
        let verify_before = args.verify.then(|| raw.map(sha256_hex)).flatten();

        let plan = rebuild::plan(source, structure);
        if plan.roots.is_empty() {
            bail!("no backup domains found in {path}; is this an iOS backup?");
        }

        let files: Vec<MatchedFile> = rebuild::files_to_rebuild(source)
            .into_iter()
            .map(|e| MatchedFile {
                entry: e.clone(),
                offsets: Vec::new(),
            })
            .collect();

        let export_plan = export::plan_tree(&files, &plan.roots);
        report_renamed(&export_plan);
        let run = rebuild_run_info(path);

        report_plan(&plan, files.len(), export_plan.total_size);

        if args.dry_run {
            eprintln!("dry run: nothing written");
            return Ok(());
        }

        match export::export_files(
            &export_plan,
            source,
            &files,
            &args.to,
            args.max_size,
            args.max_path_len,
        )? {
            ExportOutcome::Exported {
                files: n,
                bytes,
                report,
                skipped_too_long,
                portability_warnings,
                ..
            } => {
                create_directories(&args.to, &plan.directories)?;
                write_export_report_file(
                    &args.to,
                    &run,
                    &report,
                    &skipped_too_long,
                    &portability_warnings,
                )?;
                eprintln!(
                    "rebuilt {n} file(s) ({bytes} bytes) and {} director(y/ies) into {}",
                    plan.directories.len(),
                    args.to.display()
                );
            }
            ExportOutcome::Refused { total_size, cap } => {
                eprintln!(
                    "refusing to rebuild: {total_size} bytes exceeds --max-size {cap}; nothing written"
                );
            }
        }

        if let Some(before) = verify_before
            && let Some(bytes) = raw
        {
            report_verify(&before, &sha256_hex(bytes));
        }
        Ok(())
    })
}

/// Create the backup's directory records under `dir`.
///
/// Files create their own parents, so this only adds the directories a backup
/// records that hold no files — which are themselves evidence (an empty
/// `Library/Caches` says something).
fn create_directories(dir: &std::path::Path, directories: &[String]) -> Result<()> {
    for rel in directories {
        let target = dir.join(rel);
        std::fs::create_dir_all(&target)
            .map_err(|e| anyhow!("cannot create {}: {e}", target.display()))?;
    }
    Ok(())
}

/// Report any destination that had to be renamed to avoid overwriting another.
///
/// A backup can hold two files whose paths differ only in case — on a real iPhone,
/// `com.apple.Preferences.plist` and `com.apple.preferences.plist` are distinct
/// files. On a case-insensitive file system one would overwrite the other, so the
/// second is given a `~1` suffix. Silently renaming a file is nearly as bad as
/// silently losing it, so every instance is named.
fn report_renamed(plan: &export::ExportPlan) {
    if plan.renamed.is_empty() {
        return;
    }
    eprintln!(
        "⚠ {} file(s) renamed: another file already claimed that destination \
         (paths differing only in case collide on macOS/Windows):",
        plan.renamed.len()
    );
    for r in &plan.renamed {
        eprintln!("    {} -> {}", r.wanted, r.used);
    }
}

/// Report what the plan will do, including everything an examiner must not
/// discover by accident.
fn report_plan(plan: &rebuild::Rebuild, file_count: usize, total_size: u64) {
    eprintln!(
        "rebuild plan: {file_count} file(s), {} director(y/ies), {} domain(s), {total_size} bytes",
        plan.directories.len(),
        plan.roots.len()
    );
    if !plan.synthetic.is_empty() {
        eprintln!(
            "⚠ {} domain(s) map to a SYNTHETIC path: a backup records no container GUIDs, so the\n\
             \x20 bundle identifier is substituted. These paths are not ground truth:",
            plan.synthetic.len()
        );
        for domain in &plan.synthetic {
            eprintln!("    {domain}");
        }
    }
    if !plan.symlinks.is_empty() {
        eprintln!(
            "note: {} symlink record(s) are reported but not recreated",
            plan.symlinks.len()
        );
    }
    if !plan.unmapped.is_empty() {
        eprintln!(
            "⚠ {} domain(s) have no known mount point and are placed under '{}/':",
            plan.unmapped.len(),
            rebuild::UNMAPPED_ROOT
        );
        for domain in &plan.unmapped {
            eprintln!("    {domain}");
        }
    }
}

/// Run metadata for the rebuild's export report.
fn rebuild_run_info(path: &str) -> RunInfo {
    RunInfo {
        archives: vec![path.to_string()],
        platform: Some("ios-backup".to_string()),
        ..RunInfo::default()
    }
}
