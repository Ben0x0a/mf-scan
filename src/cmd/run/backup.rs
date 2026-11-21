//! Orchestrates the `backup` subcommand: `info` and `rebuild`.
//!
//! Defines: [`run_backup`] and one private orchestrator per verb.
//! Used by: `main` (the `Backup` dispatch arm).
//! Uses: `cmd::support::{sources, reporting}` for opening a source and writing output,
//! `mf_scan::ops::rebuild` for the plan, `mf_scan::report::export` for the path planning
//! every export shares, and `mf_scan::report::rebuild_zip` for the archive.

use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow, bail};

use crate::cmd::cli::{
    BackupArgs, BackupCommand, BackupInfoArgs, BackupRebuildArgs, BackupSourceArgs,
};
use crate::cmd::support::exporting::report_integrity;
use crate::cmd::support::reporting::{report_verify, sha256_hex};
use crate::cmd::support::sources::{
    BackupOptions, BackupProvenance, resolve_sources, with_operand_source,
};
use mf_scan::core::models::RunInfo;
use mf_scan::core::source::Source;
use mf_scan::ops::rebuild::{self, BackupKind};
use mf_scan::ops::search::MatchedFile;
use mf_scan::platform::ios::backup::common::BackupStructure;
use mf_scan::report::export::{self};
use mf_scan::report::rebuild_zip::{self, RebuildNotes, RebuildRequest};

/// Dispatch a `backup` verb.
pub(crate) fn run_backup(args: BackupArgs) -> Result<()> {
    match args.command {
        BackupCommand::Info(a) => run_info(a),
        BackupCommand::Rebuild(a) => run_rebuild(a),
    }
}

/// What opening a backup established, handed to a verb.
struct OpenedBackup<'a> {
    source: &'a dyn Source,
    structure: &'a BackupStructure,
    kind: BackupKind,
    /// The file as stored, for `--verify`, when the source is one file.
    raw: Option<&'a [u8]>,
    path: &'a str,
    stream_error: Option<String>,
}

/// Open the backup described by `src`, erroring clearly when the source is not a
/// backup at all.
///
/// WHY it checks rather than sniffing path shapes: `support::sources` already
/// recognises a backup when it builds the source, so the fact is available without
/// re-deriving it from entry names (which `ops::apps::detect` does, and which
/// under-reports a backup holding no third-party apps).
fn open_backup<R>(
    src: &BackupSourceArgs,
    f: impl FnOnce(OpenedBackup<'_>) -> Result<R>,
) -> Result<R> {
    // A backup is one thing, so a directory needs no flag saying how to read it.
    let resolved = resolve_sources(std::slice::from_ref(&src.source), true, false)?
        .sources
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("no source to read"))?;

    let backup_opts = BackupOptions::resolve(
        src.backup_password.as_deref(),
        src.archive_password.as_deref(),
    );
    let prov = BackupProvenance::new();
    let path_str = resolved.path.display().to_string();
    let operand = resolved.operand(src.archive_depth);

    let out = with_operand_source(
        operand,
        &backup_opts,
        src.io_mode.to_io_mode(),
        prov.sink(),
        |source, raw| {
            // The sink is filled when the source is built, which happens before this
            // closure runs. `None` means the source was not recognised as a backup at
            // all, so fail loudly rather than rebuild nothing.
            let (structure, kind) = prov.structure().zip(prov.kind()).ok_or_else(|| {
                anyhow!(
                    "{path_str} is not a backup: no iOS Manifest.plist/Manifest.db, and not an \
                     Android .ab file"
                )
            })?;
            let stream_error = prov
                .record()
                .and_then(|r| r.android)
                .and_then(|a| a.stream_error);
            f(OpenedBackup {
                source,
                structure: &structure,
                kind,
                raw,
                path: &path_str,
                stream_error,
            })
        },
    )?;

    prov.report();
    Ok(out)
}

fn run_info(args: BackupInfoArgs) -> Result<()> {
    open_backup(&args.source, |opened| {
        // The provenance line printed by `open_backup` carries the encryption state, the
        // file count and how the backup was unlocked.
        eprintln!("source: {}", opened.path);
        if let BackupKind::Android = opened.kind {
            eprintln!("platform: Android (adb backup)");
        } else {
            eprintln!("platform: iOS");
        }
        Ok(())
    })
}

fn run_rebuild(args: BackupRebuildArgs) -> Result<()> {
    let output = zip_path(&args.to);
    if args.source.source.canonicalize().ok() == output.canonicalize().ok() && output.exists() {
        bail!("--to must not overwrite the source backup");
    }

    open_backup(&args.source, |opened| {
        let OpenedBackup {
            source,
            structure,
            kind,
            raw,
            path,
            stream_error,
        } = opened;
        let verify_before = args.verify.then(|| raw.map(sha256_hex)).flatten();

        let plan = rebuild::plan(source, structure, kind);
        if plan.roots.is_empty() {
            bail!("nothing to rebuild in {path}: the backup holds no files");
        }

        let files: Vec<MatchedFile> = rebuild::files_to_rebuild(source)
            .into_iter()
            .map(|e| MatchedFile::new(e.clone(), Vec::new()))
            .collect();

        let export_plan = export::plan_tree(&files, &plan.roots);
        report_renamed(&export_plan);
        report_plan(&plan, files.len(), export_plan.total_size);

        if args.dry_run {
            eprintln!("dry run: nothing written");
            return Ok(());
        }
        if let Some(cap) = args.max_size
            && export_plan.total_size > cap
        {
            bail!(
                "refusing to rebuild: {} bytes exceeds --max-size {cap}; nothing written",
                export_plan.total_size
            );
        }

        let run = RunInfo {
            pattern: "backup rebuild".to_string(),
            archives: vec![path.to_string()],
            platform: Some(platform_label(kind).to_string()),
            ..RunInfo::default()
        };
        let outcome = rebuild_zip::write(RebuildRequest {
            source,
            plan: &export_plan,
            files: &files,
            directories: &plan.directories,
            output: &output,
            force: args.force,
            continue_on_error: args.continue_on_error,
            run: &run,
            notes: RebuildNotes {
                synthetic: plan.synthetic.clone(),
                unmapped: plan.unmapped.clone(),
                links: plan.symlinks.clone(),
                stream_error,
            },
            manifest: structure.manifest.as_ref(),
        })?;

        eprintln!(
            "rebuilt {} file(s) ({} bytes) and {} director(y/ies) into {}",
            outcome.report.len(),
            outcome.bytes,
            outcome.directories,
            output.display()
        );
        report_integrity(&outcome.report);
        if outcome.manifest.zip_paths_csv_sha256.is_some() {
            eprintln!(
                "archive root: {} (plaintext) and {} (each row's member, by fileID)",
                rebuild_zip::MANIFEST_MEMBER,
                rebuild_zip::ZIP_PATHS_MEMBER
            );
        }
        if let Some(reason) = &outcome.manifest.zip_paths_csv_error {
            eprintln!(
                "⚠ {} was NOT written ({reason}); {} is in the archive",
                rebuild_zip::ZIP_PATHS_MEMBER,
                rebuild_zip::MANIFEST_MEMBER
            );
        }
        if !outcome.failed.is_empty() {
            eprintln!(
                "⚠ {} file(s) could not be read and are NOT in the archive:",
                outcome.failed.len()
            );
            for file in &outcome.failed {
                eprintln!("    {} ({})", file.internal_path, file.reason);
            }
        }
        if !outcome.portability_warnings.is_empty() {
            eprintln!(
                "note: {} member(s) are complete in the archive but exceed Windows' path limit if \
                 extracted there (listed in {})",
                outcome.portability_warnings.len(),
                rebuild_zip::TRACEABILITY_MEMBER
            );
        }
        eprintln!(
            "archive sha256: {} -> {}",
            outcome.archive_sha256,
            outcome.sidecar.display()
        );

        if let Some(before) = verify_before
            && let Some(bytes) = raw
        {
            report_verify(&before, &sha256_hex(bytes));
        }
        Ok(())
    })
}

/// The output path, with `.zip` added when it has another extension or none: the output
/// is only ever an archive, and naming it so keeps it recognisable.
fn zip_path(to: &Path) -> PathBuf {
    let is_zip = to
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("zip"));
    if is_zip {
        return to.to_path_buf();
    }
    let mut name = to.as_os_str().to_os_string();
    name.push(".zip");
    PathBuf::from(name)
}

fn platform_label(kind: BackupKind) -> &'static str {
    match kind {
        BackupKind::Ios => "ios-backup",
        BackupKind::Android => "android-backup",
    }
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
        "rebuild plan: {file_count} file(s), {} director(y/ies), {total_size} bytes",
        plan.directories.len(),
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
            "note: {} link record(s) are reported but not recreated",
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
