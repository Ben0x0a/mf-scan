//! The `diff` subcommand orchestration.
//!
//! Defines: [`run_diff`], which opens both sides, compares them, renders the report,
//! and (optionally) exports the changed files from side B with a re-ingestable
//! manifest — the same export pipeline `grep` uses.
//! Used by: `run` (dispatched from `main`).
//! Uses: the `mf_scan` library (`diff`, `source`, `report`) plus the shared
//! `crate::support` machinery (source resolution, the output sink, the export report).
//!
//! Each side is a single source: an archive file, or a directory opened as a folder
//! (`--dir-mode folder`). Type filtering (`--type`), intra-file diff (`--inspect`),
//! decryption (`--keyfile`), and nested-archive expansion (`--archive-depth`) are
//! rejected for now rather than silently ignored — they arrive in later milestones.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Result, bail};

use mf_scan::diff::{Change, CompareMode, DiffReport, diff_sources};
use mf_scan::engine::MatchedFile;
use mf_scan::filter::EntryFilter;
use mf_scan::models::{Entry, RunInfo};
use mf_scan::report::diff::write_diff;
use mf_scan::source::Source;

use std::cell::RefCell;

use crate::cli::DiffArgs;
use crate::support::exporting::run_export_sink;
use crate::support::reporting::emit;
use crate::support::sources::{BackupOptions, IoMode, Operand, with_operand_source};

/// Run the `diff` subcommand.
pub(crate) fn run_diff(args: DiffArgs) -> Result<()> {
    reject_unsupported(&args)?;

    let mode = if args.exact {
        CompareMode::Hash
    } else if args.a.is_dir() != args.b.is_dir() {
        // A ZIP entry's mtime is a 2-second local-time DOS stamp; a folder file's
        // is a UTC filesystem epoch. Comparing them flags nearly every file as
        // modified, so a mixed zip-vs-folder diff falls back to size only.
        eprintln!(
            "warning: comparing an archive against a folder — their timestamps come \
             from different clocks, so the fast compare uses size only (pass --exact \
             to compare content)"
        );
        CompareMode::SizeOnly
    } else {
        CompareMode::Meta
    };
    // Path globs only for now (type filtering is rejected above).
    let filter = EntryFilter::new(&args.filter.path, &args.filter.not_path, &[], false);
    let want_export = args.sink.manifest.is_some() || args.sink.export.is_some();

    // Open both sides — nested so both backing buffers stay alive across the diff —
    // then render, and export side B's changes through the shared export pipeline.
    // Resolve the backup password once (flag or env); both sides share it. An
    // encrypted backup on either side is decrypted transparently by the shared
    // open path. (Backup provenance is not reported by diff yet; the per-side
    // record sink is local and discarded.)
    let backup_opts = BackupOptions::resolve(args.decrypt.backup_password.as_deref());

    with_diff_side(
        &args.a,
        args.dir_mode,
        args.archive_depth,
        &backup_opts,
        |a_src| {
            with_diff_side(
                &args.b,
                args.dir_mode,
                args.archive_depth,
                &backup_opts,
                |b_src| {
                    let report = diff_sources(a_src, b_src, mode, &filter, args.inspect)?;

                    emit(args.output.as_deref(), |w| {
                        write_diff(&report, args.format, w)
                    })?;

                    // Summary to stderr so it never pollutes a piped/redirected report.
                    let (added, removed, modified, unchanged) = report.counts();
                    eprintln!(
                        "diff: {added} added, {removed} removed, {modified} modified, {unchanged} unchanged"
                    );

                    if want_export {
                        export_changes(&args, &report, b_src)?;
                    }
                    Ok(())
                },
            )
        },
    )
}

/// Reject the flags whose `diff` behaviour is not implemented yet, so they fail
/// loudly instead of being silently ignored.
fn reject_unsupported(args: &DiffArgs) -> Result<()> {
    if !args.filter.file_type.is_empty() || args.filter.exclude_media {
        bail!("diff --type/--exclude-media filtering is not yet implemented");
    }
    if decryption_requested(args) {
        bail!("decryption-aware diff (--keyfile/--platform) is not yet implemented");
    }
    Ok(())
}

/// Whether any decryption material was supplied (shared or per-side).
fn decryption_requested(args: &DiffArgs) -> bool {
    !args.decrypt.keyfile.is_empty()
        || !args.keyfile_a.is_empty()
        || !args.keyfile_b.is_empty()
        || args.decrypt.platform.is_some()
        || args.platform_a.is_some()
        || args.platform_b.is_some()
}

/// Open one diff side as a single [`Source`] and run `f` with it.
///
/// A file is an archive; a directory must be given with `--dir-mode` (a single
/// folder source) — a diff side is one source, so there is no archive-harvesting
/// (`-r`) mode here, and a bare directory without `--dir-mode` is rejected rather
/// than guessed. The open itself is delegated to the shared [`with_operand_source`]
/// point; diff needs no raw bytes, so it ignores the `Option<&[u8]>`.
fn with_diff_side<R>(
    path: &Path,
    dir_mode: bool,
    archive_depth: u32,
    backup_opts: &BackupOptions,
    f: impl FnOnce(&dyn Source) -> Result<R>,
) -> Result<R> {
    let operand = if !path.is_dir() {
        Operand::Archive(path)
    } else if dir_mode {
        Operand::Folder {
            path,
            archive_depth,
        }
    } else {
        bail!(
            "{} is a directory; pass --dir-mode to diff it as a folder",
            path.display()
        )
    };
    let record = RefCell::new(None);
    // diff has no --io-mode flag; auto-detect a remote source per side.
    with_operand_source(
        operand,
        backup_opts,
        IoMode::Auto,
        &record,
        |source, _raw| f(source),
    )
}

/// Export the added/modified files from side B and/or write a manifest, reusing the
/// same export engine and manifest schema as `grep` (so `mf-scan export
/// --from-manifest` re-ingests a diff result with no special-casing).
fn export_changes(args: &DiffArgs, report: &DiffReport, b_src: &dyn Source) -> Result<()> {
    // Side B's entries by path, to fetch the ones that changed.
    let by_path: HashMap<&str, &Entry> = b_src
        .entries()
        .iter()
        .map(|e| (e.name.as_str(), e))
        .collect();
    let files: Vec<MatchedFile> = report
        .files
        .iter()
        .filter(|f| matches!(f.change, Change::Added | Change::Modified))
        .filter_map(|f| {
            by_path.get(f.path.as_str()).map(|e| MatchedFile {
                entry: (*e).clone(),
                offsets: Vec::new(),
            })
        })
        .collect();

    run_export_sink(&args.sink, b_src, &files, &diff_run_info(args), "changed")
}

/// Run metadata for the diff manifest/export report — informational provenance
/// describing what produced it (the two sides and any path filters).
fn diff_run_info(args: &DiffArgs) -> RunInfo {
    RunInfo {
        tool: "mf-scan".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        pattern: format!("diff {} -> {}", args.a.display(), args.b.display()),
        literal: false,
        ignore_case: false,
        match_path: false,
        inspect: false,
        archives: vec![args.a.display().to_string(), args.b.display().to_string()],
        path_globs: args.filter.path.clone(),
        not_path_globs: args.filter.not_path.clone(),
        types: Vec::new(),
        exclude_media: false,
        base64: false,
        base64_urlsafe: false,
        keyfiles: Vec::new(),
        platform: None,
        // Diff is not app-selected.
        app: None,
        app_containers: Vec::new(),
        app_group_links: Vec::new(),
    }
}
