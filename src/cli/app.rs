//! Arguments for the `app` subcommand: locate and export an application's data.
//!
//! Defines: [`AppArgs`] and its three verbs ([`AppCommand`]) — `grep` (search the
//! installed-app inventory), `paths` (list every data location of one app), and
//! `export` (copy one app's data out, kind-labelled). The shared source-opening
//! options live in [`AppSourceArgs`], flattened into each verb.
//! Used by: `cli` (the `App` variant) and `run::app` (reads the fields).
//! Uses: `clap` (derive), the shared `IoModeArg` from `common`, and
//! `mf_scan::report::output::OutputFormat` (the `--format` value) /
//! `mf_scan::report::export::DEFAULT_MAX_PATH_LEN` (the path-guard default).
//!
//! WHY `SOURCE` is the first positional in every verb (rather than the
//! pattern/bundle-id first, as the top-level `grep` does): `app grep`'s pattern is
//! optional, and clap cannot place an optional positional before a required one —
//! so `SOURCE` leads uniformly and the selector follows.

use std::path::PathBuf;

use clap::{Args, Subcommand};

use crate::cli::common::IoModeArg;
use mf_scan::report::export::DEFAULT_MAX_PATH_LEN;
use mf_scan::report::output::OutputFormat;

/// Arguments for `app`.
#[derive(Args)]
pub(crate) struct AppArgs {
    #[command(subcommand)]
    pub(crate) command: AppCommand,
}

/// The `app` verbs, mirroring the top-level `grep`/`export` where they overlap.
#[derive(Subcommand)]
pub(crate) enum AppCommand {
    /// Search the installed-app inventory: list each app's bundle id, name, and size.
    Grep(AppGrepArgs),
    /// List every data location an app or its widgets/extensions/groups can write.
    Paths(AppPathsArgs),
    /// Export all of an app's data (and its groups) into a directory, kind-labelled.
    Export(AppExportArgs),
}

/// How to open the acquisition — shared by all three verbs.
#[derive(Args)]
pub(crate) struct AppSourceArgs {
    /// Source to read: an archive file, or a directory (with `--dir-mode`).
    #[arg(value_name = "SOURCE")]
    pub(crate) source: PathBuf,

    /// Treat a directory source as a folder of loose files (nested `.zip` opened
    /// per `--archive-depth`). Required when the source is a directory.
    #[arg(long = "dir-mode")]
    pub(crate) dir_mode: bool,

    /// Levels of nested `*.zip` to open when scanning a `--dir-mode` folder.
    #[arg(long = "archive-depth", value_name = "N", default_value_t = 0)]
    pub(crate) archive_depth: u32,

    /// How to read the archive's bytes: `auto`, `mmap`, or `ranged`.
    #[arg(long = "io-mode", value_enum, default_value = "auto")]
    pub(crate) io_mode: IoModeArg,

    /// Password for an encrypted iOS backup (else `MFSCAN_BACKUP_PASSWORD`, else
    /// the acquisition defaults are tried).
    #[arg(long = "backup-password", value_name = "PASSWORD")]
    pub(crate) backup_password: Option<String>,
}

/// Arguments for `app grep`.
#[derive(Args)]
pub(crate) struct AppGrepArgs {
    #[command(flatten)]
    pub(crate) source: AppSourceArgs,

    /// Optional case-insensitive substring over the bundle id and display name;
    /// omit to list every installed app.
    #[arg(value_name = "PATTERN")]
    pub(crate) pattern: Option<String>,

    /// Output format (`txt` or `json`).
    #[arg(short = 'f', long, default_value = "txt")]
    pub(crate) format: OutputFormat,

    /// Write to this file instead of stdout.
    #[arg(short = 'o', long = "output", value_name = "FILE")]
    pub(crate) output: Option<PathBuf>,
}

/// Arguments for `app paths`.
#[derive(Args)]
pub(crate) struct AppPathsArgs {
    #[command(flatten)]
    pub(crate) source: AppSourceArgs,

    /// The app's bundle id (iOS) or package name (Android).
    #[arg(value_name = "BUNDLE_ID")]
    pub(crate) bundle_id: String,

    /// Do not include shared App Group containers (list only the app's own data
    /// and its extension/widget containers).
    #[arg(long = "no-groups")]
    pub(crate) no_groups: bool,

    /// Output format (`txt` or `json`).
    #[arg(short = 'f', long, default_value = "txt")]
    pub(crate) format: OutputFormat,

    /// Write to this file instead of stdout.
    #[arg(short = 'o', long = "output", value_name = "FILE")]
    pub(crate) output: Option<PathBuf>,
}

/// Arguments for `app export`.
#[derive(Args)]
pub(crate) struct AppExportArgs {
    #[command(flatten)]
    pub(crate) source: AppSourceArgs,

    /// The app's bundle id (iOS) or package name (Android).
    #[arg(value_name = "BUNDLE_ID")]
    pub(crate) bundle_id: String,

    /// Destination directory.
    #[arg(long = "to", value_name = "DIR")]
    pub(crate) to: PathBuf,

    /// Do not include shared App Group containers in the export.
    #[arg(long = "no-groups")]
    pub(crate) no_groups: bool,

    /// Refuse to export if the selected data exceeds this size (e.g. 500MB, 4G).
    #[arg(long = "max-size", value_name = "SIZE", value_parser = crate::cli::common::parse_size, default_value = "1G")]
    pub(crate) max_size: u64,

    /// Skip (and record) any file whose destination path would exceed this many
    /// characters. Defaults to 260 (Windows MAX_PATH); 0 disables the guard.
    #[arg(long = "max-path-len", value_name = "N", default_value_t = DEFAULT_MAX_PATH_LEN)]
    pub(crate) max_path_len: usize,

    /// Hash the archive (SHA-256) before and after the run and report whether it
    /// changed — a slower, court-defensible integrity attestation.
    #[arg(long = "verify")]
    pub(crate) verify: bool,
}
