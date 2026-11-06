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

use crate::cmd::cli::common::{IoModeArg, KeyArgs};
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
    /// List the installed apps: bundle id, name and size.
    Grep(AppGrepArgs),
    /// List everywhere an app and its widgets, extensions and groups keep data.
    Paths(AppPathsArgs),
    /// Copy all of an app's data (and its groups) into a directory.
    Export(AppExportArgs),
}

/// How to open the acquisition — shared by all three verbs.
#[derive(Args)]
pub(crate) struct AppSourceArgs {
    /// An archive, a backup, or a folder with --dir-mode.
    #[arg(value_name = "SOURCE")]
    pub(crate) source: PathBuf,

    /// Read a folder source's files.
    #[arg(long = "dir-mode")]
    pub(crate) dir_mode: bool,

    /// With --dir-mode, open nested .zip files this many levels deep.
    #[arg(
        long = "archive-depth",
        value_name = "N",
        default_value_t = 0,
        hide_default_value = true
    )]
    pub(crate) archive_depth: u32,

    /// How to read an archive: auto, mmap or ranged (network shares).
    #[arg(
        long = "io-mode",
        value_enum,
        default_value = "auto",
        hide_default_value = true,
        hide_possible_values = true,
        value_name = "MODE"
    )]
    pub(crate) io_mode: IoModeArg,

    /// Password for an encrypted backup (or set MFSCAN_BACKUP_PASSWORD).
    #[arg(long = "backup-password", value_name = "PASSWORD")]
    pub(crate) backup_password: Option<String>,
}

/// Arguments for `app grep`.
#[derive(Args)]
pub(crate) struct AppGrepArgs {
    #[command(flatten)]
    pub(crate) source: AppSourceArgs,

    /// Text in the bundle id or name, ignoring case; omit to list every app.
    #[arg(value_name = "PATTERN")]
    pub(crate) pattern: Option<String>,

    /// Output format: txt or json.
    #[arg(short = 'f', long, default_value = "txt", hide_default_value = true)]
    pub(crate) format: OutputFormat,

    /// Write to this file instead of stdout.
    #[arg(long = "output", value_name = "FILE")]
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

    /// Leave out shared App Group containers.
    #[arg(long = "no-groups")]
    pub(crate) no_groups: bool,

    /// Output format: txt or json.
    #[arg(short = 'f', long, default_value = "txt", hide_default_value = true)]
    pub(crate) format: OutputFormat,

    /// Write to this file instead of stdout.
    #[arg(long = "output", value_name = "FILE")]
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

    /// Leave out shared App Group containers.
    #[arg(long = "no-groups")]
    pub(crate) no_groups: bool,

    /// Refuse to export more than this (default 1G), e.g. 5G.
    #[arg(long = "max-size", value_name = "SIZE", value_parser = crate::cmd::cli::common::parse_size, default_value = "1G", hide_default_value = true)]
    pub(crate) max_size: u64,

    /// Skip and record longer paths (default 260, Windows); 0 is off.
    #[arg(long = "max-path-len", value_name = "N", default_value_t = DEFAULT_MAX_PATH_LEN, hide_default_value = true)]
    pub(crate) max_path_len: usize,

    /// Hash the archive before and after, to attest it did not change.
    #[arg(long = "verify")]
    pub(crate) verify: bool,

    /// Keychain/keystore dump: each app database it decrypts is also written
    /// decrypted, beside the original. A dump beside the source is found on its own.
    #[command(flatten, next_help_heading = "Decryption")]
    pub(crate) keys: KeyArgs,
}
