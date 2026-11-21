//! Arguments for the `backup` subcommand: inspect and rebuild a mobile backup.
//!
//! Defines: [`BackupArgs`] and its verbs ([`BackupCommand`]) — `info` (report what the
//! backup is, without writing anything) and `rebuild` (write it out as one ZIP archive
//! holding the device's directory tree).
//! Used by: `cli` (the `Backup` variant) and `run::backup` (reads the fields).
//! Uses: `clap` (derive), and the shared `IoModeArg` and `parse_size` from `common`.
//!
//! WHY `--to` is a file and there is no folder output: see `report::rebuild_zip`.
//!
//! WHY there is no default `--max-size`: a 1G cap, right for pulling out one app's data,
//! would refuse essentially every real backup.

use std::path::PathBuf;

use clap::{Args, Subcommand};

use crate::cmd::cli::common::{IoModeArg, parse_size};

/// Arguments for `backup`.
#[derive(Args)]
pub(crate) struct BackupArgs {
    #[command(subcommand)]
    pub(crate) command: BackupCommand,
}

/// The `backup` verbs, in the order an examiner uses them.
#[derive(Subcommand)]
pub(crate) enum BackupCommand {
    /// Report what a backup is, without writing anything.
    Info(BackupInfoArgs),
    /// Rebuild a backup into one .zip holding the device's directory tree.
    Rebuild(BackupRebuildArgs),
}

/// Options shared by every `backup` verb.
#[derive(Args)]
pub(crate) struct BackupSourceArgs {
    /// iOS backup folder, an archive of one, or an Android .ab file.
    #[arg(value_name = "SOURCE")]
    pub(crate) source: PathBuf,

    /// Password if encrypted (or set MFSCAN_BACKUP_PASSWORD).
    #[arg(long = "backup-password", value_name = "PASSWORD")]
    pub(crate) backup_password: Option<String>,

    /// Password of an encrypted 7z (or MFSCAN_ARCHIVE_PASSWORD).
    #[arg(long = "archive-password", value_name = "PASS")]
    pub(crate) archive_password: Option<String>,

    /// With a folder, open nested .zip files this many levels deep.
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
}

/// Arguments for `backup info`.
#[derive(Args)]
pub(crate) struct BackupInfoArgs {
    #[command(flatten)]
    pub(crate) source: BackupSourceArgs,
}

/// Arguments for `backup rebuild`.
#[derive(Args)]
pub(crate) struct BackupRebuildArgs {
    #[command(flatten)]
    pub(crate) source: BackupSourceArgs,

    /// The .zip file to write.
    #[arg(long = "to", value_name = "FILE.zip")]
    pub(crate) to: PathBuf,

    /// Replace the .zip if it already exists.
    #[arg(long = "force")]
    pub(crate) force: bool,

    /// Report the plan and write nothing.
    #[arg(long = "dry-run")]
    pub(crate) dry_run: bool,

    /// Keep what can be read of a damaged backup, recording the rest.
    #[arg(long = "continue-on-error")]
    pub(crate) continue_on_error: bool,

    /// Refuse to write more than this, e.g. 200G (default: no limit).
    #[arg(long = "max-size", value_name = "SIZE", value_parser = parse_size)]
    pub(crate) max_size: Option<u64>,

    /// Hash the source before and after, to attest it did not change.
    #[arg(long = "verify")]
    pub(crate) verify: bool,
}
