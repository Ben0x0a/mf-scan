//! Arguments for the `ios-backup` subcommand: inspect and rebuild an iOS backup.
//!
//! Defines: [`IosBackupArgs`] and its verbs ([`IosBackupCommand`]) — `info`
//! (report what the backup is, without writing anything) and `rebuild` (write the
//! whole backup out as a filesystem-like tree).
//! Used by: `cli` (the `IosBackup` variant) and `run::ios_backup` (reads the fields).
//! Uses: `clap` (derive), the shared `IoModeArg` from `common`, and
//! `mf_scan::report::export::DEFAULT_MAX_PATH_LEN`.
//!
//! WHY a noun with verbs rather than a flat `rebuild-ios-backup`: it mirrors the
//! existing `app grep|paths|export`, keeps every top-level command a single word,
//! and gives future backup-specific verbs a home instead of a family of
//! hyphenated top-level commands. The noun names the platform because mf-scan also
//! reads iOS full-filesystem and Android acquisitions, which are already trees and
//! have nothing to rebuild.

use std::path::PathBuf;

use clap::{Args, Subcommand};

use crate::cmd::cli::common::IoModeArg;
use mf_scan::report::export::DEFAULT_MAX_PATH_LEN;

/// Arguments for `ios-backup`.
#[derive(Args)]
pub(crate) struct IosBackupArgs {
    #[command(subcommand)]
    pub(crate) command: IosBackupCommand,
}

/// The `ios-backup` verbs, in the order an examiner uses them.
#[derive(Subcommand)]
pub(crate) enum IosBackupCommand {
    /// Report what the backup is: device, iOS version, encryption, file counts.
    Info(IosBackupInfoArgs),
    /// Rebuild the whole backup into a filesystem-like directory tree.
    Rebuild(IosBackupRebuildArgs),
}

/// Options shared by every `ios-backup` verb.
#[derive(Args)]
pub(crate) struct IosBackupSourceArgs {
    /// The backup: a directory (with `--dir-mode`) or an archive of one.
    #[arg(value_name = "SOURCE")]
    pub(crate) source: PathBuf,

    /// Treat a directory source as a folder of loose files. Required when the
    /// source is a directory.
    #[arg(long = "dir-mode")]
    pub(crate) dir_mode: bool,

    /// Levels of nested `*.zip` to open when reading a `--dir-mode` folder.
    #[arg(long = "archive-depth", value_name = "N", default_value_t = 0)]
    pub(crate) archive_depth: u32,

    /// How to read the archive's bytes: `auto`, `mmap`, or `ranged`.
    #[arg(long = "io-mode", value_enum, default_value = "auto")]
    pub(crate) io_mode: IoModeArg,

    /// Password for an encrypted backup (else `MFSCAN_BACKUP_PASSWORD`, else the
    /// acquisition defaults are tried).
    #[arg(long = "backup-password", value_name = "PASSWORD")]
    pub(crate) backup_password: Option<String>,
}

/// Arguments for `ios-backup info`.
#[derive(Args)]
pub(crate) struct IosBackupInfoArgs {
    #[command(flatten)]
    pub(crate) source: IosBackupSourceArgs,
}

/// Arguments for `ios-backup rebuild`.
///
/// WHY this does not flatten the shared `ExportSink`: that group's `--max-size`
/// defaults to 1G and REFUSES the whole export when the total exceeds it, which
/// is right for pulling one app's data out and wrong for a whole backup — every
/// real one would write nothing. The size and path-length guards here are sized
/// for a full rebuild instead.
#[derive(Args)]
pub(crate) struct IosBackupRebuildArgs {
    #[command(flatten)]
    pub(crate) source: IosBackupSourceArgs,

    /// Directory to write the rebuilt tree into.
    #[arg(long = "to", value_name = "DIR")]
    pub(crate) to: PathBuf,

    /// Refuse to write if the rebuilt tree would exceed this size. Unset means no
    /// cap, which is the usual case for a whole backup.
    #[arg(long = "max-size", value_name = "SIZE", value_parser = crate::cmd::cli::common::parse_size)]
    pub(crate) max_size: Option<u64>,

    /// Skip files whose destination path would exceed this many characters.
    /// `0` disables the guard.
    #[arg(long = "max-path-len", value_name = "N", default_value_t = DEFAULT_MAX_PATH_LEN)]
    pub(crate) max_path_len: usize,

    /// Also write a re-ingestable JSON manifest of everything written.
    #[arg(long = "manifest", value_name = "FILE")]
    pub(crate) manifest: Option<PathBuf>,

    /// Plan the rebuild and report it without writing any files.
    #[arg(long = "dry-run")]
    pub(crate) dry_run: bool,

    /// Verify the source archive's SHA-256 before and after reading it.
    #[arg(long = "verify")]
    pub(crate) verify: bool,
}
