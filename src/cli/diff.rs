//! Arguments for the `diff` subcommand.
//!
//! Defines: [`DiffArgs`] — compare two sources (archives or folders) and report
//! which files were added / removed / modified. Reuses the shared filter,
//! decryption, and export-sink groups from [`crate::cli::common`], and adds the
//! per-side keyfile/platform overrides a two-source compare needs.
//! Used by: `cli` (the `Diff` variant) and `run::diff` (reads the fields).
//! Uses: `clap` (derive), the shared groups in `common`, and
//! `mf_scan::report::output::OutputFormat` (the `--format` value).

use std::path::PathBuf;

use clap::Args;

use crate::cli::common::{DecryptArgs, ExportSink, FilterArgs, PlatformArg};
use mf_scan::report::output::OutputFormat;

/// Arguments for `diff`.
#[derive(Args)]
pub(crate) struct DiffArgs {
    /// Baseline source (side A): an archive file or a directory.
    #[arg(value_name = "A")]
    pub(crate) a: PathBuf,

    /// Comparison source (side B): an archive file or a directory.
    #[arg(value_name = "B")]
    pub(crate) b: PathBuf,

    /// Compare file *content* with SHA-256 instead of the default mtime+size check.
    /// Exact but slower; catches content changes that preserve the timestamp.
    #[arg(long = "exact")]
    pub(crate) exact: bool,

    /// Inspect modified files of supported formats and report what changed inside
    /// them (SQLite tables/rows, plist/JSON keys, text lines).
    #[arg(long = "inspect")]
    pub(crate) inspect: bool,

    #[command(flatten)]
    pub(crate) filter: FilterArgs,

    #[command(flatten)]
    pub(crate) decrypt: DecryptArgs,

    /// Keyfile(s) for side A only (overrides the shared `--keyfile` for A).
    #[arg(long = "keyfile-a", value_name = "FILE")]
    pub(crate) keyfile_a: Vec<PathBuf>,

    /// Keyfile(s) for side B only (overrides the shared `--keyfile` for B).
    #[arg(long = "keyfile-b", value_name = "FILE")]
    pub(crate) keyfile_b: Vec<PathBuf>,

    /// Platform scope for side A only (overrides the shared `--platform` for A).
    #[arg(long = "platform-a", value_name = "PLATFORM")]
    pub(crate) platform_a: Option<PlatformArg>,

    /// Platform scope for side B only (overrides the shared `--platform` for B).
    #[arg(long = "platform-b", value_name = "PLATFORM")]
    pub(crate) platform_b: Option<PlatformArg>,

    #[command(flatten)]
    pub(crate) sink: ExportSink,

    /// Output format.
    #[arg(short = 'f', long, default_value = "txt")]
    pub(crate) format: OutputFormat,

    /// Write the diff report to this file instead of stdout.
    #[arg(short = 'o', long = "output")]
    pub(crate) output: Option<PathBuf>,

    /// Treat a directory side as a folder of interest: scan the files inside it
    /// (nested `.zip` opened per `--archive-depth`). A directory side without it is
    /// rejected (no silent default).
    #[arg(long = "dir-mode")]
    pub(crate) dir_mode: bool,

    /// How many levels of nested `*.zip` (found while scanning a `--dir-mode` folder)
    /// to open and descend into. 0 = treat nested archives as opaque files.
    #[arg(long = "archive-depth", value_name = "N", default_value_t = 0)]
    pub(crate) archive_depth: u32,
}
