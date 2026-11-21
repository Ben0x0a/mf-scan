//! Arguments for the `diff` subcommand.
//!
//! Defines: [`DiffArgs`] — compare two sources (archives or folders) and report
//! which files were added / removed / modified. Reuses the shared filter,
//! decryption, and export-sink groups from [`crate::cmd::cli::common`], and adds the
//! per-side keyfile/platform overrides a two-source compare needs.
//! Used by: `cli` (the `Diff` variant) and `run::diff` (reads the fields).
//! Uses: `clap` (derive), the shared groups in `common`, and
//! `mf_scan::report::output::OutputFormat` (the `--format` value).

use std::path::PathBuf;

use clap::Args;

use crate::cmd::cli::common::{DecryptArgs, ExportSink, FilterArgs, PlatformArg};
use mf_scan::report::output::OutputFormat;

/// Arguments for `diff`.
#[derive(Args)]
pub(crate) struct DiffArgs {
    /// Baseline: an archive, a file, or a folder with --dir-mode.
    #[arg(value_name = "A")]
    pub(crate) a: PathBuf,

    /// Compared against the baseline, in the same forms.
    #[arg(value_name = "B")]
    pub(crate) b: PathBuf,

    /// Compare content (SHA-256), not just size and time.
    #[arg(long = "exact")]
    pub(crate) exact: bool,

    /// Say what changed inside SQLite, plist, JSON and text files.
    #[arg(long = "inspect")]
    pub(crate) inspect: bool,

    #[command(flatten)]
    pub(crate) filter: FilterArgs,

    #[command(flatten)]
    pub(crate) decrypt: DecryptArgs,

    // Reserved for decryption-aware diff, which is not implemented; rejected if given.
    #[arg(long = "keyfile-a", value_name = "FILE", hide = true)]
    pub(crate) keyfile_a: Vec<PathBuf>,

    #[arg(long = "keyfile-b", value_name = "FILE", hide = true)]
    pub(crate) keyfile_b: Vec<PathBuf>,

    #[arg(long = "platform-a", value_name = "PLATFORM", hide = true)]
    pub(crate) platform_a: Option<PlatformArg>,

    #[arg(long = "platform-b", value_name = "PLATFORM", hide = true)]
    pub(crate) platform_b: Option<PlatformArg>,

    #[command(flatten)]
    pub(crate) sink: ExportSink,

    /// Output format: txt, json or csv.
    #[arg(short = 'f', long, default_value = "txt", hide_default_value = true)]
    pub(crate) format: OutputFormat,

    /// Write the report to this file instead of stdout.
    #[arg(long = "output", value_name = "FILE")]
    pub(crate) output: Option<PathBuf>,

    /// Read a folder side's files.
    #[arg(long = "dir-mode")]
    pub(crate) dir_mode: bool,

    /// Open archives and compressed files found inside, this many levels deep.
    #[arg(
        long = "archive-depth",
        value_name = "N",
        default_value_t = 0,
        hide_default_value = true
    )]
    pub(crate) archive_depth: u32,

    /// With --archive-depth: the most opening them may add to memory or disk.
    #[arg(
        long = "nested-limit",
        value_name = "SIZE",
        value_parser = crate::cmd::cli::common::parse_size,
        default_value = "16G",
        hide_default_value = true
    )]
    pub(crate) nested_limit: u64,
}
