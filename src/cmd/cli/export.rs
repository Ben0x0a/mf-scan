//! Arguments for the `export` subcommand.
//!
//! Defines: [`ExportArgs`] — export files listed in a manifest out of an archive,
//! with no search. Unlike the shared [`crate::cmd::cli::common::ExportSink`] (which adds
//! a manifest/export sink onto `grep`/`diff`), this drives the standalone `export`
//! command that re-ingests a previously written manifest.
//! Used by: `cli` (the `Export` variant) and `run::export`.
//! Uses: `clap` (derive) and the shared `parse_size` parser from `common`.

use std::path::PathBuf;

use clap::Args;

use crate::cmd::cli::common::parse_size;

/// Arguments for `export`.
#[derive(Args)]
pub(crate) struct ExportArgs {
    /// Archive or backup file to export from.
    pub(crate) archive: PathBuf,

    /// Manifest from grep, find or diff --manifest.
    #[arg(long = "from-manifest", value_name = "FILE")]
    pub(crate) from_manifest: PathBuf,

    /// Destination directory.
    #[arg(long = "to", value_name = "DIR")]
    pub(crate) to: PathBuf,

    /// Refuse to export more than this (default 1G), e.g. 5G.
    #[arg(long = "max-size", value_name = "SIZE", value_parser = parse_size, default_value = "1G", hide_default_value = true)]
    pub(crate) max_size: u64,

    /// Skip and record longer paths (default 260, Windows); 0 is off.
    #[arg(long = "max-path-len", value_name = "N", default_value_t = mf_scan::report::export::DEFAULT_MAX_PATH_LEN, hide_default_value = true)]
    pub(crate) max_path_len: usize,

    /// Hash the archive before and after, to attest it did not change.
    #[arg(long = "verify")]
    pub(crate) verify: bool,
}
