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
    /// ZIP or tar archive (`.tar`/`.tar.gz`/`.tgz`) to export files from.
    pub(crate) archive: PathBuf,

    /// Manifest written by a previous `grep --manifest` (or `diff --manifest`).
    #[arg(long = "from-manifest", value_name = "FILE")]
    pub(crate) from_manifest: PathBuf,

    /// Destination directory.
    #[arg(long = "to", value_name = "DIR")]
    pub(crate) to: PathBuf,

    /// Refuse if the manifest's total size exceeds this (e.g. 200MB, 1G).
    /// Defaults to 1G as an accident guard; raise it to export more.
    #[arg(long = "max-size", value_name = "SIZE", value_parser = parse_size, default_value = "1G")]
    pub(crate) max_size: u64,

    /// Skip (and record) any file whose destination path would exceed this many
    /// characters. Defaults to 260 (Windows MAX_PATH); 0 disables the guard.
    #[arg(long = "max-path-len", value_name = "N", default_value_t = mf_scan::report::export::DEFAULT_MAX_PATH_LEN)]
    pub(crate) max_path_len: usize,

    /// Hash the archive (SHA-256) before and after the run and report whether it
    /// changed — a slower, court-defensible integrity attestation.
    #[arg(long = "verify")]
    pub(crate) verify: bool,
}
