//! Command-line interface: the top-level `Cli`/`Command` and the per-subcommand
//! argument modules.
//!
//! Defines: [`Cli`] and the [`Command`] subcommand enum; re-exports each
//! subcommand's argument struct ([`GrepArgs`], [`ExportArgs`], [`DiffArgs`]) and the
//! shared types/groups the orchestration layer reads ([`ColourWhen`], [`DecryptArgs`],
//! [`ExportSink`]).
//! Used by: `main` (parses `Cli`, dispatches `Command`) and `run` (reads the args).
//! Uses: `clap` (derive) and the submodules below. Shared value types and the
//! flatten argument groups live in `common`; no search/IO logic lives here.

mod common;
mod diff;
mod export;
mod grep;

pub(crate) use common::{ColourWhen, DecryptArgs, ExportSink};
pub(crate) use diff::DiffArgs;
pub(crate) use export::ExportArgs;
pub(crate) use grep::GrepArgs;

use clap::{Parser, Subcommand};

/// Fast, forensic-aware search, export, and diff over mobile-acquisition archives
/// and folders.
#[derive(Parser)]
#[command(name = "mf-scan", version, about)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,
}

// The variants differ in size (Grep/Diff carry far more flags than Export), but this
// enum is parsed once at startup and dispatched immediately, so the size gap is
// irrelevant — boxing the args would only add indirection (and clap's derive is
// awkward with boxed variants).
#[allow(clippy::large_enum_variant)]
#[derive(Subcommand)]
pub(crate) enum Command {
    /// Search for a regex inside the files of an archive or folder.
    Grep(GrepArgs),
    /// Export files listed in a manifest out of an archive (no search).
    Export(ExportArgs),
    /// Diff two sources (archives or folders): which files were added/removed/modified.
    Diff(DiffArgs),
}
