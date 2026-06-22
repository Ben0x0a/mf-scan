//! mf-scan — fast, forensic-aware regex search inside ZIP acquisitions.
//!
//! Defines: the binary entry point. CLI definitions live in `cli`, and the
//! orchestration that ties the parser, the search engine, the inspectors, and
//! the output/export writers together lives in `run`; `main` only parses the
//! arguments and dispatches to the chosen subcommand.
//! Used by: invoked from the shell (`mf-scan search PATTERN ARCHIVE`).
//! Uses: `cli` (clap structs), `run` (the two `search`/`export` operations) and
//! `helpers` (the support machinery those operations lean on), plus the
//! `mf_scan` library crate.
//!
//! Why mmap: phone acquisitions are large, and STORED entries (the common case)
//! are uncompressed on disk, so memory-mapping lets the SIMD regex engine run
//! straight over those bytes with no copy and no decompression — the core speed
//! win over `zipgrep`. DEFLATE entries are decompressed on demand.
//!
//! Every match reports the file path plus three offsets (file start, position
//! within the file, absolute position in the archive) — locating evidence is
//! the goal, so the "where" is always present, never gated behind a flag.

mod cli;
mod run;
mod support;

use anyhow::Result;
use clap::Parser;

use cli::{Cli, Command};

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Grep(args) => run::run_grep(args),
        Command::Export(args) => run::run_export(args),
        Command::Diff(args) => run::run_diff(args),
        Command::App(args) => run::run_app(args),
    }
}
