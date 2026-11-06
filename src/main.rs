//! mf-scan — fast, forensic-aware regex search inside mobile acquisitions.
//!
//! Defines: the binary entry point. CLI definitions live in `cmd::cli`, and the
//! orchestration that ties the parser, the search engine, the inspectors, and
//! the output/export writers together lives in `cmd::run`; `main` only parses the
//! arguments, dispatches to the chosen subcommand, and maps the result to an exit
//! status.
//! Used by: invoked from the shell (`mf-scan grep PATTERN SOURCE`).
//! Uses: `cmd::cli` (clap structs), `cmd::run` (one orchestrator per subcommand),
//! plus the `mf_scan` library crate.
//!
//! Why mmap: phone acquisitions are large, and STORED entries (the common case)
//! are uncompressed on disk, so memory-mapping lets the SIMD regex engine run
//! straight over those bytes with no copy and no decompression — the core speed
//! win over `zipgrep`. DEFLATE entries are decompressed on demand.
//!
//! Every match reports the file path plus three offsets (file start, position
//! within the file, absolute position in the archive) — locating evidence is
//! the goal, so the "where" is always present, never gated behind a flag.

mod cmd;

use std::process::ExitCode;

use anyhow::Result;

use cmd::cli::Command;
use cmd::run::EXIT_ERROR;

fn main() -> ExitCode {
    match dispatch(cmd::cli::parse().command) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("Error: {err:?}");
            ExitCode::from(EXIT_ERROR)
        }
    }
}

/// Run the chosen subcommand. `grep`, `find` and `decrypt` choose their own exit status; the others
/// succeed or fail.
fn dispatch(command: Command) -> Result<ExitCode> {
    let succeeded = |result: Result<()>| result.map(|()| ExitCode::SUCCESS);
    match command {
        Command::Grep(args) => cmd::run::run_grep(args).map(ExitCode::from),
        Command::Find(args) => cmd::run::run_find(args),
        Command::Export(args) => succeeded(cmd::run::run_export(args)),
        Command::Diff(args) => succeeded(cmd::run::run_diff(args)),
        Command::App(args) => succeeded(cmd::run::run_app(args)),
        Command::Backup(args) => succeeded(cmd::run::run_backup(args)),
        Command::Decrypt(args) => cmd::run::run_decrypt(args),
    }
}
