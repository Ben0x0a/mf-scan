//! Arguments for the `grep` subcommand.
//!
//! Defines: [`GrepArgs`] — the parsed flags for `mf-scan grep`. Filtering, decryption,
//! and the manifest/export sink are the shared groups from [`crate::cmd::cli::common`];
//! the fields unique to search live here.
//! Used by: `cli` (the `Grep` variant) and `run::grep` (reads the fields).
//! Uses: `clap` (derive), the shared groups in `common`, and
//! `mf_scan::report::output::OutputFormat` (the `--format` value).
//!
//! Help layout: every flag has one line, and `--help` is the same screen as `-h`, so a
//! doc comment here must stay a single short sentence. Detail belongs in the README.

use std::path::PathBuf;

use clap::Args;

use crate::cmd::cli::common::{ColourWhen, DecryptArgs, ExportSink, FilterArgs, IoModeArg};
use mf_scan::report::output::OutputFormat;

/// Arguments for `grep`.
#[derive(Args)]
pub(crate) struct GrepArgs {
    /// Regex to search for (omit when using -e).
    #[arg(required_unless_present = "regexps")]
    pub(crate) pattern: Option<String>,

    /// Archive, file or folder to search; without one, reads standard input.
    #[arg(value_name = "SOURCE")]
    pub(crate) archives: Vec<PathBuf>,

    /// Search for this pattern too (repeatable).
    #[arg(
        short = 'e',
        long = "regexp",
        value_name = "PATTERN",
        help_heading = "Matching"
    )]
    pub(crate) regexps: Vec<String>,

    /// Ignore case.
    #[arg(short = 'i', long, help_heading = "Matching")]
    pub(crate) ignore_case: bool,

    /// Treat patterns as plain text, not regexes.
    #[arg(
        short = 'F',
        long = "fixed-strings",
        alias = "literal-string",
        help_heading = "Matching"
    )]
    pub(crate) literal_string: bool,

    /// Match whole words only.
    #[arg(short = 'w', long = "word-regexp", help_heading = "Matching")]
    pub(crate) word_regexp: bool,

    /// Accepted for grep compatibility; the syntax is always extended.
    #[arg(short = 'E', long = "extended-regexp", help_heading = "Matching")]
    pub(crate) extended_regexp: bool,

    /// Match file paths, not contents (see also `mf-scan find`).
    #[arg(long = "match-path", help_heading = "Matching")]
    pub(crate) match_path: bool,

    /// Also find the pattern's base64 encoding (requires -F).
    #[arg(long = "base64", help_heading = "Matching")]
    pub(crate) base64: bool,

    /// Like --base64, with the URL-safe alphabet.
    #[arg(long = "base64-urlsafe", help_heading = "Matching")]
    pub(crate) base64_urlsafe: bool,

    /// List only the files with a match.
    #[arg(
        short = 'l',
        long = "files-with-matches",
        conflicts_with_all = ["count", "only_matching", "inspect", "line_number"],
        help_heading = "Output"
    )]
    pub(crate) files_with_matches: bool,

    /// Show only the matched text, not the whole line.
    #[arg(short = 'o', long = "only-matching", help_heading = "Output")]
    pub(crate) only_matching: bool,

    /// Show each match's line number, before its offset.
    #[arg(short = 'n', long = "line-number", help_heading = "Output")]
    pub(crate) line_number: bool,

    /// Print the number of matches per file.
    #[arg(
        short = 'c',
        long = "count",
        conflicts_with_all = ["manifest", "export", "inspect", "only_matching", "line_number"],
        help_heading = "Output"
    )]
    pub(crate) count: bool,

    /// Print nothing; the exit status is the answer.
    #[arg(
        short = 'q',
        long = "quiet",
        alias = "silent",
        conflicts_with_all = [
            "output", "count", "files_with_matches", "only_matching", "line_number", "inspect",
            "manifest", "export",
        ],
        help_heading = "Output"
    )]
    pub(crate) quiet: bool,

    /// Say where each match sits in its file: SQLite row, JSON key, ...
    #[arg(long = "inspect", help_heading = "Output")]
    pub(crate) inspect: bool,

    /// Output format: txt, json or csv.
    #[arg(
        short = 'f',
        long,
        default_value = "txt",
        hide_default_value = true,
        help_heading = "Output"
    )]
    pub(crate) format: OutputFormat,

    /// Write results to this file instead of stdout.
    #[arg(long = "output", value_name = "FILE", help_heading = "Output")]
    pub(crate) output: Option<PathBuf>,

    /// Highlight matches: auto, always or never.
    #[arg(
        long = "colour",
        visible_alias = "color",
        value_enum,
        default_value = "auto",
        default_missing_value = "always",
        num_args = 0..=1,
        hide_default_value = true,
        hide_possible_values = true,
        value_name = "WHEN",
        help_heading = "Output"
    )]
    pub(crate) colour: ColourWhen,

    /// Search every archive under a folder (loose files are skipped).
    #[arg(short = 'r', long = "recursive", help_heading = "Sources")]
    pub(crate) recursive: bool,

    /// Search the files inside a folder.
    #[arg(
        long = "dir-mode",
        conflicts_with = "recursive",
        help_heading = "Sources"
    )]
    pub(crate) dir_mode: bool,

    /// With --dir-mode, open nested .zip files this many levels deep.
    #[arg(
        long = "archive-depth",
        value_name = "N",
        default_value_t = 0,
        hide_default_value = true,
        help_heading = "Sources"
    )]
    pub(crate) archive_depth: u32,

    /// How to read an archive: auto, mmap or ranged (network shares).
    #[arg(
        long = "io-mode",
        value_enum,
        default_value = "auto",
        hide_default_value = true,
        hide_possible_values = true,
        value_name = "MODE",
        help_heading = "Sources"
    )]
    pub(crate) io_mode: IoModeArg,

    /// Search threads (default: one per CPU core).
    #[arg(
        short = 'j',
        long = "threads",
        value_name = "N",
        help_heading = "Sources"
    )]
    pub(crate) threads: Option<usize>,

    #[command(flatten, next_help_heading = "Filters")]
    pub(crate) filter: FilterArgs,

    /// Skip media and the bulk paths in presets/_fast.yml.
    #[arg(long = "fast", help_heading = "Filters")]
    pub(crate) fast: bool,

    /// Load options from a preset name or YAML file.
    #[arg(long = "preset", value_name = "NAME|PATH", help_heading = "Filters")]
    pub(crate) preset: Option<String>,

    #[command(flatten, next_help_heading = "Decryption")]
    pub(crate) decrypt: DecryptArgs,

    #[command(flatten, next_help_heading = "Export")]
    pub(crate) sink: ExportSink,

    /// Hash the archive before and after, to attest it did not change.
    #[arg(long = "verify", help_heading = "Records")]
    pub(crate) verify: bool,

    /// Write the scan report here, replacing any file already there.
    #[arg(
        long = "report",
        value_name = "FILE",
        conflicts_with = "no_report",
        help_heading = "Records"
    )]
    pub(crate) report: Option<PathBuf>,

    /// Do not write a scan report (default: a new timestamped file per run).
    #[arg(long = "no-report", help_heading = "Records")]
    pub(crate) no_report: bool,

    /// Do not print the coverage summary.
    #[arg(long = "no-stats", help_heading = "Records")]
    pub(crate) no_stats: bool,
}
