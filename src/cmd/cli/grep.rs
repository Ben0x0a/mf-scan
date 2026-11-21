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

use clap::{Args, ValueEnum};

use crate::cmd::cli::common::{ColourWhen, DecryptArgs, ExportSink, FilterArgs, IoModeArg};
use mf_scan::report::output::OutputFormat;

/// An encoding `--encoding` adds to the plain (UTF-8) search.
#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum EncodingArg {
    /// UTF-16, little-endian.
    Utf16le,
    /// UTF-16, big-endian (binary plists, NSString archives).
    Utf16be,
    /// UTF-16, both byte orders.
    Utf16,
    /// Base64, standard alphabet.
    Base64,
    /// Base64, URL-safe alphabet.
    Base64url,
    /// The other Unicode normal form: `é` as one character or as `e` + an accent.
    Nfd,
    /// Java's modified UTF-8: an emoji as two 3-byte surrogates.
    Cesu8,
    /// JSON escapes: `\u00e9`, `\ud83d\ude02`.
    Json,
    /// Percent-encoding, as in URLs: `%C3%A9`.
    Url,
    /// Every encoding above.
    All,
}

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
    #[arg(
        long = "match-path",
        help_heading = "Matching",
        conflicts_with = "and_paths"
    )]
    pub(crate) match_path: bool,

    /// Match contents and file paths too, in one pass (grep + find).
    #[arg(long = "and-paths", help_heading = "Matching")]
    pub(crate) and_paths: bool,

    /// Also as utf16[le|be], json, url, cesu8, nfd, base64[url] or all (-F).
    #[arg(
        long = "encoding",
        value_enum,
        value_name = "ENC",
        hide_possible_values = true,
        help_heading = "Matching"
    )]
    pub(crate) encodings: Vec<EncodingArg>,

    /// Find it in every encoding at once: UTF-8, UTF-16, JSON, URL, … (-F).
    #[arg(long = "all-encodings", help_heading = "Matching")]
    pub(crate) all_encodings: bool,

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

    /// With -l or -c: also show each file's type, size and modified time (UTC).
    #[arg(long = "long", help_heading = "Output")]
    pub(crate) long: bool,

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

    /// Open archives and compressed files found inside, this many levels deep.
    #[arg(
        long = "archive-depth",
        value_name = "N",
        default_value_t = 0,
        hide_default_value = true,
        help_heading = "Sources"
    )]
    pub(crate) archive_depth: u32,

    /// With --archive-depth: the most opening them may add to memory or disk.
    #[arg(
        long = "nested-limit",
        value_name = "SIZE",
        value_parser = crate::cmd::cli::common::parse_size,
        default_value = "16G",
        hide_default_value = true,
        help_heading = "Sources"
    )]
    pub(crate) nested_limit: u64,

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
