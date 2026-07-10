//! Arguments for the `grep` subcommand.
//!
//! Defines: [`GrepArgs`] — the parsed flags for `mf-scan grep`. Filtering,
//! decryption, and the manifest/export sink are the shared groups from
//! [`crate::cmd::cli::common`]; the fields unique to search live here.
//! Used by: `cli` (the `Grep` variant) and `run::grep` (reads the fields).
//! Uses: `clap` (derive), the shared groups in `common`, and
//! `mf_scan::report::output::OutputFormat` (the `--format` value).

use std::path::PathBuf;

use clap::Args;

use crate::cmd::cli::common::{ColourWhen, DecryptArgs, ExportSink, FilterArgs, IoModeArg};
use mf_scan::report::output::OutputFormat;

/// Arguments for `grep`.
#[derive(Args)]
pub(crate) struct GrepArgs {
    /// Regular expression to search for (matched against raw bytes).
    pub(crate) pattern: String,

    /// Source(s) to search (after the PATTERN): archive file(s) and/or directories.
    /// A directory requires `--dir-mode` or `-r` to say how to read it. More than one
    /// source tags each result with its origin.
    #[arg(value_name = "SOURCE", required = true)]
    pub(crate) archives: Vec<PathBuf>,

    /// Walk a directory operand recursively for `*.zip` files, treating each as its own
    /// source. To scan a directory's loose files instead, use `--dir-mode`.
    #[arg(short = 'r', long = "recursive")]
    pub(crate) recursive: bool,

    /// Treat a directory operand as a folder of interest: scan the files inside it
    /// (nested `.zip` opened per `--archive-depth`). Mutually exclusive with `-r`; a
    /// directory given with neither is rejected (no silent default).
    #[arg(long = "dir-mode", conflicts_with = "recursive")]
    pub(crate) dir_mode: bool,

    /// How many levels of nested `*.zip` (found while scanning a `--dir-mode` folder)
    /// to open and descend into. 0 = treat nested archives as opaque files.
    #[arg(long = "archive-depth", value_name = "N", default_value_t = 0)]
    pub(crate) archive_depth: u32,

    /// Case-insensitive matching.
    #[arg(short = 'i', long)]
    pub(crate) ignore_case: bool,

    /// Treat the pattern as a literal string instead of a regex.
    #[arg(short = 'l', long = "literal-string", visible_alias = "fixed-strings")]
    pub(crate) literal_string: bool,

    /// Accepted for grep compatibility; the engine is already ERE-like, so this
    /// has no effect.
    #[arg(short = 'E', long = "extended-regexp")]
    pub(crate) extended_regexp: bool,

    /// Output format.
    #[arg(short = 'f', long, default_value = "txt")]
    pub(crate) format: OutputFormat,

    /// Write results to this file instead of stdout.
    #[arg(short = 'o', long = "output")]
    pub(crate) output: Option<PathBuf>,

    /// Number of search threads (default: one per CPU core).
    #[arg(short = 'j', long = "threads")]
    pub(crate) threads: Option<usize>,

    #[command(flatten)]
    pub(crate) filter: FilterArgs,

    /// Speed preset: exclude media + the path globs in `presets/_fast.yml`.
    /// Bundles the common speed options behind one flag; edit `_fast.yml` to
    /// tune the excluded paths without recompiling.
    #[arg(long = "fast")]
    pub(crate) fast: bool,

    /// Load a preset by name from the `presets/` directory next to the binary
    /// (e.g. `--preset mobile` loads `presets/mobile.yml`), or by path to any
    /// YAML file (e.g. `--preset ./my-preset.yml`). A reference containing a
    /// path separator or a `.yml`/`.yaml` extension is treated as a file path;
    /// anything else is a name. Preset values are applied before CLI flags;
    /// CLI flags always take precedence. Vec fields (path, not_path, file_type)
    /// are merged with CLI values.
    #[arg(long = "preset", value_name = "NAME|PATH")]
    pub(crate) preset: Option<String>,

    /// Match the PATTERN against each file's internal path instead of its
    /// content, listing the files whose path matches (e.g. PATTERN `banking`
    /// finds every file with "banking" in its path). No file content is read.
    #[arg(long = "match-path")]
    pub(crate) match_path: bool,

    /// Inspect matching files of supported formats for richer context.
    #[arg(long = "inspect")]
    pub(crate) inspect: bool,

    /// Also search for the base64 encoding of the pattern, not just its plaintext.
    /// Finds the value however it is stored; each hit is tagged with its encoding.
    /// Requires `-l` (a literal can be encoded; a regex cannot) and cannot be used
    /// with `--match-path`.
    #[arg(long = "base64")]
    pub(crate) base64: bool,

    /// Use the URL-safe base64 alphabet (`-_`) instead of the standard one (`+/`).
    /// Implies `--base64`.
    #[arg(long = "base64-urlsafe")]
    pub(crate) base64_urlsafe: bool,

    #[command(flatten)]
    pub(crate) decrypt: DecryptArgs,

    /// Print only the match count per file (one line per file), not each match.
    /// Counting never exports, so combining it with `--manifest`/`--export` is
    /// rejected rather than silently ignoring the sink.  Counting also forces
    /// `deep = false`, so `--inspect` would be silently ignored — rejected here
    /// instead (no silent flag ignores in this tool).
    #[arg(short = 'c', long = "count", conflicts_with_all = ["manifest", "export", "inspect"])]
    pub(crate) count: bool,

    #[command(flatten)]
    pub(crate) sink: ExportSink,

    /// Hash the archive (SHA-256) before and after the run and report whether it
    /// changed — a slower, court-defensible integrity attestation.
    #[arg(long = "verify")]
    pub(crate) verify: bool,

    /// How to read the archive's bytes: `auto` (default — positioned reads for a
    /// remote SMB/NFS source, memory-map otherwise), `mmap`, or `ranged`. Ranged
    /// reads avoid mapping a multi-GB archive over a network share.
    #[arg(long = "io-mode", value_enum, default_value = "auto")]
    pub(crate) io_mode: IoModeArg,

    /// Write the scan report (run metadata + coverage statistics) to this file.
    /// Defaults to `<output>.report.json` beside `-o`, else `mf-scan-report.json`
    /// in the current directory. The report records what was scanned and what each
    /// filter skipped — important when `--fast`/presets exclude whole subtrees.
    #[arg(long = "report", value_name = "FILE", conflicts_with = "no_report")]
    pub(crate) report: Option<PathBuf>,

    /// Do not write the scan report sidecar file (it is written by default).
    #[arg(long = "no-report")]
    pub(crate) no_report: bool,

    /// Highlight matches (txt to a terminal only): auto, always, or never.
    #[arg(
        long = "colour",
        visible_alias = "color",
        value_enum,
        default_value = "auto",
        default_missing_value = "always",
        num_args = 0..=1,
    )]
    pub(crate) colour: ColourWhen,
}
