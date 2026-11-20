//! Arguments for the `find` subcommand, and acceptance of `find`'s own spellings.
//!
//! Defines: [`FindArgs`] and [`normalise_find_args`], which rewrites `-name` to `--name`
//! and so on, so a `find` command line works as typed.
//! Used by: `cli` (the `Find` variant and argument parsing) and `run::find`.
//! Uses: `clap` (derive), the shared groups in `common`, and
//! `mf_scan::report::output::OutputFormat`.
//!
//! WHY rewrite rather than define `-name`: clap reads `-name` as the short flags `-n -a
//! -m -e`, and the rest of this tool uses `--long` flags. Rewriting lets `--name` and
//! `-name` both work without giving `find` a parser of its own.

use std::ffi::OsString;
use std::path::PathBuf;

use clap::Args;

use crate::cmd::cli::common::{DecryptArgs, ExportSink, IoModeArg};
use mf_scan::report::output::OutputFormat;

/// Arguments for `find`.
#[derive(Args)]
pub(crate) struct FindArgs {
    /// Archive, file or folder to list.
    #[arg(value_name = "SOURCE", required = true)]
    pub(crate) sources: Vec<PathBuf>,

    /// File name matches this wildcard (repeatable: any may match).
    #[arg(long = "name", value_name = "GLOB", help_heading = "Tests")]
    pub(crate) name: Vec<String>,

    /// Like --name, ignoring case.
    #[arg(long = "iname", value_name = "GLOB", help_heading = "Tests")]
    pub(crate) iname: Vec<String>,

    /// Whole path matches this wildcard, where * also crosses /.
    #[arg(long = "path", value_name = "GLOB", help_heading = "Tests")]
    pub(crate) path: Vec<String>,

    /// Like --path, ignoring case.
    #[arg(long = "ipath", value_name = "GLOB", help_heading = "Tests")]
    pub(crate) ipath: Vec<String>,

    /// Only this app: its containers, extensions, groups (repeatable).
    #[arg(long = "app", value_name = "ID", help_heading = "Tests")]
    pub(crate) app: Vec<String>,

    /// Whole path matches this regex.
    #[arg(long = "regex", value_name = "REGEX", help_heading = "Tests")]
    pub(crate) regex: Vec<String>,

    /// Like --regex, ignoring case.
    #[arg(long = "iregex", value_name = "REGEX", help_heading = "Tests")]
    pub(crate) iregex: Vec<String>,

    /// File name does not match this wildcard (or `! -name`).
    #[arg(long = "not-name", value_name = "GLOB", help_heading = "Tests")]
    pub(crate) not_name: Vec<String>,

    /// Whole path does not match this wildcard (or `! -path`).
    #[arg(long = "not-path", value_name = "GLOB", help_heading = "Tests")]
    pub(crate) not_path: Vec<String>,

    /// f, d, or a detected format or category: sqlite, plist, media, ...
    #[arg(long = "type", value_name = "TYPE", help_heading = "Tests")]
    pub(crate) file_type: Vec<String>,

    /// Size: +10M is over, -1k under, 4096 exactly; k, M, G; bytes if bare.
    #[arg(
        long = "size",
        value_name = "SIZE",
        allow_hyphen_values = true,
        help_heading = "Tests"
    )]
    pub(crate) size: Vec<String>,

    /// Modified after this UTC time, e.g. 2026-01-31 or 2026-01-31T12:00.
    #[arg(long = "newer", value_name = "DATE", help_heading = "Tests")]
    pub(crate) newer: Option<String>,

    /// Modified before this UTC time.
    #[arg(long = "older", value_name = "DATE", help_heading = "Tests")]
    pub(crate) older: Option<String>,

    /// Descend at most this many levels; top-level names are level 1.
    #[arg(long = "maxdepth", value_name = "N", help_heading = "Tests")]
    pub(crate) maxdepth: Option<usize>,

    /// Show type, size and modified time (UTC) before each path.
    #[arg(long = "long", help_heading = "Output")]
    pub(crate) long: bool,

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

    /// With a folder, open nested .zip files this many levels deep.
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

    /// Keychain/keystore dump and backup password. A dump beside the source is found
    /// on its own; with `--export`, each database it decrypts is also written
    /// decrypted, beside the original.
    #[command(flatten, next_help_heading = "Decryption")]
    pub(crate) decrypt: DecryptArgs,

    #[command(flatten, next_help_heading = "Export")]
    pub(crate) sink: ExportSink,
}

/// `find`'s single-dash spellings that take a value, and their flags here.
const VALUE_TESTS: &[(&str, &str)] = &[
    ("-name", "--name"),
    ("-iname", "--iname"),
    ("-path", "--path"),
    ("-ipath", "--ipath"),
    ("-regex", "--regex"),
    ("-iregex", "--iregex"),
    ("-type", "--type"),
    ("-size", "--size"),
    ("-newermt", "--newer"),
    ("-maxdepth", "--maxdepth"),
];

/// Rewrite `find`'s spellings when the subcommand is `find`, leaving anything else alone.
pub(crate) fn normalise_find_args(args: Vec<OsString>) -> Vec<OsString> {
    if args.get(1).and_then(|a| a.to_str()) != Some("find") {
        return args;
    }
    let mut out = Vec::with_capacity(args.len());
    let mut iter = args.into_iter().peekable();
    while let Some(arg) = iter.next() {
        let Some(text) = arg.to_str() else {
            out.push(arg);
            continue;
        };
        if let Some((_, flag)) = VALUE_TESTS.iter().find(|(spelling, _)| *spelling == text) {
            out.push(OsString::from(flag));
            // The value is copied as is, whatever it looks like: `-name -name` looks for
            // a file called "-name".
            out.extend(iter.next());
        } else if text == "!" || text == "-not" {
            match iter.peek().and_then(|next| next.to_str()) {
                Some("-name") => out.push(OsString::from("--not-name")),
                Some("-path") => out.push(OsString::from("--not-path")),
                _ => {
                    out.push(arg);
                    continue;
                }
            }
            iter.next();
            out.extend(iter.next());
        } else if text == "-ls" {
            out.push(OsString::from("--long"));
        } else if text != "-print" {
            // `-print` is what this does anyway, so it adds nothing.
            out.push(arg);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn normalise(args: &[&str]) -> Vec<String> {
        normalise_find_args(args.iter().map(OsString::from).collect())
            .into_iter()
            .map(|a| a.into_string().unwrap())
            .collect()
    }

    #[test]
    fn find_spellings_become_flags() {
        assert_eq!(
            normalise(&[
                "mf-scan", "find", "a.zip", "-name", "*.db", "-type", "f", "-ls"
            ]),
            [
                "mf-scan", "find", "a.zip", "--name", "*.db", "--type", "f", "--long"
            ]
        );
        assert_eq!(
            normalise(&["mf-scan", "find", "a.zip", "!", "-name", "*.db", "-print"]),
            ["mf-scan", "find", "a.zip", "--not-name", "*.db"]
        );
        assert_eq!(
            normalise(&[
                "mf-scan",
                "find",
                "a.zip",
                "-newermt",
                "2026-01-01",
                "-size",
                "+1M"
            ]),
            [
                "mf-scan",
                "find",
                "a.zip",
                "--newer",
                "2026-01-01",
                "--size",
                "+1M"
            ]
        );
    }

    #[test]
    fn a_value_is_never_rewritten_and_other_commands_are_untouched() {
        assert_eq!(
            normalise(&["mf-scan", "find", "a.zip", "-name", "-name"]),
            ["mf-scan", "find", "a.zip", "--name", "-name"]
        );
        let grep = ["mf-scan", "grep", "-name", "a.zip"];
        assert_eq!(normalise(&grep), grep);
    }
}
