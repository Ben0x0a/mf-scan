//! Command-line interface: the top-level `Cli`/`Command` and the per-subcommand
//! argument modules.
//!
//! Defines: [`Cli`], the [`Command`] subcommand enum, and [`parse`]; re-exports each
//! subcommand's argument struct ([`GrepArgs`], [`ExportArgs`], [`DiffArgs`], ...) and the
//! shared types/groups the orchestration layer reads ([`ColourWhen`], [`KeyArgs`],
//! [`ExportSink`]).
//! Used by: `main` (parses `Cli`, dispatches `Command`) and `run` (reads the args).
//! Uses: `clap` (derive) and the submodules below. Shared value types and the
//! flatten argument groups live in `common`; no search/IO logic lives here.

mod app;
mod backup;
mod common;
pub(crate) mod decrypt;
mod diff;
mod examples;
mod export;
mod find;
mod grep;

pub(crate) use app::{
    AppArgs, AppCommand, AppExportArgs, AppGrepArgs, AppPathsArgs, AppSourceArgs,
};
pub(crate) use backup::{
    BackupArgs, BackupCommand, BackupInfoArgs, BackupRebuildArgs, BackupSourceArgs,
};
pub(crate) use common::{ColourWhen, ExportSink, KeyArgs, KeySources};
pub(crate) use decrypt::DecryptCmdArgs;
pub(crate) use diff::DiffArgs;
pub(crate) use export::ExportArgs;
pub(crate) use find::FindArgs;
pub(crate) use grep::GrepArgs;

use clap::{Parser, Subcommand};

/// Fast, forensic-aware search, export, and diff over mobile-acquisition archives
/// and folders.
#[derive(Parser)]
#[command(name = "mf-scan", version, about, after_help = examples::TOP)]
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
    /// Search inside the files of an archive, folder or backup.
    #[command(
        after_help = examples::GREP,
        override_usage = "mf-scan grep [OPTIONS] PATTERN [SOURCE]...\n       mf-scan grep [OPTIONS] -e PATTERN... [SOURCE]..."
    )]
    Grep(GrepArgs),
    /// List files by name, size, date and type, as the find command does.
    #[command(after_help = examples::FIND)]
    Find(FindArgs),
    /// Export files listed in a manifest out of an archive (no search).
    #[command(after_help = examples::EXPORT)]
    Export(ExportArgs),
    /// Compare two sources: which files were added, removed or modified.
    #[command(after_help = examples::DIFF)]
    Diff(DiffArgs),
    /// Locate and export an application's data (iOS FFS / iOS backup / Android).
    #[command(after_help = examples::APP)]
    App(AppArgs),
    /// Inspect a mobile backup, or rebuild it into one .zip (iOS and Android).
    #[command(after_help = examples::BACKUP)]
    Backup(BackupArgs),
    /// Decrypt app databases; with --to, write the source plus decrypted copies.
    #[command(after_help = examples::DECRYPT)]
    Decrypt(DecryptCmdArgs),
}

/// Parse the process's arguments, accepting `find`'s own spellings for `mf-scan find`.
pub(crate) fn parse() -> Cli {
    Cli::parse_from(find::normalise_find_args(std::env::args_os().collect()))
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::Cli;

    /// `--count` never exports, so the sink flags must be rejected up front
    /// instead of silently writing nothing (review finding L1).
    #[test]
    fn count_conflicts_with_the_export_sink() {
        assert!(
            Cli::try_parse_from(["mf-scan", "grep", "x", "a.zip", "-c", "--export", "out"])
                .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "mf-scan",
                "grep",
                "x",
                "a.zip",
                "-c",
                "--manifest",
                "m.json"
            ])
            .is_err()
        );
        assert!(Cli::try_parse_from(["mf-scan", "grep", "x", "a.zip", "-c"]).is_ok());
    }

    /// Every help screen stays short enough to take in. That `--help` adds nothing to
    /// `-h` is checked through the binary, in `tests/cli.rs`.
    #[test]
    fn help_is_one_short_screen_for_every_command() {
        use clap::CommandFactory;

        fn check(command: &mut clap::Command, path: &str) {
            let short = command.render_help().to_string();
            assert!(
                short.lines().count() <= 80,
                "{path}: {} lines",
                short.lines().count()
            );
            let longest = short.lines().map(|l| l.chars().count()).max().unwrap_or(0);
            assert!(longest <= 100, "{path}: a {longest}-character line");
            let names: Vec<String> = command
                .get_subcommands()
                .map(|c| c.get_name().to_string())
                .filter(|n| n != "help")
                .collect();
            for name in names {
                let sub = command.find_subcommand_mut(&name).expect("listed above");
                check(sub, &format!("{path} {name}"));
            }
        }

        let mut command = Cli::command();
        command.build();
        check(&mut command, "mf-scan");
    }

    /// `-l`, `-o` and `-F` follow grep, and `-o` takes no value: `-o hello a.zip` must
    /// read `hello` as the pattern, never as a file to create.
    #[test]
    fn short_flags_follow_grep() {
        let cli = Cli::try_parse_from(["mf-scan", "grep", "-l", "-o", "-F", "x", "a.zip"]);
        assert!(cli.is_err(), "-l and -o are mutually exclusive");

        let cli = Cli::try_parse_from(["mf-scan", "grep", "-o", "-F", "hello", "a.zip"]).unwrap();
        let crate::cmd::cli::Command::Grep(args) = cli.command else {
            panic!("expected grep");
        };
        assert!(args.only_matching && args.literal_string);
        assert_eq!(args.pattern.as_deref(), Some("hello"));
        assert_eq!(args.archives, [std::path::PathBuf::from("a.zip")]);
        assert!(args.output.is_none());
    }

    /// `--count` forces `deep = false`, so `--inspect` would be silently ignored —
    /// reject the combination up front rather than accepting a flag that does nothing.
    #[test]
    fn count_conflicts_with_inspect() {
        assert!(
            Cli::try_parse_from(["mf-scan", "grep", "x", "a.zip", "-c", "--inspect"]).is_err(),
            "-c --inspect must be rejected"
        );
        // -c alone is still valid (regression guard).
        assert!(
            Cli::try_parse_from(["mf-scan", "grep", "x", "a.zip", "-c"]).is_ok(),
            "-c alone must parse successfully"
        );
        // --inspect alone is still valid (regression guard).
        assert!(
            Cli::try_parse_from(["mf-scan", "grep", "x", "a.zip", "--inspect"]).is_ok(),
            "--inspect alone must parse successfully"
        );
    }
}
