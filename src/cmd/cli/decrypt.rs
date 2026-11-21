//! Arguments for the `decrypt` subcommand: decrypt an acquisition's app databases.
//!
//! Defines: [`DecryptCmdArgs`] — the source, the optional output archive, and the
//! shared key flags.
//! Used by: `cli` (the `Decrypt` variant) and `run::decrypt` (reads the fields).
//! Uses: `clap` (derive) and the shared `KeySources`/`IoModeArg` from `common`.
//!
//! WHY `--to` is a file and there is no folder output: the archive keeps every device
//! path whole, which a folder tree on Windows cannot (see `report::rebuild_zip`), and
//! `grep`/`find`/`app export --export` already write decrypted copies to a folder.

use std::path::PathBuf;

use clap::Args;

use crate::cmd::cli::common::{IoModeArg, KeySources};

/// Arguments for `decrypt`.
#[derive(Args)]
pub(crate) struct DecryptCmdArgs {
    /// An archive, a backup, or a folder with --dir-mode.
    #[arg(value_name = "SOURCE")]
    pub(crate) source: PathBuf,

    /// Write the source plus decrypted copies to this .zip.
    #[arg(long = "to", value_name = "FILE")]
    pub(crate) to: Option<PathBuf>,

    /// Replace an archive already at --to.
    #[arg(long = "force")]
    pub(crate) force: bool,

    /// Read a folder source's files.
    #[arg(long = "dir-mode")]
    pub(crate) dir_mode: bool,

    /// How to read an archive: auto, mmap or ranged (network shares).
    #[arg(
        long = "io-mode",
        value_enum,
        default_value = "auto",
        hide_default_value = true,
        hide_possible_values = true,
        value_name = "MODE"
    )]
    pub(crate) io_mode: IoModeArg,

    /// Password for an encrypted backup (or set MFSCAN_BACKUP_PASSWORD).
    #[arg(long = "backup-password", value_name = "PASSWORD")]
    pub(crate) backup_password: Option<String>,

    /// Password of an encrypted 7z (or MFSCAN_ARCHIVE_PASSWORD).
    #[arg(long = "archive-password", value_name = "PASS")]
    pub(crate) archive_password: Option<String>,

    #[command(flatten, next_help_heading = "Decryption")]
    pub(crate) keys: KeySources,
}
