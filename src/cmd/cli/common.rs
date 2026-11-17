//! Shared CLI value types, the human size parser, and the reusable clap argument
//! groups that are flattened into more than one subcommand.
//!
//! Defines: the value enums [`ColourWhen`], [`PlatformArg`], [`DirMode`]; the human
//! size parser [`parse_size`]; and the flatten groups [`FilterArgs`] (path/type
//! filtering), [`DecryptArgs`] (keyfile/platform/no-decrypt) and [`ExportSink`]
//! (manifest/export/max-size) shared by `grep` and `diff`.
//! Used by: `cli::grep` and `cli::diff` (flatten the groups) and `run`/`support`
//! (read the parsed fields).
//! Uses: `clap` (derive) and `mf_scan::decrypt::Platform` (the `--platform` mapping).

use std::path::PathBuf;

use clap::{Args, ValueEnum};

/// When to colourise matched text in the output.
#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum ColourWhen {
    // Colourise only when writing txt to a terminal.
    Auto,
    Always,
    Never,
}

/// Platform scope for decryption profiles (`--platform`).
#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum PlatformArg {
    Ios,
    Android,
}

/// How to read an archive's bytes (`--io-mode`).
///
/// `auto` (the default) memory-maps a local archive but switches to positioned
/// reads when the source is on a network mount (SMB/NFS), where mmap-ing a huge
/// file would fault page-by-page over the network. `mmap`/`ranged` force one mode.
#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum IoModeArg {
    // Positioned reads for a remote (SMB/NFS) source, mmap otherwise.
    Auto,
    // Always memory-map the archive (fast for local files).
    Mmap,
    // Always read with positioned reads (no whole-file map), for network shares.
    Ranged,
}

impl IoModeArg {
    /// Map to the library/support I/O mode.
    pub(crate) fn to_io_mode(self) -> crate::cmd::support::sources::IoMode {
        match self {
            IoModeArg::Auto => crate::cmd::support::sources::IoMode::Auto,
            IoModeArg::Mmap => crate::cmd::support::sources::IoMode::Mmap,
            IoModeArg::Ranged => crate::cmd::support::sources::IoMode::Ranged,
        }
    }
}

impl PlatformArg {
    /// Map to the library's platform type.
    pub(crate) fn to_platform(self) -> mf_scan::decrypt::Platform {
        match self {
            PlatformArg::Ios => mf_scan::decrypt::Platform::Ios,
            PlatformArg::Android => mf_scan::decrypt::Platform::Android,
        }
    }
}

/// Path and type filtering — which files a command handles. Shared by `grep`/`diff`.
#[derive(Args, Clone)]
pub(crate) struct FilterArgs {
    /// Only paths matching this wildcard, e.g. '*.sqlite' (repeatable).
    #[arg(long = "path", value_name = "GLOB")]
    pub(crate) path: Vec<String>,

    /// Skip paths matching this wildcard (repeatable; beats --path).
    #[arg(long = "not-path", value_name = "GLOB")]
    pub(crate) not_path: Vec<String>,

    /// Only this type: sqlite, jpeg, database, media, ... (repeatable).
    #[arg(short = 't', long = "type", value_name = "TYPE")]
    pub(crate) file_type: Vec<String>,

    /// Skip image, video and audio files, for speed.
    #[arg(long = "exclude-media")]
    pub(crate) exclude_media: bool,
}

/// Where database keys come from: the key dump(s) and the platform scope.
///
/// Used alone by `decrypt`, for which turning decryption off means nothing, and
/// inside [`KeyArgs`] by every command that decrypts on the way.
#[derive(Args, Clone)]
pub(crate) struct KeySources {
    /// Keychain or keystore dump, to decrypt app databases (repeatable).
    #[arg(long = "keyfile", value_name = "FILE")]
    pub(crate) keyfile: Vec<PathBuf>,

    /// Use only one platform's decryption profiles: ios or android.
    #[arg(
        long = "platform",
        value_name = "PLATFORM",
        hide_possible_values = true
    )]
    pub(crate) platform: Option<PlatformArg>,
}

/// [`KeySources`] plus `--no-decrypt`, for commands where decryption is a side step.
///
/// Its own group so a command that decrypts databases but opens no backup
/// (`app export` takes the backup password with its source) can reuse it.
#[derive(Args, Clone)]
pub(crate) struct KeyArgs {
    #[command(flatten)]
    pub(crate) sources: KeySources,

    /// Turn off decryption, even with a dump beside the source.
    #[arg(long = "no-decrypt")]
    pub(crate) no_decrypt: bool,
}

/// Decryption inputs shared by `grep`, `find` and `diff` (`diff` adds per-side
/// overrides): the database keys, and the password of an encrypted backup.
#[derive(Args, Clone)]
pub(crate) struct DecryptArgs {
    #[command(flatten)]
    pub(crate) keys: KeyArgs,

    /// Password for an encrypted backup (or set MFSCAN_BACKUP_PASSWORD).
    #[arg(long = "backup-password", value_name = "PASSWORD")]
    pub(crate) backup_password: Option<String>,
}

/// Manifest/export sink shared by `grep` and `diff`: persist the selected files.
#[derive(Args, Clone)]
pub(crate) struct ExportSink {
    /// List the selected files in a manifest, to review first.
    #[arg(long = "manifest", value_name = "FILE")]
    pub(crate) manifest: Option<PathBuf>,

    /// Copy the selected files here, with integrity hashes.
    #[arg(long = "export", value_name = "DIR")]
    pub(crate) export: Option<PathBuf>,

    /// Refuse to export more than this (default 1G), e.g. 5G.
    #[arg(long = "max-size", value_name = "SIZE", value_parser = parse_size, default_value = "1G", hide_default_value = true)]
    pub(crate) max_size: u64,

    /// Skip and record longer paths (default 260, Windows); 0 is off.
    #[arg(long = "max-path-len", value_name = "N", default_value_t = mf_scan::report::export::DEFAULT_MAX_PATH_LEN, hide_default_value = true)]
    pub(crate) max_path_len: usize,

    /// Also write DIR.work/: a writable copy of the read-only export.
    #[arg(long = "work-copy")]
    pub(crate) work_copy: bool,
}

/// Parse a human size like `1024`, `200KB`, `50M`, `2G` into bytes (1024-based).
pub(crate) fn parse_size(s: &str) -> Result<u64, String> {
    let lower = s.trim().to_ascii_lowercase();
    let (digits, multiplier) = if let Some(n) = strip_unit(&lower, "gb").or(strip_unit(&lower, "g"))
    {
        (n, 1u64 << 30)
    } else if let Some(n) = strip_unit(&lower, "mb").or(strip_unit(&lower, "m")) {
        (n, 1u64 << 20)
    } else if let Some(n) = strip_unit(&lower, "kb").or(strip_unit(&lower, "k")) {
        (n, 1u64 << 10)
    } else {
        (lower.as_str(), 1)
    };
    let value: u64 = digits
        .trim()
        .parse()
        .map_err(|_| format!("invalid size '{s}' (expected e.g. 200MB, 1G, or a byte count)"))?;
    value
        .checked_mul(multiplier)
        .ok_or_else(|| format!("size '{s}' overflows"))
}

/// Strip a unit suffix, returning the numeric part if present.
fn strip_unit<'a>(s: &'a str, unit: &str) -> Option<&'a str> {
    s.strip_suffix(unit)
}

#[cfg(test)]
mod tests {
    use super::parse_size;

    #[test]
    fn parse_size_handles_units() {
        assert_eq!(parse_size("1024").unwrap(), 1024);
        assert_eq!(parse_size("1k").unwrap(), 1024);
        assert_eq!(parse_size("2MB").unwrap(), 2 * 1024 * 1024);
        assert_eq!(parse_size("1G").unwrap(), 1024 * 1024 * 1024);
        assert!(parse_size("nope").is_err());
    }
}
