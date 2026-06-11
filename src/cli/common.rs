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
    /// Colourise only when writing txt to a terminal.
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
    /// Only handle files whose internal path matches this wildcard (`*`, `?`).
    /// Repeatable; a file matching any pattern is kept.
    #[arg(long = "path", value_name = "GLOB")]
    pub(crate) path: Vec<String>,

    /// Skip files whose internal path matches this wildcard. Repeatable; takes
    /// precedence over --path.
    #[arg(long = "not-path", value_name = "GLOB")]
    pub(crate) not_path: Vec<String>,

    /// Only handle files of this type — a format name (e.g. `sqlite`, `jpeg`) or a
    /// category (e.g. `media`, `database`, `structured`, `text`). The type is
    /// detected by content header first, then file extension. Repeatable; a file
    /// matching any value is kept.
    #[arg(short = 't', long = "type", value_name = "TYPE")]
    pub(crate) file_type: Vec<String>,

    /// Skip image/video/audio files. They are handled by default; this excludes
    /// them for speed (they hold no searchable text and dominate acquisition size).
    #[arg(long = "exclude-media")]
    pub(crate) exclude_media: bool,
}

/// Decryption inputs shared by `grep` and `diff` (`diff` adds per-side overrides).
#[derive(Args, Clone)]
pub(crate) struct DecryptArgs {
    /// Keychain/keystore dump file to decrypt databases with (repeatable). Accepts
    /// iOS keychain *and* Android keystore dumps. When given, each database an
    /// internal profile recognises is decrypted with a key from the dump before
    /// being handled. Provenance (which key decrypted which database, and the
    /// ciphertext/plaintext SHA-256) is written to the report.
    #[arg(long = "keyfile", value_name = "FILE")]
    pub(crate) keyfile: Vec<PathBuf>,

    /// Limit decryption profiles to one platform (`ios` or `android`).
    #[arg(long = "platform", value_name = "PLATFORM")]
    pub(crate) platform: Option<PlatformArg>,

    /// Disable database decryption entirely: skip both `--keyfile` and the automatic
    /// search for a keyfile dump beside the source. By default, when a keyfile dump is
    /// found next to the source (or given via `--keyfile`), profile-matched databases
    /// are decrypted before being handled.
    #[arg(long = "no-decrypt")]
    pub(crate) no_decrypt: bool,
}

/// Manifest/export sink shared by `grep` and `diff`: persist the selected files.
#[derive(Args, Clone)]
pub(crate) struct ExportSink {
    /// Write a re-ingestable manifest of the selected files (with total size) here.
    #[arg(long = "manifest", value_name = "FILE")]
    pub(crate) manifest: Option<PathBuf>,

    /// Also export the selected files into this directory (one-step).
    #[arg(long = "export", value_name = "DIR")]
    pub(crate) export: Option<PathBuf>,

    /// Refuse exporting if the selected files exceed this size (e.g. 200MB, 1G).
    /// Defaults to 1G as an accident guard; raise it to export more.
    #[arg(long = "max-size", value_name = "SIZE", value_parser = parse_size, default_value = "1G")]
    pub(crate) max_size: u64,
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
