//! Behaviour-preset loading and application for the `grep` subcommand.
//!
//! Defines: the preset resolver/loader and [`apply_preset`], which merges a
//! preset's values into the parsed CLI arguments.
//! Used by: `run::grep` (applies a named preset and `--fast`).
//! Uses: `mf_scan::preset` (the deserialised preset) and `crate::cmd::cli`.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use mf_scan::preset::Preset;

use crate::cmd::cli::GrepArgs;

/// Resolve the `presets/` directory sitting next to the running binary.
fn find_presets_dir() -> Result<PathBuf> {
    crate::cmd::support::dir_beside_binary("presets")
}

/// Resolve a `--preset` reference into a YAML file path.
///
/// A reference that looks like a path — it contains a path separator or carries
/// a `.yml`/`.yaml` extension — is taken verbatim (relative to the current
/// directory or absolute). A bare reference like `mobile` is resolved as a named
/// preset: `presets/mobile.yml` beside the binary. This lets callers either name
/// a shipped preset or point at a one-off file anywhere on disk.
fn resolve_preset_path(reference: &str) -> Result<PathBuf> {
    if looks_like_path(reference) {
        Ok(PathBuf::from(reference))
    } else {
        Ok(find_presets_dir()?.join(format!("{reference}.yml")))
    }
}

/// Whether a `--preset` reference should be treated as a filesystem path rather
/// than a name to look up in the `presets/` directory.
fn looks_like_path(reference: &str) -> bool {
    reference.contains('/')
        || reference.contains(std::path::MAIN_SEPARATOR)
        || Path::new(reference)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("yml") || ext.eq_ignore_ascii_case("yaml"))
}

/// Load a preset from `reference`, which may be either a named preset in the
/// `presets/` directory or a path to a YAML file (see [`resolve_preset_path`]).
pub(crate) fn load_preset(reference: &str) -> Result<Preset> {
    let path = resolve_preset_path(reference)?;
    let content = std::fs::read_to_string(&path)
        .with_context(|| format!("cannot read preset file {}", path.display()))?;
    Preset::from_yaml(&content)
        .with_context(|| format!("invalid YAML in preset {}", path.display()))
}

/// Merge `preset` values into `cli`.
///
/// Merge rules:
/// - Booleans: OR — preset can enable a flag; CLI `true` is never overridden.
/// - `Vec` fields: preset values are appended to CLI values (both active).
/// - `Option<usize>` (threads): CLI value wins when `Some`; preset fills in otherwise.
pub(crate) fn apply_preset(cli: &mut GrepArgs, preset: &Preset) {
    cli.filter.exclude_media = cli.filter.exclude_media || preset.exclude_media.unwrap_or(false);
    cli.ignore_case = cli.ignore_case || preset.ignore_case.unwrap_or(false);
    cli.literal_string = cli.literal_string || preset.literal_string.unwrap_or(false);
    cli.recursive = cli.recursive || preset.recursive.unwrap_or(false);
    cli.match_path = cli.match_path || preset.match_path.unwrap_or(false);
    cli.inspect = cli.inspect || preset.inspect.unwrap_or(false);
    cli.count = cli.count || preset.count.unwrap_or(false);
    cli.verify = cli.verify || preset.verify.unwrap_or(false);
    if cli.threads.is_none() {
        cli.threads = preset.threads;
    }
    if let Some(v) = &preset.path {
        cli.filter.path.extend(v.iter().cloned());
    }
    if let Some(v) = &preset.not_path {
        cli.filter.not_path.extend(v.iter().cloned());
    }
    if let Some(v) = &preset.file_type {
        cli.filter.file_type.extend(v.iter().cloned());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn bare_names_are_not_paths() {
        assert!(!looks_like_path("mobile"));
        assert!(!looks_like_path("_fast"));
        assert!(!looks_like_path("ios-sqlite"));
    }

    #[test]
    fn separators_and_yaml_extensions_are_paths() {
        assert!(looks_like_path("./mobile.yml"));
        assert!(looks_like_path("/cases/2026/ios.yml"));
        assert!(looks_like_path("custom.yaml"));
        assert!(looks_like_path("dir/preset")); // separator, no extension
        assert!(looks_like_path("UPPER.YML")); // extension match is case-insensitive
    }

    #[test]
    fn load_preset_reads_an_explicit_file_path() {
        let mut file = tempfile::Builder::new()
            .suffix(".yml")
            .tempfile()
            .expect("create temp preset");
        writeln!(file, "exclude_media: true").unwrap();
        let path = file.path().to_str().unwrap();

        let preset = load_preset(path).expect("load preset from path");
        assert_eq!(preset.exclude_media, Some(true));
    }
}
