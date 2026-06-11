//! Behaviour-preset loading and application for the `grep` subcommand.
//!
//! Defines: the preset resolver/loader and [`apply_preset`], which merges a
//! preset's values into the parsed CLI arguments.
//! Used by: `run::grep` (applies a named preset and `--fast`).
//! Uses: `mf_scan::preset` (the deserialised preset) and `crate::cli`.

use std::path::PathBuf;

use anyhow::{Context, Result};

use mf_scan::preset::Preset;

use crate::cli::GrepArgs;

/// Resolve the `presets/` directory sitting next to the running binary.
///
/// The directory must be in the same folder as the binary — no parent-directory
/// walking is attempted. In releases the folder is shipped alongside the binary.
/// In dev builds, copy or symlink the repo's `presets/` into `target/debug/`.
fn find_presets_dir() -> Result<PathBuf> {
    let exe = std::env::current_exe().context("cannot determine binary path")?;
    let dir = exe
        .parent()
        .ok_or_else(|| anyhow::anyhow!("binary has no parent directory"))?
        .join("presets");
    if dir.is_dir() {
        Ok(dir)
    } else {
        Err(anyhow::anyhow!(
            "cannot find 'presets/' directory next to the binary (looked in {})",
            dir.display()
        ))
    }
}

/// Load the preset named `name` from `presets/<name>.yml` beside the binary.
pub(crate) fn load_named_preset(name: &str) -> Result<Preset> {
    let path = find_presets_dir()?.join(format!("{name}.yml"));
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
