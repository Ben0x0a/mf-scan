//! Support modules for the `run` operations — the machinery the two subcommands
//! lean on, kept out of the command files so `run/` exposes only the core ops.
//!
//! Defines: the module surface for the binary's command support.
//! Used by: `run::search` (all of them) and `run::export` (`sources`, `reporting`,
//! `exporting`).
//! Uses: the submodules below.
//!
//! ── Modules ──────────────────────────────────────────────────────────────────
//!   • `sources`    — resolve archive operands into sources and memory-map them.
//!   • `presets`    — load and apply behaviour presets / `--fast`.
//!   • `decryption` — build the decryption context (incl. keychain auto-detect).
//!   • `progress`   — drive the engine search with a live TTY progress line.
//!   • `reporting`  — operator-facing status, the scan report, verify, the sink.
//!   • `exporting`  — the search-time manifest/export machinery.
//!
//! Names are roles (verbs/gerunds) so they do not collide with the library's
//! capability modules (`decrypt`, `preset`, `report`, `export`). These are leaves:
//! none imports another (only the library and `crate::cli`), keeping deps acyclic.

pub(crate) mod decryption;
pub(crate) mod exporting;
pub(crate) mod presets;
pub(crate) mod progress;
pub(crate) mod reporting;
pub(crate) mod sources;

use std::path::PathBuf;

use anyhow::{Context, Result};

/// Resolve a data directory sitting next to the running binary (`presets/`,
/// `profiles/`).
///
/// The directory must be in the same folder as the binary — no parent-directory
/// walking is attempted. In releases the folder is shipped alongside the binary.
/// In dev builds, copy or symlink the repo's folder into `target/debug/`.
///
/// Lives in the module root (not a submodule) so the submodules stay leaves
/// that never import one another.
pub(crate) fn dir_beside_binary(name: &str) -> Result<PathBuf> {
    let exe = std::env::current_exe().context("cannot determine binary path")?;
    let dir = exe
        .parent()
        .ok_or_else(|| anyhow::anyhow!("binary has no parent directory"))?
        .join(name);
    if dir.is_dir() {
        Ok(dir)
    } else {
        Err(anyhow::anyhow!(
            "cannot find '{name}/' directory next to the binary (looked in {})",
            dir.display()
        ))
    }
}
