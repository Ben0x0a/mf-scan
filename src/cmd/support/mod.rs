//! Support modules for the `run` operations — the machinery the two subcommands
//! lean on, kept out of the command files so `run/` exposes only the core ops.
//!
//! Defines: the module surface for the binary's command support.
//! Used by: the `run` commands (`grep`, `find`, `diff`, `export`, `app`, `backup`,
//! `decrypt`), each taking the modules it needs.
//! Uses: the submodules below.
//!
//! ── Modules ──────────────────────────────────────────────────────────────────
//!   • `sources`    — resolve archive operands into sources and memory-map them.
//!   • `presets`    — load and apply behaviour presets / `--fast`.
//!   • `decryption` — build the decryption context (incl. keychain auto-detect).
//!   • `progress`   — drive the engine search with a live TTY progress line.
//!   • `reporting`  — operator-facing status, the scan report, verify, the sink.
//!   • `exporting`  — the manifest/export machinery: the archive's name, the outcome.
//!   • `scoping`    — an app id resolved: `--app`'s path prefixes, and the report.
//!
//! Names are roles (verbs/gerunds) so they do not collide with the library's
//! capability modules (`decrypt`, `preset`, `report`, `export`). These are leaves:
//! none imports another (only the library and `crate::cmd::cli`), keeping deps acyclic.

pub(crate) mod decryption;
pub(crate) mod exporting;
pub(crate) mod presets;
pub(crate) mod progress;
pub(crate) mod reporting;
pub(crate) mod scoping;
pub(crate) mod sources;

use std::path::PathBuf;

use anyhow::{Context, Result};

/// What a command's result may leave out, said on stderr with every result.
pub(crate) enum Caveat {
    /// `grep`: matches.
    Matches,
    /// `find`: files.
    Files,
    /// `diff`: changes.
    Changes,
    /// `app list`: apps.
    Apps,
    /// `app paths`, `app export`, `--app`: an app's containers.
    Containers,
}

/// Say what the result may leave out, and to check by hand when in doubt.
///
/// WHY on every result: the tool guides an examination, it does not close it. A
/// result read as complete would hide what mf-scan cannot see, and missing data is
/// the costliest error there is. Lives in the module root so the submodules, which
/// all use it, stay leaves.
pub(crate) fn caveat(what: Caveat) {
    let text = match what {
        Caveat::Matches => {
            "other matches may exist that mf-scan cannot see (a format, encoding or \
             compression it does not read, encrypted data, skipped files)"
        }
        Caveat::Files => {
            "other files may match: types are read from headers and extensions, and \
             not every format is recognised"
        }
        Caveat::Changes => {
            "other changes may exist that this comparison does not show (content it \
             does not read, files filtered out)"
        }
        Caveat::Apps => {
            "other apps may exist that this list misses (no container recognised here, \
             or data kept elsewhere)"
        }
        Caveat::Containers => {
            "the app may have other containers or files that mf-scan does not attribute \
             to it"
        }
    };
    eprintln!("note: {text}; when in doubt, check by hand");
}

/// Resolve a data directory sitting next to the running binary (`presets/`,
/// `profiles/`).
///
/// The directory must be in the same folder as the binary — no parent-directory
/// walking is attempted. In releases the folder is shipped alongside the binary.
/// In dev builds, copy or symlink the repo's folder into `target/debug/`.
///
/// Lives in the module root (not a submodule) so the submodules stay leaves
/// that never import one another (as [`caveat`] does).
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
