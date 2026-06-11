//! The binary's core operations — the `grep`, `export`, and `diff` subcommands.
//!
//! Defines: the operation surface, re-exporting [`run_grep`], [`run_export`], and
//! [`run_diff`].
//! Used by: `main` (dispatches to them).
//! Uses: the per-command submodules `grep`, `export`, and `diff`, which in turn
//! lean on the `crate::support` support modules.
//!
//! This module is the "ops" layer: it exposes exactly the three callable operations
//! and nothing else. Everything they need (source resolution, presets, decryption
//! setup, progress, reporting, the export machinery) lives in `crate::support`, so
//! the command files stay focused on orchestration.

mod diff;
mod export;
mod grep;

pub(crate) use diff::run_diff;
pub(crate) use export::run_export;
pub(crate) use grep::run_grep;
