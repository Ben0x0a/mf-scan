//! The binary's core operations — the `grep`, `export`, `diff`, and `app`
//! subcommands.
//!
//! Defines: the operation surface, re-exporting [`run_grep`], [`run_export`],
//! [`run_diff`], and [`run_app`].
//! Used by: `main` (dispatches to them).
//! Uses: the per-command submodules `grep`, `export`, `diff`, and `app`, which in
//! turn lean on the `crate::cmd::support` support modules.
//!
//! This module is the "ops" layer: it exposes exactly the callable operations and
//! nothing else. Everything they need (source resolution, presets, decryption
//! setup, progress, reporting, the export machinery) lives in `crate::cmd::support`, so
//! the command files stay focused on orchestration.

mod app;
mod diff;
mod export;
mod grep;

pub(crate) use app::run_app;
pub(crate) use diff::run_diff;
pub(crate) use export::run_export;
pub(crate) use grep::run_grep;
