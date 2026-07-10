//! Operations over a `Source` — the things the tool *does*, as peer modules.
//!
//! Defines: the operations namespace. Each submodule is one analysis the binary
//! exposes as a subcommand, all at the same level:
//!   • `search` — scan a source for a pattern → `Findings` (the `grep` subcommand).
//!   • `diff`   — compare two sources → `DiffReport` (the `diff` subcommand).
//!   • `apps`   — locate & export an application's data (the `app` subcommand).
//! Used by: the binary's `cmd::run` orchestrators, and the integration tests.
//! Uses: `crate::engine` (the shared drive logic these operations build on) plus the
//! `core` / `formats` / `platform` / `decrypt` capability layers.
//!
//! WHY grouped: search, diff, and apps are the same *kind* of thing — an operation
//! driven over the `core::source::Source` abstraction — so they live at one depth.
//! The mechanics they share (entry selection, progress reporting) are factored out
//! into `crate::engine`; the per-OS and per-format knowledge they call lives in
//! `platform` / `formats`. This keeps each operation focused on its own logic.

pub mod apps;
pub mod diff;
pub mod search;
