//! The binary's own modules — everything that is *not* the reusable library.
//!
//! Defines: the binary-only namespace, grouping the three module trees that exist
//! solely to serve the `mf-scan` executable: `cli` (clap argument structs), `run`
//! (one orchestrator per subcommand), and `support` (the machinery those
//! orchestrators share — source resolution, presets, decryption setup, progress,
//! reporting, exporting).
//! Used by: `main.rs` only.
//! Uses: the `mf_scan` library crate (the `crate::*` capability modules) plus the
//! submodules below.
//!
//! WHY this folder exists: the library↔binary boundary is the biggest divide in the
//! tree. Everything declared in `lib.rs` is the reusable, unit-tested core; everything
//! here is the CLI front end built on top of it. Keeping these three trees under one
//! roof makes that boundary structural rather than something a reader has to infer
//! from which modules `lib.rs` happens to omit.

pub(crate) mod cli;
pub(crate) mod run;
pub(crate) mod support;
