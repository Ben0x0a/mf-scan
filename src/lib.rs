//! mf-scan library crate.
//!
//! Defines: the public module surface so both the `mf-scan` binary and the
//! integration tests can use the parser and search engine without going through
//! the CLI. Grouped by concern:
//!   • `core` — the foundation primitives: `models` (shared data types), `source`
//!     (the ZIP central-directory parser + the `Source` trait the engine reads
//!     through), `filter` (entry selection), and `util` (tiny helpers).
//!   • `engine` — the shared drive logic over a `Source`: the `is_selected` entry
//!     rule and the `Progress` contract that `ops::search` and `ops::diff` both reuse.
//!   • `ops` — the operations driven over a `Source`, as peer modules: `search`
//!     (scan → `Findings`, incl. the byte-search + per-entry `classify`), `diff`
//!     (compare two sources), and `apps` (locate/select an app's data across
//!     acquisition types — iOS FFS / iOS backup / Android — powering `app`).
//!   • `formats` — file-content understanding: the `inspect` parsers (SQLite, plist,
//!     JSON, …) that resolve a match, plus the low-level `sqlite` reader they share.
//!   • `decrypt` — database decryption (profiles, keyfile providers, ciphers).
//!   • `report` — result `output`, coverage `stats`, and the `diff` report.
//!   • `preset` — the behaviour-preset schema (file/manifest export lives in `report`).
//!   • `platform` — per-OS artefact parsing; today `platform::ios` (container
//!     GUID → bundle-ID map, the iTunes/Finder backup reader).
//! Used by: `main.rs` (the binary) and everything under `tests/`.
//! Uses: the modules it declares.
//!
//! Why a separate lib crate: keeping the logic in a library (rather than only
//! in `main.rs`) lets `tests/` link against it directly, which is the standard
//! Rust layout for a tool that wants both a CLI and a tested core.

pub mod core;
pub mod decrypt;
pub mod engine;
pub mod formats;
pub mod ops;
pub mod platform;
pub mod preset;
pub mod report;

/// Test-only helpers shared across the library's unit tests (see [`testutil`]).
#[cfg(test)]
pub(crate) mod testutil;
