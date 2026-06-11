//! mf-scan library crate.
//!
//! Defines: the public module surface so both the `mf-scan` binary and the
//! integration tests can use the parser and search engine without going through
//! the CLI. Grouped by concern:
//!   • `models` / `source` — shared data types and the source containers (the ZIP
//!     central-directory parser + the `Source` trait the engine reads through).
//!   • `engine` — the search engine: drivers + per-entry `classify`, with `filter`
//!     and `search` (byte search) as submodules.
//!   • `inspect` — format parsers (SQLite, plist, JSON, …) that resolve a match.
//!   • `decrypt` — database decryption (profiles, keyfile providers, ciphers).
//!   • `diff` — compare two sources: which files were added/removed/modified.
//!   • `report` — result `output`, coverage `stats`, and the `diff` report.
//!   • `export` / `preset` — file/manifest export and the behaviour-preset schema.
//! Used by: `main.rs` (the binary) and everything under `tests/`.
//! Uses: the modules it declares.
//!
//! Why a separate lib crate: keeping the logic in a library (rather than only
//! in `main.rs`) lets `tests/` link against it directly, which is the standard
//! Rust layout for a tool that wants both a CLI and a tested core.

pub mod decrypt;
pub mod diff;
pub mod engine;
pub mod filter;
pub mod inspect;
pub mod models;
pub mod preset;
pub mod report;
pub mod search;
pub mod source;
