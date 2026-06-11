//! Result handling: render matches, tally coverage, and extract matched files.
//!
//! Defines: the report module surface — [`output`] (render matches as txt/json/csv
//! and write the sidecar scan report), [`stats`] (the run's coverage tally),
//! [`export`] (the file/manifest export engine that copies matched files out), and
//! [`diff`] (render a [`crate::diff::DiffReport`]).
//! Used by: the binary's `support::{reporting, exporting}` and `run` commands; the
//! engine fills [`stats`].
//! Uses: the submodules below.

pub mod diff;
pub mod export;
pub mod output;
pub mod stats;
