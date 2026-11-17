//! Result handling: render matches, tally coverage, and extract matched files.
//!
//! Defines: the report module surface — [`output`] (render matches as txt/json/csv
//! and write the sidecar scan report),
//! [`export`] (the file/manifest export engine that copies matched files out),
//! [`diff`] (render a [`crate::ops::diff::DiffReport`]), [`zip_writer`] (a timestamp-
//! preserving ZIP writer), [`rebuild_zip`] (a backup rebuild's one output archive), and
//! [`decrypted_zip`] (an acquisition with its decrypted databases added).
//! Used by: the binary's `support::{reporting, exporting}` and `run` commands. The
//! coverage tally the reports embed lives in `core::stats`.
//! Uses: the submodules below.

pub mod decrypted_zip;
pub mod diff;
pub mod export;
pub mod output;
pub mod rebuild_zip;
pub mod zip_writer;
