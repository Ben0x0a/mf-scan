//! File-format understanding — turning raw bytes into meaning.
//!
//! Defines: the format namespace, grouping the two layers that understand a file's
//! *content* (as opposed to where its bytes live, which is `core::source`):
//!   • `inspect` — the `Inspector` registry (txt/json/xml/csv/plist/sqlite + media):
//!     file-type detection, match resolution (`--inspect`), and intra-file diff.
//!   • `sqlite` — the low-level SQLite reader (page/record/schema/table), shared by
//!     the SQLite inspector and the iOS-backup `Manifest.db` reader.
//! Used by: `engine` (deep search + type filtering), `diff` (intra-file diff),
//! `report`, `apps`, and `ios::backup` (the `Manifest.db` walk).
//! Uses: `core` (data types) and external parsers.
//!
//! WHY one folder: both modules answer "what is in this file?" — `inspect` at the
//! format level, `sqlite` as the reader the SQLite inspector and the backup manifest
//! both lean on. Grouping them separates content understanding from the byte-source
//! plumbing it runs over.

pub mod inspect;
pub mod sqlite;
