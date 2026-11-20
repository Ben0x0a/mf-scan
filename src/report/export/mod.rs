//! Export matched files: plan output paths, write a manifest, copy files into a ZIP.
//!
//! Defines: `ExportItem`/`ExportPlan` (the plan), `plan` (build it),
//! `write_manifest` (re-ingestable JSON), and `export_files` (write the files as one
//! ZIP archive, honouring a size cap).
//!
//! Note on vocabulary: "export" is the file-copying action (also the `export`
//! subcommand); "extract" is reserved for extracting *meaning* from a file (the
//! inspectors). So the functions here are `export_*`, not `extract`.
//! Used by: the binary's export paths, `report::rebuild_zip`, `report::decrypted_zip`.
//! Uses: its submodules: `plan` (where files go), `write` (the archive, read-only and
//! never over an existing one), `record` (what was written, with hashes), `manifest`
//! (the re-ingestable list).
//!
//! Layout: each matched file is written to `<basename>_<hash>/<basename>` —
//! the file keeps its real name inside a folder named after the basename plus a
//! short, stable hash of the file's internal path. The path hash is stable
//! across acquisitions, so a recurrent file always lands in the same-named
//! folder (recognisable by habit). Uniqueness is guaranteed: on the rare hash
//! collision (two different paths, same `basename_hash`), `_0x<offset>` is
//! appended, since the archive offset is unique. Only a basename is ever joined
//! under the folder, so an entry path can never escape the folder the archive is
//! extracted to (no zip-slip).

mod manifest;
mod plan;
mod record;
mod write;

#[cfg(test)]
mod tests;

pub use manifest::{Manifest, ManifestEntry, read_manifest, write_manifest};
pub use plan::{ExportItem, ExportPlan, Renamed, plan, plan_tree};
pub(crate) use plan::{decrypted_name_numbered, fold_case};
pub use record::{
    ExportNotes, ExportedFile, FileNote, IntegritySummary, StoredIntegrity, write_export_report,
};
pub(crate) use write::extraction_warning;
pub use write::{
    ExportArchive, ExportOutcome, REPORT_MEMBER, WINDOWS_MAX_PATH, export_files,
    export_from_manifest,
};
