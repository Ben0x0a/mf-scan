//! Export matched files: plan output paths, write a manifest, copy files to disk.
//!
//! Defines: `ExportItem`/`ExportPlan` (the plan), `plan` (build it),
//! `write_manifest` (re-ingestable JSON), and `export_files` (copy files to a
//! directory, honouring a size cap).
//!
//! Note on vocabulary: "export" is the file-copying action (also the `export`
//! subcommand); "extract" is reserved for extracting *meaning* from a file (the
//! inspectors). So the functions here are `export_*`, not `extract`.
//! Used by: the binary's export paths, `report::rebuild_zip`, `report::decrypted_zip`.
//! Uses: its submodules: `plan` (where files go), `write` (copying them, read-only and
//! never over an existing file), `record` (what was written, with hashes), `manifest`
//! (the re-ingestable list), `work_copy` (an editable copy of a finished export).
//!
//! Layout: each matched file is written to `DIR/<basename>_<hash>/<basename>` —
//! the file keeps its real name inside a folder named after the basename plus a
//! short, stable hash of the file's internal path. The path hash is stable
//! across acquisitions, so a recurrent file always lands in the same-named
//! folder (recognisable by habit). Uniqueness is guaranteed: on the rare hash
//! collision (two different paths, same `basename_hash`), `_0x<offset>` is
//! appended, since the archive offset is unique. Only a basename is ever joined
//! under the folder, so an entry path can never escape `DIR` (no zip-slip).

mod manifest;
mod plan;
mod record;
mod work_copy;
mod write;

#[cfg(test)]
mod tests;

pub use manifest::{Manifest, ManifestEntry, read_manifest, write_manifest};
pub use plan::{ExportItem, ExportPlan, Renamed, decrypted_name, plan, plan_tree};
pub use record::{
    ExportNotes, ExportedFile, IntegritySummary, SkippedFile, StoredIntegrity, write_export_report,
};
pub(crate) use work_copy::make_writable;
pub use work_copy::{WorkCopy, work_copy};
pub(crate) use write::set_read_only;
pub use write::{
    DEFAULT_MAX_PATH_LEN, ExportOutcome, export_files, export_from_manifest, write_read_only,
};
