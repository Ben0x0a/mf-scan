//! The export manifest: the re-ingestable list of what an export would write.
//!
//! Defines: [`Manifest`] / [`ManifestEntry`], [`write_manifest`], [`read_manifest`].
//! Used by: the binary's `--manifest` and the `export --from-manifest` command.
//! Uses: `report::export::plan::{ExportItem, ExportPlan}`, `core::models::RunInfo`.

use std::collections::BTreeMap;
use std::io::{Read, Write};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::plan::{ExportItem, ExportPlan};
use crate::core::models::RunInfo;

/// Write the plan as a re-ingestable JSON manifest.
///
/// `run` records the query and filters (and the source archive paths) at the
/// head of the manifest, so it documents what produced it; it is informational
/// when the manifest is later re-ingested against a different archive.
pub fn write_manifest(plan: &ExportPlan, run: &RunInfo, w: &mut dyn Write) -> Result<()> {
    let manifest = Manifest {
        run: run.clone(),
        total_size: plan.total_size,
        file_count: plan.items.len(),
        files: plan.items.iter().map(ManifestEntry::from).collect(),
    };
    serde_json::to_writer_pretty(&mut *w, &manifest).context("failed writing manifest")?;
    writeln!(w).context("failed writing manifest")?;
    Ok(())
}

/// Read a manifest previously written by [`write_manifest`].
pub fn read_manifest(reader: impl Read) -> Result<Manifest> {
    serde_json::from_reader(reader).context("failed to parse manifest")
}

/// JSON manifest shape (re-ingestable).
///
/// `run` (the query, filters, and source archive paths) heads the manifest for
/// documentation; the remaining fields drive re-ingestion.
#[derive(Serialize, Deserialize)]
pub struct Manifest {
    pub run: RunInfo,
    pub total_size: u64,
    pub file_count: usize,
    pub files: Vec<ManifestEntry>,
}

#[derive(Serialize, Deserialize)]
pub struct ManifestEntry {
    pub internal_path: String,
    pub output_path: String,
    pub size: u64,
    pub compressed: bool,
    pub offsets: Vec<u64>,
    /// Matches per encoding (`{"plain": 7, "utf16le": 5}`), when other encodings than
    /// plain were found: why a file with few readable matches was exported. Absent
    /// otherwise, and from manifests written before it existed.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub encodings: BTreeMap<String, usize>,
}

impl From<&ExportItem> for ManifestEntry {
    fn from(item: &ExportItem) -> Self {
        Self {
            internal_path: item.internal_path.clone(),
            output_path: item.output_path(),
            size: item.size,
            compressed: item.compressed,
            offsets: item.offsets.clone(),
            encodings: item
                .encodings
                .iter()
                .map(|(e, n)| (e.as_str().to_string(), *n))
                .collect(),
        }
    }
}
