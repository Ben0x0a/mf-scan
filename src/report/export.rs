//! Export matched files: plan output paths, write a manifest, copy files to disk.
//!
//! Defines: `ExportItem`/`ExportPlan` (the plan), `plan` (build it),
//! `write_manifest` (re-ingestable JSON), and `export_files` (copy files to a
//! directory, honouring a size cap).
//!
//! Note on vocabulary: "export" is the file-copying action (also the `export`
//! subcommand); "extract" is reserved for extracting *meaning* from a file (the
//! inspectors). So the functions here are `export_*`, not `extract`.
//! Used by: `main.rs`.
//! Uses: `crate::engine::MatchedFile`, `crate::models::Entry`, `crate::source::zip`
//! (parse + content), `serde`/`serde_json`, `anyhow`.
//!
//! Layout: each matched file is written to `DIR/<basename>_<hash>/<basename>` —
//! the file keeps its real name inside a folder named after the basename plus a
//! short, stable hash of the file's internal path. The path hash is stable
//! across acquisitions, so a recurrent file always lands in the same-named
//! folder (recognisable by habit). Uniqueness is guaranteed: on the rare hash
//! collision (two different paths, same `basename_hash`), `_0x<offset>` is
//! appended, since the archive offset is unique. Only a basename is ever joined
//! under the folder, so an entry path can never escape `DIR` (no zip-slip).

use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::engine::MatchedFile;
use crate::models::{Entry, RunInfo};
use crate::source::Source;
use crate::util::sha256_hex;

/// Number of hex characters (4 bits each) of the path hash in a folder name.
const HASH_HEX_LEN: usize = 10;

/// One file to export, with its assigned output location.
pub struct ExportItem {
    pub internal_path: String,
    pub file_start: u64,
    pub folder: String, // <basename>_<hash>[ _0x<offset> on collision ]
    pub name: String,   // sanitised basename (the file inside the folder)
    pub size: u64,
    pub compressed: bool,
    pub offsets: Vec<u64>,
}

impl ExportItem {
    /// Relative output path: `<folder>/<basename>`.
    fn output_path(&self) -> String {
        format!("{}/{}", self.folder, self.name)
    }
}

/// A complete export plan plus the total size of all matched files.
pub struct ExportPlan {
    pub items: Vec<ExportItem>,
    pub total_size: u64,
}

/// One exported file recorded with its integrity hash, for the export report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedFile {
    /// Path inside the source archive.
    pub internal_path: String,
    /// Path written, relative to the export destination directory.
    pub output_path: String,
    pub size: u64,
    /// SHA-256 of the written bytes, lowercase hex.
    pub sha256: String,
}

/// The result of an export attempt.
pub enum ExportOutcome {
    Exported {
        files: usize,
        bytes: u64,
        /// Manifest entries whose file was not found in the archive (re-ingest).
        skipped: usize,
        /// Each written file with its SHA-256 (main files and sidecars).
        report: Vec<ExportedFile>,
    },
    Refused {
        total_size: u64,
        cap: u64,
    },
}

/// The export report: the run metadata plus every written file and its hash.
#[derive(Serialize)]
struct ExportReport<'a> {
    run: &'a RunInfo,
    file_count: usize,
    files: &'a [ExportedFile],
}

/// Write the export report (run metadata + per-file SHA-256) as JSON.
pub fn write_export_report(run: &RunInfo, files: &[ExportedFile], w: &mut dyn Write) -> Result<()> {
    let report = ExportReport {
        run,
        file_count: files.len(),
        files,
    };
    serde_json::to_writer_pretty(&mut *w, &report).context("failed writing export report")?;
    writeln!(w).context("failed writing export report")?;
    Ok(())
}

/// Build an export plan from the matched files (one item per file, in order).
///
/// HOW: assign each file `<basename>_<path-hash>` as its folder, then resolve
/// the (rare) folder collision by appending the unique hex offset.
pub fn plan(files: &[MatchedFile]) -> ExportPlan {
    let mut total_size = 0u64;
    let mut items: Vec<ExportItem> = files
        .iter()
        .map(|file| {
            total_size += file.entry.uncompressed_size;
            let name = sanitise_basename(&file.entry.name);
            let folder = format!("{name}_{}", path_hash(&file.entry.name));
            ExportItem {
                internal_path: file.entry.name.clone(),
                file_start: file.entry.archive_data_start().unwrap_or(0),
                folder,
                name,
                size: file.entry.uncompressed_size,
                compressed: file.entry.is_compressed(),
                offsets: file.offsets.clone(),
            }
        })
        .collect();

    // Disambiguate any folder name shared by more than one file. Comparison is
    // case-insensitive because Windows/macOS file systems are.
    let mut counts: HashMap<String, usize> = HashMap::new();
    for item in &items {
        *counts.entry(item.folder.to_ascii_lowercase()).or_default() += 1;
    }
    for item in &mut items {
        if counts[&item.folder.to_ascii_lowercase()] > 1 {
            item.folder = format!("{}_0x{:x}", item.folder, item.file_start);
        }
    }

    ExportPlan { items, total_size }
}

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

/// Export the matched files to `dir`.
///
/// When `max_size` is set and the total exceeds it, nothing is written and
/// `Refused` is returned — the caller can still have written the manifest, so
/// the operator can inspect the total and adjust before retrying.
pub fn export_files(
    plan: &ExportPlan,
    source: &dyn Source,
    files: &[MatchedFile],
    dir: &Path,
    max_size: Option<u64>,
) -> Result<ExportOutcome> {
    if let Some(cap) = max_size
        && plan.total_size > cap
    {
        return Ok(ExportOutcome::Refused {
            total_size: plan.total_size,
            cap,
        });
    }

    // The full entry list lets us also export each database's SQLite sidecars.
    let by_path: HashMap<&str, &Entry> = source
        .entries()
        .iter()
        .map(|e| (e.name.as_str(), e))
        .collect();

    let mut report: Vec<ExportedFile> = Vec::new();
    let mut bytes = 0u64;
    for (item, file) in plan.items.iter().zip(files) {
        // Content is read (and decompressed/read-from-disk) once, here.
        let content = source.content(&file.entry)?;
        let dest = dir.join(&item.folder).join(&item.name);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("cannot create {}", parent.display()))?;
        }
        fs::write(&dest, &content).with_context(|| format!("cannot write {}", dest.display()))?;
        bytes += content.len() as u64;
        report.push(exported_file(&file.entry.name, &dest, dir, &content));

        // Sidecars to export come from the file's inspector (e.g. SQLite's -wal).
        let suffixes = crate::inspect::sidecars_for(&file.entry.name, &content);
        let mut sidecars =
            export_sidecars(source, &by_path, &file.entry.name, &dest, dir, suffixes)?;
        bytes += sidecars.iter().map(|f| f.size).sum::<u64>();
        report.append(&mut sidecars);
    }

    Ok(ExportOutcome::Exported {
        files: report.len(),
        bytes,
        skipped: 0,
        report,
    })
}

/// Read a manifest previously written by [`write_manifest`].
pub fn read_manifest(reader: impl Read) -> Result<Manifest> {
    serde_json::from_reader(reader).context("failed to parse manifest")
}

/// Export the files listed in `manifest` out of `archive` into `dir`, reusing
/// the manifest's recorded output paths.
///
/// This re-ingestion path does not search: it locates each listed file in the
/// archive by its internal path and copies it to the stored output path. As
/// with a fresh export, the size cap is honoured up front.
pub fn export_from_manifest(
    manifest: &Manifest,
    source: &dyn Source,
    dir: &Path,
    max_size: Option<u64>,
) -> Result<ExportOutcome> {
    if let Some(cap) = max_size
        && manifest.total_size > cap
    {
        return Ok(ExportOutcome::Refused {
            total_size: manifest.total_size,
            cap,
        });
    }

    let entries = source.entries();
    let by_path: HashMap<&str, &Entry> = entries.iter().map(|e| (e.name.as_str(), e)).collect();

    let mut report: Vec<ExportedFile> = Vec::new();
    let mut bytes = 0u64;
    let mut skipped = 0usize;
    for entry in &manifest.files {
        let Some(found) = by_path.get(entry.internal_path.as_str()) else {
            skipped += 1; // listed file is absent from this archive
            continue;
        };
        let content = source.content(found)?;
        let dest = safe_join(dir, &entry.output_path);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("cannot create {}", parent.display()))?;
        }
        fs::write(&dest, &content).with_context(|| format!("cannot write {}", dest.display()))?;
        bytes += content.len() as u64;
        report.push(exported_file(&entry.internal_path, &dest, dir, &content));

        let suffixes = crate::inspect::sidecars_for(&entry.internal_path, &content);
        let mut sidecars =
            export_sidecars(source, &by_path, &entry.internal_path, &dest, dir, suffixes)?;
        bytes += sidecars.iter().map(|f| f.size).sum::<u64>();
        report.append(&mut sidecars);
    }

    Ok(ExportOutcome::Exported {
        files: report.len(),
        bytes,
        skipped,
        report,
    })
}

/// Export a file's declared sidecars into the same folder as `main_dest` (e.g.
/// `sms.db` → `sms.db-wal`), returning one [`ExportedFile`] (with hash) per
/// sidecar written.
///
/// The `suffixes` come from the file's inspector (see
/// [`crate::inspect::sidecars_for`]); each one names a sibling entry to fetch if
/// present. For SQLite this keeps the exported database complete — uncommitted
/// rows live in the `-wal`.
fn export_sidecars(
    source: &dyn Source,
    by_path: &HashMap<&str, &Entry>,
    internal_path: &str,
    main_dest: &Path,
    dir: &Path,
    suffixes: &[&str],
) -> Result<Vec<ExportedFile>> {
    let main_name = main_dest
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();

    let mut written = Vec::new();
    for suffix in suffixes {
        let sidecar_path = format!("{internal_path}{suffix}");
        let Some(entry) = by_path.get(sidecar_path.as_str()) else {
            continue;
        };
        let content = source.content(entry)?;
        let mut dest = main_dest.to_path_buf();
        dest.set_file_name(format!("{main_name}{suffix}"));
        fs::write(&dest, &content).with_context(|| format!("cannot write {}", dest.display()))?;
        written.push(exported_file(&sidecar_path, &dest, dir, &content));
    }
    Ok(written)
}

/// Build an [`ExportedFile`] record: the destination path relative to the export
/// directory, the size, and the SHA-256 of the written bytes.
fn exported_file(internal_path: &str, dest: &Path, dir: &Path, content: &[u8]) -> ExportedFile {
    let output_path = dest
        .strip_prefix(dir)
        .unwrap_or(dest)
        .to_string_lossy()
        .replace('\\', "/");
    ExportedFile {
        internal_path: internal_path.to_string(),
        output_path,
        size: content.len() as u64,
        sha256: sha256_hex(content),
    }
}

/// Join a manifest `output_path` under `dir`, dropping any `..`/empty/absolute
/// components so a tampered manifest can never escape the destination.
fn safe_join(dir: &Path, output_path: &str) -> std::path::PathBuf {
    let mut dest = dir.to_path_buf();
    for segment in output_path.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            continue;
        }
        dest.push(segment);
    }
    dest
}

/// Stable short hash of an internal path: low `HASH_HEX_LEN` hex digits of
/// FNV-1a-64.
///
/// WHY FNV-1a and not `std::hash::DefaultHasher`: the standard hasher's output
/// is explicitly *not* stable across Rust versions/platforms, which would break
/// the promise that the same file path always yields the same folder name. A
/// fixed algorithm keeps the name identical forever.
fn path_hash(path: &str) -> String {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = FNV_OFFSET;
    for &byte in path.as_bytes() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    let bits = HASH_HEX_LEN * 4;
    let mask = if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    };
    format!("{:0width$x}", hash & mask, width = HASH_HEX_LEN)
}

/// Reduce an internal path to a host-safe basename.
///
/// Strips the directory part, replaces characters illegal on Windows/Unix with
/// `_`, trims trailing dots/spaces (which Windows rejects), and falls back to a
/// placeholder for an empty result (e.g. a directory entry).
fn sanitise_basename(path: &str) -> String {
    let base = path.rsplit('/').next().unwrap_or(path);
    let mut name: String = base
        .chars()
        .map(|c| {
            if c.is_control() || matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*') {
                '_'
            } else {
                c
            }
        })
        .collect();
    let trimmed = name.trim_end_matches([' ', '.']);
    if trimmed.len() != name.len() {
        name = trimmed.to_string();
    }
    if name.is_empty() {
        name.push_str("unnamed");
    }
    name
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
}

impl From<&ExportItem> for ManifestEntry {
    fn from(item: &ExportItem) -> Self {
        Self {
            internal_path: item.internal_path.clone(),
            output_path: item.output_path(),
            size: item.size,
            compressed: item.compressed,
            offsets: item.offsets.clone(),
        }
    }
}
