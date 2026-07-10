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
//! Uses: `crate::ops::search::MatchedFile`, `crate::core::models::Entry`, `crate::core::source::zip`
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

use crate::core::models::{Entry, RunInfo};
use crate::core::source::Source;
use crate::core::util::sha256_hex;
use crate::ops::search::MatchedFile;

/// Number of hex characters (4 bits each) of the path hash in a folder name.
const HASH_HEX_LEN: usize = 10;

/// Default cap on a written file's full destination path length, in characters.
///
/// WHY 260: classic Windows `MAX_PATH` is 260; an export that exceeds it cannot be
/// opened by many Windows tools even though the bytes copied fine. Exported
/// artefacts are evidence that routinely move between machines (often to Windows
/// for analysis), so the guard is applied cross-platform to keep output portable —
/// `--max-path-len 0` disables it. macOS/Linux additionally enforce a 255-character
/// per-component limit, which is checked whenever the guard is active.
pub const DEFAULT_MAX_PATH_LEN: usize = 260;

/// The per-path-component (file/dir name) length limit enforced when the guard is
/// active. 255 is the `NAME_MAX` of the common Unix filesystems and of NTFS.
const MAX_COMPONENT_LEN: usize = 255;

/// A file that was NOT written because its destination path would exceed the
/// length guard — recorded (rather than silently dropped or truncated) so the
/// analyst can re-export to a shorter root or raise `--max-path-len`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkippedFile {
    /// Path inside the source that was skipped.
    pub internal_path: String,
    /// The destination path that would have been written, relative to the dir.
    pub output_path: String,
    /// Why it was skipped (which limit it hit), for the operator and the report.
    pub reason: String,
}

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

/// One exported file recorded with its integrity hashes, for the export report.
///
/// Two independent SHA-256 hashes are recorded so a silent copy error (a bad
/// disk write, a truncated copy) is caught: `source_sha256` is the bytes read
/// out of the source, `sha256` is the bytes read back from the written file. The
/// export attests `copy_verified` (they match) — and, for an encrypted backup,
/// `stored_integrity` (the encrypted blob matched the SHA-1 in `Manifest.db`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedFile {
    /// Path inside the source archive.
    pub internal_path: String,
    /// Path written, relative to the export destination directory.
    pub output_path: String,
    pub size: u64,
    /// SHA-256 of the written bytes (read back from disk), lowercase hex.
    pub sha256: String,
    /// SHA-256 of the source bytes (as read out of the source), lowercase hex.
    pub source_sha256: String,
    /// Whether `source_sha256 == sha256` — the source-vs-copy attestation. A
    /// `false` here means the bytes on disk differ from what was read (a silent
    /// copy error) and is surfaced loudly.
    pub copy_verified: bool,
    /// Source-recorded stored-bytes integrity, when the source carries one (an
    /// encrypted backup's per-file SHA-1). `Unrecorded` for plain sources.
    pub stored_integrity: StoredIntegrity,
}

/// The serialisable form of [`crate::core::source::IntegrityCheck`] for the report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum StoredIntegrity {
    /// The source records no digest for this file.
    Unrecorded,
    /// The source's recorded digest matched the stored bytes.
    Verified { algorithm: String },
    /// The source's recorded digest did NOT match — corrupt original evidence.
    Mismatch {
        algorithm: String,
        expected: String,
        actual: String,
    },
}

impl From<crate::core::source::IntegrityCheck> for StoredIntegrity {
    fn from(check: crate::core::source::IntegrityCheck) -> Self {
        use crate::core::source::IntegrityCheck as I;
        match check {
            I::Unrecorded => StoredIntegrity::Unrecorded,
            I::Verified { algorithm } => StoredIntegrity::Verified {
                algorithm: algorithm.to_string(),
            },
            I::Mismatch {
                algorithm,
                expected,
                actual,
            } => StoredIntegrity::Mismatch {
                algorithm: algorithm.to_string(),
                expected,
                actual,
            },
        }
    }
}

impl ExportedFile {
    /// Whether this file's export is fully attested: the on-disk copy matches the
    /// source bytes AND any source-recorded stored digest matched. A `false` is
    /// reported loudly to the operator.
    pub fn is_intact(&self) -> bool {
        self.copy_verified && !matches!(self.stored_integrity, StoredIntegrity::Mismatch { .. })
    }
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
        /// Files NOT written because the destination path cannot exist on THIS
        /// platform (a single component over 255, or — on Windows — the absolute
        /// path over the limit). Recorded, never silently dropped.
        skipped_too_long: Vec<SkippedFile>,
        /// Files that WERE written but whose relative output path exceeds the limit,
        /// so they will not be extractable if the export is later moved to Windows
        /// (raised only on non-Windows hosts, where the local write succeeds).
        portability_warnings: Vec<SkippedFile>,
    },
    Refused {
        total_size: u64,
        cap: u64,
    },
}

/// The verdict of the path-length guard for one file.
enum PathCheck {
    /// Safe to write, and portable.
    Ok,
    /// Cannot be written on the current platform — skip it (an error).
    Skip(String),
    /// Written here, but the relative path is too long for Windows — warn.
    NotPortable(String),
}

/// Decide how the length guard treats one file, given the output directory, the
/// file's relative `output_path`, and the limit (`0` disables the guard).
///
/// The rule (see the approved design):
/// - any single path component over [`MAX_COMPONENT_LEN`] cannot exist on any
///   common filesystem ⇒ `Skip` everywhere;
/// - on **Windows**, the OS enforces the absolute-path limit, so an over-limit
///   absolute path genuinely cannot be created ⇒ `Skip`;
/// - on **other platforms**, the local write succeeds (PATH_MAX is far larger), so
///   the file is exported, but if its RELATIVE path already exceeds the limit it
///   could never be re-extracted under any Windows directory ⇒ `NotPortable`
///   (a warning). WHY measure the relative path off-Windows: the absolute length
///   depends on the operator's chosen output directory and the eventual Windows
///   root, neither fixed; the relative path is the portable, machine-independent
///   part — if it alone exceeds the limit, no Windows host can hold it.
fn check_export_path(dir: &Path, output_path: &str, max_path_len: usize) -> PathCheck {
    if max_path_len == 0 {
        return PathCheck::Ok;
    }
    // A component longer than the filesystem's NAME_MAX is unwritable everywhere.
    for component in output_path.split('/') {
        let len = component.chars().count();
        if len > MAX_COMPONENT_LEN {
            return PathCheck::Skip(format!(
                "path component length {len} exceeds the {MAX_COMPONENT_LEN}-char filesystem limit"
            ));
        }
    }

    if cfg!(target_os = "windows") {
        let abs_len = dir
            .join(output_path)
            .as_os_str()
            .to_string_lossy()
            .chars()
            .count();
        if abs_len > max_path_len {
            return PathCheck::Skip(format!(
                "absolute path length {abs_len} exceeds the Windows MAX_PATH limit {max_path_len}"
            ));
        }
        PathCheck::Ok
    } else {
        let rel_len = output_path.chars().count();
        if rel_len > max_path_len {
            return PathCheck::NotPortable(format!(
                "export path length {rel_len} exceeds {max_path_len} — this file will not be extractable on Windows"
            ));
        }
        PathCheck::Ok
    }
}

/// The export report: run metadata, an integrity summary, every written file with
/// its hashes, and any files skipped for an over-length destination path.
#[derive(Serialize)]
struct ExportReport<'a> {
    run: &'a RunInfo,
    file_count: usize,
    integrity: IntegritySummary,
    files: &'a [ExportedFile],
    /// Files not written because their path could not exist on this platform.
    /// Omitted from the JSON when empty so a clean export's report is unchanged.
    #[serde(skip_serializing_if = "<[SkippedFile]>::is_empty")]
    skipped_too_long: &'a [SkippedFile],
    /// Files written but whose path is too long to move to Windows. Omitted when empty.
    #[serde(skip_serializing_if = "<[SkippedFile]>::is_empty")]
    portability_warnings: &'a [SkippedFile],
}

/// Aggregate integrity outcome over all exported files, surfaced at the head of
/// the report so an operator sees at a glance whether every copy is attested.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegritySummary {
    /// Files whose on-disk copy matched the source bytes AND any stored digest.
    pub intact: usize,
    /// Files whose written copy did NOT match the source bytes read.
    pub copy_mismatches: usize,
    /// Files whose source-recorded stored digest did NOT match (corrupt original).
    pub stored_digest_mismatches: usize,
    /// Files carrying a source-recorded stored digest that was verified.
    pub stored_digest_verified: usize,
}

impl IntegritySummary {
    /// Tally the per-file outcomes into the aggregate.
    pub fn of(files: &[ExportedFile]) -> Self {
        let mut s = IntegritySummary {
            intact: 0,
            copy_mismatches: 0,
            stored_digest_mismatches: 0,
            stored_digest_verified: 0,
        };
        for f in files {
            if f.is_intact() {
                s.intact += 1;
            }
            if !f.copy_verified {
                s.copy_mismatches += 1;
            }
            match f.stored_integrity {
                StoredIntegrity::Verified { .. } => s.stored_digest_verified += 1,
                StoredIntegrity::Mismatch { .. } => s.stored_digest_mismatches += 1,
                StoredIntegrity::Unrecorded => {}
            }
        }
        s
    }

    /// Whether any file failed either integrity check.
    pub fn has_failures(&self) -> bool {
        self.copy_mismatches > 0 || self.stored_digest_mismatches > 0
    }
}

/// Write the export report (run metadata + integrity summary + per-file hashes,
/// plus any files skipped for an over-length path).
pub fn write_export_report(
    run: &RunInfo,
    files: &[ExportedFile],
    skipped_too_long: &[SkippedFile],
    portability_warnings: &[SkippedFile],
    w: &mut dyn Write,
) -> Result<()> {
    let report = ExportReport {
        run,
        file_count: files.len(),
        integrity: IntegritySummary::of(files),
        files,
        skipped_too_long,
        portability_warnings,
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

/// Build an export plan that PRESERVES each file's directory tree under a
/// per-container label — the layout the `app export` path wants (one output
/// subfolder per app container, real names retained).
///
/// `roots` is a list of `(prefix, label)` pairs: `prefix` is a resolved source
/// path prefix (an app's data container, an extension/widget container, an App
/// Group, or a backup domain) and `label` is the output subfolder it maps to
/// (e.g. `"com.app/AppData_5A92C2C1"`). Each file is attributed to the LONGEST
/// matching prefix, that prefix is stripped, and the remaining relative path is
/// rebuilt under `label` with every segment host-sanitised so the on-device tree
/// is mirrored safely under the destination.
///
/// WHY longest-prefix wins: containers can nest (an extension container may sit
/// inside another registered directory), so the most specific owner must claim the
/// file — the same rule [`crate::platform::ios::containers::AppContainerMap::resolve`] uses.
/// WHY per-segment sanitisation (not a single `safe_join` at write time): the tree
/// is reconstructed here, so each component must be made host-safe as it is built;
/// re-ingestion still passes through [`safe_join`], which rejects any `..`.
pub fn plan_tree(files: &[MatchedFile], roots: &[(String, String)]) -> ExportPlan {
    let mut total_size = 0u64;
    let items = files
        .iter()
        .map(|file| {
            total_size += file.entry.uncompressed_size;
            let path = file.entry.name.as_str();
            // The longest `prefix` that contains this file, with the file's path
            // relative to that prefix.
            let best = roots
                .iter()
                .filter_map(|(prefix, label)| {
                    relative_under(prefix, path).map(|rel| (prefix.len(), label, rel))
                })
                .max_by_key(|(prefix_len, _, _)| *prefix_len);

            let (folder, name) = match best {
                Some((_, label, rel)) => {
                    let (dirs, base) = split_dir_base(rel);
                    let mut folder = label.clone();
                    for seg in dirs {
                        folder.push('/');
                        folder.push_str(&sanitise_segment(seg));
                    }
                    (folder, sanitise_segment(base))
                }
                // Defensive: a file under no root keeps the flat hashed layout
                // rather than being lost (should not happen — callers pass only
                // files gathered from these prefixes).
                None => {
                    let name = sanitise_basename(path);
                    (format!("{name}_{}", path_hash(path)), name)
                }
            };

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

    ExportPlan { items, total_size }
}

/// The portion of `path` inside container `prefix`: `Some("")` when `path` IS the
/// prefix, `Some(rest)` when `path` is `prefix/rest`, `None` when `path` is not
/// under `prefix`. Mirrors the segment-boundary rule in `AppContainerMap`.
fn relative_under<'a>(prefix: &str, path: &'a str) -> Option<&'a str> {
    if path == prefix {
        return Some("");
    }
    path.strip_prefix(prefix)
        .and_then(|rest| rest.strip_prefix('/'))
}

/// Split a `/`-separated relative path into its directory segments and basename,
/// dropping empty segments. `"Library/Caches/x.db"` → `(["Library","Caches"], "x.db")`.
fn split_dir_base(rel: &str) -> (Vec<&str>, &str) {
    match rel.rfind('/') {
        Some(pos) => (
            rel[..pos].split('/').filter(|s| !s.is_empty()).collect(),
            &rel[pos + 1..],
        ),
        None => (Vec::new(), rel),
    }
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

/// Writes one file (plus its sidecars) per call and accumulates the outcome.
///
/// WHY this exists: a fresh export ([`export_files`]) and a manifest re-ingestion
/// ([`export_from_manifest`]) share the same per-file body — path-length guard,
/// read content, `create_dir_all`, write, integrity check, sidecars — differing
/// only in how each computes the destination and iterates. Owning that body here
/// keeps the two loops from drifting (they already had: `safe_join` was applied on
/// only one path). Each caller keeps its own iteration and destination rule and
/// hands the located entry + paths to [`write_one`](Self::write_one).
struct FileExporter<'a> {
    source: &'a dyn Source,
    /// The full entry list, so a written file's declared sidecars can be fetched.
    by_path: &'a HashMap<&'a str, &'a Entry>,
    dir: &'a Path,
    max_path_len: usize,
    report: Vec<ExportedFile>,
    skipped_too_long: Vec<SkippedFile>,
    portability_warnings: Vec<SkippedFile>,
    bytes: u64,
}

impl<'a> FileExporter<'a> {
    fn new(
        source: &'a dyn Source,
        by_path: &'a HashMap<&'a str, &'a Entry>,
        dir: &'a Path,
        max_path_len: usize,
    ) -> Self {
        FileExporter {
            source,
            by_path,
            dir,
            max_path_len,
            report: Vec::new(),
            skipped_too_long: Vec::new(),
            portability_warnings: Vec::new(),
            bytes: 0,
        }
    }

    /// Write `entry` to `dest` and record it. `internal_path` is the source path
    /// (label + sidecar lookup key); `output_path` is the destination relative to
    /// `dir` (used for the length guard and the skip records). The length guard runs
    /// BEFORE any bytes are read: an unwritable destination is recorded, not read; a
    /// non-portable (but locally writable) path is still exported, with a warning.
    fn write_one(
        &mut self,
        entry: &Entry,
        internal_path: &str,
        output_path: &str,
        dest: &Path,
    ) -> Result<()> {
        match check_export_path(self.dir, output_path, self.max_path_len) {
            PathCheck::Skip(reason) => {
                self.skipped_too_long.push(SkippedFile {
                    internal_path: internal_path.to_string(),
                    output_path: output_path.to_string(),
                    reason,
                });
                return Ok(());
            }
            PathCheck::NotPortable(reason) => self.portability_warnings.push(SkippedFile {
                internal_path: internal_path.to_string(),
                output_path: output_path.to_string(),
                reason,
            }),
            PathCheck::Ok => {}
        }
        // Content is read (and decompressed/read-from-disk) once, here.
        let content = self.source.content(entry)?;
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("cannot create {}", parent.display()))?;
        }
        fs::write(dest, &content).with_context(|| format!("cannot write {}", dest.display()))?;
        self.bytes += content.len() as u64;
        let integrity = self.source.integrity_check(entry).into();
        self.report.push(exported_file(
            internal_path,
            dest,
            self.dir,
            &content,
            integrity,
        )?);

        // Sidecars to export come from the file's inspector (e.g. SQLite's -wal).
        let suffixes = crate::formats::inspect::sidecars_for(internal_path, &content);
        let mut sidecars = export_sidecars(
            self.source,
            self.by_path,
            internal_path,
            dest,
            self.dir,
            suffixes,
        )?;
        self.bytes += sidecars.iter().map(|f| f.size).sum::<u64>();
        self.report.append(&mut sidecars);
        Ok(())
    }

    /// Consume the accumulated files into an [`ExportOutcome::Exported`]. `skipped`
    /// is the count of listed files absent from the source (manifest re-ingestion
    /// only; a fresh export passes 0).
    fn finish(self, skipped: usize) -> ExportOutcome {
        ExportOutcome::Exported {
            files: self.report.len(),
            bytes: self.bytes,
            skipped,
            report: self.report,
            skipped_too_long: self.skipped_too_long,
            portability_warnings: self.portability_warnings,
        }
    }
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
    max_path_len: usize,
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

    let mut exporter = FileExporter::new(source, &by_path, dir, max_path_len);
    for (item, file) in plan.items.iter().zip(files) {
        let dest = dir.join(&item.folder).join(&item.name);
        exporter.write_one(&file.entry, &file.entry.name, &item.output_path(), &dest)?;
    }
    Ok(exporter.finish(0))
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
    max_path_len: usize,
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

    let mut exporter = FileExporter::new(source, &by_path, dir, max_path_len);
    let mut skipped = 0usize;
    for entry in &manifest.files {
        let Some(found) = by_path.get(entry.internal_path.as_str()) else {
            skipped += 1; // listed file is absent from this archive
            continue;
        };
        // The manifest path is joined through `safe_join` so a tampered manifest
        // cannot escape `dir`; a fresh export builds its own `dir/folder/name`.
        let dest = safe_join(dir, &entry.output_path);
        exporter.write_one(found, &entry.internal_path, &entry.output_path, &dest)?;
    }
    Ok(exporter.finish(skipped))
}

/// Export a file's declared sidecars into the same folder as `main_dest` (e.g.
/// `sms.db` → `sms.db-wal`), returning one [`ExportedFile`] (with hash) per
/// sidecar written.
///
/// The `suffixes` come from the file's inspector (see
/// [`crate::formats::inspect::sidecars_for`]); each one names a sibling entry to fetch if
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
        let integrity = source.integrity_check(entry).into();
        written.push(exported_file(
            &sidecar_path,
            &dest,
            dir,
            &content,
            integrity,
        )?);
    }
    Ok(written)
}

/// Build an [`ExportedFile`] record with full integrity attestation.
///
/// Hashes the source bytes (`content`), reads the just-written file back from
/// disk and hashes that, and records both plus whether they match — catching a
/// silent copy error. `stored_integrity` carries any source-recorded digest
/// check (an encrypted backup's per-file SHA-1).
fn exported_file(
    internal_path: &str,
    dest: &Path,
    dir: &Path,
    content: &[u8],
    stored_integrity: StoredIntegrity,
) -> Result<ExportedFile> {
    let output_path = dest
        .strip_prefix(dir)
        .unwrap_or(dest)
        .to_string_lossy()
        .replace('\\', "/");
    let source_sha256 = sha256_hex(content);
    // Read the bytes back from disk so the recorded hash is of what actually
    // landed, not just of what we intended to write — this is the copy check.
    let written = fs::read(dest).with_context(|| format!("cannot read back {}", dest.display()))?;
    let sha256 = sha256_hex(&written);
    let copy_verified = sha256 == source_sha256;
    Ok(ExportedFile {
        internal_path: internal_path.to_string(),
        output_path,
        size: content.len() as u64,
        sha256,
        source_sha256,
        copy_verified,
        stored_integrity,
    })
}

/// Join a manifest `output_path` under `dir`, dropping any `..`/empty/absolute
/// components so a tampered manifest can never escape the destination.
///
/// WHY backslashes are split too: a path like `a\..\..\evil.exe` contains no `/`,
/// so a `/`-only split would hand it to the OS as a single opaque segment. On
/// Windows the OS then resolves the backslashes and `..`, escaping the destination
/// directory (zip-slip via a tampered manifest). Treating `\` as a separator on all
/// platforms decomposes such paths into individual segments and subjects every `..`
/// to the same rejection as a `/`-separated traversal.
fn safe_join(dir: &Path, output_path: &str) -> std::path::PathBuf {
    let mut dest = dir.to_path_buf();
    // Split on both `/` and `\` so backslash-encoded traversal is decomposed and
    // any `..` components are rejected just like a forward-slash traversal would be.
    for segment in output_path.split(['/', '\\']) {
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
/// Strips the directory part, then sanitises the last segment via
/// [`sanitise_segment`].
fn sanitise_basename(path: &str) -> String {
    sanitise_segment(path.rsplit('/').next().unwrap_or(path))
}

/// Make one path component host-safe.
///
/// Replaces characters illegal on Windows/Unix with `_`, trims trailing dots and
/// spaces (which Windows rejects), and falls back to a placeholder for an empty
/// result (e.g. a directory placeholder entry). WHY a per-segment helper:
/// [`plan_tree`] rebuilds a whole relative tree and must sanitise every segment,
/// not just the basename — both callers share this one rule so the two layouts
/// can never sanitise differently.
fn sanitise_segment(segment: &str) -> String {
    let mut name: String = segment
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::models::{Entry, Location};
    use crate::ops::search::MatchedFile;
    use std::path::PathBuf;

    /// A loose-file [`MatchedFile`] at `name` of `size` bytes, for the planner tests.
    fn loose(name: &str, size: u64) -> MatchedFile {
        MatchedFile {
            entry: Entry {
                name: name.to_string(),
                uncompressed_size: size,
                mtime: None,
                location: Location::Loose { path: name.into() },
            },
            offsets: Vec::new(),
        }
    }

    /// `plan_tree` preserves the directory tree under a per-container label, and
    /// routes each file to the LONGEST matching root prefix.
    #[test]
    fn plan_tree_preserves_tree_under_longest_root() {
        let files = [
            loose("/c/Data/App/GUID/Library/Preferences/x.plist", 10),
            loose("/c/Data/App/GUID/Extra/GUID2/y.db", 20),
        ];
        let roots = [
            (
                "/c/Data/App/GUID".to_string(),
                "id/AppData_GUID".to_string(),
            ),
            // A deeper, more specific root that must win for the second file.
            (
                "/c/Data/App/GUID/Extra/GUID2".to_string(),
                "id/Extension_GUID2".to_string(),
            ),
        ];
        let plan = plan_tree(&files, &roots);

        assert_eq!(plan.total_size, 30);
        assert_eq!(plan.items[0].folder, "id/AppData_GUID/Library/Preferences");
        assert_eq!(plan.items[0].name, "x.plist");
        // The second file is under both roots; the longest (the extension) wins.
        assert_eq!(plan.items[1].folder, "id/Extension_GUID2");
        assert_eq!(plan.items[1].name, "y.db");
    }

    /// The path-length guard: a safe path passes, `0` disables it, a >255-char
    /// component is unwritable everywhere (`Skip`), and a long relative path is a
    /// portability warning on non-Windows (the host these tests run on).
    #[test]
    fn path_length_guard_classifies_paths() {
        let dir = Path::new("/out");
        assert!(matches!(
            check_export_path(dir, "app/file.db", 260),
            PathCheck::Ok
        ));
        // Disabled guard never flags anything.
        assert!(matches!(
            check_export_path(dir, &"a".repeat(300), 0),
            PathCheck::Ok
        ));
        // A single component over 255 cannot exist on any filesystem.
        let long_component = format!("{}/f", "b".repeat(300));
        assert!(matches!(
            check_export_path(dir, &long_component, 100_000),
            PathCheck::Skip(_)
        ));
    }

    /// On a non-Windows host, an over-limit RELATIVE path is exported but flagged
    /// as not Windows-portable (rather than skipped).
    #[cfg(not(target_os = "windows"))]
    #[test]
    fn long_relative_path_is_a_portability_warning_off_windows() {
        let dir = Path::new("/out");
        // 300 single-char segments: no component exceeds 255, but the whole path does.
        let rel = vec!["a"; 300].join("/");
        assert!(matches!(
            check_export_path(dir, &rel, 260),
            PathCheck::NotPortable(_)
        ));
    }

    /// `safe_join` must not let a backslash-encoded traversal escape the destination.
    ///
    /// A tampered manifest entry like `a\..\..\evil.exe` contains no `/`, so a
    /// `/`-only split would pass it to the OS as one segment; on Windows the OS
    /// resolves the `..` components and escapes the destination directory.  Splitting
    /// on `\` too decomposes the payload so every `..` is dropped.
    #[test]
    fn safe_join_blocks_backslash_traversal() {
        let dir = PathBuf::from("/export/out");

        // Forward-slash traversal (already blocked before this fix).
        let result = safe_join(&dir, "../../etc/passwd");
        assert!(
            result.starts_with(&dir),
            "forward-slash traversal escaped: {result:?}"
        );

        // Backslash traversal — the fix under test.
        let result = safe_join(&dir, r"a\..\..\evil.exe");
        assert!(
            result.starts_with(&dir),
            "backslash traversal escaped: {result:?}"
        );

        // Mixed separators.
        let result = safe_join(&dir, r"a\..\../secret");
        assert!(
            result.starts_with(&dir),
            "mixed traversal escaped: {result:?}"
        );

        // A legitimate path must still resolve correctly under the dir.
        let result = safe_join(&dir, "folder/file.db");
        assert_eq!(result, dir.join("folder").join("file.db"));
    }
}
