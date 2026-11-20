//! Write an export as one ZIP archive: each planned file, its sidecars and its
//! decrypted copy as members, and the export report inside, attesting every byte.
//!
//! Defines: [`export_files`], [`export_from_manifest`], [`ExportOutcome`] and
//! [`ExportArchive`], [`WINDOWS_MAX_PATH`], [`REPORT_MEMBER`], and the
//! `FileExporter` both share.
//! Used by: the binary's `grep`/`find`/`diff --export`, `app export` and `export`.
//! Uses: `report::zip_writer` (the format), `report::publish` (failing closed: the
//! partial file, the read-back check, publishing with a `.sha256` sidecar, never
//! over an existing name),
//! `report::export::{plan, record, manifest}`, `core::source`,
//! `ops::decrypting::DerivedCopy` (the decrypted-copy hook).
//!
//! WHY a ZIP and never a folder: a device path is long before the operator's
//! destination is added, and a tree on disk crosses Windows' 260-character limit,
//! where tools that do not handle long paths cannot open it (the folder export
//! skipped such files: data silently missing from the export). Inside a ZIP a path is
//! only a member name, so every file is exported, under its exact name, on every
//! platform; a name too long to extract on Windows is still written, and listed.
//! WHY written member by member and not a folder zipped afterwards: the folder would
//! hit the same limit while being filled.
//!
//! Failing closed: the archive is written beside its destination under a temporary
//! name, read back with the tool's own reader, and only then moved into place, so a
//! failed run never leaves something that looks like a finished export.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::Result;

use super::manifest::Manifest;
use super::plan::{ExportPlan, Renamed, decrypted_name_numbered, fold_case};
use super::record::{ExportNotes, ExportedFile, FileNote, StoredIntegrity, write_export_report};
use crate::core::models::{Entry, RunInfo};
use crate::core::source::Source;
use crate::core::util::now_unix;
use crate::core::util::{UtcTime, sha256_hex};
use crate::ops::decrypting::{Derived, DerivedCopy};
use crate::ops::search::MatchedFile;
use crate::report::publish::{
    PartialFile, Reservation, check_and_hash, prepare, publish_new, reserve,
};
use crate::report::zip_writer::ZipWriter;

/// The Windows path limit (`MAX_PATH`) a member name is checked against, in
/// characters.
///
/// WHY 260: classic Windows `MAX_PATH`. A member whose name alone exceeds it cannot
/// be extracted under any Windows folder by tools that do not handle long paths; it
/// is written all the same, and listed, so the examiner knows before extracting.
pub const WINDOWS_MAX_PATH: usize = 260;

/// The longest file or folder name the common file systems hold (`NAME_MAX`, NTFS).
const MAX_COMPONENT_LEN: usize = 255;

/// The export report's name inside the archive. No exported file takes it: every
/// planned file sits in a folder, and a manifest's file of that name is renamed.
pub const REPORT_MEMBER: &str = "export-report.json";

/// A finished export archive.
pub struct ExportArchive {
    pub files: usize,
    pub bytes: u64,
    /// Manifest entries whose file was not found in the source (re-ingest).
    pub skipped: usize,
    /// Each written file with its SHA-256 (main files, sidecars, decrypted copies).
    pub report: Vec<ExportedFile>,
    /// Files written differently, to report alongside: names too long to extract on
    /// Windows, databases whose decrypted copy failed, files written under another
    /// name.
    pub notes: ExportNotes,
    /// Where the archive is, its SHA-256, and its `.sha256` sidecar.
    pub archive: PathBuf,
    pub archive_sha256: String,
    pub sidecar: PathBuf,
}

/// The result of an export attempt.
pub enum ExportOutcome {
    Exported(ExportArchive),
    /// Over `--max-size`: nothing written.
    Refused {
        total_size: u64,
        cap: u64,
    },
}

/// Why `name`, a member's name, could not be extracted on Windows or on any common
/// file system, if so.
pub(crate) fn extraction_warning(name: &str) -> Option<String> {
    if let Some(len) = name
        .split('/')
        .map(|c| c.chars().count())
        .find(|&len| len > MAX_COMPONENT_LEN)
    {
        return Some(format!(
            "a name of {len} characters exceeds the {MAX_COMPONENT_LEN}-character file-system \
             limit if extracted"
        ));
    }
    let len = name.chars().count();
    (len > WINDOWS_MAX_PATH).then(|| {
        format!("path length {len} exceeds the Windows limit of {WINDOWS_MAX_PATH} if extracted")
    })
}

/// A member name from a relative output path: split on `/` and `\`, with empty, `.`
/// and `..` parts dropped, so a tampered manifest cannot name a member that escapes
/// the folder it is extracted to.
///
/// WHY backslashes are split too: `a\..\..\evil.exe` contains no `/`, and an
/// extractor on Windows would resolve the backslashes and `..`.
pub(super) fn member_name(output_path: &str) -> String {
    output_path
        .split(['/', '\\'])
        .filter(|s| !s.is_empty() && *s != "." && *s != "..")
        .collect::<Vec<_>>()
        .join("/")
}

/// Writes one file (plus its sidecars and decrypted copy) per call into the archive
/// and accumulates the outcome.
///
/// WHY this exists: a fresh export ([`export_files`]) and a manifest re-ingestion
/// ([`export_from_manifest`]) share the per-file body and differ only in how each
/// computes the member name and iterates.
struct FileExporter<'a> {
    source: &'a dyn Source,
    zip: ZipWriter,
    /// Writes a derived copy (a decrypted database) beside each file that has one.
    derive: Option<&'a dyn DerivedCopy>,
    /// Every member name taken so far or reserved by the plan, case-folded: a derived
    /// copy never takes a planned file's name.
    claimed: HashSet<String>,
    /// Every member the plan itself fills (case-folded). A sidecar whose name is one
    /// of them is a planned item of its own (a tree export plans a database's `-wal`
    /// beside it), so it is not written a second time as a sidecar.
    planned: HashSet<String>,
    /// Every member written, case-folded. WHY folded: extracted on Windows or macOS,
    /// two names differing only in case (or accent form) would be one file.
    written: HashSet<String>,
    /// The full entry list, so a written file's declared sidecars can be fetched.
    by_path: &'a HashMap<&'a str, &'a Entry>,
    /// `--max-size`, held to the bytes actually written: sidecars and decrypted
    /// copies count too, which the plan's total does not include.
    cap: Option<u64>,
    report: Vec<ExportedFile>,
    notes: ExportNotes,
    bytes: u64,
}

/// Writing a member would take the export over `--max-size`: the export stops, and
/// its partial archive is removed.
#[derive(Debug)]
struct OverCap {
    would_write: u64,
    cap: u64,
}

impl std::fmt::Display for OverCap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the export would exceed --max-size {}", self.cap)
    }
}

impl std::error::Error for OverCap {}

impl<'a> FileExporter<'a> {
    fn new(
        source: &'a dyn Source,
        zip: ZipWriter,
        by_path: &'a HashMap<&'a str, &'a Entry>,
        planned: HashSet<String>,
        cap: Option<u64>,
    ) -> Self {
        let mut claimed = planned.clone();
        claimed.insert(fold_case(REPORT_MEMBER));
        FileExporter {
            source,
            zip,
            derive: None,
            claimed,
            planned,
            written: HashSet::from([fold_case(REPORT_MEMBER)]),
            by_path,
            cap,
            report: Vec::new(),
            notes: ExportNotes::default(),
            bytes: 0,
        }
    }

    /// Write `entry` as the member `name` and record it, then its decrypted copy and
    /// its sidecars. `internal_path` is the source path (label + sidecar lookup key).
    fn write_one(&mut self, entry: &Entry, internal_path: &str, name: &str) -> Result<()> {
        // Content is read (and decompressed/read-from-disk) once, here.
        let content = self.source.content(entry)?;
        let integrity = self.source.integrity_check(entry).into();
        let name = self.write_member(internal_path, name, entry.mtime, &content, integrity)?;

        // A derived copy (a decrypted database) goes beside the original.
        // A copy that should exist but cannot be made is recorded, never dropped:
        // `find` and `app export` run no search that would report it otherwise.
        let derived = match self
            .derive
            .filter(|d| d.wants(entry))
            .and_then(|d| d.derive(entry, &content))
        {
            Some(Ok(derived)) => Some(derived),
            Some(Err(reason)) => {
                self.notes.undecrypted.push(FileNote {
                    internal_path: internal_path.to_string(),
                    output_path: name.clone(),
                    reason,
                });
                None
            }
            None => None,
        };
        if let Some(derived) = &derived {
            self.write_derived(internal_path, &name, entry.mtime, derived)?;
        }

        // Sidecars to export come from the file's inspector (e.g. SQLite's -wal). An
        // encrypted database is not recognised as SQLite, so its decrypted form names
        // them instead: its -wal is evidence even though the copy already applied it.
        let mut suffixes = crate::formats::inspect::sidecars_for(internal_path, &content);
        if suffixes.is_empty()
            && let Some(derived) = &derived
        {
            suffixes = crate::formats::inspect::sidecars_for(internal_path, &derived.bytes);
        }
        self.write_sidecars(internal_path, &name, suffixes)
    }

    /// Add `bytes` as a member named `wanted`, or, when that name is taken, the first
    /// free `name~1`, `name~2`, … (the rename recorded); read it back and record it.
    /// Returns the name used.
    fn write_member(
        &mut self,
        internal_path: &str,
        wanted: &str,
        mtime: Option<u64>,
        bytes: &[u8],
        stored_integrity: StoredIntegrity,
    ) -> Result<String> {
        let name = (0usize..)
            .map(|n| {
                if n == 0 {
                    wanted.to_string()
                } else {
                    format!("{wanted}~{n}")
                }
            })
            .find(|candidate| !self.written.contains(&fold_case(candidate)))
            .expect("an unbounded range always yields a free name");
        if name != wanted {
            self.notes.renamed.push(Renamed {
                internal_path: internal_path.to_string(),
                wanted: wanted.to_string(),
                used: name.clone(),
            });
        }
        self.written.insert(fold_case(&name));
        self.claimed.insert(fold_case(&name));
        if let Some(reason) = extraction_warning(&name) {
            self.notes.portability_warnings.push(FileNote {
                internal_path: internal_path.to_string(),
                output_path: name.clone(),
                reason,
            });
        }

        let would_write = self.bytes + bytes.len() as u64;
        if let Some(cap) = self.cap
            && would_write > cap
        {
            return Err(OverCap { would_write, cap }.into());
        }
        let member = self.zip.add_file(&name, mtime, bytes)?;
        // Read the member back from the archive, so the recorded hash is of what
        // landed, not of what was meant to be written: this is the copy check.
        let sha256 = self.zip.sha256_of(member)?;
        let source_sha256 = sha256_hex(bytes);
        self.bytes += bytes.len() as u64;
        self.report.push(ExportedFile {
            internal_path: internal_path.to_string(),
            output_path: name.clone(),
            size: bytes.len() as u64,
            copy_verified: sha256 == source_sha256,
            sha256,
            source_sha256,
            stored_integrity,
            mtime_utc: mtime.map(|m| UtcTime::from_unix(m).iso()),
            derived: None,
        });
        Ok(name)
    }

    /// Write a file's declared sidecars beside `main` (e.g. `sms.db` → `sms.db-wal`),
    /// each recorded with its hashes.
    ///
    /// The `suffixes` come from the file's inspector (see
    /// [`crate::formats::inspect::sidecars_for`]); each one names a sibling entry to
    /// fetch if present. For SQLite this keeps the exported database complete:
    /// uncommitted rows live in the `-wal`.
    fn write_sidecars(&mut self, internal_path: &str, main: &str, suffixes: &[&str]) -> Result<()> {
        for suffix in suffixes {
            let sidecar_path = format!("{internal_path}{suffix}");
            let wanted = format!("{main}{suffix}");
            if self.planned.contains(&fold_case(&wanted)) {
                continue;
            }
            let Some(entry) = self.by_path.get(sidecar_path.as_str()) else {
                continue;
            };
            let content = self.source.content(entry)?;
            let integrity = self.source.integrity_check(entry).into();
            self.write_member(&sidecar_path, &wanted, entry.mtime, &content, integrity)?;
        }
        Ok(())
    }

    /// Write `derived` beside `original` (the original's member name) and record it.
    /// The record keeps the original's internal path and says, in `derived`, how the
    /// bytes were produced.
    fn write_derived(
        &mut self,
        internal_path: &str,
        original: &str,
        mtime: Option<u64>,
        derived: &Derived,
    ) -> Result<()> {
        let (folder, file) = match original.rsplit_once('/') {
            Some((folder, file)) => (Some(folder), file),
            None => (None, original),
        };
        // The first free name: `x.decrypted.db`, then `x.decrypted-2.db`, … taken by
        // no planned or written member.
        let wanted = (1..)
            .map(|n| {
                let name = decrypted_name_numbered(file, n);
                match folder {
                    Some(folder) => format!("{folder}/{name}"),
                    None => name,
                }
            })
            .find(|name| !self.claimed.contains(&fold_case(name)))
            .expect("an unbounded range always yields a free name");
        self.write_member(
            internal_path,
            &wanted,
            mtime,
            &derived.bytes,
            StoredIntegrity::Unrecorded,
        )?;
        if let Some(record) = self.report.last_mut() {
            record.derived = Some(derived.note.clone());
        }
        Ok(())
    }

    /// Write the report inside the archive, finish it, read it back, and move it to
    /// `output` with its `.sha256` sidecar. `skipped` is the count of listed files
    /// absent from the source (manifest re-ingestion only; a fresh export passes 0).
    fn finish(
        mut self,
        reservation: Reservation,
        partial: PartialFile,
        output: &Path,
        run: &RunInfo,
        skipped: usize,
    ) -> Result<ExportOutcome> {
        let mut record = Vec::new();
        write_export_report(run, &self.report, &self.notes, &mut record)?;
        self.zip
            .add_file(REPORT_MEMBER, Some(now_unix()), &record)?;
        self.zip.finish()?;
        let archive_sha256 = check_and_hash(&partial.0, self.report.len() + 1)?;
        let sidecar = publish_new(&partial.0, output, &archive_sha256, reservation)?;
        Ok(ExportOutcome::Exported(ExportArchive {
            files: self.report.len(),
            bytes: self.bytes,
            skipped,
            report: self.report,
            notes: self.notes,
            archive: output.to_path_buf(),
            archive_sha256,
            sidecar,
        }))
    }
}

/// Claim `output` (a new name, never replacing anything) and create the partial
/// archive beside it.
fn start(output: &Path) -> Result<(Reservation, PartialFile, ZipWriter)> {
    let partial = prepare(output, None)?;
    let reservation = reserve(output)?;
    let zip = ZipWriter::create(&partial.0)?;
    Ok((reservation, partial, zip))
}

/// Export the matched files to the archive `output` (a new `.zip`), with the report
/// for `run` inside.
///
/// When `max_size` is set and the planned total exceeds it, nothing is written and
/// `Refused` is returned — the caller can still have written the manifest, so the
/// operator can inspect the total and adjust before retrying. The cap also holds for
/// the bytes actually written (sidecars and decrypted copies included): an export
/// that would go over it stops, leaves nothing, and is `Refused`.
///
/// With `derive`, each file that has a derived form (a decrypted database) also gets
/// that copy written beside it.
pub fn export_files(
    plan: &ExportPlan,
    source: &dyn Source,
    files: &[MatchedFile],
    output: &Path,
    run: &RunInfo,
    max_size: Option<u64>,
    derive: Option<&dyn DerivedCopy>,
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
    let names: Vec<String> = plan
        .items
        .iter()
        .map(|i| member_name(&i.output_path()))
        .collect();
    let planned = names.iter().map(|n| fold_case(n)).collect();

    let (reservation, partial, zip) = start(output)?;
    let mut exporter = FileExporter::new(source, zip, &by_path, planned, max_size);
    exporter.derive = derive;
    let written = names
        .iter()
        .zip(files)
        .try_for_each(|(name, file)| exporter.write_one(&file.entry, &file.entry.name, name));
    if let Err(e) = written {
        return refused_or(e);
    }
    exporter.finish(reservation, partial, output, run, 0)
}

/// A write that went over `--max-size` as a [`Refused`](ExportOutcome::Refused)
/// outcome, any other error as it is. Either way the partial archive and the name's
/// reservation are removed as the caller returns (the writer, declared after them,
/// is closed first).
fn refused_or(e: anyhow::Error) -> Result<ExportOutcome> {
    match e.downcast::<OverCap>() {
        Ok(over) => Ok(ExportOutcome::Refused {
            total_size: over.would_write,
            cap: over.cap,
        }),
        Err(e) => Err(e),
    }
}

/// Export the files listed in `manifest` out of `source` into the archive `output`,
/// reusing the manifest's recorded output paths as member names and its run record
/// in the report.
///
/// This re-ingestion path does not search: it locates each listed file in the
/// source by its internal path. The size cap is honoured as for a fresh export.
pub fn export_from_manifest(
    manifest: &Manifest,
    source: &dyn Source,
    output: &Path,
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
    let planned = manifest
        .files
        .iter()
        .map(|f| fold_case(&member_name(&f.output_path)))
        .collect();

    let (reservation, partial, zip) = start(output)?;
    let mut exporter = FileExporter::new(source, zip, &by_path, planned, max_size);
    let mut skipped = 0usize;
    for entry in &manifest.files {
        let Some(found) = by_path.get(entry.internal_path.as_str()) else {
            skipped += 1; // listed file is absent from this source
            continue;
        };
        let name = member_name(&entry.output_path);
        if let Err(e) = exporter.write_one(found, &entry.internal_path, &name) {
            return refused_or(e);
        }
    }
    exporter.finish(reservation, partial, output, &manifest.run, skipped)
}
