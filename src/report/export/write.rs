//! Write an export to disk: copy each planned file, its sidecars and its decrypted
//! copy, guarding path lengths and attesting every byte written.
//!
//! Defines: [`export_files`], [`export_from_manifest`], [`ExportOutcome`],
//! [`DEFAULT_MAX_PATH_LEN`], and the `FileExporter` both share.
//! Used by: the binary's `grep`/`find`/`diff`/`app export`/`export` commands.
//! Uses: `report::export::{plan, record, manifest}`, `core::source`,
//! `ops::decrypting::DerivedCopy` (the decrypted-copy hook).

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use super::manifest::Manifest;
use super::plan::{ExportPlan, Renamed, decrypted_name_numbered, fold_case};
use super::record::{ExportNotes, ExportedFile, SkippedFile, StoredIntegrity};
use crate::core::models::Entry;
use crate::core::source::Source;
use crate::core::util::sha256_hex;
use crate::ops::decrypting::{Derived, DerivedCopy};
use crate::ops::search::MatchedFile;

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

/// The result of an export attempt.
pub enum ExportOutcome {
    Exported {
        files: usize,
        bytes: u64,
        /// Manifest entries whose file was not found in the archive (re-ingest).
        skipped: usize,
        /// Each written file with its SHA-256 (main files and sidecars).
        report: Vec<ExportedFile>,
        /// Files skipped or written differently, to report alongside: paths too long
        /// for this platform (skipped) or for Windows (written, warned), databases
        /// whose decrypted copy failed, and files written under another name.
        notes: ExportNotes,
    },
    Refused {
        total_size: u64,
        cap: u64,
    },
}

/// The verdict of the path-length guard for one file.
pub(super) enum PathCheck {
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
pub(super) fn check_export_path(dir: &Path, output_path: &str, max_path_len: usize) -> PathCheck {
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
    /// Writes a derived copy (a decrypted database) beside each file that has one.
    derive: Option<&'a dyn DerivedCopy>,
    /// Every output path taken so far, case-folded: the plan's, then each derived
    /// copy's, so a derived copy never overwrites a planned file or the reverse.
    claimed: HashSet<String>,
    /// Every destination the plan itself fills (relative, case-folded). A sidecar
    /// whose destination is one of them is a planned item of its own (a tree export
    /// plans a database's `-wal` beside it), so it is not written a second time as a
    /// sidecar, which would land as `name~1` since an export never overwrites. In the
    /// one-folder-per-file layout the destinations differ, and the sidecar is still
    /// written beside its database.
    planned: HashSet<String>,
    /// The full entry list, so a written file's declared sidecars can be fetched.
    by_path: &'a HashMap<&'a str, &'a Entry>,
    dir: &'a Path,
    max_path_len: usize,
    report: Vec<ExportedFile>,
    notes: ExportNotes,
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
            derive: None,
            claimed: HashSet::new(),
            planned: HashSet::new(),
            by_path,
            dir,
            max_path_len,
            report: Vec::new(),
            notes: ExportNotes::default(),
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
                self.notes.skipped_too_long.push(SkippedFile {
                    internal_path: internal_path.to_string(),
                    output_path: output_path.to_string(),
                    reason,
                });
                return Ok(());
            }
            PathCheck::NotPortable(reason) => self.notes.portability_warnings.push(SkippedFile {
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
        let dest = &self.write_new(internal_path, dest, &content)?;
        self.bytes += content.len() as u64;
        let integrity = self.source.integrity_check(entry).into();
        self.report.push(exported_file(
            internal_path,
            dest,
            self.dir,
            &content,
            integrity,
        )?);

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
                self.notes.undecrypted.push(SkippedFile {
                    internal_path: internal_path.to_string(),
                    output_path: output_path.to_string(),
                    reason,
                });
                None
            }
            None => None,
        };
        if let Some(derived) = &derived {
            self.write_derived(internal_path, output_path, dest, derived)?;
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
        self.write_sidecars(internal_path, dest, suffixes)
    }

    /// Write `bytes` to `dest`, read-only, never over an existing file: if the name
    /// is taken, the file is written as `name~1`, `name~2`, … and the rename is
    /// recorded. Returns the path actually written.
    fn write_new(&mut self, internal_path: &str, dest: &Path, bytes: &[u8]) -> Result<PathBuf> {
        let written = write_read_only(dest, bytes)?;
        if written != dest {
            let relative = |p: &Path| {
                p.strip_prefix(self.dir)
                    .unwrap_or(p)
                    .to_string_lossy()
                    .replace('\\', "/")
            };
            self.notes.renamed.push(Renamed {
                internal_path: internal_path.to_string(),
                wanted: relative(dest),
                used: relative(&written),
            });
        }
        Ok(written)
    }

    /// Write a file's declared sidecars into the same folder as `main_dest` (e.g.
    /// `sms.db` → `sms.db-wal`), each recorded with its hashes.
    ///
    /// The `suffixes` come from the file's inspector (see
    /// [`crate::formats::inspect::sidecars_for`]); each one names a sibling entry to
    /// fetch if present. For SQLite this keeps the exported database complete:
    /// uncommitted rows live in the `-wal`.
    fn write_sidecars(
        &mut self,
        internal_path: &str,
        main_dest: &Path,
        suffixes: &[&str],
    ) -> Result<()> {
        let main_name = main_dest
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        for suffix in suffixes {
            let sidecar_path = format!("{internal_path}{suffix}");
            let wanted = main_dest.with_file_name(format!("{main_name}{suffix}"));
            let relative = wanted
                .strip_prefix(self.dir)
                .unwrap_or(&wanted)
                .to_string_lossy()
                .replace('\\', "/");
            if self.planned.contains(&fold_case(&relative)) {
                continue;
            }
            let Some(entry) = self.by_path.get(sidecar_path.as_str()) else {
                continue;
            };
            let content = self.source.content(entry)?;
            let dest = self.write_new(&sidecar_path, &wanted, &content)?;
            let integrity = self.source.integrity_check(entry).into();
            self.bytes += content.len() as u64;
            self.report.push(exported_file(
                &sidecar_path,
                &dest,
                self.dir,
                &content,
                integrity,
            )?);
        }
        Ok(())
    }

    /// Write `derived` beside `dest` (the original's destination) and record it.
    ///
    /// The same path-length guard as the original applies. The record keeps the
    /// original's internal path and says, in `derived`, how the bytes were produced.
    fn write_derived(
        &mut self,
        internal_path: &str,
        output_path: &str,
        dest: &Path,
        derived: &Derived,
    ) -> Result<()> {
        let original = dest.file_name().map_or_else(
            || "unnamed".to_string(),
            |n| n.to_string_lossy().into_owned(),
        );
        let in_folder = |name: &str| match output_path.rsplit_once('/') {
            Some((folder, _)) => format!("{folder}/{name}"),
            None => name.to_string(),
        };
        // The first free name: `x.decrypted.db`, then `x.decrypted-2.db`, … taken
        // neither by a planned file nor by a file already on disk.
        let (name, derived_output) = (1..)
            .map(|n| {
                let name = decrypted_name_numbered(&original, n);
                let output = in_folder(&name);
                (name, output)
            })
            .find(|(_, output)| !self.claimed.contains(&fold_case(output)))
            .expect("an unbounded range always yields a free name");
        self.claimed.insert(fold_case(&derived_output));
        let derived_dest = dest.with_file_name(&name);
        if let PathCheck::Skip(reason) =
            check_export_path(self.dir, &derived_output, self.max_path_len)
        {
            self.notes.skipped_too_long.push(SkippedFile {
                internal_path: internal_path.to_string(),
                output_path: derived_output,
                reason,
            });
            return Ok(());
        }
        let derived_dest = self.write_new(internal_path, &derived_dest, &derived.bytes)?;
        self.bytes += derived.bytes.len() as u64;
        let mut record = exported_file(
            internal_path,
            &derived_dest,
            self.dir,
            &derived.bytes,
            StoredIntegrity::Unrecorded,
        )?;
        record.derived = Some(derived.note.clone());
        self.report.push(record);
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
            notes: self.notes,
        }
    }
}

/// Export the matched files to `dir`.
///
/// When `max_size` is set and the total exceeds it, nothing is written and
/// `Refused` is returned — the caller can still have written the manifest, so
/// the operator can inspect the total and adjust before retrying.
///
/// With `derive`, each file that has a derived form (a decrypted database) also gets
/// that copy written beside it.
pub fn export_files(
    plan: &ExportPlan,
    source: &dyn Source,
    files: &[MatchedFile],
    dir: &Path,
    max_size: Option<u64>,
    max_path_len: usize,
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

    let mut exporter = FileExporter::new(source, &by_path, dir, max_path_len);
    exporter.derive = derive;
    exporter.claimed = plan
        .items
        .iter()
        .map(|i| fold_case(&i.output_path()))
        .collect();
    exporter.planned = exporter.claimed.clone();
    for (item, file) in plan.items.iter().zip(files) {
        let dest = dir.join(&item.folder).join(&item.name);
        exporter.write_one(&file.entry, &file.entry.name, &item.output_path(), &dest)?;
    }
    Ok(exporter.finish(0))
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
    exporter.planned = manifest
        .files
        .iter()
        .map(|f| fold_case(&f.output_path))
        .collect();
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

/// Write `bytes` to a new file at `dest` and make it read-only, never replacing an
/// existing file: when `dest` is taken, the first free `name~1`, `name~2`, … is used.
/// Returns the path written.
///
/// WHY "create new" rather than checking first: the operating system then decides
/// what "taken" means, so a name this file system treats as equal to an existing one
/// (a case or accent-form variant the export plan could not foresee, or a file left
/// by an earlier export) is never overwritten. WHY read-only: an exported file is
/// evidence; `--work-copy` makes an editable copy for analysis.
pub fn write_read_only(dest: &Path, bytes: &[u8]) -> Result<PathBuf> {
    let file_name = dest
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    for n in 0usize.. {
        let candidate = if n == 0 {
            dest.to_path_buf()
        } else {
            dest.with_file_name(format!("{file_name}~{n}"))
        };
        let mut file = match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(e).with_context(|| format!("cannot create {}", candidate.display()));
            }
        };
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .with_context(|| format!("cannot write {}", candidate.display()))?;
        drop(file);
        set_read_only(&candidate)?;
        return Ok(candidate);
    }
    unreachable!("an unbounded range always yields a free name")
}

/// Make `path` read-only for everyone.
pub(crate) fn set_read_only(path: &Path) -> Result<()> {
    let mut permissions = fs::metadata(path)
        .with_context(|| format!("cannot read {}", path.display()))?
        .permissions();
    permissions.set_readonly(true);
    fs::set_permissions(path, permissions)
        .with_context(|| format!("cannot make {} read-only", path.display()))
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
        mtime_utc: None,
        derived: None,
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
pub(super) fn safe_join(dir: &Path, output_path: &str) -> std::path::PathBuf {
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
