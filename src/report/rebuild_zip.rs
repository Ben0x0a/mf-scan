//! Write a rebuilt backup as one ZIP archive, with its traceability record inside.
//!
//! Defines: [`RebuildRequest`] and [`write()`] (the archive and its `.sha256` sidecar),
//! and [`TRACEABILITY_MEMBER`].
//! Used by: the binary's `backup rebuild` orchestrator (`cmd::run::backup`).
//! Uses: `report::zip_writer` (the format), `report::export` (the plan and the per-file
//! integrity records every export shares), `core::source`.
//!
//! WHY a ZIP and never a folder: a rebuilt device path is long before the operator's
//! destination is added (`private/var/mobile/Containers/Data/Application/<bundle>/...`,
//! `data/data/<package>/databases/...`). As a tree on disk it can cross Windows' 260-
//! character limit, which tools that do not handle long paths cannot read. Inside a
//! ZIP a path is only a member name, so the output is complete on every platform, and
//! it is the shape a full-filesystem acquisition is delivered in. A member that would
//! exceed the limit if later extracted on Windows is still written, and is listed.
//!
//! Failing closed: the archive is written beside its destination under a temporary name
//! and moved into place only once complete and read back, so a failed run never leaves
//! something that looks like a finished archive.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::{Context, Result, bail};
use serde::Serialize;

use crate::core::models::RunInfo;
use crate::core::source::Source;
use crate::core::source::zip::ZipSource;
use crate::core::util::{UtcTime, sha256_hex};
use crate::ops::rebuild::RebuildDirectory;
use crate::ops::search::MatchedFile;
use crate::platform::ios::backup::common::{ManifestDb, manifest_zip_paths_csv};
use crate::report::export::{
    DEFAULT_MAX_PATH_LEN, ExportPlan, ExportedFile, IntegritySummary, SkippedFile, StoredIntegrity,
};
use crate::report::export::{make_writable, set_read_only};
use crate::report::zip_writer::ZipWriter;

/// The traceability record's name inside the archive. No device path can take this or
/// the two names below: every rebuilt member sits under a device root or an
/// unmapped-domain root.
pub const TRACEABILITY_MEMBER: &str = "_traceability/mf-scan.rebuild.traceability.json";
/// An iOS backup's `Manifest.db` at the archive root, in plaintext.
pub const MANIFEST_MEMBER: &str = "Manifest.db";
/// Each `Manifest.db` row's member name in the archive, joined to it by `fileID`.
pub const ZIP_PATHS_MEMBER: &str = "Manifest.mf-scan.zip-paths.csv";

/// What a backup rebuild needs to write its archive.
pub struct RebuildRequest<'a> {
    pub source: &'a dyn Source,
    pub plan: &'a ExportPlan,
    pub files: &'a [MatchedFile],
    pub directories: &'a [RebuildDirectory],
    pub output: &'a Path,
    /// Replace an archive already at `output`.
    pub force: bool,
    /// Keep going past a file that cannot be read, recording it, and accept a backup
    /// whose payload is damaged. Otherwise both fail the run and write nothing.
    pub continue_on_error: bool,
    pub run: &'a RunInfo,
    pub notes: RebuildNotes,
    /// The backup's `Manifest.db`, for an iOS backup.
    pub manifest: Option<&'a ManifestDb>,
}

/// Facts about the rebuild an examiner must not discover by accident.
#[derive(Debug, Default, Serialize)]
pub struct RebuildNotes {
    /// Domains whose path includes a component not in the evidence.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub synthetic: Vec<String>,
    /// Domains with no known mount point.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub unmapped: Vec<String>,
    /// Link records, which are reported and not recreated.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub links: Vec<String>,
    /// What cut a damaged backup short.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream_error: Option<String>,
}

/// The `Manifest.db` members written to the archive root, all empty for Android.
#[derive(Debug, Default, Serialize)]
pub struct ManifestMembers {
    /// SHA-256 of the plaintext `Manifest.db`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest_db_sha256: Option<String>,
    /// SHA-256 of the zip-path list.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zip_paths_csv_sha256: Option<String>,
    /// Why the zip-path list could not be built. `Manifest.db` itself is still there.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zip_paths_csv_error: Option<String>,
}

impl ManifestMembers {
    fn member_count(&self) -> usize {
        usize::from(self.manifest_db_sha256.is_some())
            + usize::from(self.zip_paths_csv_sha256.is_some())
    }
}

/// What a finished archive holds.
pub struct RebuildOutcome {
    pub report: Vec<ExportedFile>,
    pub bytes: u64,
    pub directories: usize,
    /// Files that could not be read, with `continue_on_error`.
    pub failed: Vec<SkippedFile>,
    /// Members that would exceed the Windows path limit if extracted there.
    pub non_portable: Vec<SkippedFile>,
    /// What was written to the archive root for an iOS backup.
    pub manifest: ManifestMembers,
    /// SHA-256 of the finished archive.
    pub archive_sha256: String,
    pub sidecar: PathBuf,
}

/// The traceability record written into the archive.
#[derive(Serialize)]
struct Traceability<'a> {
    run: &'a RunInfo,
    created_utc: String,
    file_count: usize,
    directory_count: usize,
    integrity: IntegritySummary,
    #[serde(flatten)]
    notes: &'a RebuildNotes,
    #[serde(flatten)]
    manifest: &'a ManifestMembers,
    files: &'a [ExportedFile],
    #[serde(skip_serializing_if = "<[SkippedFile]>::is_empty")]
    failed: &'a [SkippedFile],
    #[serde(skip_serializing_if = "<[SkippedFile]>::is_empty")]
    non_portable: &'a [SkippedFile],
}

/// Removes the temporary archive unless it was moved into place.
pub(crate) struct PartialFile(pub(crate) PathBuf);

impl Drop for PartialFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

/// Move a finished archive from `partial` to `output`, write its `.sha256` sidecar,
/// and make both read-only. Returns the sidecar's path.
///
/// An archive already at `output` (callers allow it only with `--force`) and its
/// sidecar are removed first: they are read-only, and Windows refuses to replace a
/// read-only file. Shared by the backup rebuild and `decrypt --to`.
pub(crate) fn publish_archive(
    partial: &Path,
    output: &Path,
    archive_sha256: &str,
) -> Result<PathBuf> {
    let sidecar = sidecar_path(output);
    remove_read_only(output)?;
    remove_read_only(&sidecar)?;
    fs::rename(partial, output)
        .with_context(|| format!("cannot move the archive to {}", output.display()))?;
    set_read_only(output)?;
    let file_name = output.file_name().unwrap_or_default().to_string_lossy();
    // `sha256sum` format, verifiable with `sha256sum -c` or `shasum -a 256 -c`.
    fs::write(&sidecar, format!("{archive_sha256}  {file_name}\n"))
        .with_context(|| format!("cannot write {}", sidecar.display()))?;
    set_read_only(&sidecar)?;
    Ok(sidecar)
}

/// Remove `path` if it exists, read-only or not.
fn remove_read_only(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    make_writable(path)?;
    fs::remove_file(path).with_context(|| format!("cannot replace {}", path.display()))
}

/// Where the sidecar for `output` goes: `<name>.zip.sha256`.
pub(crate) fn sidecar_path(output: &Path) -> PathBuf {
    let mut name = output.file_name().unwrap_or_default().to_os_string();
    name.push(".sha256");
    output.with_file_name(name)
}

/// Write the archive described by `request`.
pub fn write(request: RebuildRequest<'_>) -> Result<RebuildOutcome> {
    let RebuildRequest {
        source,
        plan,
        files,
        directories,
        output,
        force,
        continue_on_error,
        run,
        notes,
        manifest,
    } = request;

    if let Some(reason) = &notes.stream_error
        && !continue_on_error
    {
        bail!(
            "the backup is damaged ({reason}); nothing written. Pass --continue-on-error to \
             rebuild what could be read"
        );
    }
    if output.is_dir() {
        bail!(
            "{} is a directory; --to takes a .zip file",
            output.display()
        );
    }
    if output.exists() && !force {
        bail!(
            "{} already exists; pass --force to replace it",
            output.display()
        );
    }
    if let Some(parent) = output.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)
            .with_context(|| format!("cannot create {}", parent.display()))?;
    }

    let mut partial_name = output.file_name().unwrap_or_default().to_os_string();
    partial_name.push(format!(".partial-{}", std::process::id()));
    let partial = PartialFile(output.with_file_name(partial_name));
    let mut zip = ZipWriter::create(&partial.0)?;

    // A directory that is also a file's path cannot exist on a file system, and on a
    // case-insensitive one neither can a difference in case alone. The file is the
    // evidence, so it wins, and the directory's record is dropped.
    let file_paths: HashSet<String> = plan
        .items
        .iter()
        .map(|item| item.output_path().to_lowercase())
        .collect();
    let mut directory_count = 0;
    // Each logical name's member in the archive, for the zip-path list.
    let mut zip_paths: HashMap<String, String> = HashMap::new();
    for directory in directories {
        if !file_paths.contains(&directory.path.to_lowercase()) {
            zip.add_directory(&directory.path, directory.mtime)?;
            directory_count += 1;
            for name in &directory.names {
                zip_paths.insert(name.clone(), format!("{}/", directory.path));
            }
        }
    }

    let mut report = Vec::with_capacity(files.len());
    let mut failed = Vec::new();
    let mut non_portable = Vec::new();
    let mut bytes = 0u64;
    for (item, file) in plan.items.iter().zip(files) {
        let output_path = item.output_path();
        let content = match source.content(&file.entry) {
            Ok(content) => content,
            Err(err) if continue_on_error => {
                failed.push(SkippedFile {
                    internal_path: file.entry.name.clone(),
                    output_path,
                    reason: format!("{err:#}"),
                });
                continue;
            }
            Err(err) => {
                return Err(err).with_context(|| {
                    format!(
                        "cannot read {}; nothing written. Pass --continue-on-error to keep the \
                         rest",
                        file.entry.name
                    )
                });
            }
        };
        if output_path.chars().count() > DEFAULT_MAX_PATH_LEN {
            non_portable.push(SkippedFile {
                internal_path: file.entry.name.clone(),
                output_path: output_path.clone(),
                reason: format!(
                    "path length {} exceeds the Windows limit of {DEFAULT_MAX_PATH_LEN} if extracted",
                    output_path.chars().count()
                ),
            });
        }
        let member = zip.add_file(&output_path, file.entry.mtime, &content)?;
        let source_sha256 = sha256_hex(&content);
        let sha256 = zip.sha256_of(member)?;
        if sha256 != source_sha256 {
            bail!("{output_path} did not read back as written; nothing written");
        }
        let stored_integrity: StoredIntegrity = source.integrity_check(&file.entry).into();
        bytes += content.len() as u64;
        zip_paths.insert(file.entry.name.clone(), output_path.clone());
        report.push(ExportedFile {
            internal_path: file.entry.name.clone(),
            output_path,
            size: content.len() as u64,
            sha256,
            source_sha256,
            copy_verified: true,
            stored_integrity,
            mtime_utc: file.entry.mtime.map(|m| UtcTime::from_unix(m).iso()),
            derived: None,
        });
    }

    let now = now_unix();
    let root = write_manifest_members(&mut zip, manifest, &zip_paths, now)?;

    let traceability = Traceability {
        run,
        created_utc: UtcTime::from_unix(now).iso(),
        file_count: report.len(),
        directory_count,
        integrity: IntegritySummary::of(&report),
        notes: &notes,
        manifest: &root,
        files: &report,
        failed: &failed,
        non_portable: &non_portable,
    };
    let record = serde_json::to_vec_pretty(&traceability).context("cannot encode the report")?;
    zip.add_file(TRACEABILITY_MEMBER, Some(now), &record)?;
    zip.finish()?;

    let expected = report.len() + directory_count + root.member_count() + 1;
    let archive_sha256 = check_and_hash(&partial.0, expected)?;

    let sidecar = publish_archive(&partial.0, output, &archive_sha256)?;

    Ok(RebuildOutcome {
        report,
        bytes,
        directories: directory_count,
        failed,
        non_portable,
        manifest: root,
        archive_sha256,
        sidecar,
    })
}

/// Write `Manifest.db` and the zip-path list to the archive root.
///
/// `Manifest.db` is the database the rebuild walked, byte for byte: decrypted for an
/// encrypted backup, else as stored, with the backup's own timestamp. A failure to build
/// the list is recorded rather than failing the run, because the evidence itself is all
/// still there.
fn write_manifest_members(
    zip: &mut ZipWriter,
    manifest: Option<&ManifestDb>,
    zip_paths: &HashMap<String, String>,
    now: u64,
) -> Result<ManifestMembers> {
    let Some(manifest) = manifest else {
        return Ok(ManifestMembers::default());
    };
    let member = zip.add_file(MANIFEST_MEMBER, manifest.mtime, &manifest.bytes)?;
    let mut members = ManifestMembers {
        manifest_db_sha256: Some(zip.sha256_of(member)?),
        ..ManifestMembers::default()
    };
    match manifest_zip_paths_csv(&manifest.bytes, zip_paths) {
        Ok(list) => {
            let member = zip.add_file(ZIP_PATHS_MEMBER, Some(now), &list)?;
            members.zip_paths_csv_sha256 = Some(zip.sha256_of(member)?);
        }
        Err(err) => members.zip_paths_csv_error = Some(format!("{err:#}")),
    }
    Ok(members)
}

/// Read the finished archive back with the tool's own reader, confirm it holds what was
/// written, and hash it. Scoped so the map is gone before the file is moved: Windows
/// refuses to rename a mapped file.
pub(crate) fn check_and_hash(path: &Path, expected_members: usize) -> Result<String> {
    let file = fs::File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
    // SAFETY: a read-only map of a file this process just finished writing.
    let map = unsafe { memmap2::Mmap::map(&file) }
        .with_context(|| format!("cannot map {}", path.display()))?;
    let source = ZipSource::open(&map).context("the written archive does not read back")?;
    let members = source.entries().len();
    if members != expected_members {
        bail!("the written archive holds {members} members, expected {expected_members}");
    }
    Ok(sha256_hex(&map))
}

pub(crate) fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}
