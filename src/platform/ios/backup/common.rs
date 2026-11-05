//! Shared backup-source machinery (encrypted and unencrypted).
//!
//! Defines: the logic both [`super::source::EncryptedBackupSource`] and
//! [`super::source::PlainBackupSource`] need, in one place — locating
//! a file's on-disk blob ([`blob_names`], [`read_backup_blob`]), reading an entry
//! by logical name ([`read_entry`]), walking `Manifest.db`'s `Files` table into
//! present-on-disk records ([`read_present_files`], [`FileRecord`]), building the
//! logical [`Entry`] ([`logical_entry`]), mapping an entry back to its metadata
//! ([`name_index`], [`meta_index`]), and the SHA-1 `Digest` attestation
//! ([`BlobStore::attest`]).
//! Used by: `source::encrypted` and `source::plain` — the two sources differ only
//! in how they turn a [`FileRecord`] into their own per-entry metadata and (for
//! encrypted) decrypt the bytes; everything structural lives here so they never
//! drift.
//! Uses: `crate::formats::sqlite` (the `Manifest.db` reader), `super::manifest`
//! (`MBFile` decode), `crate::core::source` (the `Source` trait), `sha1`.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use sha1::{Digest as _, Sha1};

use crate::core::models::{Entry, Location};
use crate::core::source::{IntegrityCheck, Source};
use crate::formats::sqlite::{Value as SqliteValue, parse_header, read_table as read_sqlite_table};
use crate::platform::ios::backup::manifest::{MBFile, parse_mbfile};

/// The zip-path list's column naming each row's member in the archive. The same name as the
/// Python reconstructor's added column.
const ZIP_PATH_COLUMN_NAME: &str = "zipPath";
const UTF8_BOM: &[u8] = b"\xef\xbb\xbf";

/// The `Files.flags` value marking a regular file.
const FLAG_REGULAR_FILE: i64 = 1;
/// The `Files.flags` value marking a directory. Directory rows carry no blob and
/// are read separately by [`read_directory_records`], never through `entries()`.
const FLAG_DIRECTORY: i64 = 2;
/// The `Files.flags` value marking a symlink. Recorded for reporting, not recreated.
const FLAG_SYMLINK: i64 = 4;

/// One regular backed-up file recovered from `Manifest.db`, whose blob is present
/// on disk. The two sources turn this into their own per-entry metadata.
pub(crate) struct FileRecord {
    /// The logical name `domain/relativePath`.
    pub(crate) name: String,
    /// The 40-hex `fileID` naming the on-disk blob.
    pub(crate) file_id: String,
    /// The decoded `MBFile` (size, digest, and — for an encrypted backup — the
    /// wrapped key and protection class).
    pub(crate) mb: MBFile,
}

/// The two candidate on-disk names a backup file's blob may live under, given the
/// backup root prefix and the 40-hex `fileID`: the modern sharded layout
/// `<root>/<id[0:2]>/<id>`, then the flat legacy layout `<root>/<id>`.
pub(crate) fn blob_names(root_prefix: &str, file_id: &str) -> (String, String) {
    let sharded = format!(
        "{root_prefix}{}/{file_id}",
        &file_id[..2.min(file_id.len())]
    );
    let flat = format!("{root_prefix}{file_id}");
    (sharded, flat)
}

/// Locate and read a backup file's on-disk blob from `inner`, trying the sharded
/// Locates a backup's on-disk blobs inside the inner source, by `fileID`.
///
/// Holds a name → index map over the inner source's entries, built once. WHY that
/// matters: every blob lookup used to be a linear scan of the inner source, and
/// `Source::content` plus `Source::integrity_check` each perform one per file. A
/// whole-backup operation touches every file, so the cost was quadratic in the
/// entry count — invisible when exporting one app's data out of a large backup,
/// prohibitive when rebuilding the whole thing.
///
/// The same index answers "does the backup actually hold this blob?", which the
/// `Manifest.db` walk needs, so one structure serves both.
pub(crate) struct BlobStore {
    /// The backup root within the inner source's namespace (`""` or `"<udid>/"`).
    root_prefix: String,
    /// Inner entry name → index into `inner.entries()`.
    index: HashMap<String, usize>,
}

impl BlobStore {
    /// Index `inner`'s entries once for the backup rooted at `root_prefix`.
    pub(crate) fn build(inner: &dyn Source, root_prefix: &str) -> Self {
        Self {
            root_prefix: root_prefix.to_string(),
            index: name_index(inner.entries()),
        }
    }

    /// Whether the inner source holds an entry with this exact name.
    pub(crate) fn contains(&self, name: &str) -> bool {
        self.index.contains_key(name)
    }

    /// Whether either candidate blob path for `file_id` is present on disk.
    pub(crate) fn holds_blob(&self, file_id: &str) -> bool {
        let (sharded, flat) = blob_names(&self.root_prefix, file_id);
        self.contains(&sharded) || self.contains(&flat)
    }

    /// Read a blob's bytes, trying the sharded layout then the flat one.
    pub(crate) fn read(&self, inner: &dyn Source, file_id: &str) -> Result<Vec<u8>> {
        let (sharded, flat) = blob_names(&self.root_prefix, file_id);
        if let Some(bytes) = self.read_named(inner, &sharded) {
            return Ok(bytes);
        }
        self.read_named(inner, &flat)
            .with_context(|| format!("blob for {file_id} not found in the backup"))
    }

    /// Read an inner entry's bytes by exact name, or `None` if it is absent.
    pub(crate) fn read_named(&self, inner: &dyn Source, name: &str) -> Option<Vec<u8>> {
        let entry = inner.entries().get(*self.index.get(name)?)?;
        inner.content(entry).ok().map(|c| c.into_owned())
    }

    /// Attest a file's on-disk blob against the SHA-1 `Digest` recorded in
    /// `Manifest.db`.
    ///
    /// The recorded digest is the SHA-1 of the bytes as stored on disk — the
    /// ciphertext for an encrypted backup, the file content for an unencrypted one
    /// — so recomputing it from the blob attests the original evidence was read
    /// intact. Returns [`IntegrityCheck::Unrecorded`] when no digest is recorded or
    /// the blob cannot be located (degrade, don't fail — the export still records
    /// what it wrote).
    pub(crate) fn attest(
        &self,
        inner: &dyn Source,
        file_id: &str,
        expected: Option<&[u8]>,
    ) -> IntegrityCheck {
        let Some(expected) = expected else {
            return IntegrityCheck::Unrecorded;
        };
        let Ok(blob) = self.read(inner, file_id) else {
            return IntegrityCheck::Unrecorded;
        };
        attest_bytes(&blob, expected)
    }
}

/// Compare a SHA-1 of `bytes` against the digest `Manifest.db` recorded.
pub(crate) fn attest_bytes(bytes: &[u8], expected: &[u8]) -> IntegrityCheck {
    let actual = Sha1::digest(bytes);
    if actual.as_slice() == expected {
        IntegrityCheck::Verified { algorithm: "sha1" }
    } else {
        IntegrityCheck::Mismatch {
            algorithm: "sha1",
            expected: hex(expected),
            actual: hex(&actual),
        }
    }
}

/// Read an entry's bytes from `source` by exact logical name, erroring if absent.
///
/// Used for the handful of one-off reads at build time (`Manifest.plist`,
/// `Manifest.db`), so a linear scan is fine here — unlike the per-file blob reads,
/// which go through [`BlobStore`].
pub(crate) fn read_entry(source: &dyn Source, name: &str) -> Result<Vec<u8>> {
    let entry = source
        .entries()
        .iter()
        .find(|e| e.name == name)
        .with_context(|| format!("backup file {name} not found"))?;
    Ok(source.content(entry)?.into_owned())
}

/// Walk `Manifest.db`'s `Files` table into the regular files whose blob is present
/// on disk (sorted by logical name), plus the count of regular files that were
/// listed but absent.
///
/// Keeps only regular files (`flags == 1`) with a non-empty `relativePath` and a
/// decodable `MBFile`. A file that passes those checks but whose blob is not in
/// `inner` is counted as missing (and omitted, since its bytes cannot be served)
/// — surfaced by the caller rather than dropped silently, since a file the
/// manifest lists but the backup does not hold signals an incomplete or modified
/// acquisition. Records are sorted by name so each source's `entries`/`meta` stay
/// aligned and deterministic.
pub(crate) fn read_present_files(
    manifest_db: &[u8],
    blobs: &BlobStore,
) -> (Vec<FileRecord>, usize) {
    let columns = ["fileID", "domain", "relativePath", "flags", "file"];
    let Some(rows) = read_sqlite_table(manifest_db, "Files", &columns) else {
        return (Vec::new(), 0);
    };

    let mut records = Vec::new();
    let mut missing = 0usize;
    for row in rows {
        let (Some(file_id), Some(domain), Some(rel), Some(flags), Some(file_blob)) = (
            as_text(&row[0]),
            as_text(&row[1]),
            as_text(&row[2]),
            as_int(&row[3]),
            as_blob(&row[4]),
        ) else {
            continue;
        };
        if flags != FLAG_REGULAR_FILE || rel.is_empty() {
            continue;
        }
        let Some(mb) = parse_mbfile(file_blob) else {
            continue;
        };
        // A file the manifest lists but the backup does not actually hold is
        // detected here rather than failing lazily when it is read.
        if !blobs.holds_blob(file_id) {
            missing += 1;
            continue;
        }
        records.push(FileRecord {
            name: format!("{domain}/{rel}"),
            file_id: file_id.to_string(),
            mb,
        });
    }

    records.sort_by(|a, b| a.name.cmp(&b.name));
    (records, missing)
}

/// The non-file structure a backup records: directories and symlinks.
///
/// WHY these are returned separately rather than as `entries()`:
/// - a directory row has no blob, so the `Manifest.db` walk would count every one
///   as a missing file and destroy the "incomplete or modified acquisition" signal
///   that `missing_files` carries;
/// - the encrypted source drops records with no `EncryptionKey`, which directories
///   have none of, so the two sources would disagree about what a backup contains;
/// - `report::export` calls `Source::content` unconditionally, so the first
///   directory entry would abort a whole export.
///
/// Callers that want to recreate the tree ask for these explicitly.
#[derive(Debug, Default, Clone)]
pub struct BackupStructure {
    /// Directory records, sorted by name.
    pub directories: Vec<DirectoryRecord>,
    /// Logical names of symlink records, sorted. Reported, never recreated — the
    /// target is not recorded in a form we resolve, and writing a link into an
    /// export is a way to escape it.
    pub symlinks: Vec<String>,
    /// The `Manifest.db` this was read from, in plaintext; `None` for a backup with no
    /// such database (Android).
    pub manifest: Option<ManifestDb>,
}

/// Remove the AES padding from a just-decrypted `Manifest.db`, when it has some.
///
/// HOW: a SQLite file is a whole number of pages, so bytes past the last page that form
/// valid PKCS7 padding are padding.
/// WHY the page test, not just valid-looking padding: an unpadded database whose last byte
/// happens to be `0x01` looks validly padded too, and stripping it would corrupt evidence.
pub(crate) fn strip_manifest_padding(mut manifest_db: Vec<u8>) -> Vec<u8> {
    let Some(db) = parse_header(&manifest_db) else {
        return manifest_db;
    };
    let excess = manifest_db.len() % db.page_size;
    let padded = (1..=16).contains(&excess)
        && manifest_db[manifest_db.len() - excess..]
            .iter()
            .all(|&b| b as usize == excess);
    if padded {
        manifest_db.truncate(manifest_db.len() - excess);
    }
    manifest_db
}

/// A backup's `Manifest.db`: decrypted for an encrypted backup, else as stored.
#[derive(Clone)]
pub struct ManifestDb {
    pub bytes: Arc<[u8]>,
    /// The time the backup's own file records (Unix seconds), when known.
    pub mtime: Option<u64>,
}

impl std::fmt::Debug for ManifestDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ManifestDb({} bytes)", self.bytes.len())
    }
}

/// A CSV with one row per `Manifest.db` `Files` row, sorted by `fileID`, giving its member
/// name inside the rebuilt archive: `fileID,domain,relativePath,flags,zipPath`.
///
/// `zip_paths` is keyed by logical name (`domain/relativePath`, or `domain` for a domain's
/// own directory). A row not in the archive (a missing blob, a symlink) has an empty
/// `zipPath`, so every row is accounted for and none is mistaken for a path.
///
/// WHY a CSV rather than a column added to a copy of `Manifest.db`: this crate only reads
/// SQLite, and adding a column means rewriting b-trees, overflow chains and pointer maps. The
/// `fileID` joins this to `Manifest.db` just as well, and it opens anywhere. UTF-8 with a BOM
/// so Excel decodes accented paths.
pub fn manifest_zip_paths_csv(
    manifest_db: &[u8],
    zip_paths: &HashMap<String, String>,
) -> Result<Vec<u8>> {
    let columns = ["fileID", "domain", "relativePath", "flags"];
    let Some(mut rows) = read_sqlite_table(manifest_db, "Files", &columns) else {
        bail!("cannot read the Files table of Manifest.db");
    };
    rows.sort_by(|a, b| as_text(&a[0]).cmp(&as_text(&b[0])));

    let mut writer = csv::Writer::from_writer(UTF8_BOM.to_vec());
    writer.write_record(columns.iter().chain(&[ZIP_PATH_COLUMN_NAME]))?;
    for row in &rows {
        let domain = as_text(&row[1]).unwrap_or_default();
        let relative = as_text(&row[2]).unwrap_or_default();
        let name = if relative.is_empty() {
            domain.to_string()
        } else {
            format!("{domain}/{relative}")
        };
        let flags = as_int(&row[3]).map(|f| f.to_string()).unwrap_or_default();
        writer.write_record([
            as_text(&row[0]).unwrap_or_default(),
            domain,
            relative,
            &flags,
            zip_paths.get(&name).map_or("", String::as_str),
        ])?;
    }
    writer
        .into_inner()
        .context("cannot finish the zip-path list")
}

/// The directory and symlink rows of `manifest_db`, holding on to the database itself,
/// whose file in `inner` is `manifest_name`.
pub(crate) fn read_structure(
    inner: &dyn Source,
    manifest_name: &str,
    manifest_db: &[u8],
) -> BackupStructure {
    let mut structure = read_directory_records(manifest_db);
    let mtime = inner
        .entries()
        .iter()
        .find(|e| e.name == manifest_name)
        .and_then(|e| e.mtime);
    structure.manifest = Some(ManifestDb {
        bytes: Arc::from(manifest_db),
        mtime,
    });
    structure
}

/// A directory a backup records.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DirectoryRecord {
    /// The logical name.
    pub name: String,
    /// When it last changed on the device (Unix seconds), when recorded. Kept because
    /// a directory's modification time is itself evidence.
    pub mtime: Option<u64>,
}

/// Read the directory and symlink rows from `Manifest.db`.
///
/// Independent of [`read_present_files`], which handles regular files, so neither
/// walk can perturb the other's counters.
fn read_directory_records(manifest_db: &[u8]) -> BackupStructure {
    let columns = ["domain", "relativePath", "flags", "file"];
    let Some(rows) = read_sqlite_table(manifest_db, "Files", &columns) else {
        return BackupStructure::default();
    };
    let mut out = BackupStructure::default();
    for row in rows {
        let (Some(domain), Some(rel), Some(flags)) =
            (as_text(&row[0]), as_text(&row[1]), as_int(&row[2]))
        else {
            continue;
        };
        // An empty relative path is the domain's own root directory, which has its own
        // record and its own timestamp, like any other directory.
        let name = if rel.is_empty() {
            domain.to_string()
        } else {
            format!("{domain}/{rel}")
        };
        match flags {
            FLAG_DIRECTORY => {
                let mtime = match &row[3] {
                    SqliteValue::Blob(blob) => parse_mbfile(blob).and_then(|m| m.last_modified),
                    _ => None,
                };
                out.directories.push(DirectoryRecord { name, mtime });
            }
            FLAG_SYMLINK => out.symlinks.push(name),
            _ => {}
        }
    }
    out.directories.sort();
    out.symlinks.sort();
    out
}

/// Build the public logical [`Entry`] for a backup file.
///
/// The `Location::Loose` path is the logical name itself: both sources serve bytes
/// via `Source::content`, so it is never opened from disk — it only gives the
/// entry a stable, non-archive identity.
pub(crate) fn logical_entry(name: &str, size: u64, mtime: Option<u64>) -> Entry {
    Entry {
        name: name.to_string(),
        uncompressed_size: size,
        mtime,
        location: Location::Loose {
            path: std::path::PathBuf::from(name),
        },
    }
}

/// Build a name → index map over `entries`.
///
/// WHY first-wins on a duplicate name: this replaced an `Iterator::position`
/// scan, which returned the FIRST match. Two `Files` rows can in principle map to
/// the same `domain/relativePath`, so inserting only when absent keeps the
/// resolution identical to the scan it replaces.
pub(crate) fn name_index(entries: &[Entry]) -> HashMap<String, usize> {
    let mut map = HashMap::with_capacity(entries.len());
    for (idx, entry) in entries.iter().enumerate() {
        map.entry(entry.name.clone()).or_insert(idx);
    }
    map
}

/// The index in `entries` (and the parallel `meta`) of the entry named `name`.
///
/// `entries` and a source's `meta` are built together and never reordered apart,
/// so a name lookup yields the right metadata slot.
pub(crate) fn meta_index(index: &HashMap<String, usize>, name: &str) -> Result<usize> {
    index
        .get(name)
        .copied()
        .with_context(|| format!("unknown backup entry {name}"))
}

/// Lowercase-hex encode bytes (for digest reporting).
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Borrow a [`SqliteValue::Text`] as `&str`.
fn as_text(v: &SqliteValue) -> Option<&str> {
    match v {
        SqliteValue::Text(s) => Some(s),
        _ => None,
    }
}

/// Read a [`SqliteValue::Int`].
fn as_int(v: &SqliteValue) -> Option<i64> {
    match v {
        SqliteValue::Int(i) => Some(*i),
        _ => None,
    }
}

/// Borrow a [`SqliteValue::Blob`].
fn as_blob(v: &SqliteValue) -> Option<&[u8]> {
    match v {
        SqliteValue::Blob(b) => Some(b),
        _ => None,
    }
}

#[cfg(test)]
mod manifest_padding_tests {
    use super::strip_manifest_padding;

    /// A one-page database: the 16-bit page size in the header is all the check reads.
    fn database(page_size: u16, last_byte: u8) -> Vec<u8> {
        let mut db = vec![0u8; page_size as usize];
        db[..16].copy_from_slice(b"SQLite format 3\0");
        db[16..18].copy_from_slice(&page_size.to_be_bytes());
        *db.last_mut().unwrap() = last_byte;
        db
    }

    #[test]
    fn padding_past_the_last_page_is_removed() {
        let clean = database(4096, 0);
        let mut padded = clean.clone();
        padded.extend_from_slice(&[16u8; 16]);
        assert_eq!(strip_manifest_padding(padded), clean);
    }

    /// Ending in 0x01 looks like valid padding, but a whole number of pages has none.
    #[test]
    fn a_whole_number_of_pages_is_left_alone() {
        let db = database(4096, 1);
        assert_eq!(strip_manifest_padding(db.clone()), db);
    }

    #[test]
    fn bytes_that_are_not_padding_are_left_alone() {
        let mut odd = database(4096, 0);
        odd.extend_from_slice(&[9u8; 16]);
        assert_eq!(strip_manifest_padding(odd.clone()), odd);
        let not_sqlite = vec![16u8; 32];
        assert_eq!(strip_manifest_padding(not_sqlite.clone()), not_sqlite);
    }
}
