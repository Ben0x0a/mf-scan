//! Shared backup-source machinery (encrypted and unencrypted).
//!
//! Defines: the logic both [`super::source::EncryptedBackupSource`] and
//! [`super::source::PlainBackupSource`] need, in one place — locating
//! a file's on-disk blob ([`blob_names`], [`read_backup_blob`]), reading an entry
//! by logical name ([`read_entry`]), walking `Manifest.db`'s `Files` table into
//! present-on-disk records ([`read_present_files`], [`FileRecord`]), building the
//! logical [`Entry`] ([`logical_entry`]), mapping an entry back to its metadata
//! ([`meta_index`]), and the SHA-1 `Digest` attestation ([`check_blob_digest`]).
//! Used by: `source::encrypted` and `source::plain` — the two sources differ only
//! in how they turn a [`FileRecord`] into their own per-entry metadata and (for
//! encrypted) decrypt the bytes; everything structural lives here so they never
//! drift.
//! Uses: `crate::formats::sqlite` (the `Manifest.db` reader), `super::manifest`
//! (`MBFile` decode), `crate::core::source` (the `Source` trait), `sha1`.

use std::collections::HashSet;

use anyhow::{Context, Result};
use sha1::{Digest as _, Sha1};

use crate::core::models::{Entry, Location};
use crate::core::source::{IntegrityCheck, Source};
use crate::formats::sqlite::{Value as SqliteValue, read_table as read_sqlite_table};
use crate::platform::ios::backup::manifest::{MBFile, parse_mbfile};

/// The `Files.flags` value marking a regular file. Directories and symlinks carry
/// other values and are skipped.
const FLAG_REGULAR_FILE: i64 = 1;

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
/// path first then the flat one. Errors when neither is present.
pub(crate) fn read_backup_blob(
    inner: &dyn Source,
    root_prefix: &str,
    file_id: &str,
) -> Result<Vec<u8>> {
    let (sharded, flat) = blob_names(root_prefix, file_id);
    if let Some(bytes) = try_read_entry(inner, &sharded) {
        return Ok(bytes);
    }
    try_read_entry(inner, &flat)
        .with_context(|| format!("blob for {file_id} not found in the backup"))
}

/// Read an entry's bytes from `source` by exact logical name, erroring if absent.
pub(crate) fn read_entry(source: &dyn Source, name: &str) -> Result<Vec<u8>> {
    try_read_entry(source, name).with_context(|| format!("backup file {name} not found"))
}

/// Read an entry's bytes by exact logical name, or `None` if it is absent.
fn try_read_entry(source: &dyn Source, name: &str) -> Option<Vec<u8>> {
    let entry = source.entries().iter().find(|e| e.name == name)?;
    source.content(entry).ok().map(|c| c.into_owned())
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
    inner: &dyn Source,
    root_prefix: &str,
) -> (Vec<FileRecord>, usize) {
    let columns = ["fileID", "domain", "relativePath", "flags", "file"];
    let Some(rows) = read_sqlite_table(manifest_db, "Files", &columns) else {
        return (Vec::new(), 0);
    };

    // Names present on disk, so a file the manifest lists but the backup does not
    // actually hold is detected here rather than failing lazily when searched.
    let present: HashSet<&str> = inner.entries().iter().map(|e| e.name.as_str()).collect();

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
        let (sharded, flat) = blob_names(root_prefix, file_id);
        if !present.contains(sharded.as_str()) && !present.contains(flat.as_str()) {
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

/// Build the public logical [`Entry`] for a backup file.
///
/// The `Location::Loose` path is the logical name itself: both sources serve bytes
/// via `Source::content`, so it is never opened from disk — it only gives the
/// entry a stable, non-archive identity.
pub(crate) fn logical_entry(name: &str, size: u64) -> Entry {
    Entry {
        name: name.to_string(),
        uncompressed_size: size,
        mtime: None,
        location: Location::Loose {
            path: std::path::PathBuf::from(name),
        },
    }
}

/// The index in `entries` (and the parallel `meta`) of the entry named `name`.
///
/// `entries` and a source's `meta` are built together and never reordered apart,
/// so a name lookup yields the right metadata slot.
pub(crate) fn meta_index(entries: &[Entry], name: &str) -> Result<usize> {
    entries
        .iter()
        .position(|e| e.name == name)
        .with_context(|| format!("unknown backup entry {name}"))
}

/// Attest a file's on-disk blob against the SHA-1 `Digest` recorded in
/// `Manifest.db`.
///
/// The recorded digest is the SHA-1 of the bytes as stored on disk — the
/// ciphertext for an encrypted backup, the file content for an unencrypted one —
/// so recomputing it from the blob attests the original evidence was read intact.
/// Returns [`IntegrityCheck::Unrecorded`] when no digest is recorded or the blob
/// cannot be located (degrade, don't fail — the export still records what it
/// wrote).
pub(crate) fn check_blob_digest(
    inner: &dyn Source,
    root_prefix: &str,
    file_id: &str,
    expected: Option<&[u8]>,
) -> IntegrityCheck {
    let Some(expected) = expected else {
        return IntegrityCheck::Unrecorded;
    };
    let Ok(blob) = read_backup_blob(inner, root_prefix, file_id) else {
        return IntegrityCheck::Unrecorded;
    };
    let actual = Sha1::digest(&blob);
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
