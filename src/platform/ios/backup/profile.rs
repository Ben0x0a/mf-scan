//! Backup recognition: is this source an iOS backup, and is it encrypted?
//!
//! Defines: [`BackupProfile`] (the located backup root plus its encryption flag
//! and version metadata) and [`detect`], the single source of truth for
//! recognising an iOS iTunes/Finder backup inside a [`Source`].
//! Used by: `support::sources` (decide whether to wrap a folder/zip in a
//! `BackupSource`) and `ios::backup::source` (reuse the same located root).
//! Uses: `crate::core::source::Source` (enumerate + read the manifest files) and the
//! `plist` crate (read `Manifest.plist`/`Status.plist`).
//!
//! ── What identifies an iOS backup ───────────────────────────────────────────
//! A backup directory holds `Manifest.plist`, `Manifest.db`, `Status.plist` and
//! `Info.plist` side by side. The backup may be the source root, or — when a
//! whole `MobileSync/Backup` tree is handed over — a single UDID subdirectory.
//! We locate it by finding `Manifest.plist` by basename and taking its parent as
//! the root, then confirming `Manifest.db` and `Status.plist` sit beside it.
//! `Manifest.plist`'s `IsEncrypted` boolean says whether the payload is
//! encrypted. This recognition lives ONLY here so the profiler and the source
//! never drift on what "is a backup" means (the one-source-of-truth rule).

use plist::Value;

use crate::core::source::Source;

/// The three sibling files that mark a directory as an iOS backup root.
const MANIFEST_PLIST: &str = "Manifest.plist";
const MANIFEST_DB: &str = "Manifest.db";
const STATUS_PLIST: &str = "Status.plist";

/// A recognised iOS backup within a source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupProfile {
    /// The backup root *prefix* within the source's logical namespace: either the
    /// empty string (the backup is the source root) or `"<udid>/"` (a UDID
    /// subdirectory). Joined to a basename it yields the entry name to read.
    pub root_prefix: String,
    /// Whether `Manifest.plist` declares the payload encrypted.
    pub encrypted: bool,
    /// The UDID directory name, when the backup lives in one (provenance).
    pub udid: Option<String>,
    /// The iOS/product version from `Status.plist`/`Manifest.plist`, when present
    /// (provenance only — not required for decryption).
    pub product_version: Option<String>,
}

/// Detect whether `source` contains an iOS backup, returning its profile.
///
/// Returns `None` when no `Manifest.plist` with the required siblings is found —
/// the source is then handled as ordinary files. A backup whose `Manifest.plist`
/// cannot be read is treated as not-a-backup (degrade, don't die): better to
/// search the raw files than to abort.
pub fn detect(source: &dyn Source) -> Option<BackupProfile> {
    let root_prefix = locate_root_prefix(source)?;

    // Confirm the two other marker files sit beside Manifest.plist.
    let has = |base: &str| entry_named(source, &format!("{root_prefix}{base}")).is_some();
    if !has(MANIFEST_DB) || !has(STATUS_PLIST) {
        return None;
    }

    // Read Manifest.plist for IsEncrypted (+ best-effort version provenance).
    let manifest_name = format!("{root_prefix}{MANIFEST_PLIST}");
    let manifest = read_plist(source, &manifest_name)?;
    let dict = manifest.as_dictionary()?;
    let encrypted = dict
        .get("IsEncrypted")
        .and_then(Value::as_boolean)
        .unwrap_or(false);

    let udid = root_prefix.strip_suffix('/').map(str::to_string);
    let product_version = product_version(source, &root_prefix, dict);

    Some(BackupProfile {
        root_prefix,
        encrypted,
        udid,
        product_version,
    })
}

/// Find the backup root prefix by locating `Manifest.plist` by basename.
///
/// The root is the entry's parent path with a trailing `/` (or empty when the
/// manifest is at the source root). Only the first match is used — a source with
/// several backups is out of scope; the operator points at one.
fn locate_root_prefix(source: &dyn Source) -> Option<String> {
    for entry in source.entries() {
        let name = &entry.name;
        if name == MANIFEST_PLIST {
            return Some(String::new());
        }
        if let Some(parent) = name.strip_suffix(MANIFEST_PLIST)
            && parent.ends_with('/')
        {
            return Some(parent.to_string());
        }
    }
    None
}

/// The entry whose logical name is exactly `name`, if present.
fn entry_named<'a>(source: &'a dyn Source, name: &str) -> Option<&'a crate::core::models::Entry> {
    source.entries().iter().find(|e| e.name == name)
}

/// Read and parse a plist entry from the source, or `None` on any failure.
fn read_plist(source: &dyn Source, name: &str) -> Option<Value> {
    let entry = entry_named(source, name)?;
    let bytes = source.content(entry).ok()?;
    Value::from_reader(std::io::Cursor::new(&*bytes)).ok()
}

/// Best-effort product/iOS version for provenance: `Status.plist` first (it
/// carries `ProductVersion` on modern backups), then the `Lockdown` dict in
/// `Manifest.plist`. Never fails the detection — version is informational.
fn product_version(
    source: &dyn Source,
    root_prefix: &str,
    manifest: &plist::Dictionary,
) -> Option<String> {
    if let Some(status) = read_plist(source, &format!("{root_prefix}{STATUS_PLIST}"))
        && let Some(dict) = status.as_dictionary()
        && let Some(v) = dict.get("ProductVersion").and_then(Value::as_string)
    {
        return Some(v.to_string());
    }
    manifest
        .get("Lockdown")
        .and_then(Value::as_dictionary)
        .and_then(|l| l.get("ProductVersion"))
        .and_then(Value::as_string)
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::models::{Entry, Location};
    use crate::core::source::Content;

    /// A tiny in-memory `Source` over (name, bytes) pairs, for profiler tests.
    struct MemSource {
        entries: Vec<Entry>,
        blobs: Vec<Vec<u8>>,
    }

    impl MemSource {
        fn new(files: &[(&str, Vec<u8>)]) -> Self {
            let mut entries = Vec::new();
            let mut blobs = Vec::new();
            for (name, bytes) in files {
                entries.push(Entry {
                    name: (*name).to_string(),
                    uncompressed_size: bytes.len() as u64,
                    mtime: None,
                    location: Location::Loose {
                        path: std::path::PathBuf::from(*name),
                    },
                });
                blobs.push(bytes.clone());
            }
            Self { entries, blobs }
        }
    }

    impl Source for MemSource {
        fn entries(&self) -> &[Entry] {
            &self.entries
        }
        fn content(&self, entry: &Entry) -> anyhow::Result<Content<'_>> {
            let idx = self
                .entries
                .iter()
                .position(|e| e.name == entry.name)
                .unwrap();
            Ok(Content::Owned(self.blobs[idx].clone()))
        }
    }

    /// A minimal XML plist with the given IsEncrypted value.
    fn manifest_plist(encrypted: bool) -> Vec<u8> {
        let mut dict = plist::Dictionary::new();
        dict.insert("IsEncrypted".into(), Value::Boolean(encrypted));
        let mut buf = Vec::new();
        Value::Dictionary(dict).to_writer_xml(&mut buf).unwrap();
        buf
    }

    #[test]
    fn detects_encrypted_backup_at_root() {
        let src = MemSource::new(&[
            ("Manifest.plist", manifest_plist(true)),
            ("Manifest.db", b"SQLite format 3\x00".to_vec()),
            ("Status.plist", b"x".to_vec()),
        ]);
        let p = detect(&src).unwrap();
        assert!(p.encrypted);
        assert_eq!(p.root_prefix, "");
        assert_eq!(p.udid, None);
    }

    #[test]
    fn detects_backup_in_udid_subdir() {
        let udid = "00008030-ABCDEF";
        let src = MemSource::new(&[
            (&format!("{udid}/Manifest.plist"), manifest_plist(false)),
            (&format!("{udid}/Manifest.db"), b"db".to_vec()),
            (&format!("{udid}/Status.plist"), b"s".to_vec()),
        ]);
        let p = detect(&src).unwrap();
        assert!(!p.encrypted);
        assert_eq!(p.root_prefix, format!("{udid}/"));
        assert_eq!(p.udid.as_deref(), Some(udid));
    }

    #[test]
    fn missing_siblings_is_not_a_backup() {
        // Manifest.plist alone (no Manifest.db / Status.plist) is not a backup.
        let src = MemSource::new(&[("Manifest.plist", manifest_plist(true))]);
        assert!(detect(&src).is_none());
    }

    #[test]
    fn ordinary_files_are_not_a_backup() {
        let src = MemSource::new(&[("a.txt", b"hi".to_vec()), ("b.txt", b"yo".to_vec())]);
        assert!(detect(&src).is_none());
    }
}
