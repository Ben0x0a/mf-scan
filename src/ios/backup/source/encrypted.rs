//! `EncryptedBackupSource`: expose an encrypted iOS backup as decrypted logical files.
//!
//! Defines: [`EncryptedBackupSource`], a [`Source`] decorator that wraps the inner
//! folder/zip an encrypted backup lives in and presents each backed-up file at
//! its logical `domain/relativePath` with decrypted content — lazily, so only
//! files the engine actually reads are ever decrypted.
//! Used by: `support::sources` (wraps the inner source when the profiler reports
//! an encrypted backup) and, through the [`Source`] trait, the search/diff
//! engines.
//! Uses: `ios::backup::{keybag, keys, manifest, password, profile}` (the crypto
//! and recognition layers), `crate::sqlite::read_table` (the in-house low-level
//! `Manifest.db` reader), the `plist` crate (`Manifest.plist`).
//!
//! ── Build (eager, once) ──────────────────────────────────────────────────────
//! 1. Read `Manifest.plist`: `IsEncrypted`, `BackupKeyBag` (the keybag blob),
//!    `ManifestKey` (4-byte LE class + the wrapped `Manifest.db` key).
//! 2. Parse the keybag (4a) and unwrap the class keys with a password candidate
//!    (Part E). This is where a wrong password is caught.
//! 3. Decrypt `Manifest.db`: unwrap its per-DB key with its class key, then
//!    AES-256-CBC with a zero IV → a normal SQLite file.
//! 4. Read the `Files` table; for each regular file (`flags == 1`) decode its
//!    `MBFile` and record a `BackupEntry` keyed by `domain/relativePath`.
//!
//! Class keys are derived ONCE here; per-file work is one key-unwrap + one CBC
//! pass (see [`EncryptedBackupSource::content`]).
//!
//! ── Read (lazy, per searched file) ───────────────────────────────────────────
//! [`Source::content`] locates the encrypted blob in the inner source
//! (`<root>/<fileID[0:2]>/<fileID>`, falling back to flat `<root>/<fileID>`),
//! unwraps the per-file key with the file's class key, AES-CBC-decrypts with a
//! zero IV, and truncates to the `MBFile` `Size`. Because this runs only when the
//! engine asks for an entry's bytes, files excluded by `--path`/`--type`/media
//! filters are NEVER decrypted — the performance guarantee for a backup where
//! every file is encrypted.

use std::collections::BTreeMap;
use std::io::Cursor;

use anyhow::{Context, Result, bail};
use plist::Value;

use crate::ios::backup::common::{
    check_blob_digest, logical_entry, meta_index, read_backup_blob, read_entry, read_present_files,
};
use crate::ios::backup::keybag;
use crate::ios::backup::keys::{aes_cbc_decrypt, aes_unwrap};
use crate::ios::backup::password::{UnlockProvenance, try_unlock};
use crate::ios::backup::profile::BackupProfile;
use crate::models::Entry;
use crate::source::{Content, IntegrityCheck, Source};

/// AES-256 class/file key size, in bytes.
const KEY_SZ: usize = 32;
/// Zero IV used for backup CBC decryption (the format fixes the IV to all zero;
/// each file's key is unique, so a constant IV is safe here).
const ZERO_IV: [u8; 16] = [0u8; 16];

/// Per-file decryption metadata recovered from `Manifest.db`.
///
/// Kept beside each public [`Entry`] (by index) so [`Source::content`] can find
/// the encrypted blob and unwrap it without re-reading the manifest.
struct BackupEntry {
    /// The 40-hex `fileID` naming the on-disk encrypted blob.
    file_id: String,
    /// Data-protection class whose key unwraps `wrapped_key`.
    protection_class: u32,
    /// The RFC 3394-wrapped per-file key.
    wrapped_key: Vec<u8>,
    /// The real plaintext length (the CBC truncation target).
    size: u64,
    /// The `MBFile` `Digest` (SHA-1 of the encrypted on-disk blob), when present.
    /// Used by the export path to attest the stored ciphertext was read intact.
    digest: Option<Vec<u8>>,
}

/// A [`Source`] presenting a decrypted view of an encrypted iOS backup.
///
/// Borrows the inner source (`'a`) it decrypts blobs from, matching the existing
/// closure-passing lifetime model: the inner folder/zip and its mmap outlive the
/// decorator.
pub struct EncryptedBackupSource<'a> {
    inner: &'a dyn Source,
    /// The backup root prefix within the inner source's namespace (e.g. `""` or
    /// `"<udid>/"`).
    root_prefix: String,
    /// Class number → 32-byte class key, recovered once at build.
    class_keys: BTreeMap<u32, [u8; KEY_SZ]>,
    /// Public logical entries (sorted by name), parallel to `meta`.
    entries: Vec<Entry>,
    /// Per-entry decryption metadata, indexed parallel to `entries`.
    meta: Vec<BackupEntry>,
    /// Files `Manifest.db` lists as regular files but whose encrypted blob is
    /// absent on disk — surfaced (never dropped silently) as a sign of an
    /// incomplete or modified acquisition.
    missing_files: usize,
    /// How the backup was unlocked (provenance for stderr + the report).
    provenance: UnlockProvenance,
}

impl<'a> EncryptedBackupSource<'a> {
    /// Build a decrypted view over `inner` for the backup at `profile`.
    ///
    /// `supplied_password` is the resolved `--backup-password`/env value, or
    /// `None` to try the acquisition defaults. Errors when the manifest is
    /// unreadable or no password candidate unlocks the keybag.
    pub fn build(
        inner: &'a dyn Source,
        profile: &BackupProfile,
        supplied_password: Option<&str>,
    ) -> Result<Self> {
        let root_prefix = profile.root_prefix.clone();

        // ── Manifest.plist: keybag + ManifestKey ────────────────────────────
        let manifest_plist = read_entry(inner, &format!("{root_prefix}Manifest.plist"))
            .context("cannot read Manifest.plist")?;
        let plist = Value::from_reader(Cursor::new(&manifest_plist))
            .context("Manifest.plist is not a valid plist")?;
        let dict = plist
            .as_dictionary()
            .context("Manifest.plist root is not a dictionary")?;

        let keybag_blob = dict
            .get("BackupKeyBag")
            .and_then(Value::as_data)
            .context("Manifest.plist has no BackupKeyBag")?;
        let manifest_key = dict
            .get("ManifestKey")
            .and_then(Value::as_data)
            .context("Manifest.plist has no ManifestKey")?;

        // ── Unwrap class keys with a password candidate ─────────────────────
        let keybag = keybag::parse(keybag_blob).context("cannot parse BackupKeyBag")?;
        let (class_keys, provenance) = try_unlock(&keybag, supplied_password)?;

        // ── Decrypt Manifest.db ─────────────────────────────────────────────
        // ManifestKey is a 4-byte LE class number followed by the wrapped DB key.
        if manifest_key.len() < 4 {
            bail!("ManifestKey is too short to carry a class number");
        }
        let manifest_class = u32::from_le_bytes([
            manifest_key[0],
            manifest_key[1],
            manifest_key[2],
            manifest_key[3],
        ]);
        let wrapped_db_key = &manifest_key[4..];
        let db_class_key = class_keys.get(&manifest_class).with_context(|| {
            format!("no class key for the Manifest.db protection class {manifest_class}")
        })?;
        let db_key = unwrap_key(db_class_key, wrapped_db_key)
            .context("cannot unwrap the Manifest.db key (wrong password?)")?;

        let manifest_db_enc = read_entry(inner, &format!("{root_prefix}Manifest.db"))
            .context("cannot read Manifest.db")?;
        let manifest_db = aes_cbc_decrypt(&db_key, &ZERO_IV, &manifest_db_enc)
            .context("cannot decrypt Manifest.db")?;

        // ── Read the Files table, build the logical entries ─────────────────
        let (entries, meta, missing_files) = build_entries(&manifest_db, inner, &root_prefix);

        Ok(Self {
            inner,
            root_prefix,
            class_keys,
            entries,
            meta,
            missing_files,
            provenance,
        })
    }

    /// How the backup was unlocked, for provenance reporting.
    pub fn provenance(&self) -> &UnlockProvenance {
        &self.provenance
    }

    /// The number of files `Manifest.db` listed whose encrypted blob was absent on
    /// disk — reported as a sign of an incomplete or modified acquisition.
    pub fn missing_count(&self) -> usize {
        self.missing_files
    }

    /// Locate, read and decrypt one backed-up file's blob.
    ///
    /// HOW: try the modern sharded path `<root>/<id[0:2]>/<id>` first, then the
    /// flat legacy path `<root>/<id>`; unwrap the per-file key with its class
    /// key; AES-CBC-decrypt with the zero IV; truncate to the real size.
    fn decrypt_file(&self, meta: &BackupEntry) -> Result<Vec<u8>> {
        let class_key = self
            .class_keys
            .get(&meta.protection_class)
            .with_context(|| {
                format!(
                    "no class key for protection class {} (file {})",
                    meta.protection_class, meta.file_id
                )
            })?;
        let file_key = unwrap_key(class_key, &meta.wrapped_key)
            .with_context(|| format!("cannot unwrap per-file key for {}", meta.file_id))?;

        let blob = self.read_blob(&meta.file_id)?;
        let mut plain = aes_cbc_decrypt(&file_key, &ZERO_IV, &blob)
            .with_context(|| format!("cannot decrypt {}", meta.file_id))?;
        // CBC rounds up to a block; the manifest size is authoritative.
        plain.truncate(meta.size as usize);
        Ok(plain)
    }

    /// Read the encrypted on-disk blob for `file_id` from the inner source.
    fn read_blob(&self, file_id: &str) -> Result<Vec<u8>> {
        read_backup_blob(self.inner, &self.root_prefix, file_id)
    }
}

impl Source for EncryptedBackupSource<'_> {
    fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// LAZY decrypt: this is the ONLY place a file's bytes are decrypted, and the
    /// engine calls it only for entries that survive the path/type/media filters.
    /// Filtered-out files are therefore never decrypted — the performance
    /// guarantee for a backup where every file is individually encrypted.
    fn content(&self, entry: &Entry) -> Result<Content<'_>> {
        let idx = meta_index(&self.entries, &entry.name)?;
        let plain = self.decrypt_file(&self.meta[idx])?;
        Ok(Content::Owned(plain))
    }

    /// Sum of the logical (real) file sizes, for the coverage report.
    fn byte_size(&self) -> u64 {
        self.entries.iter().map(|e| e.uncompressed_size).sum()
    }

    /// Verify the file's encrypted on-disk blob against the SHA-1 `Digest`
    /// recorded for it in `Manifest.db`. WHY the ciphertext and not the
    /// plaintext: a modern iOS `Manifest.db` records the digest of the *encrypted*
    /// blob as stored, so checking it attests the original evidence was read
    /// intact before decryption. Entries with no recorded digest, or that can't
    /// be located, return [`IntegrityCheck::Unrecorded`] (degrade, don't fail —
    /// the export still records the bytes it wrote).
    fn integrity_check(&self, entry: &Entry) -> IntegrityCheck {
        let Ok(idx) = meta_index(&self.entries, &entry.name) else {
            return IntegrityCheck::Unrecorded;
        };
        let meta = &self.meta[idx];
        check_blob_digest(
            self.inner,
            &self.root_prefix,
            &meta.file_id,
            meta.digest.as_deref(),
        )
    }
}

/// Unwrap an RFC 3394-wrapped key into a fixed 32-byte array.
fn unwrap_key(kek: &[u8; KEY_SZ], wrapped: &[u8]) -> Result<[u8; KEY_SZ]> {
    let unwrapped = aes_unwrap(kek, wrapped)?;
    if unwrapped.len() != KEY_SZ {
        bail!(
            "unwrapped key has wrong length {} (expected {KEY_SZ})",
            unwrapped.len()
        );
    }
    let mut key = [0u8; KEY_SZ];
    key.copy_from_slice(&unwrapped);
    Ok(key)
}

/// Build the logical entries and parallel decryption metadata from the decrypted
/// `Manifest.db`, plus a count of regular files listed but absent on disk.
///
/// The shared [`read_present_files`] walk does the filtering, missing-file
/// counting, and name building (see there); this only keeps the files that carry
/// an `EncryptionKey` — a present regular file without one is not decryptable and
/// is dropped (it is not counted as missing). Records arrive sorted by name, so
/// `entries`/`meta` stay aligned and deterministic.
fn build_entries(
    manifest_db: &[u8],
    inner: &dyn Source,
    root_prefix: &str,
) -> (Vec<Entry>, Vec<BackupEntry>, usize) {
    let (records, missing) = read_present_files(manifest_db, inner, root_prefix);

    let mut entries = Vec::new();
    let mut meta = Vec::new();
    for r in records {
        let Some(wrapped_key) = r.mb.encryption_key else {
            continue;
        };
        entries.push(logical_entry(&r.name, r.mb.size));
        meta.push(BackupEntry {
            file_id: r.file_id,
            protection_class: r.mb.protection_class,
            wrapped_key,
            size: r.mb.size,
            digest: r.mb.digest,
        });
    }
    (entries, meta, missing)
}
