//! `MBFile` decode: pull the per-file crypto fields out of a `Manifest.db` blob.
//!
//! Defines: [`MBFile`] (the three fields a `BackupSource` needs to decrypt one
//! backed-up file) and [`parse_mbfile`], which decodes the NSKeyedArchiver
//! `MBFile` BLOB stored in each `Files.file` cell.
//! Used by: `ios::backup::source` (the `BackupSource` builder), once per regular
//! file, to learn its protection class, wrapped per-file key, and real length.
//! Uses: the `plist` crate (already a dependency) to parse the archive, then a
//! manual UID unflatten — the same NSKeyedArchiver shape `inspect::nskeyed`
//! walks, but here we extract typed values rather than resolve a match path.
//!
//! ── What an `MBFile` is ──────────────────────────────────────────────────────
//! `Manifest.db`'s `Files` table stores, per backed-up file, an NSKeyedArchiver
//! blob describing the file's metadata (an `MBFile`). Three of its fields drive
//! decryption:
//!   • `ProtectionClass` (int) — which data-protection class key unwraps this
//!     file's per-file key;
//!   • `EncryptionKey` (data) — the RFC 3394-wrapped per-file key. Its bytes are
//!     a 4-byte little-endian class number followed by the wrapped key (the same
//!     class number, repeated), OR — on some producers — just the wrapped key;
//!   • `Size` (int) — the file's real plaintext length. AES-CBC rounds the
//!     ciphertext up to a block boundary, so this is the authoritative length to
//!     truncate the decrypted bytes to.
//!
//! ── NSKeyedArchiver unflattening (how `parse_mbfile` reads it) ───────────────
//! `plist::Value::from_reader` yields the raw archive: a root dict with `$top`
//! (a dict mapping `root` → a `Uid`) and `$objects` (a flat array). We follow
//! `$top.root` (a `Uid`) into `$objects` to reach the `MBFile` dict, read its
//! `ProtectionClass`/`Size` integers directly, and follow its `EncryptionKey`
//! `Uid` into `$objects` to reach the key bytes — which appear either as a bare
//! `Data` object or as an `NSMutableData` wrapper dict carrying an `NS.data`
//! field. Both forms are handled.
//!
//! Degrade-don't-die: a record with no usable `EncryptionKey` (a directory,
//! symlink, or other non-regular entry) is simply not a decryptable file, so
//! `parse_mbfile` returns `None` and the caller skips it rather than failing.

use plist::Value;

/// The crypto-relevant fields of one backed-up file's `MBFile` record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MBFile {
    /// Data-protection class whose class key unwraps [`MBFile::encryption_key`].
    /// `0` when the record carries no protection class (an unencrypted backup).
    pub(crate) protection_class: u32,
    /// The RFC 3394-wrapped per-file key (the 4-byte class prefix, when present,
    /// is stripped — this is the wrapped key bytes only). `None` for a file with
    /// no `EncryptionKey` — i.e. every file of an UNENCRYPTED backup, and
    /// directories/symlinks of an encrypted one.
    pub(crate) encryption_key: Option<Vec<u8>>,
    /// The file's real plaintext length, in bytes (the CBC truncation target).
    pub(crate) size: u64,
    /// The `Digest` recorded for the file, when present — for encrypted backups
    /// this is the SHA-1 (20 bytes) of the *encrypted* on-disk blob, used by the
    /// export path to attest that the stored ciphertext was read intact before
    /// decryption (see `ios::backup::source`). `None` when the record carries no
    /// digest (older producers, or a non-file entry).
    pub(crate) digest: Option<Vec<u8>>,
}

/// Parse an `MBFile` NSKeyedArchiver blob into its fields.
///
/// Returns `None` only when the blob is not a parseable NSKeyedArchiver, the
/// `MBFile` dict cannot be reached, or it carries no `Size` — i.e. it is not a
/// usable file record. A missing `EncryptionKey` is NOT a failure: it yields
/// `encryption_key: None`, which is the normal case for every file of an
/// unencrypted backup (and for directories/symlinks of an encrypted one). The
/// caller decides what to do with a keyless record (skip it when decrypting,
/// keep it when reading an unencrypted backup).
pub(crate) fn parse_mbfile(blob: &[u8]) -> Option<MBFile> {
    let root = Value::from_reader(std::io::Cursor::new(blob)).ok()?;
    let root = root.as_dictionary()?;
    let objects = root.get("$objects")?.as_array()?;

    // $top.root is a UID into $objects pointing at the MBFile dict.
    let top = root.get("$top")?.as_dictionary()?;
    let mbfile_idx = uid_index(top.get("root")?)?;
    let mbfile = objects.get(mbfile_idx)?.as_dictionary()?;

    // ProtectionClass / Size are stored as plain integers directly in the dict.
    // WHY signed-then-cast: NSKeyedArchiver encodes them as signed integers; a
    // real protection class / size is non-negative, so a lossless cast is safe
    // and a negative value (corruption) simply yields a nonsensical-but-bounded
    // number rather than a panic. ProtectionClass is absent on an unencrypted
    // backup, so it defaults to 0 there.
    let protection_class = mbfile
        .get("ProtectionClass")
        .and_then(Value::as_signed_integer)
        .unwrap_or(0) as u32;
    let size = mbfile.get("Size")?.as_signed_integer()? as u64;

    // EncryptionKey is a UID → either a bare Data object or an NSMutableData
    // wrapper dict with an `NS.data` field. Absent on an unencrypted backup.
    let encryption_key = mbfile
        .get("EncryptionKey")
        .and_then(uid_index)
        .and_then(|i| objects.get(i))
        .and_then(data_bytes)
        // The wrapped-key bytes are a 4-byte little-endian class number followed
        // by the wrapped key. Strip that prefix when present so the caller gets
        // the wrapped key alone; some producers omit it, in which case we pass
        // the bytes through unchanged. WHY length-based detection: an RFC 3394-
        // wrapped 32-byte key is 40 bytes; with the 4-byte class prefix the blob
        // is 44. Anything exactly 4 longer than a valid wrap length carries it.
        .map(strip_class_prefix);

    // Digest is optional: a UID → a data object (bare Data or NS.data wrapper).
    // Absent/non-data ⇒ no attestable digest for this file (degrade, don't fail).
    let digest = mbfile
        .get("Digest")
        .and_then(uid_index)
        .and_then(|i| objects.get(i))
        .and_then(data_bytes);

    Some(MBFile {
        protection_class,
        encryption_key,
        size,
        digest,
    })
}

/// The `$objects` index a `plist::Value::Uid` refers to, or `None` if not a UID.
fn uid_index(value: &Value) -> Option<usize> {
    match value {
        Value::Uid(uid) => Some(uid.get() as usize),
        _ => None,
    }
}

/// Extract data bytes from an `EncryptionKey` object: a bare `Data`, or an
/// `NSMutableData`/`NSData` wrapper dict whose `NS.data` field holds the bytes.
fn data_bytes(obj: &Value) -> Option<Vec<u8>> {
    match obj {
        Value::Data(d) => Some(d.clone()),
        Value::Dictionary(dict) => dict.get("NS.data").and_then(|v| match v {
            Value::Data(d) => Some(d.clone()),
            _ => None,
        }),
        _ => None,
    }
}

/// Strip the optional 4-byte little-endian class-number prefix from the wrapped
/// key bytes.
///
/// The class number prefix is purely informational here (the protection class is
/// already read from `ProtectionClass`); the per-file unwrap needs only the
/// wrapped key. A wrapped AES-256 key is a multiple of 8 bytes (RFC 3394); the
/// prefixed form is that plus 4. So when the length is `≡ 4 (mod 8)` we drop the
/// leading 4 bytes; otherwise the bytes are already the bare wrapped key.
fn strip_class_prefix(bytes: Vec<u8>) -> Vec<u8> {
    if bytes.len() >= 4 && bytes.len() % 8 == 4 {
        bytes[4..].to_vec()
    } else {
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal NSKeyedArchiver `MBFile` blob with the three fields, using
    /// the `plist` crate to serialise the same `$objects`/`$top` shape Apple's
    /// archiver produces. This is a SYNTHETIC equivalent of a real record — no
    /// bytes from any real backup — modelled on the structure observed via
    /// `plutil` on an archiver-produced dictionary.
    fn synthetic_mbfile(
        protection_class: i64,
        key_bytes: &[u8],
        size: i64,
        wrap_key_as_nsdata: bool,
    ) -> Vec<u8> {
        use plist::{Dictionary, Uid};

        // $objects[0] = "$null"; [1] = MBFile dict; [2] = ProtectionClass int;
        // [3] = Size int; [4] = the key data (bare Data, or NSMutableData wrapper).
        let mut mbfile = Dictionary::new();
        mbfile.insert(
            "ProtectionClass".into(),
            Value::Integer(protection_class.into()),
        );
        mbfile.insert("Size".into(), Value::Integer(size.into()));
        mbfile.insert("EncryptionKey".into(), Value::Uid(Uid::new(4)));

        let key_obj = if wrap_key_as_nsdata {
            // An NSMutableData-style wrapper dict: { NS.data: <bytes> }.
            let mut w = Dictionary::new();
            w.insert("NS.data".into(), Value::Data(key_bytes.to_vec()));
            Value::Dictionary(w)
        } else {
            Value::Data(key_bytes.to_vec())
        };

        let objects = vec![
            Value::String("$null".into()),
            Value::Dictionary(mbfile),
            Value::Integer(protection_class.into()),
            Value::Integer(size.into()),
            key_obj,
        ];

        let mut top = Dictionary::new();
        top.insert("root".into(), Value::Uid(Uid::new(1)));

        let mut root = Dictionary::new();
        root.insert("$archiver".into(), Value::String("NSKeyedArchiver".into()));
        root.insert("$version".into(), Value::Integer(100_000.into()));
        root.insert("$top".into(), Value::Dictionary(top));
        root.insert("$objects".into(), Value::Array(objects));

        let mut buf = Vec::new();
        Value::Dictionary(root)
            .to_writer_binary(&mut buf)
            .expect("serialise synthetic MBFile");
        buf
    }

    #[test]
    fn parses_fields_with_class_prefixed_key() {
        // 4-byte LE class (3) + 40-byte wrapped key ⇒ 44 bytes; the prefix is
        // stripped, leaving the 40-byte wrapped key.
        let mut key = vec![0x03, 0x00, 0x00, 0x00];
        key.extend(std::iter::repeat_n(0xAB, 40));
        let blob = synthetic_mbfile(3, &key, 12_345, false);

        let mb = parse_mbfile(&blob).unwrap();
        assert_eq!(mb.protection_class, 3);
        assert_eq!(mb.size, 12_345);
        assert_eq!(mb.encryption_key, Some(vec![0xAB; 40]));
    }

    #[test]
    fn parses_key_from_nsmutabledata_wrapper() {
        // Same prefixed key, but delivered inside an NS.data wrapper dict.
        let mut key = vec![0x04, 0x00, 0x00, 0x00];
        key.extend(std::iter::repeat_n(0xCD, 40));
        let blob = synthetic_mbfile(4, &key, 7, true);

        let mb = parse_mbfile(&blob).unwrap();
        assert_eq!(mb.protection_class, 4);
        assert_eq!(mb.encryption_key, Some(vec![0xCD; 40]));
    }

    #[test]
    fn key_without_prefix_passes_through() {
        // A bare 40-byte wrapped key (no class prefix): length 40 ≡ 0 (mod 8), so
        // nothing is stripped.
        let key = vec![0xEE; 40];
        let blob = synthetic_mbfile(2, &key, 100, false);
        let mb = parse_mbfile(&blob).unwrap();
        assert_eq!(mb.encryption_key, Some(vec![0xEE; 40]));
    }

    #[test]
    fn record_without_encryption_key_keeps_size_and_digest() {
        // An unencrypted-backup MBFile: no EncryptionKey, but Size present and a
        // Digest (SHA-1 of the plaintext file). $objects[0]=$null, [1]=MBFile,
        // [2]=Size, [3]=Digest data.
        use plist::{Dictionary, Uid};
        let mut mbfile = Dictionary::new();
        mbfile.insert("Size".into(), Value::Integer(4096.into()));
        mbfile.insert("Digest".into(), Value::Uid(Uid::new(3)));

        let digest = vec![0x11u8; 20];
        let objects = vec![
            Value::String("$null".into()),
            Value::Dictionary(mbfile),
            Value::Integer(4096.into()),
            Value::Data(digest.clone()),
        ];
        let mut top = Dictionary::new();
        top.insert("root".into(), Value::Uid(Uid::new(1)));
        let mut root = Dictionary::new();
        root.insert("$top".into(), Value::Dictionary(top));
        root.insert("$objects".into(), Value::Array(objects));
        let mut buf = Vec::new();
        Value::Dictionary(root).to_writer_binary(&mut buf).unwrap();

        let mb = parse_mbfile(&buf).unwrap();
        assert_eq!(mb.encryption_key, None);
        assert_eq!(mb.protection_class, 0);
        assert_eq!(mb.size, 4096);
        assert_eq!(mb.digest, Some(digest));
    }

    #[test]
    fn parses_optional_digest_when_present() {
        use plist::{Dictionary, Uid};

        // Hand-build an MBFile that also carries a `Digest` UID → Data object.
        // $objects[0]=$null, [1]=MBFile, [2]=ProtectionClass, [3]=Size,
        // [4]=EncryptionKey data, [5]=Digest data.
        let mut mbfile = Dictionary::new();
        mbfile.insert("ProtectionClass".into(), Value::Integer(3.into()));
        mbfile.insert("Size".into(), Value::Integer(99.into()));
        mbfile.insert("EncryptionKey".into(), Value::Uid(Uid::new(4)));
        mbfile.insert("Digest".into(), Value::Uid(Uid::new(5)));

        let digest = vec![0xDEu8; 20];
        let objects = vec![
            Value::String("$null".into()),
            Value::Dictionary(mbfile),
            Value::Integer(3.into()),
            Value::Integer(99.into()),
            Value::Data(vec![0xAB; 40]),
            Value::Data(digest.clone()),
        ];

        let mut top = Dictionary::new();
        top.insert("root".into(), Value::Uid(Uid::new(1)));
        let mut root = Dictionary::new();
        root.insert("$top".into(), Value::Dictionary(top));
        root.insert("$objects".into(), Value::Array(objects));

        let mut buf = Vec::new();
        Value::Dictionary(root)
            .to_writer_binary(&mut buf)
            .expect("serialise MBFile with Digest");

        let mb = parse_mbfile(&buf).unwrap();
        assert_eq!(mb.digest, Some(digest));
    }

    #[test]
    fn digest_absent_is_none() {
        // The standard synthetic builder writes no Digest field.
        let blob = synthetic_mbfile(3, &[0xAB; 40], 1, false);
        let mb = parse_mbfile(&blob).unwrap();
        assert_eq!(mb.digest, None);
    }

    #[test]
    fn non_archive_blob_is_none() {
        assert!(parse_mbfile(b"not a plist").is_none());
    }
}
