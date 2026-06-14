//! iOS backup (iTunes/Finder) support: recognition, crypto, and logical views.
//!
//! Defines: this namespace covering both backup flavours behind one
//! [`source::BackupSource`] — an enum over [`source::EncryptedBackupSource`] and
//! [`source::PlainBackupSource`], picked from the recognised [`profile`]. For an
//! ENCRYPTED backup, the low-level crypto layer that unlocks it lives in the
//! `BackupKeyBag` parser ([`keybag`]) and the KDF / AES key-unwrap / AES-CBC
//! primitives ([`keys`]); for an UNENCRYPTED backup, no decryption is needed. The
//! two sources share their structure through `source::common` (the `Manifest.db`
//! `Files` walk, blob locating, missing-file counting, logical-entry building,
//! and the SHA-1 digest attestation); they also share the `MBFile` decode
//! (`manifest`), backup recognition ([`profile`]), and the provenance record
//! ([`password::BackupRecord`]). Each source is then only what
//! is unique to it: per-file decryption for the encrypted one, nothing extra for
//! the unencrypted one.
//! Used by: `support::sources` — the profiler picks the encrypted vs unencrypted
//! source; both expose the decrypted/logical view through the `Source` trait.
//! Uses: RustCrypto crates `aes` (AES-256 single-block for RFC 3394 key unwrap
//! and AES-256-CBC), `cbc` (CBC mode), `pbkdf2` + `sha1`/`sha2` (the
//! double-PBKDF2 backup-password KDF) — all pure-Rust, no new dependency.
//!
//! ── How an encrypted iOS backup is unlocked (what this layer implements) ─────
//! `Manifest.plist` carries a `BackupKeyBag`: a flat TLV blob describing a set of
//! data-protection classes, each holding a class key wrapped (RFC 3394) by a key
//! derived from the backup password. The flow is:
//!   1. parse the keybag (`keybag::parse`) → salt, iteration counts, per-class
//!      wrapped keys (`keys.rs` consumes this);
//!   2. derive the keybag key from the password (`keys::derive_keybag_key`) —
//!      a single PBKDF2-HMAC-SHA1, or the iOS 10.2+ double PBKDF2 (SHA256 then
//!      SHA1) when the keybag carries `DPSL`/`DPIC`;
//!   3. AES-key-unwrap each passcode-wrapped class key with that keybag key
//!      (`keys::unwrap_class_keys`) → class number → 32-byte class key;
//!   4. (next sub-stage) each file's `Manifest.db` record names its class and
//!      carries its own wrapped per-file key; unwrap it with the class key and
//!      AES-256-CBC-decrypt the file with a zero IV (`keys::aes_cbc_decrypt`).
//!
//! ✓ VALIDATION STATUS
//! The AES key-unwrap primitive ([`keys::aes_unwrap`]) is validated against the
//! published RFC 3394 §4.6 known-answer vector ("Wrap 256 bits of Key Data with a
//! 256-bit KEK"), with a corrupted-ciphertext case asserted to fail the integrity
//! check.
//! The end-to-end path is ALSO validated against a real encrypted iOS backup (a
//! Finder/iTunes backup of an A12 device, `00008030-…`, with backup encryption
//! enabled): the supplied password unlocks the keybag, `Manifest.db` decrypts to
//! a valid SQLite database, and every per-file blob decrypts. The known answer is
//! the per-file `Digest` recorded in `Manifest.db`: for each file the SHA-1 of
//! the *encrypted* on-disk blob matched its recorded `Digest` (435/435 files),
//! which independently confirms both that `Manifest.db` decrypted correctly (the
//! digests were read from the right place) and that the right blobs were located.
//! This digest check is wired into the export path as a forensic integrity
//! attestation (see [`source::EncryptedBackupSource`]'s `integrity_check`).
//! The format details remain assembled from the open-source descriptions in the
//! `iphone-dataprotection` project and the `mvt-project` / `mvt` toolkit; the
//! single-vs-double PBKDF2 KDF path is exercised by the double-PBKDF2 backup
//! validated above (it carries `DPSL`/`DPIC`).
//! The UNENCRYPTED path ([`source::PlainBackupSource`]) is validated against a real
//! unencrypted backup (`00008120-…`): files are presented by logical
//! `domain/relativePath`, and where `Manifest.db` records a per-file `Digest` the
//! SHA-1 of the on-disk file content matched it (41/41 of a sampled set, 0
//! mismatches; many files legitimately carry no `Digest`). For an unencrypted
//! backup the `Digest` is the SHA-1 of the file *content* (the blob is plaintext),
//! versus the SHA-1 of the *ciphertext* in the encrypted case — both are the SHA-1
//! of the bytes on disk, so the `Source::integrity_check` is identical for both.

pub(crate) mod common;
pub mod keybag;
pub mod keys;
pub(crate) mod manifest;
pub mod password;
pub mod profile;
pub mod source;
