//! Integration tests over the committed mini iOS-backup fixtures.
//!
//! The fixtures under `tests/fixtures/backup/{unencrypted,encrypted}` are tiny,
//! fully-synthetic but structurally real backups (see `generate.py` there). They
//! let the encrypted/unencrypted `BackupSource` paths be exercised end to end —
//! profile detection, logical `domain/relativePath` naming, decryption, the SHA-1
//! `Digest` attestation, and the missing-on-disk count — without any real data.

use std::path::PathBuf;

use mf_scan::core::models::Entry;
use mf_scan::core::source::folder::FolderSource;
use mf_scan::core::source::{IntegrityCheck, Source};
use mf_scan::platform::ios::backup::profile;
use mf_scan::platform::ios::backup::source::BackupSource;

/// Path to a fixture backup directory.
fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/backup")
        .join(name)
}

/// The logical names this source exposes.
fn names(src: &dyn Source) -> Vec<String> {
    src.entries().iter().map(|e| e.name.clone()).collect()
}

/// The entry named `name` (panicking if absent — the test asserts presence).
fn entry<'a>(src: &'a dyn Source, name: &str) -> &'a Entry {
    src.entries()
        .iter()
        .find(|e| e.name == name)
        .unwrap_or_else(|| panic!("entry {name} not found in {:?}", names(src)))
}

const SMS: &str = "HomeDomain/Library/SMS/sms.db";
const NOTES: &str = "AppDomain-com.test.app/Documents/notes.txt";
const NOTES_CONTENT: &[u8] = b"hello SECRET_TOKEN_42 world\n";

#[test]
fn unencrypted_backup_maps_logical_paths_and_skips_missing() {
    let path = fixture("unencrypted");
    let folder = FolderSource::open(&path, 0).unwrap();

    let p = profile::detect(&folder).expect("fixture is recognised as a backup");
    assert!(!p.encrypted);

    let bs = BackupSource::build(&folder, &p, None).unwrap();

    // Provenance: 3 files mapped, the 1 manifest-only file counted as missing.
    let rec = bs.record(&p);
    assert!(!rec.encrypted);
    assert_eq!(rec.files, 3);
    assert_eq!(rec.missing_files, 1);

    // Logical names; the directory row and the missing file are not exposed.
    let names = names(&bs);
    assert!(names.contains(&SMS.to_string()));
    assert!(names.contains(&NOTES.to_string()));
    assert!(!names.iter().any(|n| n.contains("ghost.db")));
    assert!(!names.iter().any(|n| n == "HomeDomain/Library"));

    // Content is served straight through (no decryption).
    assert_eq!(&*bs.content(entry(&bs, NOTES)).unwrap(), NOTES_CONTENT);

    // A file with a recorded Digest verifies; one without is Unrecorded.
    assert!(matches!(
        bs.integrity_check(entry(&bs, SMS)),
        IntegrityCheck::Verified { algorithm: "sha1" }
    ));
    assert_eq!(
        bs.integrity_check(entry(&bs, NOTES)),
        IntegrityCheck::Unrecorded
    );
}

#[test]
fn encrypted_backup_decrypts_with_password() {
    let path = fixture("encrypted");
    let folder = FolderSource::open(&path, 0).unwrap();

    let p = profile::detect(&folder).expect("fixture is recognised as a backup");
    assert!(p.encrypted);

    let bs = BackupSource::build(&folder, &p, Some("1234")).unwrap();

    let rec = bs.record(&p);
    assert!(rec.encrypted);
    assert_eq!(rec.files, 3);
    assert_eq!(rec.missing_files, 1);

    // The blob decrypts to the original plaintext.
    assert_eq!(&*bs.content(entry(&bs, NOTES)).unwrap(), NOTES_CONTENT);

    // The stored ciphertext matches its Manifest.db SHA-1 Digest.
    assert!(matches!(
        bs.integrity_check(entry(&bs, SMS)),
        IntegrityCheck::Verified { algorithm: "sha1" }
    ));
}

#[test]
fn encrypted_backup_wrong_password_errors() {
    let path = fixture("encrypted");
    let folder = FolderSource::open(&path, 0).unwrap();
    let p = profile::detect(&folder).unwrap();
    assert!(BackupSource::build(&folder, &p, Some("not-the-password")).is_err());
}
