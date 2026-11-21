//! Tests of encrypted ZIP inputs (WinZip AES, ZipCrypto) and of entries whose
//! compression method is not read.
//!
//! Defines: tests over the mapped and the ranged ZIP readers (every scheme decodes,
//! a missing or wrong password and damaged data fail, saying why), and runs of the
//! binary (the password from the environment, the stderr notes, the exit status).
//! Used by: `cargo test`.
//! Uses: `tests/fixtures/encrypted_zip/` (made by 7-Zip and Info-ZIP, see the
//! fixtures README), `mf_scan::core::source::{zip, ranged}`, `tempfile`, the binary.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use mf_scan::core::models::{Entry, Location};
use mf_scan::core::source::Source;
use mf_scan::core::source::ranged::RangedZipSource;
use mf_scan::core::source::zip::{ZipSource, not_searched_notes};
use tempfile::tempdir;

/// The fixtures' made-up password.
const PASSWORD: &str = "fixture-password";
const PASSWORD_VAR: &str = "MFSCAN_ARCHIVE_PASSWORD";
/// Every archive whose two files are encrypted, each scheme and tool.
const ENCRYPTED: [&str; 6] = [
    "note.aes256.zip",
    "note.aes192.zip",
    "note.aes128.zip",
    "note.aes256-stored.zip",
    "note.zipcrypto.zip",
    "note.infozip.zip",
];

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/encrypted_zip")
        .join(name)
}

fn filler() -> String {
    (0..2000)
        .map(|i| format!("line {i} of filler text\n"))
        .collect()
}

fn read(source: &dyn Source, name: &str) -> anyhow::Result<Vec<u8>> {
    let entry = source
        .entries()
        .iter()
        .find(|e| e.name == name)
        .unwrap_or_else(|| panic!("no {name}"));
    Ok(source.content(entry)?.into_owned())
}

#[test]
fn every_scheme_decodes_through_both_readers() {
    for name in ENCRYPTED {
        let bytes = fs::read(fixture(name)).unwrap();
        let mapped = ZipSource::open_with_password(&bytes, Some(PASSWORD)).unwrap();
        let ranged = RangedZipSource::open_with_password(&fixture(name), Some(PASSWORD)).unwrap();
        for source in [&mapped as &dyn Source, &ranged] {
            assert_eq!(
                read(source, "evidence/note.txt").unwrap(),
                b"needle in a zip\n",
                "{name}"
            );
            assert_eq!(
                read(source, "evidence/filler.txt").unwrap(),
                filler().as_bytes(),
                "{name}"
            );
            // Every file is encrypted (the `evidence/` directory entry has no data).
            let files = source.entries().iter().filter(|e| !e.is_dir());
            assert!(
                files.clone().count() == 2 && files.clone().all(Entry::is_encrypted),
                "{name}"
            );
        }
        let notes = not_searched_notes(mapped.entries(), true);
        assert_eq!(notes.len(), 1, "{name}: {notes:?}");
        assert!(
            notes[0].contains("decrypted with the supplied password"),
            "{notes:?}"
        );
    }
}

#[test]
fn without_the_password_encrypted_files_are_listed_and_fail_saying_why() {
    for name in ENCRYPTED {
        let bytes = fs::read(fixture(name)).unwrap();
        let source = ZipSource::open_with_password(&bytes, None).unwrap();
        let files = source.entries().iter().filter(|e| !e.is_dir()).count();
        assert_eq!(files, 2, "{name}: listed, not dropped");
        let e = read(&source, "evidence/note.txt").unwrap_err();
        assert!(
            format!("{e:#}").contains("--archive-password"),
            "{name}: {e:#}"
        );
        let notes = not_searched_notes(source.entries(), false);
        assert!(
            notes
                .iter()
                .any(|n| n.contains("2 encrypted file(s)") && n.contains("NOT searched")),
            "{name}: {notes:?}"
        );
    }
}

#[test]
fn a_wrong_password_fails_on_open() {
    for name in ENCRYPTED {
        let bytes = fs::read(fixture(name)).unwrap();
        let Err(e) = ZipSource::open_with_password(&bytes, Some("not the password")) else {
            panic!("{name}: opened with a wrong password");
        };
        assert!(format!("{e:#}").contains("does not open"), "{name}: {e:#}");
        assert!(
            RangedZipSource::open_with_password(&fixture(name), Some("not the password")).is_err(),
            "{name}: the ranged reader opened with a wrong password"
        );
    }
}

#[test]
fn damaged_encrypted_data_fails_its_check() {
    // One byte inside `filler.txt`'s ciphertext: AES fails its authentication code,
    // ZipCrypto its CRC-32 (or its inflate). Never a wrong result.
    for name in ENCRYPTED {
        let mut bytes = fs::read(fixture(name)).unwrap();
        let offset = {
            let source = ZipSource::open(&bytes).unwrap();
            let entry = source
                .entries()
                .iter()
                .find(|e| e.name == "evidence/filler.txt")
                .unwrap();
            let Location::Zip { data_offset, .. } = entry.location else {
                panic!("a mapped entry");
            };
            data_offset as usize
        };
        bytes[offset + 40] ^= 0x55;
        // `note.txt`, the smallest, still opens: the damage is found where it is.
        let source = ZipSource::open_with_password(&bytes, Some(PASSWORD)).unwrap();
        assert!(
            read(&source, "evidence/filler.txt").is_err(),
            "{name}: damaged data must fail"
        );
    }
}

#[test]
fn a_plain_file_beside_encrypted_ones_reads_without_a_password() {
    let bytes = fs::read(fixture("mixed.zip")).unwrap();
    let source = ZipSource::open_with_password(&bytes, None).unwrap();
    assert_eq!(
        read(&source, "plain.txt").unwrap(),
        b"plain needle beside encrypted files\n"
    );
    assert!(read(&source, "evidence/note.txt").is_err());
}

#[test]
fn a_method_not_read_is_listed_and_fails_saying_which() {
    for (name, method) in [
        ("note.bzip2.zip", "bzip2 (12)"),
        ("note.lzma.zip", "LZMA (14)"),
    ] {
        let bytes = fs::read(fixture(name)).unwrap();
        let source = ZipSource::open(&bytes).unwrap();
        // 7-Zip stored the small file, and compressed the other.
        assert_eq!(
            read(&source, "evidence/note.txt").unwrap(),
            b"needle in a zip\n"
        );
        let e = read(&source, "evidence/filler.txt").unwrap_err();
        assert!(format!("{e:#}").contains("does not read"), "{name}: {e:#}");
        let notes = not_searched_notes(source.entries(), false);
        assert_eq!(notes.len(), 1, "{name}: {notes:?}");
        assert!(
            notes[0].contains(&format!("1 {method}")),
            "{name}: {notes:?}"
        );
    }
}

fn grep(dir: &Path, operand: &str, password: Option<&str>, extra: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_mf-scan"));
    command
        .current_dir(dir)
        .args(["grep", "--no-report", "--no-stats"])
        .args(extra)
        .args(["needle", operand])
        .env_remove(PASSWORD_VAR);
    if let Some(password) = password {
        command.env(PASSWORD_VAR, password);
    }
    command.output().expect("run mf-scan")
}

#[test]
fn the_binary_decrypts_with_the_password_and_fails_loudly_without() {
    let dir = tempdir().unwrap();
    for name in ENCRYPTED {
        fs::copy(fixture(name), dir.path().join(name)).unwrap();
        for io in ["mmap", "ranged"] {
            let out = grep(
                dir.path(),
                name,
                Some(PASSWORD),
                &["-f", "json", "--io-mode", io],
            );
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert_eq!(out.status.code(), Some(0), "{name} {io}: {stderr}");
            let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
            let hit = &json["results"][0];
            assert_eq!(hit["path"], "evidence/note.txt", "{name} {io}");
            // Found in decrypted bytes: flagged, and no archive byte claimed for it.
            assert_eq!(hit["decrypted"], true, "{name} {io}: {hit}");
            assert!(
                stderr.contains("decrypted with the supplied password"),
                "{stderr}"
            );
        }

        // No password: listed, NOT searched, exit 2 (not 1, "no match").
        let out = grep(dir.path(), name, None, &["-l"]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{name}: {stderr}");
        assert!(stderr.contains("NOT searched"), "{name}: {stderr}");

        // A wrong password stops the run, saying so.
        let out = grep(dir.path(), name, Some("not the password"), &["-l"]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{name}: {stderr}");
        assert!(stderr.contains("does not open"), "{name}: {stderr}");
    }
}

#[test]
fn the_binary_searches_the_plain_files_and_still_reports_the_rest() {
    let dir = tempdir().unwrap();
    for (name, found) in [
        ("mixed.zip", "plain.txt"),
        ("note.bzip2.zip", "evidence/note.txt"),
    ] {
        fs::copy(fixture(name), dir.path().join(name)).unwrap();
        let out = grep(dir.path(), name, None, &["-l"]);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stdout.contains(found), "{name}: {stdout}");
        // A match, but files were not searched: the error outranks it.
        assert_eq!(out.status.code(), Some(2), "{name}: {stderr}");
        assert!(stderr.contains("NOT searched"), "{name}: {stderr}");
    }
}
