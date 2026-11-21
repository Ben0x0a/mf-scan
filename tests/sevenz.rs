//! End-to-end tests of 7z inputs: plain, PPMd, BZip2, and AES-encrypted.
//!
//! Defines: tests that grep each fixture through the real binary, under its own name
//! and under a name that says nothing, with the password from the environment, and
//! without it.
//! Used by: `cargo test`.
//! Uses: `tests/fixtures/sevenz/` (made by 7-Zip, see the fixtures README),
//! `tempfile`, and the binary Cargo builds.
//!
//! WHY through the binary: what a file is gets decided where the operand is opened
//! (`sniff_container`), the password comes from the command line or the environment,
//! and the provenance line is printed there; only a run covers all three.

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use tempfile::tempdir;

/// The fixtures' made-up password.
const PASSWORD: &str = "fixture-password";
const PASSWORD_VAR: &str = "MFSCAN_ARCHIVE_PASSWORD";

fn fixture(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/sevenz")
        .join(name);
    fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn grep_files(dir: &Path, operand: &str, password: Option<&str>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_mf-scan"));
    command
        .current_dir(dir)
        .args(["grep", "--no-report", "--no-stats", "-l", "needle", operand])
        .env_remove(PASSWORD_VAR);
    if let Some(password) = password {
        command.env(PASSWORD_VAR, password);
    }
    command.output().expect("run mf-scan")
}

#[test]
fn each_7z_is_searched_by_name_and_by_content() {
    let dir = tempdir().unwrap();
    for (name, password) in [
        ("note.7z", None),
        ("note.ppmd.7z", None),
        ("note.bzip2.7z", None),
        ("note.aes.7z", Some(PASSWORD)),
        ("note.aes-header.7z", Some(PASSWORD)),
    ] {
        for operand in [name, "evidence.bin"] {
            fs::write(dir.path().join(operand), fixture(name)).unwrap();
            let out = grep_files(dir.path(), operand, password);
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert_eq!(out.status.code(), Some(0), "{name} as {operand}: {stderr}");
            assert!(
                stdout.contains("evidence/note.txt"),
                "{name} as {operand}: {stdout}"
            );
            // An encrypted archive says so, and that the password opened it.
            assert_eq!(
                stderr.contains("decrypted with the supplied password"),
                password.is_some(),
                "{name} as {operand}: {stderr}"
            );
        }
    }
}

#[test]
fn an_encrypted_7z_without_its_password_fails_loudly() {
    let dir = tempdir().unwrap();
    for name in ["note.aes.7z", "note.aes-header.7z"] {
        fs::write(dir.path().join(name), fixture(name)).unwrap();
        let out = grep_files(dir.path(), name, None);
        // Exit 2 (an error), not 1 (no match): an archive that could not be read
        // must not look like one that was searched.
        assert_eq!(out.status.code(), Some(2), "{name}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("--archive-password"), "{name}: {stderr}");
    }
}
