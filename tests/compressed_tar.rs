//! End-to-end tests of compressed tar inputs (gzip, bzip2, xz, zstd).
//!
//! Defines: tests that grep each fixture through the real binary, under its own name
//! and under a name that says nothing, and grep a damaged copy.
//! Used by: `cargo test`.
//! Uses: `tests/fixtures/compressed/` (made by the reference tools, see the fixtures
//! README), `tempfile`, and the binary Cargo builds.
//!
//! WHY through the binary: what a file is gets decided where the operand is opened
//! (`sniff_container`), then read by the tar source; only a run covers both.

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use tempfile::tempdir;

const FIXTURES: [&str; 4] = ["note.tar.gz", "note.tar.bz2", "note.tar.xz", "note.tar.zst"];

fn fixture(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/compressed")
        .join(name);
    fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn grep_files(dir: &Path, operand: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mf-scan"))
        .current_dir(dir)
        .args(["grep", "--no-report", "--no-stats", "-l", "needle", operand])
        .output()
        .expect("run mf-scan")
}

#[test]
fn each_compressed_tar_is_searched_by_name_and_by_content() {
    let dir = tempdir().unwrap();
    for name in FIXTURES {
        // Its own name, then a name that says nothing: the content decides.
        for operand in [name, "evidence.bin"] {
            fs::write(dir.path().join(operand), fixture(name)).unwrap();
            let out = grep_files(dir.path(), operand);
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert_eq!(
                out.status.code(),
                Some(0),
                "{name} as {operand}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            assert!(
                stdout.contains("evidence/note.txt"),
                "{name} as {operand}: {stdout}"
            );
        }
    }
}

#[test]
fn a_damaged_compressed_tar_fails_loudly() {
    let dir = tempdir().unwrap();
    for name in FIXTURES {
        let mut bytes = fixture(name);
        let at = bytes.len() - 12;
        bytes[at] ^= 0x55;
        fs::write(dir.path().join(name), &bytes).unwrap();
        let out = grep_files(dir.path(), name);
        // Exit 2 (an error), not 1 (no match): a damaged stream must not read as a
        // smaller archive that happens not to match.
        assert_eq!(out.status.code(), Some(2), "{name}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("cannot decompress"), "{name}: {stderr}");
    }
}
