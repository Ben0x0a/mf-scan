//! Tests of nested containers (`--archive-depth`) inside a ZIP source: tar.gz, 7z, a
//! single gzip file, a renamed xz tar, a ZIP holding a 7z, and an encrypted 7z.
//!
//! Defines: tests over `ExpandedSource` (what is listed, read, marked expanded, and
//! noted) and runs of the binary (depth 0 against 1 and 2, the statistics line, the
//! `nested:` notes, `--nested-limit`).
//! Used by: `cargo test`.
//! Uses: `common` (the ZIP builder), the fixtures of `tests/fixtures/compressed/` and
//! `tests/fixtures/sevenz/`, `flate2` (a gzip file), `tempfile`, the binary.

mod common;

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output};

use common::{FileSpec, build_zip};
use mf_scan::core::source::Source;
use mf_scan::core::source::expand::{ExpandedSource, Nesting};
use mf_scan::core::source::zip::ZipSource;
use tempfile::tempdir;

fn fixture(path: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(path);
    fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// A log compressible enough that its gzip holds no literal (a short input can be
/// stored uncompressed, and its needle then found without opening anything).
fn log() -> Vec<u8> {
    let mut log = b"a rotated log line\n".repeat(200);
    log.extend_from_slice(b"with a needle inside\n");
    log
}

/// A ZIP holding one of each container, all STORED, so none of the needles can
/// be found without opening them; `g/plain.txt` is the one plain file.
fn case_zip() -> Vec<u8> {
    let tar_gz = fixture("compressed/note.tar.gz");
    let tar_xz = fixture("compressed/note.tar.xz");
    let sevenz = fixture("sevenz/note.7z");
    let locked = fixture("sevenz/note.aes.7z");
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(&log()).unwrap();
    let log_gz = gz.finish().unwrap();
    assert!(
        !log_gz.windows(6).any(|w| w == b"needle"),
        "the control needs a gzip without the needle in clear"
    );
    let inner = build_zip(&[FileSpec::stored("deep/note.7z", &sevenz)], false);
    build_zip(
        &[
            FileSpec::stored("a/note.tar.gz", &tar_gz),
            FileSpec::stored("b/note.7z", &sevenz),
            FileSpec::stored("c/app.log.gz", &log_gz),
            FileSpec::stored("d/locked.7z", &locked),
            // Named like nothing: recognised by its content.
            FileSpec::stored("e/blob.bin", &tar_xz),
            FileSpec::stored("f/inner.zip", &inner),
            FileSpec::stored("g/plain.txt", b"a plain needle\n"),
        ],
        false,
    )
}

fn at(depth: u32) -> Nesting {
    Nesting {
        depth,
        ..Nesting::default()
    }
}

fn read(source: &dyn Source, name: &str) -> Vec<u8> {
    let entry = source
        .entries()
        .iter()
        .find(|e| e.name == name)
        .unwrap_or_else(|| panic!("no {name} in {:?}", names(source)));
    source.content(entry).unwrap().into_owned()
}

fn names(source: &dyn Source) -> Vec<String> {
    source.entries().iter().map(|e| e.name.clone()).collect()
}

#[test]
fn each_container_is_opened_by_its_content() {
    let bytes = case_zip();
    let zip = ZipSource::open(&bytes).unwrap();
    let source = ExpandedSource::open(&zip, at(1)).unwrap();

    assert_eq!(
        read(&source, "a/note.tar.gz/evidence/note.txt"),
        b"needle in a compressed tar\n"
    );
    assert_eq!(
        read(&source, "b/note.7z/evidence/note.txt"),
        b"needle in a 7z\n"
    );
    assert_eq!(read(&source, "c/app.log.gz/app.log"), log());
    assert_eq!(
        read(&source, "e/blob.bin/evidence/note.txt"),
        b"needle in a compressed tar\n"
    );
    // One level only: the 7z inside inner.zip is listed, not opened.
    let all = names(&source);
    assert!(
        all.contains(&"f/inner.zip/deep/note.7z".to_string()),
        "{all:?}"
    );
    assert!(
        !all.iter()
            .any(|n| n.starts_with("f/inner.zip/deep/note.7z/")),
        "{all:?}"
    );

    // Every archive stays listed; those opened are marked, the rest are not.
    let expanded = |name: &str| {
        let entry = source.entries().iter().find(|e| e.name == name).unwrap();
        source.is_expanded(entry)
    };
    for name in [
        "a/note.tar.gz",
        "b/note.7z",
        "c/app.log.gz",
        "e/blob.bin",
        "f/inner.zip",
    ] {
        assert!(expanded(name), "{name} should be expanded");
    }
    assert!(
        !expanded("d/locked.7z"),
        "an encrypted 7z is searched as one file"
    );
    assert!(!expanded("g/plain.txt"));

    // The encrypted one says why it was not opened.
    let notes = source.notes().join("\n");
    assert!(notes.contains("d/locked.7z: not opened"), "{notes}");
    assert!(notes.contains("not decrypted"), "{notes}");
}

#[test]
fn depth_two_opens_a_7z_inside_a_zip_inside_the_source() {
    let bytes = case_zip();
    let zip = ZipSource::open(&bytes).unwrap();
    let source = ExpandedSource::open(&zip, at(2)).unwrap();
    assert_eq!(
        read(&source, "f/inner.zip/deep/note.7z/evidence/note.txt"),
        b"needle in a 7z\n"
    );
}

#[test]
fn depth_zero_opens_nothing() {
    let bytes = case_zip();
    let zip = ZipSource::open(&bytes).unwrap();
    let source = ExpandedSource::open(&zip, at(0)).unwrap();
    assert_eq!(names(&source), names(&zip));
    assert!(source.entries().iter().all(|e| !source.is_expanded(e)));
}

fn grep(dir: &Path, extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mf-scan"))
        .current_dir(dir)
        .args(["grep", "--no-report", "-l"])
        .args(extra)
        .args(["needle", "case.zip"])
        .output()
        .expect("run mf-scan")
}

#[test]
fn the_binary_searches_inside_nested_containers_only_when_asked() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("case.zip"), case_zip()).unwrap();

    // Depth 0, the control: only the plain file holds a needle the search can see.
    let out = grep(dir.path(), &[]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(stdout.trim(), "g/plain.txt", "{stdout}");

    let out = grep(dir.path(), &["--archive-depth", "2"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    for found in [
        "a/note.tar.gz/evidence/note.txt",
        "b/note.7z/evidence/note.txt",
        "c/app.log.gz/app.log",
        "e/blob.bin/evidence/note.txt",
        "f/inner.zip/deep/note.7z/evidence/note.txt",
        "g/plain.txt",
    ] {
        assert!(
            stdout.lines().any(|l| l == found),
            "{found} missing:\n{stdout}"
        );
    }
    assert!(
        stderr.contains("nested: d/locked.7z: not opened"),
        "{stderr}"
    );
    assert!(stderr.contains("expanded (archives opened"), "{stderr}");
    // The encrypted 7z's contents were not searched: a gap, so exit 2, as for a file
    // that could not be read, even though matches were found.
    assert!(
        stderr.contains("nested archives NOT fully searched"),
        "{stderr}"
    );
    assert_eq!(out.status.code(), Some(2), "{stderr}");
}

#[test]
fn the_nested_limit_stops_the_run_loudly() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("case.zip"), case_zip()).unwrap();
    let out = grep(
        dir.path(),
        &["--archive-depth", "1", "--nested-limit", "1K"],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("--nested-limit"), "{stderr}");
}

/// A manifest written with `--archive-depth` lists files inside nested archives;
/// `export` reopens the source as the manifest's run did, so it finds them again.
#[test]
fn export_from_a_manifest_reopens_nested_archives() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("case.zip"), case_zip()).unwrap();
    let out = grep(
        dir.path(),
        &["--archive-depth", "2", "--manifest", "m.json"],
    );
    assert!(
        dir.path().join("m.json").exists(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let out = Command::new(env!("CARGO_BIN_EXE_mf-scan"))
        .current_dir(dir.path())
        .args([
            "export",
            "case.zip",
            "--from-manifest",
            "m.json",
            "--to",
            "out",
        ])
        .output()
        .expect("run mf-scan");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(stderr.contains("as the manifest's run did"), "{stderr}");

    let exported = fs::read_dir(dir.path().join("out"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|x| x == "zip"))
        .expect("an export zip");
    let bytes = fs::read(exported).unwrap();
    let zip = ZipSource::open(&bytes).unwrap();
    // Every file the manifest lists was exported (named `<name>_<hash>/<name>`),
    // those from nested archives included, with their decoded content.
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(dir.path().join("m.json")).unwrap()).unwrap();
    let listed = manifest["file_count"].as_u64().unwrap() as usize;
    let files: Vec<_> = zip
        .entries()
        .iter()
        .filter(|e| !e.name.ends_with("export-report.json"))
        .collect();
    assert_eq!(files.len(), listed, "{:?}", names(&zip));
    let contents: Vec<Vec<u8>> = files
        .iter()
        .map(|e| zip.content(e).unwrap().into_owned())
        .collect();
    for want in [
        &b"needle in a 7z\n"[..],
        b"needle in a compressed tar\n",
        &log(),
    ] {
        assert!(
            contents.iter().any(|c| c == want),
            "missing {:?}",
            String::from_utf8_lossy(want)
        );
    }
}

#[test]
fn a_damaged_nested_tar_is_a_gap_and_is_searched_as_one_file_too() {
    let tar = fixture("compressed/note.tar");
    // Cut inside the first member's data: the walk stops there, damaged.
    let cut = &tar[..512 + 10];
    let outer = build_zip(&[FileSpec::stored("t/cut.tar", cut)], false);
    let zip = ZipSource::open(&outer).unwrap();
    let source = ExpandedSource::open(&zip, at(1)).unwrap();
    let entry = &source.entries()[0];
    assert_eq!(entry.name, "t/cut.tar");
    assert!(
        !source.is_expanded(entry),
        "a damaged tar is searched as one file too"
    );
    assert_eq!(source.nested_gaps(), ["t/cut.tar"]);
    assert!(
        source.notes().join("\n").contains("damaged"),
        "{:?}",
        source.notes()
    );
}

#[test]
fn two_entries_of_one_name_are_told_apart() {
    let inner = build_zip(&[FileSpec::stored("in.txt", b"inner")], false);
    let outer = build_zip(
        &[
            FileSpec::stored("x.zip", &inner),
            FileSpec::stored("x.zip", b"a later version, not an archive"),
        ],
        false,
    );
    let zip = ZipSource::open(&outer).unwrap();
    let source = ExpandedSource::open(&zip, at(1)).unwrap();
    let both: Vec<_> = source
        .entries()
        .iter()
        .filter(|e| e.name == "x.zip")
        .collect();
    assert_eq!(both.len(), 2);
    assert!(source.is_expanded(both[0]));
    assert!(
        !source.is_expanded(both[1]),
        "the second is searched, not skipped"
    );
}

#[test]
fn a_stored_container_is_read_in_place_and_costs_nothing_against_the_limit() {
    let inner = build_zip(&[FileSpec::stored("in.txt", b"inner needle")], false);
    let outer = build_zip(&[FileSpec::stored("x.zip", &inner)], false);
    let zip = ZipSource::open(&outer).unwrap();
    let tight = Nesting { depth: 1, limit: 1 };
    let source = ExpandedSource::open(&zip, tight).unwrap();
    assert_eq!(read(&source, "x.zip/in.txt"), b"inner needle");
}

#[test]
fn a_container_read_into_memory_is_checked_against_the_limit_first() {
    let inner = build_zip(&[FileSpec::stored("in.txt", b"inner needle")], false);
    let mut deflate =
        flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    deflate.write_all(&inner).unwrap();
    let packed = deflate.finish().unwrap();
    let outer = build_zip(
        &[FileSpec::deflate("x.zip", &packed, inner.len() as u32)],
        false,
    );
    let zip = ZipSource::open(&outer).unwrap();
    let tight = Nesting {
        depth: 1,
        limit: inner.len() as u64 - 1,
    };
    let Err(e) = ExpandedSource::open(&zip, tight) else {
        panic!("an inflated container past the limit must be refused");
    };
    assert!(format!("{e:#}").contains("--nested-limit"), "{e:#}");
    let enough = Nesting {
        depth: 1,
        limit: inner.len() as u64,
    };
    let source = ExpandedSource::open(&zip, enough).unwrap();
    assert_eq!(read(&source, "x.zip/in.txt"), b"inner needle");
}

#[test]
fn a_nested_zip_member_is_checked_against_its_recorded_crc() {
    use mf_scan::core::source::IntegrityCheck;
    let inner = build_zip(&[FileSpec::stored("m.txt", b"hello")], false);
    let check = |inner: &[u8]| {
        let outer = build_zip(&[FileSpec::stored("x.zip", inner)], false);
        let zip = ZipSource::open(&outer).unwrap();
        let source = ExpandedSource::open(&zip, at(1)).unwrap();
        let entry = source
            .entries()
            .iter()
            .find(|e| e.name == "x.zip/m.txt")
            .unwrap()
            .clone();
        source.integrity_check(&entry)
    };
    assert!(matches!(check(&inner), IntegrityCheck::Verified { .. }));
    let mut damaged = inner.clone();
    let at = damaged.windows(5).position(|w| w == b"hello").unwrap();
    damaged[at] ^= 0x20;
    assert!(matches!(check(&damaged), IntegrityCheck::Mismatch { .. }));
}

#[test]
fn diff_fails_when_a_nested_archive_is_not_fully_read() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("case.zip"), case_zip()).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_mf-scan"))
        .current_dir(dir.path())
        .args(["diff", "case.zip", "case.zip", "--archive-depth", "1"])
        .output()
        .expect("run mf-scan");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("not fully read"), "{stderr}");
}
