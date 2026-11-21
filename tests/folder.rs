//! Integration tests for folder scanning and nested-archive expansion.
//!
//! Defines: folder scanning, and `--archive-depth` over a folder — a nested `.zip` is
//! one file at depth 0, opened (and still listed) at depth 1, and a zip-in-zip is
//! opened at depth 2 — plus that a nested entry reads back the inner file's bytes.
//! Uses: `common` (fixture builder) and `mf_scan::core::source::{folder, expand}`.

mod common;

use std::fs;

use common::{FileSpec, build_zip};
use mf_scan::core::filter::EntryFilter;
use mf_scan::core::source::Source;
use mf_scan::core::source::expand::{ExpandedSource, Nesting};
use mf_scan::core::source::folder::FolderSource;
use mf_scan::engine::NoProgress;
use mf_scan::ops::search::{MatchOn, Query, search_source};
use mf_scan::report::export::{self, ExportOutcome};
use regex::bytes::Regex;
use tempfile::tempdir;

/// Entry names of a source, in its order.
fn names(src: &dyn Source) -> Vec<String> {
    src.entries().iter().map(|e| e.name.clone()).collect()
}

fn depth(depth: u32) -> Nesting {
    Nesting {
        depth,
        ..Nesting::default()
    }
}

#[test]
fn archive_depth_controls_nested_expansion() {
    let inner = build_zip(
        &[
            FileSpec::stored("inner1.txt", b"AAA"),
            FileSpec::stored("sub/inner2.txt", b"BBBB"),
        ],
        false,
    );
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("backup.zip"), &inner).unwrap();
    fs::write(dir.path().join("loose.txt"), b"loose").unwrap();

    // depth 0: the nested zip is a single opaque file.
    let folder = FolderSource::open(dir.path()).unwrap();
    let d0 = ExpandedSource::open(&folder, depth(0)).unwrap();
    assert_eq!(names(&d0), ["backup.zip", "loose.txt"]);

    // depth 1: the zip is opened; it stays listed, its files follow it under its
    // path, and it is marked expanded (its members are searched in its place).
    let d1 = ExpandedSource::open(&folder, depth(1)).unwrap();
    assert_eq!(
        names(&d1),
        [
            "backup.zip",
            "backup.zip/inner1.txt",
            "backup.zip/sub/inner2.txt",
            "loose.txt"
        ]
    );
    assert!(d1.is_expanded(&d1.entries()[0]));
    assert!(!d1.is_expanded(&d1.entries()[1]));

    // A nested entry reads back the inner file's bytes.
    let e = d1
        .entries()
        .iter()
        .find(|e| e.name == "backup.zip/inner1.txt")
        .unwrap();
    assert_eq!(&*d1.content(e).unwrap(), b"AAA");
}

#[test]
fn depth_two_opens_a_zip_inside_a_zip() {
    let deep = build_zip(&[FileSpec::stored("deep.txt", b"deep!")], false);
    // outer.zip stores deep.zip verbatim plus a normal file.
    let outer = build_zip(
        &[
            FileSpec::stored("deep.zip", &deep),
            FileSpec::stored("top.txt", b"top"),
        ],
        false,
    );
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("outer.zip"), &outer).unwrap();

    // depth 1: outer is opened but deep.zip inside it stays opaque.
    let folder = FolderSource::open(dir.path()).unwrap();
    let d1 = ExpandedSource::open(&folder, depth(1)).unwrap();
    assert_eq!(
        names(&d1),
        ["outer.zip", "outer.zip/deep.zip", "outer.zip/top.txt"]
    );

    // depth 2: deep.zip is opened too, so its file surfaces.
    let d2 = ExpandedSource::open(&folder, depth(2)).unwrap();
    assert_eq!(
        names(&d2),
        [
            "outer.zip",
            "outer.zip/deep.zip",
            "outer.zip/deep.zip/deep.txt",
            "outer.zip/top.txt"
        ]
    );
    let e = d2
        .entries()
        .iter()
        .find(|e| e.name == "outer.zip/deep.zip/deep.txt")
        .unwrap();
    assert_eq!(&*d2.content(e).unwrap(), b"deep!");
}

#[test]
fn search_and_export_run_over_a_folder_source() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("hit.txt"), b"find SECRET here").unwrap();
    fs::write(dir.path().join("miss.txt"), b"nothing").unwrap();

    // Search the folder through the same engine entry point grep uses.
    let src = FolderSource::open(dir.path()).unwrap();
    let re = Regex::new("SECRET").unwrap();
    let findings = search_source(
        &src,
        &Query::plain(&re),
        false,
        MatchOn::Content,
        &EntryFilter::all(),
        None,
        &NoProgress,
    )
    .unwrap();
    assert_eq!(findings.files.len(), 1);
    assert_eq!(findings.files[0].entry.name, "hit.txt");

    // Export the matched loose file out of the folder source.
    let out = tempdir().unwrap();
    let zip = out.path().join("out.zip");
    let plan = export::plan(&findings.files);
    let run = mf_scan::core::models::RunInfo::default();
    match export::export_files(&plan, &src, &findings.files, &zip, &run, None, None).unwrap() {
        ExportOutcome::Exported(done) => assert_eq!(done.files, 1),
        ExportOutcome::Refused { .. } => panic!("should not refuse without a cap"),
    }
    let bytes = fs::read(&zip).unwrap();
    let archive = mf_scan::core::source::zip::ZipSource::open(&bytes).unwrap();
    let member = format!("{}/hit.txt", plan.items[0].folder);
    let entry = archive.entries().iter().find(|e| e.name == member).unwrap();
    assert_eq!(&*archive.content(entry).unwrap(), b"find SECRET here");
}

/// One unreadable file must not abort the scan: it is tallied as unreadable
/// while every other file is still searched (review finding L3 — acquisitions
/// are routinely partial; degrade, don't die).
#[cfg(unix)]
#[test]
fn unreadable_file_is_counted_and_does_not_abort_the_scan() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempdir().unwrap();
    fs::write(dir.path().join("hit.txt"), b"find SECRET here").unwrap();
    let blocked = dir.path().join("blocked.txt");
    fs::write(&blocked, b"SECRET but unreadable").unwrap();
    fs::set_permissions(&blocked, fs::Permissions::from_mode(0o000)).unwrap();

    let src = FolderSource::open(dir.path()).unwrap();
    let re = Regex::new("SECRET").unwrap();
    let findings = search_source(
        &src,
        &Query::plain(&re),
        false,
        MatchOn::Content,
        &EntryFilter::all(),
        None,
        &NoProgress,
    )
    .unwrap();

    // Restore permissions so the tempdir can be cleaned up.
    fs::set_permissions(&blocked, fs::Permissions::from_mode(0o644)).unwrap();

    assert_eq!(findings.files.len(), 1);
    assert_eq!(findings.files[0].entry.name, "hit.txt");
    assert_eq!(findings.stats.unreadable.count, 1);
    assert_eq!(findings.stats.files_scanned, 1);
}

/// Resource-exhaustion guard (review finding S4): what opening nested containers
/// adds (decoded data, or containers read into memory) has a cap for the whole
/// source. Reaching it must fail loudly — not degrade silently (coverage cut short)
/// and not fill the memory or the disk (a crafted bomb). Containers read in place (a
/// folder's own files) cost nothing against it.
#[test]
fn nested_limit_exhaustion_fails_loudly() {
    use std::io::Write;
    let dir = tempdir().unwrap();
    let decoded = vec![b'x'; 1000];
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(&decoded).unwrap();
    let gz = gz.finish().unwrap();
    fs::write(dir.path().join("a.log.gz"), &gz).unwrap();
    fs::write(dir.path().join("b.log.gz"), &gz).unwrap();
    let folder = FolderSource::open(dir.path()).unwrap();

    // Room to decode one file but not both.
    let small = Nesting {
        depth: 1,
        limit: 1500,
    };
    let err = match ExpandedSource::open(&folder, small) {
        Ok(_) => panic!("expected the nested limit to be reached"),
        Err(e) => e,
    };
    assert!(
        format!("{err:#}").contains("--nested-limit"),
        "unexpected error: {err:#}"
    );

    // A sufficient limit decodes both.
    let enough = Nesting {
        depth: 1,
        limit: 2000,
    };
    let src = ExpandedSource::open(&folder, enough).unwrap();
    assert_eq!(
        names(&src),
        ["a.log.gz", "a.log.gz/a.log", "b.log.gz", "b.log.gz/b.log"]
    );
}
