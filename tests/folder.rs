//! Integration tests for folder scanning and nested-archive expansion.
//!
//! Defines: `--archive-depth` behaviour — a nested `.zip` is opaque at depth 0,
//! opened one level at depth 1, and a zip-in-zip is opened at depth 2 — plus that a
//! nested entry's content reads back the inner file's bytes.
//! Uses: `common` (fixture builder) and `mf_scan::source::{folder, Source}`.

mod common;

use std::fs;

use common::{FileSpec, build_zip};
use mf_scan::engine::{NoProgress, Query, search_source};
use mf_scan::filter::EntryFilter;
use mf_scan::report::export::{self, ExportOutcome};
use mf_scan::source::Source;
use mf_scan::source::folder::FolderSource;
use regex::bytes::Regex;
use tempfile::tempdir;

/// Entry names of a folder source, in their (sorted) order.
fn names(src: &FolderSource) -> Vec<String> {
    src.entries().iter().map(|e| e.name.clone()).collect()
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
    let d0 = FolderSource::open(dir.path(), 0).unwrap();
    assert_eq!(names(&d0), ["backup.zip", "loose.txt"]);

    // depth 1: the zip is opened; its files appear under its path.
    let d1 = FolderSource::open(dir.path(), 1).unwrap();
    assert_eq!(
        names(&d1),
        [
            "backup.zip/inner1.txt",
            "backup.zip/sub/inner2.txt",
            "loose.txt"
        ]
    );

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
    let d1 = FolderSource::open(dir.path(), 1).unwrap();
    assert_eq!(names(&d1), ["outer.zip/deep.zip", "outer.zip/top.txt"]);

    // depth 2: deep.zip is opened too, so its file surfaces.
    let d2 = FolderSource::open(dir.path(), 2).unwrap();
    assert_eq!(
        names(&d2),
        ["outer.zip/deep.zip/deep.txt", "outer.zip/top.txt"]
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
    let src = FolderSource::open(dir.path(), 0).unwrap();
    let re = Regex::new("SECRET").unwrap();
    let findings = search_source(
        &src,
        &Query::plain(&re),
        false,
        false,
        &EntryFilter::all(),
        None,
        &NoProgress,
    )
    .unwrap();
    assert_eq!(findings.files.len(), 1);
    assert_eq!(findings.files[0].entry.name, "hit.txt");

    // Export the matched loose file out of the folder source.
    let out = tempdir().unwrap();
    let plan = export::plan(&findings.files);
    match export::export_files(&plan, &src, &findings.files, out.path(), None, 0).unwrap() {
        ExportOutcome::Exported { files, .. } => assert_eq!(files, 1),
        ExportOutcome::Refused { .. } => panic!("should not refuse without a cap"),
    }
    let written = fs::read(out.path().join(&plan.items[0].folder).join("hit.txt")).unwrap();
    assert_eq!(written, b"find SECRET here");
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

    let src = FolderSource::open(dir.path(), 0).unwrap();
    let re = Regex::new("SECRET").unwrap();
    let findings = search_source(
        &src,
        &Query::plain(&re),
        false,
        false,
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

/// Resource-exhaustion guard (review finding S4): nested-archive expansion has
/// a cumulative arena budget. Exhausting it must fail loudly — not degrade
/// silently (coverage cut short) and not OOM (crafted archive-of-archives).
#[test]
fn nested_arena_budget_exhaustion_fails_loudly() {
    let dir = tempdir().unwrap();
    let inner = build_zip(&[FileSpec::stored("inner.txt", b"hello nested")], false);
    fs::write(dir.path().join("a.zip"), &inner).unwrap();
    fs::write(dir.path().join("b.zip"), &inner).unwrap();

    // Room for one archive but not both.
    let small = inner.len() as u64 + 1;
    let err = match FolderSource::open_with_arena_budget(dir.path(), 1, small) {
        Ok(_) => panic!("expected the arena budget to be exceeded"),
        Err(e) => e,
    };
    assert!(
        format!("{err:#}").contains("nested archives exceed"),
        "unexpected error: {err:#}"
    );

    // A sufficient budget expands both.
    let src = FolderSource::open_with_arena_budget(dir.path(), 1, 10 * inner.len() as u64).unwrap();
    assert_eq!(names(&src), ["a.zip/inner.txt", "b.zip/inner.txt"]);
}
