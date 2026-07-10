//! Integration tests for the diff engine.
//!
//! Defines: file-level diff classification (added/removed/modified/unchanged) under
//! the default metadata compare, and the `--exact` content compare catching a change
//! that preserves size (the fixtures carry no timestamp, so metadata falls back to
//! size alone — exactly the case `--exact` exists for).
//! Uses: `common` (fixture builder) and `mf_scan::{diff, filter, source}`.

mod common;

use common::{FileSpec, build_zip};
use mf_scan::core::filter::EntryFilter;
use mf_scan::core::source::zip::ZipSource;
use mf_scan::ops::diff::{Change, CompareMode, diff_sources};

/// The change recorded for `path` in the report (panics if absent).
fn change_of(report: &mf_scan::ops::diff::DiffReport, path: &str) -> Change {
    report
        .files
        .iter()
        .find(|f| f.path == path)
        .unwrap_or_else(|| panic!("{path} missing from diff report"))
        .change
}

#[test]
fn classifies_added_removed_modified_unchanged() {
    let a = build_zip(
        &[
            FileSpec::stored("a.txt", b"one"),
            FileSpec::stored("b.txt", b"shared"),
            FileSpec::stored("gone.txt", b"removed me"),
        ],
        false,
    );
    let b = build_zip(
        &[
            FileSpec::stored("a.txt", b"ONE!!"), // different size -> modified
            FileSpec::stored("b.txt", b"shared"), // identical -> unchanged
            FileSpec::stored("new.txt", b"added"), // only in B -> added
        ],
        false,
    );
    let (sa, sb) = (ZipSource::open(&a).unwrap(), ZipSource::open(&b).unwrap());

    let report = diff_sources(&sa, &sb, CompareMode::Meta, &EntryFilter::all(), false).unwrap();

    assert_eq!(change_of(&report, "a.txt"), Change::Modified);
    assert_eq!(change_of(&report, "b.txt"), Change::Unchanged);
    assert_eq!(change_of(&report, "gone.txt"), Change::Removed);
    assert_eq!(change_of(&report, "new.txt"), Change::Added);

    assert_eq!(report.counts(), (1, 1, 1, 1)); // added, removed, modified, unchanged
}

#[test]
fn exact_catches_same_size_content_change() {
    // Same path, same byte length, different content, no timestamp in either.
    let a = build_zip(&[FileSpec::stored("x.bin", b"AAAA")], false);
    let b = build_zip(&[FileSpec::stored("x.bin", b"BBBB")], false);
    let (sa, sb) = (ZipSource::open(&a).unwrap(), ZipSource::open(&b).unwrap());

    // Metadata compare can't tell them apart (equal size, no mtime).
    let meta = diff_sources(&sa, &sb, CompareMode::Meta, &EntryFilter::all(), false).unwrap();
    assert_eq!(change_of(&meta, "x.bin"), Change::Unchanged);

    // The exact content compare does.
    let exact = diff_sources(&sa, &sb, CompareMode::Hash, &EntryFilter::all(), false).unwrap();
    assert_eq!(change_of(&exact, "x.bin"), Change::Modified);
}

#[test]
fn size_only_ignores_mismatched_clock_mtimes() {
    use std::fs;

    use mf_scan::core::source::folder::FolderSource;

    // Zip-vs-folder: the zip entry carries no mtime, the loose file a real one,
    // so the Meta compare flags the file as modified on timestamp alone. The
    // SizeOnly fallback (chosen by `run::diff` for mixed container kinds) must
    // call equal-sized files unchanged.
    let a = build_zip(&[FileSpec::stored("x.bin", b"AAAA")], false);
    let sa = ZipSource::open(&a).unwrap();

    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("x.bin"), b"AAAA").unwrap();
    fs::write(dir.path().join("bigger.bin"), b"BBBBBBBB").unwrap();
    let sb = FolderSource::open(dir.path(), 0).unwrap();

    let meta = diff_sources(&sa, &sb, CompareMode::Meta, &EntryFilter::all(), false).unwrap();
    assert_eq!(change_of(&meta, "x.bin"), Change::Modified); // mtime clocks differ

    let size_only =
        diff_sources(&sa, &sb, CompareMode::SizeOnly, &EntryFilter::all(), false).unwrap();
    assert_eq!(change_of(&size_only, "x.bin"), Change::Unchanged);
    assert_eq!(change_of(&size_only, "bigger.bin"), Change::Added);
}

#[test]
fn inspect_reports_intra_file_json_changes() {
    let a = build_zip(
        &[FileSpec::stored(
            "config.json",
            br#"{"a": 1, "drop": true, "nested": {"k": "old"}}"#,
        )],
        false,
    );
    let b = build_zip(
        &[FileSpec::stored(
            "config.json",
            br#"{"a": 1, "added": 9, "nested": {"k": "new"}}"#,
        )],
        false,
    );
    let (sa, sb) = (ZipSource::open(&a).unwrap(), ZipSource::open(&b).unwrap());

    // With --inspect, the modified JSON file carries a structured content diff.
    let report = diff_sources(&sa, &sb, CompareMode::Hash, &EntryFilter::all(), true).unwrap();
    let f = report
        .files
        .iter()
        .find(|f| f.path == "config.json")
        .unwrap();
    assert_eq!(f.change, Change::Modified);
    let content = f.content.as_ref().expect("a structured diff for JSON");
    assert_eq!(content.format, "json");
    // $.added is new, $.drop is gone, $.nested.k changed value.
    assert_eq!(content.detail["counts"]["added"], 1);
    assert_eq!(content.detail["counts"]["removed"], 1);
    assert_eq!(content.detail["counts"]["changed"], 1);

    // Without --inspect, no content diff is attached.
    let plain = diff_sources(&sa, &sb, CompareMode::Hash, &EntryFilter::all(), false).unwrap();
    assert!(
        plain
            .files
            .iter()
            .find(|f| f.path == "config.json")
            .unwrap()
            .content
            .is_none()
    );
}
