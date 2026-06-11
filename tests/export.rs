//! Tests for export: planning, manifest, and exporting to disk.
//!
//! Defines: tests for folder naming (basename + stable path hash), manifest
//! content + total size, export layout/content, and the --max-size refusal.
//! Uses: `common` (fixture builder), `mf_scan::{engine, export}`,
//! `serde_json`, `tempfile`.

mod common;

use std::fs;

use common::{FileSpec, build_zip};
use mf_scan::engine::search_archive;
use mf_scan::filter::EntryFilter;
use mf_scan::models::RunInfo;
use mf_scan::report::export::{self, ExportOutcome};
use mf_scan::source::zip::ZipSource;
use regex::bytes::Regex;

/// Minimal run metadata for manifest tests.
fn run_info() -> RunInfo {
    RunInfo {
        tool: "mf-scan".into(),
        version: "test".into(),
        pattern: "TARGET".into(),
        literal: false,
        ignore_case: false,
        match_path: false,
        inspect: false,
        archives: vec!["test.zip".into()],
        path_globs: vec![],
        not_path_globs: vec![],
        types: vec![],
        exclude_media: false,
        base64: false,
        base64_urlsafe: false,
        keyfiles: vec![],
        platform: None,
    }
}

/// Build a two-file archive (same basename, different dirs) and search it.
fn findings_two_infoplists() -> (Vec<u8>, mf_scan::engine::Findings) {
    let files = [
        FileSpec::stored("AppA/Info.plist", b"key TARGET one"),
        FileSpec::stored("AppB/Info.plist", b"key TARGET two"),
    ];
    let zip = build_zip(&files, false);
    let findings = search_archive(
        &zip,
        &Regex::new("TARGET").unwrap(),
        false,
        &EntryFilter::all(),
    )
    .unwrap();
    (zip, findings)
}

#[test]
fn plan_names_folders_by_basename_and_stable_hash() {
    let (_zip, findings) = findings_two_infoplists();
    let plan = export::plan(&findings.files);

    assert_eq!(plan.items.len(), 2);
    for item in &plan.items {
        // <basename>_<10 hex>
        assert!(item.folder.starts_with("Info.plist_"));
        let hash = item.folder.strip_prefix("Info.plist_").unwrap();
        assert_eq!(hash.len(), 10);
        assert!(hash.bytes().all(|b| b.is_ascii_hexdigit()));
    }
    // Different internal paths -> different folders (no collision).
    assert_ne!(plan.items[0].folder, plan.items[1].folder);
    // total size is the sum of the two files.
    assert_eq!(plan.total_size, 14 + 14);
}

#[test]
fn hash_is_stable_across_runs() {
    let (_z1, f1) = findings_two_infoplists();
    let (_z2, f2) = findings_two_infoplists();
    let p1 = export::plan(&f1.files);
    let p2 = export::plan(&f2.files);
    // Same internal path => same folder name every time (recognisable).
    assert_eq!(p1.items[0].folder, p2.items[0].folder);
}

#[test]
fn manifest_lists_files_with_total_size() {
    let (_zip, findings) = findings_two_infoplists();
    let plan = export::plan(&findings.files);

    let mut buf = Vec::new();
    export::write_manifest(&plan, &run_info(), &mut buf).unwrap();
    let json: serde_json::Value = serde_json::from_slice(&buf).unwrap();

    assert_eq!(json["file_count"], 2);
    assert_eq!(json["total_size"], 28);
    let first = &json["files"][0];
    assert_eq!(first["internal_path"], "AppA/Info.plist");
    assert!(
        first["output_path"]
            .as_str()
            .unwrap()
            .ends_with("/Info.plist")
    );
    assert_eq!(first["offsets"][0], 4); // "key " precedes TARGET
}

#[test]
fn export_writes_files_under_their_folders() {
    let (zip, findings) = findings_two_infoplists();
    let plan = export::plan(&findings.files);
    let dir = tempfile::tempdir().unwrap();

    let outcome = export::export_files(
        &plan,
        &ZipSource::open(&zip).unwrap(),
        &findings.files,
        dir.path(),
        None,
    )
    .unwrap();
    match outcome {
        ExportOutcome::Exported { files, .. } => assert_eq!(files, 2),
        ExportOutcome::Refused { .. } => panic!("should not refuse without a cap"),
    }

    // Each file lands at DIR/<folder>/Info.plist with its real content.
    for item in &plan.items {
        let path = dir.path().join(&item.folder).join("Info.plist");
        let content = fs::read(&path).unwrap();
        assert!(content.starts_with(b"key TARGET"));
    }
}

#[test]
fn export_includes_sqlite_sidecars() {
    // A matched database with -wal/-shm sidecars in the archive.
    let files = [
        FileSpec::stored("Library/sms.db", b"row with TARGET"),
        FileSpec::stored("Library/sms.db-wal", b"wal-bytes"),
        FileSpec::stored("Library/sms.db-shm", b"shm-bytes"),
    ];
    let zip = build_zip(&files, false);
    let findings = search_archive(
        &zip,
        &Regex::new("TARGET").unwrap(),
        false,
        &EntryFilter::all(),
    )
    .unwrap();
    assert_eq!(findings.files.len(), 1); // only sms.db matched

    let plan = export::plan(&findings.files);
    let dir = tempfile::tempdir().unwrap();
    let outcome = export::export_files(
        &plan,
        &ZipSource::open(&zip).unwrap(),
        &findings.files,
        dir.path(),
        None,
    )
    .unwrap();
    match outcome {
        ExportOutcome::Exported { files, .. } => assert_eq!(files, 3), // db + wal + shm
        ExportOutcome::Refused { .. } => panic!("should not refuse without a cap"),
    }

    // The sidecars land in the same folder as the database, beside it.
    let folder = dir.path().join(&plan.items[0].folder);
    assert!(folder.join("sms.db").exists());
    assert_eq!(fs::read(folder.join("sms.db-wal")).unwrap(), b"wal-bytes");
    assert!(folder.join("sms.db-shm").exists());
}

#[test]
fn export_refuses_when_over_max_size() {
    let (zip, findings) = findings_two_infoplists();
    let plan = export::plan(&findings.files);
    let dir = tempfile::tempdir().unwrap();

    // Cap below the 28-byte total.
    let outcome = export::export_files(
        &plan,
        &ZipSource::open(&zip).unwrap(),
        &findings.files,
        dir.path(),
        Some(10),
    )
    .unwrap();
    match outcome {
        ExportOutcome::Refused { total_size, cap } => {
            assert_eq!(total_size, 28);
            assert_eq!(cap, 10);
        }
        ExportOutcome::Exported { .. } => panic!("should have refused"),
    }
    // Nothing was written.
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[test]
fn export_from_manifest_round_trips() {
    let (zip, findings) = findings_two_infoplists();
    let plan = export::plan(&findings.files);

    // Write the manifest, then read it back and export from it.
    let mut buf = Vec::new();
    export::write_manifest(&plan, &run_info(), &mut buf).unwrap();
    let manifest = export::read_manifest(&buf[..]).unwrap();

    let dir = tempfile::tempdir().unwrap();
    let outcome =
        export::export_from_manifest(&manifest, &ZipSource::open(&zip).unwrap(), dir.path(), None)
            .unwrap();
    match outcome {
        ExportOutcome::Exported { files, skipped, .. } => {
            assert_eq!(files, 2);
            assert_eq!(skipped, 0);
        }
        ExportOutcome::Refused { .. } => panic!("should not refuse without a cap"),
    }

    // Each file exists at the path the manifest recorded.
    for entry in &manifest.files {
        let mut path = dir.path().to_path_buf();
        for seg in entry.output_path.split('/') {
            path.push(seg);
        }
        assert!(path.exists(), "missing {}", path.display());
    }
}

#[test]
fn export_from_manifest_skips_missing_entries() {
    let (zip, _findings) = findings_two_infoplists();
    let manifest = export::Manifest {
        run: run_info(),
        total_size: 5,
        file_count: 1,
        files: vec![export::ManifestEntry {
            internal_path: "does/not/exist".into(),
            output_path: "ghost_0000000000/exist".into(),
            size: 5,
            compressed: false,
            offsets: vec![],
        }],
    };
    let dir = tempfile::tempdir().unwrap();

    let outcome =
        export::export_from_manifest(&manifest, &ZipSource::open(&zip).unwrap(), dir.path(), None)
            .unwrap();
    match outcome {
        ExportOutcome::Exported { files, skipped, .. } => {
            assert_eq!(files, 0);
            assert_eq!(skipped, 1);
        }
        ExportOutcome::Refused { .. } => panic!("should not refuse"),
    }
}
