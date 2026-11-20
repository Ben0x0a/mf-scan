//! Tests for export: planning, manifest, and exporting into a ZIP archive.
//!
//! Defines: tests for folder naming (basename + stable path hash), manifest
//! content + total size, the archive's members, report and sidecar, and the
//! --max-size refusal.
//! Uses: `common` (fixture builder), `mf_scan::{engine, export}`,
//! `serde_json`, `tempfile`.

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use common::{FileSpec, build_zip};
use mf_scan::core::filter::EntryFilter;
use mf_scan::core::models::RunInfo;
use mf_scan::core::source::Source;
use mf_scan::core::source::zip::ZipSource;
use mf_scan::engine::NoProgress;
use mf_scan::ops::search::{MatchOn, Query, search_with_query};
use mf_scan::report::export::{self, ExportOutcome};
use regex::bytes::Regex;

/// Minimal run metadata for manifest tests.
fn run_info() -> RunInfo {
    RunInfo {
        tool: "mf-scan".into(),
        version: "test".into(),
        pattern: "TARGET".into(),
        patterns: vec![],
        literal: false,
        ignore_case: false,
        match_path: false,
        inspect: false,
        archives: vec!["test.zip".into()],
        path_globs: vec![],
        not_path_globs: vec![],
        types: vec![],
        exclude_media: false,
        encodings: Vec::new(),
        keyfiles: vec![],
        platform: None,
        app: None,
        app_containers: vec![],
        app_group_links: vec![],
        loose_files_skipped: 0,
    }
}

/// Export `files` (planned as `plan`) out of `zip` into `<tmp>/out.zip`.
fn export_to_zip(
    plan: &export::ExportPlan,
    zip: &[u8],
    files: &[mf_scan::ops::search::MatchedFile],
    cap: Option<u64>,
) -> (tempfile::TempDir, PathBuf, ExportOutcome) {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.zip");
    let outcome = export::export_files(
        plan,
        &ZipSource::open(zip).unwrap(),
        files,
        &out,
        &run_info(),
        cap,
        None,
    )
    .unwrap();
    (dir, out, outcome)
}

/// Every member of the archive at `path`, read with the tool's own reader.
fn members(path: &Path) -> BTreeMap<String, Vec<u8>> {
    let bytes = fs::read(path).unwrap();
    let source = ZipSource::open(&bytes).unwrap();
    source
        .entries()
        .iter()
        .map(|e| (e.name.clone(), source.content(e).unwrap().to_vec()))
        .collect()
}

/// Build a two-file archive (same basename, different dirs) and search it.
fn findings_two_infoplists() -> (Vec<u8>, mf_scan::ops::search::Findings) {
    let files = [
        FileSpec::stored("AppA/Info.plist", b"key TARGET one"),
        FileSpec::stored("AppB/Info.plist", b"key TARGET two"),
    ];
    let zip = build_zip(&files, false);
    let re = Regex::new("TARGET").unwrap();
    let findings = search_with_query(
        &zip,
        &Query::plain(&re),
        false,
        MatchOn::Content,
        &EntryFilter::all(),
        None,
        &NoProgress,
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
fn export_writes_one_archive_with_its_report_and_sidecar() {
    let (zip, findings) = findings_two_infoplists();
    let plan = export::plan(&findings.files);
    let (_dir, out, outcome) = export_to_zip(&plan, &zip, &findings.files, None);
    let ExportOutcome::Exported(done) = outcome else {
        panic!("should not refuse without a cap");
    };
    assert_eq!(done.files, 2);
    assert_eq!(done.archive, out);

    // Each file is the member <folder>/Info.plist with its real content, and the
    // report sits at the root.
    let members = members(&out);
    assert_eq!(members.len(), 3);
    for item in &plan.items {
        let content = &members[&format!("{}/Info.plist", item.folder)];
        assert!(content.starts_with(b"key TARGET"));
    }
    let report: serde_json::Value =
        serde_json::from_slice(&members[export::REPORT_MEMBER]).unwrap();
    assert_eq!(report["file_count"], 2);

    // The archive is read-only, and its sidecar holds its SHA-256.
    assert!(fs::metadata(&out).unwrap().permissions().readonly());
    let sidecar = fs::read_to_string(&done.sidecar).unwrap();
    assert!(sidecar.starts_with(&done.archive_sha256));
    assert_eq!(
        done.archive_sha256,
        mf_scan::core::util::sha256_hex(&fs::read(&out).unwrap())
    );
}

#[test]
fn an_export_never_replaces_an_existing_archive() {
    let (zip, findings) = findings_two_infoplists();
    let plan = export::plan(&findings.files);
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.zip");
    fs::write(&out, b"earlier export").unwrap();
    let result = export::export_files(
        &plan,
        &ZipSource::open(&zip).unwrap(),
        &findings.files,
        &out,
        &run_info(),
        None,
        None,
    );
    assert!(result.is_err());
    assert_eq!(fs::read(&out).unwrap(), b"earlier export");
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
    let re = Regex::new("TARGET").unwrap();
    let findings = search_with_query(
        &zip,
        &Query::plain(&re),
        false,
        MatchOn::Content,
        &EntryFilter::all(),
        None,
        &NoProgress,
    )
    .unwrap();
    assert_eq!(findings.files.len(), 1); // only sms.db matched

    let plan = export::plan(&findings.files);
    let (_dir, out, outcome) = export_to_zip(&plan, &zip, &findings.files, None);
    let ExportOutcome::Exported(done) = outcome else {
        panic!("should not refuse without a cap");
    };
    assert_eq!(done.files, 3); // db + wal + shm

    // The sidecars land in the same folder as the database, beside it.
    let members = members(&out);
    let folder = &plan.items[0].folder;
    assert!(members.contains_key(&format!("{folder}/sms.db")));
    assert_eq!(members[&format!("{folder}/sms.db-wal")], b"wal-bytes");
    assert!(members.contains_key(&format!("{folder}/sms.db-shm")));
}

/// `--max-size` holds for what is written, sidecars included, which the plan's total
/// leaves out: over it, the export stops and leaves nothing.
#[test]
fn the_size_cap_counts_sidecars_and_leaves_nothing_when_exceeded() {
    let files = [
        FileSpec::stored("Library/sms.db", b"row with TARGET"),
        FileSpec::stored("Library/sms.db-wal", b"wal-bytes"),
    ];
    let zip = build_zip(&files, false);
    let re = Regex::new("TARGET").unwrap();
    let findings = search_with_query(
        &zip,
        &Query::plain(&re),
        false,
        MatchOn::Content,
        &EntryFilter::all(),
        None,
        &NoProgress,
    )
    .unwrap();
    let plan = export::plan(&findings.files);
    assert_eq!(plan.total_size, 15);
    let (dir, _out, outcome) = export_to_zip(&plan, &zip, &findings.files, Some(20));
    match outcome {
        ExportOutcome::Refused { total_size, cap } => {
            assert_eq!((total_size, cap), (24, 20));
        }
        ExportOutcome::Exported(_) => panic!("the -wal takes it over the cap"),
    }
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[test]
fn export_report_attests_copy_and_zip_crc() {
    // A STORED archive records a real CRC-32; the export must verify both the
    // source-vs-copy hash and the central-directory CRC for every file.
    let (zip, findings) = findings_two_infoplists();
    let plan = export::plan(&findings.files);
    let (_dir, _out, outcome) = export_to_zip(&plan, &zip, &findings.files, None);
    let ExportOutcome::Exported(done) = outcome else {
        panic!("should not refuse without a cap");
    };
    let report = done.report;

    assert_eq!(report.len(), 2);
    for f in &report {
        // Source bytes and written bytes match (no silent copy error).
        assert!(f.copy_verified, "{} not copy-verified", f.internal_path);
        assert_eq!(f.sha256, f.source_sha256);
        // The STORED entry's CRC-32 was verified against the central directory.
        assert_eq!(
            f.stored_integrity,
            export::StoredIntegrity::Verified {
                algorithm: "crc32".into()
            },
            "{} CRC not verified",
            f.internal_path
        );
        assert!(f.is_intact());
    }

    let summary = export::IntegritySummary::of(&report);
    assert_eq!(summary.intact, 2);
    assert_eq!(summary.stored_digest_verified, 2);
    assert!(!summary.has_failures());
}

/// A path too long to extract on Windows is exported all the same, and listed.
#[test]
fn a_long_path_is_exported_and_flagged() {
    let long = format!("{}/file.db", vec!["folder_name"; 30].join("/"));
    let files = [FileSpec::stored(&long, b"TARGET")];
    let zip = build_zip(&files, false);
    let re = Regex::new("TARGET").unwrap();
    let findings = search_with_query(
        &zip,
        &Query::plain(&re),
        false,
        MatchOn::Content,
        &EntryFilter::all(),
        None,
        &NoProgress,
    )
    .unwrap();
    let roots = vec![("folder_name".to_string(), "app".to_string())];
    let plan = export::plan_tree(&findings.files, &roots);
    let (_dir, out, outcome) = export_to_zip(&plan, &zip, &findings.files, None);
    let ExportOutcome::Exported(done) = outcome else {
        panic!("should not refuse without a cap");
    };
    assert_eq!(done.files, 1);
    assert_eq!(done.notes.portability_warnings.len(), 1);
    let name = &done.report[0].output_path;
    assert!(name.chars().count() > export::WINDOWS_MAX_PATH);
    assert_eq!(members(&out)[name], b"TARGET");
}

#[test]
fn zip_integrity_check_detects_corruption() {
    use mf_scan::core::source::{IntegrityCheck, Source};

    // Build a STORED archive, then flip a byte inside the first entry's payload.
    let payload = b"hello forensic world";
    let files = [
        FileSpec::stored("a.txt", payload),
        FileSpec::stored("b.txt", b"intact file"),
    ];
    let mut zip = build_zip(&files, false);

    // The payload sits right after the first local header + name. Locate it and
    // corrupt one byte so the recomputed CRC-32 diverges from the recorded one.
    let at = zip
        .windows(payload.len())
        .position(|w| w == payload)
        .expect("payload present in archive");
    zip[at + 1] ^= 0xFF;

    let src = ZipSource::open(&zip).unwrap();
    let entries = src.entries().to_vec();
    let a = entries.iter().find(|e| e.name == "a.txt").unwrap();
    let b = entries.iter().find(|e| e.name == "b.txt").unwrap();

    // The corrupted entry is reported as a mismatch; the intact one verifies.
    assert!(matches!(
        src.integrity_check(a),
        IntegrityCheck::Mismatch {
            algorithm: "crc32",
            ..
        }
    ));
    assert!(matches!(
        src.integrity_check(b),
        IntegrityCheck::Verified { algorithm: "crc32" }
    ));
}

#[test]
fn export_refuses_when_over_max_size() {
    let (zip, findings) = findings_two_infoplists();
    let plan = export::plan(&findings.files);

    // Cap below the 28-byte total.
    let (dir, _out, outcome) = export_to_zip(&plan, &zip, &findings.files, Some(10));
    match outcome {
        ExportOutcome::Refused { total_size, cap } => {
            assert_eq!(total_size, 28);
            assert_eq!(cap, 10);
        }
        ExportOutcome::Exported(_) => panic!("should have refused"),
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
    let out = dir.path().join("out.zip");
    let outcome =
        export::export_from_manifest(&manifest, &ZipSource::open(&zip).unwrap(), &out, None)
            .unwrap();
    let ExportOutcome::Exported(done) = outcome else {
        panic!("should not refuse without a cap");
    };
    assert_eq!(done.files, 2);
    assert_eq!(done.skipped, 0);

    // Each file is a member at the path the manifest recorded.
    let members = members(&out);
    for entry in &manifest.files {
        assert!(
            members.contains_key(&entry.output_path),
            "missing {}",
            entry.output_path
        );
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
            encodings: Default::default(),
        }],
    };
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.zip");
    let outcome =
        export::export_from_manifest(&manifest, &ZipSource::open(&zip).unwrap(), &out, None)
            .unwrap();
    let ExportOutcome::Exported(done) = outcome else {
        panic!("should not refuse");
    };
    assert_eq!(done.files, 0);
    assert_eq!(done.skipped, 1);
}

#[test]
fn a_sidecar_planned_as_its_own_item_is_written_once() {
    // A tree export plans a database and its -wal side by side. The -wal must not
    // also be written as the database's sidecar: the second copy would land as
    // `sms.db-wal~1`.
    let files = [
        FileSpec::stored("App/Library/sms.db", b"row with TARGET"),
        FileSpec::stored("App/Library/sms.db-wal", b"wal with TARGET"),
    ];
    let zip = build_zip(&files, false);
    let re = Regex::new("TARGET").unwrap();
    let findings = search_with_query(
        &zip,
        &Query::plain(&re),
        false,
        MatchOn::Content,
        &EntryFilter::all(),
        None,
        &NoProgress,
    )
    .unwrap();
    assert_eq!(findings.files.len(), 2);

    let roots = vec![("App".to_string(), "app".to_string())];
    let plan = export::plan_tree(&findings.files, &roots);
    let (_dir, _out, outcome) = export_to_zip(&plan, &zip, &findings.files, None);
    let ExportOutcome::Exported(done) = outcome else {
        panic!("should not refuse without a cap");
    };
    assert_eq!(done.files, 2, "the db and its -wal, each once");
    assert!(done.notes.renamed.is_empty(), "{:?}", done.notes.renamed);
}
