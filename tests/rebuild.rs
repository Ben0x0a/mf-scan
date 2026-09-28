//! Integration tests for rebuilding a whole iOS backup into a filesystem tree.
//!
//! Drives `ops::rebuild` over the committed mini backups and through the real
//! export engine, so the domain mapping, the directory records, the synthetic-path
//! reporting and the SHA-1 attestation are all exercised end to end.

use std::path::PathBuf;

use mf_scan::core::source::Source;
use mf_scan::core::source::folder::FolderSource;
use mf_scan::ops::rebuild;
use mf_scan::ops::search::MatchedFile;
use mf_scan::platform::ios::backup::profile;
use mf_scan::platform::ios::backup::source::BackupSource;
use mf_scan::report::export::{self, ExportOutcome};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/backup")
        .join(name)
}

/// Rebuild a fixture into `dir`, returning the plan and the exported report.
fn rebuild_fixture(
    name: &str,
    password: Option<&str>,
    dir: &std::path::Path,
) -> (rebuild::Rebuild, Vec<String>) {
    let folder = FolderSource::open(&fixture(name), 0).expect("fixture opens");
    let profile = profile::detect(&folder).expect("fixture is a backup");
    let source = BackupSource::build(&folder, &profile, password).expect("builds");

    let plan = rebuild::plan(&source, source.structure());
    let files: Vec<MatchedFile> = rebuild::files_to_rebuild(&source)
        .into_iter()
        .map(|e| MatchedFile {
            entry: e.clone(),
            offsets: Vec::new(),
        })
        .collect();
    let export_plan = export::plan_tree(&files, &plan.roots);
    let outcome =
        export::export_files(&export_plan, &source, &files, dir, None, 0).expect("export succeeds");
    let written = match outcome {
        ExportOutcome::Exported { report, .. } => {
            report.iter().map(|f| f.output_path.clone()).collect()
        }
        ExportOutcome::Refused { .. } => panic!("export refused unexpectedly"),
    };
    for rel in &plan.directories {
        std::fs::create_dir_all(dir.join(rel)).expect("directory created");
    }
    (plan, written)
}

#[test]
fn rebuilds_the_unencrypted_backup_into_device_paths() {
    let out = tempfile::tempdir().expect("tempdir");
    let (plan, written) = rebuild_fixture("unencrypted", None, out.path());

    // HomeDomain maps to the device home, so its relativePath continues from there.
    let sms = out.path().join("private/var/mobile/Library/SMS/sms.db");
    assert!(
        sms.is_file(),
        "sms.db must land at the device path; wrote {written:?}"
    );

    // An app domain has no GUID in the evidence, so the bundle id is substituted.
    let notes = out
        .path()
        .join("private/var/mobile/Containers/Data/Application/com.test.app/Documents/notes.txt");
    assert!(
        notes.is_file(),
        "app data must land under its container path"
    );
    assert_eq!(plan.synthetic, vec!["AppDomain-com.test.app"]);

    // The directory record is recreated.
    assert!(
        out.path().join("private/var/mobile/Library").is_dir(),
        "the directory record must be created"
    );
    assert!(plan.unmapped.is_empty(), "every fixture domain is mapped");

    // The manifest-only missing file must NOT appear — and must not abort the run.
    assert!(
        !out.path()
            .join("private/var/mobile/Library/Missing/ghost.db")
            .exists(),
        "a file absent on disk cannot be rebuilt"
    );
    assert_eq!(written.len(), 3);
}

/// The two fixtures hold the same content, one encrypted. A rebuild of each must
/// produce byte-identical files — the check that decryption and the rebuild agree.
#[test]
fn encrypted_and_unencrypted_rebuilds_are_identical() {
    let plain_dir = tempfile::tempdir().expect("tempdir");
    let enc_dir = tempfile::tempdir().expect("tempdir");
    let (plain_plan, _) = rebuild_fixture("unencrypted", None, plain_dir.path());
    let (enc_plan, _) = rebuild_fixture("encrypted", Some("1234"), enc_dir.path());

    assert_eq!(
        plain_plan.roots, enc_plan.roots,
        "both map domains identically"
    );

    for rel in [
        "private/var/mobile/Library/SMS/sms.db",
        "private/var/mobile/Library/Preferences/com.test.plist",
        "private/var/mobile/Containers/Data/Application/com.test.app/Documents/notes.txt",
    ] {
        let a = std::fs::read(plain_dir.path().join(rel)).expect("plain file");
        let b = std::fs::read(enc_dir.path().join(rel)).expect("decrypted file");
        assert_eq!(
            a, b,
            "{rel} differs between the encrypted and plain rebuild"
        );
    }
}

/// Nothing may fall into `plan_tree`'s flat hashed fallback: an unmapped domain
/// must be reported AND given a root, or its files scatter across the output root.
#[test]
fn every_entry_is_attributable_to_a_root() {
    let folder = FolderSource::open(&fixture("unencrypted"), 0).expect("opens");
    let profile = profile::detect(&folder).expect("is a backup");
    let source = BackupSource::build(&folder, &profile, None).expect("builds");
    let plan = rebuild::plan(&source, source.structure());

    for entry in source.entries() {
        let attributed = plan.roots.iter().any(|(prefix, _)| {
            entry.name == *prefix || entry.name.starts_with(&format!("{prefix}/"))
        });
        assert!(attributed, "{} fell under no root", entry.name);
    }
}
