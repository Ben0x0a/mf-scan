//! End-to-end tests of `mf-scan backup rebuild`: the one archive it writes, and that
//! device timestamps survive into it.
//!
//! Defines: an Android `.ab` writer and tests that run the real binary over it and over
//! the committed mini iOS backups, then read the archive back with mf-scan's own reader.
//! Used by: `cargo test`.
//! Uses: `flate2` and `tempfile`, and `mf_scan::core::source::zip`.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use flate2::Compression;
use flate2::write::ZlibEncoder;
use mf_scan::core::models::Entry;
use mf_scan::core::source::Source;
use mf_scan::core::source::zip::ZipSource;

/// 2023-11-14T22:13:21Z, an odd second, which a DOS timestamp alone would round away.
const FILE_TIME: u64 = 1_700_000_001;
const DIR_TIME: u64 = 1_700_000_101;

fn tar_member(name: &str, data: &[u8], mtime: u64) -> Vec<u8> {
    let mut header = [0u8; 512];
    header[..name.len()].copy_from_slice(name.as_bytes());
    header[100..107].copy_from_slice(b"0000644");
    header[124..135].copy_from_slice(format!("{:011o}", data.len()).as_bytes());
    header[136..147].copy_from_slice(format!("{mtime:011o}").as_bytes());
    header[156] = if name.ends_with('/') { b'5' } else { b'0' };
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    header[148..156].fill(b' ');
    let sum: u32 = header.iter().map(|&b| b as u32).sum();
    header[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
    let mut out = header.to_vec();
    out.extend_from_slice(data);
    out.resize(out.len().next_multiple_of(512), 0);
    out
}

/// A compressed, unencrypted `.ab`, holding a path far past Windows' limit.
fn write_ab(path: &Path) -> String {
    let long_rest = format!("{}/deep.txt", ["segment"; 45].join("/"));
    let long_member = format!("apps/com.x/f/{long_rest}");
    let mut tar = tar_member("apps/com.x/_manifest", b"manifest", FILE_TIME);
    tar.extend(tar_member("apps/com.x/db/", b"", DIR_TIME));
    tar.extend(tar_member("apps/com.x/db/m.db", b"needle", FILE_TIME));
    tar.extend(tar_member("shared/0/DCIM/a.jpg", b"jpeg", FILE_TIME));
    // A long name, as the GNU `L` record tar and AOSP's PAX records carry one.
    let mut long_header = tar_member("././@LongLink", long_member.as_bytes(), 0);
    long_header[156] = b'L';
    long_header[148..156].fill(b' ');
    let sum: u32 = long_header[..512].iter().map(|&b| b as u32).sum();
    long_header[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
    tar.extend(long_header);
    tar.extend(tar_member("placeholder", b"long", FILE_TIME));
    tar.extend(vec![0u8; 1024]);

    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&tar).unwrap();
    let mut ab = b"ANDROID BACKUP\n5\n1\nnone\n".to_vec();
    ab.extend(encoder.finish().unwrap());
    fs::write(path, ab).unwrap();
    format!("data/data/com.x/files/{long_rest}")
}

fn mf_scan(cwd: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mf-scan"))
        .current_dir(cwd)
        .args(args)
        .output()
        .expect("run mf-scan")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/backup")
        .join(name)
}

/// Read an archive back, and hand its entries to `check`.
fn with_archive(path: &Path, check: impl FnOnce(&ZipSource, &[Entry])) {
    let bytes = fs::read(path).expect("the archive exists");
    let source = ZipSource::open(&bytes).expect("the archive reads back");
    check(&source, source.entries());
}

fn entry<'e>(entries: &'e [Entry], name: &str) -> &'e Entry {
    entries
        .iter()
        .find(|e| e.name == name)
        .unwrap_or_else(|| panic!("{name} is not in the archive"))
}

#[test]
fn an_android_backup_rebuilds_to_device_paths_with_device_timestamps() {
    let dir = tempfile::tempdir().unwrap();
    let long_path = write_ab(&dir.path().join("phone.ab"));

    let output = mf_scan(
        dir.path(),
        &["backup", "rebuild", "phone.ab", "--to", "device.zip"],
    );
    assert!(output.status.success(), "{}", stderr(&output));

    with_archive(&dir.path().join("device.zip"), |source, entries| {
        let db = entry(entries, "data/data/com.x/databases/m.db");
        assert_eq!(&*source.content(db).unwrap(), b"needle");
        assert_eq!(db.mtime, Some(FILE_TIME), "the exact device second is kept");

        let directory = entry(entries, "data/data/com.x/databases/");
        assert_eq!(
            directory.mtime,
            Some(DIR_TIME),
            "directories keep theirs too"
        );

        entry(entries, "storage/emulated/0/DCIM/a.jpg");
        entry(entries, "backup_only/apps/com.x/_manifest");

        // Far past Windows' limit, and complete all the same.
        assert!(long_path.len() > 300, "{}", long_path.len());
        assert_eq!(
            &*source.content(entry(entries, &long_path)).unwrap(),
            b"long"
        );

        let record = source
            .content(entry(
                entries,
                "_traceability/mf-scan.rebuild.traceability.json",
            ))
            .unwrap();
        let record = String::from_utf8_lossy(&record);
        assert!(record.contains(r#""tool": "mf-scan""#), "{record}");
        assert!(
            record.contains(r#""mtime_utc": "2023-11-14T22:13:21Z""#),
            "{record}"
        );
        assert!(record.contains(r#""non_portable""#), "{record}");
    });
    assert!(stderr(&output).contains("exceed Windows' path limit"));

    // The sidecar is in sha256sum format, over the archive as it stands.
    let sidecar = fs::read_to_string(dir.path().join("device.zip.sha256")).unwrap();
    let (hash, name) = sidecar.trim_end().split_once("  ").unwrap();
    assert_eq!(name, "device.zip");
    let archive = fs::read(dir.path().join("device.zip")).unwrap();
    assert_eq!(hash, mf_scan::core::util::sha256_hex(&archive));
}

#[test]
fn an_ios_backup_rebuilds_to_a_zip_and_keeps_its_folder_input_simple() {
    for (name, password) in [("unencrypted", None), ("encrypted", Some("1234"))] {
        let dir = tempfile::tempdir().unwrap();
        let backup = fixture(name);
        let mut args = vec![
            "backup",
            "rebuild",
            backup.to_str().unwrap(),
            "--to",
            "d.zip",
        ];
        if let Some(password) = password {
            args.extend(["--backup-password", password]);
        }
        let output = mf_scan(dir.path(), &args);
        assert!(output.status.success(), "{name}: {}", stderr(&output));
        with_archive(&dir.path().join("d.zip"), |source, entries| {
            let sms = entry(entries, "private/var/mobile/Library/SMS/sms.db");
            assert!(!source.content(sms).unwrap().is_empty());
        });
    }
}

#[test]
fn the_old_command_name_is_gone() {
    let dir = tempfile::tempdir().unwrap();
    let backup = fixture("unencrypted");
    let path = backup.to_str().unwrap();
    assert_eq!(
        mf_scan(dir.path(), &["ios-backup", "info", path])
            .status
            .code(),
        Some(2)
    );
    assert_eq!(
        mf_scan(dir.path(), &["backup", "info", path, "--dir-mode"])
            .status
            .code(),
        Some(2),
        "a folder needs no flag"
    );
    assert!(
        mf_scan(dir.path(), &["backup", "info", path])
            .status
            .success()
    );
}

/// The archive root holds `Manifest.db` unchanged and decrypted, and a CSV naming each
/// row's member.
#[test]
fn an_ios_archive_holds_the_plaintext_manifest_and_its_zip_paths() {
    let plain_manifest = fs::read(fixture("unencrypted").join("Manifest.db")).unwrap();
    for (name, password) in [("unencrypted", None), ("encrypted", Some("1234"))] {
        let dir = tempfile::tempdir().unwrap();
        let backup = fixture(name);
        let mut args = vec![
            "backup",
            "rebuild",
            backup.to_str().unwrap(),
            "--to",
            "d.zip",
        ];
        if let Some(password) = password {
            args.extend(["--backup-password", password]);
        }
        let output = mf_scan(dir.path(), &args);
        assert!(output.status.success(), "{name}: {}", stderr(&output));
        assert!(
            stderr(&output).contains("Manifest.mf-scan.zip-paths.csv"),
            "{}",
            stderr(&output)
        );

        with_archive(&dir.path().join("d.zip"), |source, entries| {
            let manifest = source.content(entry(entries, "Manifest.db")).unwrap();
            assert!(
                manifest.starts_with(b"SQLite format 3\0"),
                "{name}: not plaintext"
            );
            if name == "unencrypted" {
                assert_eq!(&*manifest, plain_manifest.as_slice(), "must be untouched");
            }
            let list = source
                .content(entry(entries, "Manifest.mf-scan.zip-paths.csv"))
                .unwrap();
            let list = list
                .strip_prefix(b"\xef\xbb\xbf")
                .expect("UTF-8 with a BOM, for Excel");
            let mut reader = csv::Reader::from_reader(list);
            assert_eq!(
                reader.headers().unwrap(),
                vec!["fileID", "domain", "relativePath", "flags", "zipPath"]
            );
            let rows: Vec<csv::StringRecord> = reader.records().map(Result::unwrap).collect();
            let zip_path = |relative: &str| {
                rows.iter()
                    .find(|r| r[2].ends_with(relative))
                    .unwrap_or_else(|| panic!("no row for {relative}"))[4]
                    .to_string()
            };
            // The path given is a real member of this archive.
            let sms = zip_path("Library/SMS/sms.db");
            assert_eq!(sms, "private/var/mobile/Library/SMS/sms.db");
            entry(entries, &sms);
            // A file missing from the backup has no member, so no path, but is listed.
            assert_eq!(zip_path("ghost.db"), "");
            // A directory's member name ends in `/`.
            assert!(
                rows.iter()
                    .filter(|r| &r[3] == "2")
                    .all(|r| r[4].ends_with('/'))
            );
            assert!(
                rows.windows(2).all(|w| w[0][0] <= w[1][0]),
                "sorted by fileID"
            );

            let record = source
                .content(entry(
                    entries,
                    "_traceability/mf-scan.rebuild.traceability.json",
                ))
                .unwrap();
            let record = String::from_utf8_lossy(&record);
            let digest = mf_scan::core::util::sha256_hex(&manifest);
            assert!(record.contains(&digest), "the record must state its digest");
            assert!(record.contains("zip_paths_csv_sha256"), "{record}");
        });
    }
}

#[test]
fn an_android_archive_has_no_manifest_members() {
    let dir = tempfile::tempdir().unwrap();
    write_ab(&dir.path().join("phone.ab"));
    let output = mf_scan(
        dir.path(),
        &["backup", "rebuild", "phone.ab", "--to", "d.zip"],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    with_archive(&dir.path().join("d.zip"), |_, entries| {
        assert!(!entries.iter().any(|e| e.name.starts_with("Manifest")));
    });
}

#[test]
fn output_is_only_ever_a_zip_and_is_not_overwritten_by_accident() {
    let dir = tempfile::tempdir().unwrap();
    write_ab(&dir.path().join("phone.ab"));
    let rebuild = |to: &str, extra: &[&str]| {
        let mut args = vec!["backup", "rebuild", "phone.ab", "--to", to];
        args.extend_from_slice(extra);
        mf_scan(dir.path(), &args)
    };

    // A name without .zip gets it: there is no folder output.
    assert!(rebuild("out", &[]).status.success());
    assert!(dir.path().join("out.zip").is_file());

    let again = rebuild("out.zip", &[]);
    assert_eq!(again.status.code(), Some(2));
    assert!(stderr(&again).contains("--force"));
    assert!(rebuild("out.zip", &["--force"]).status.success());

    let cap = rebuild("capped.zip", &["--max-size", "1"]);
    assert_eq!(cap.status.code(), Some(2));
    assert!(!dir.path().join("capped.zip").exists());

    let dry = rebuild("dry.zip", &["--dry-run"]);
    assert!(dry.status.success());
    assert!(!dir.path().join("dry.zip").exists());

    // No temporary file is left behind by any of it.
    let leftovers: Vec<_> = fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(".partial"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}

#[test]
fn a_damaged_backup_fails_closed_unless_told_otherwise() {
    let dir = tempfile::tempdir().unwrap();
    write_ab(&dir.path().join("whole.ab"));
    let whole = fs::read(dir.path().join("whole.ab")).unwrap();
    fs::write(dir.path().join("cut.ab"), &whole[..whole.len() - 40]).unwrap();

    let refused = mf_scan(
        dir.path(),
        &["backup", "rebuild", "cut.ab", "--to", "a.zip"],
    );
    assert_eq!(refused.status.code(), Some(2));
    assert!(stderr(&refused).contains("damaged"), "{}", stderr(&refused));
    assert!(!dir.path().join("a.zip").exists());

    let kept = mf_scan(
        dir.path(),
        &[
            "backup",
            "rebuild",
            "cut.ab",
            "--to",
            "b.zip",
            "--continue-on-error",
        ],
    );
    assert!(kept.status.success(), "{}", stderr(&kept));
    assert!(dir.path().join("b.zip").exists());

    // Searching it still works, but the exit status says the search was incomplete.
    let search = mf_scan(
        dir.path(),
        &["grep", "needle", "cut.ab", "--no-report", "--no-stats"],
    );
    assert_eq!(search.status.code(), Some(2));
}

#[test]
fn not_a_backup_is_said_plainly() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("notes.txt"), "text").unwrap();
    let output = mf_scan(dir.path(), &["backup", "info", "notes.txt"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        stderr(&output).contains("is not a backup"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn every_other_command_reads_an_android_backup_directly() {
    let dir = tempfile::tempdir().unwrap();
    write_ab(&dir.path().join("phone.ab"));

    let grep = mf_scan(
        dir.path(),
        &[
            "grep",
            "-l",
            "needle",
            "phone.ab",
            "--no-report",
            "--no-stats",
        ],
    );
    assert_eq!(
        String::from_utf8_lossy(&grep.stdout),
        "apps/com.x/db/m.db\n"
    );

    let find = mf_scan(dir.path(), &["find", "phone.ab", "-name", "*.db"]);
    assert_eq!(
        String::from_utf8_lossy(&find.stdout),
        "apps/com.x/db/m.db\n"
    );

    let app = mf_scan(dir.path(), &["app", "list", "phone.ab"]);
    assert!(
        String::from_utf8_lossy(&app.stdout).contains("com.x"),
        "{}",
        stderr(&app)
    );

    // And `app` reads the rebuilt archive too, whose paths are relative.
    mf_scan(
        dir.path(),
        &["backup", "rebuild", "phone.ab", "--to", "device.zip"],
    );
    let rebuilt = mf_scan(dir.path(), &["app", "list", "device.zip"]);
    assert!(
        String::from_utf8_lossy(&rebuilt.stdout).contains("com.x"),
        "{}",
        stderr(&rebuilt)
    );
}
