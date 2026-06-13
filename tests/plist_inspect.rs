//! Tests for the plist inspector (XML plists and binary plists).
//!
//! Defines: tests that a match offset resolves to a dict-key / array-index path
//! in both encodings, and that detection is header-first.  Also covers the
//! NSKeyedArchiver resolver (`inspect::nskeyed`) against the committed fixture
//! `fixtures/nskeyed.bplist`, which encodes a logical tree of
//! `{ root: { count: 42, nested: { inner: "DEEP-needle-xyz" }, title: "FINDME-needle" } }`.
//! Uses: `mf_scan::inspect` and the committed `fixtures/sample.plist`
//! (XML) and `fixtures/sample.bplist` (binary, produced by `plutil`). Both
//! encode `{ Account: { Username: "XML_NEEDLE", Servers: ["first",
//! "ARRAY_NEEDLE"] } }`.

use mf_scan::inspect::{diff, inspect};

const XML: &[u8] = include_bytes!("fixtures/sample.plist");
const BIN: &[u8] = include_bytes!("fixtures/sample.bplist");
const NK: &[u8] = include_bytes!("fixtures/nskeyed.bplist");

fn at(hay: &[u8], needle: &str) -> usize {
    hay.windows(needle.len())
        .position(|w| w == needle.as_bytes())
        .expect("needle not found in fixture")
}

#[test]
fn xml_plist_resolves_nested_key_path() {
    let insp = inspect("sample.plist", XML, at(XML, "XML_NEEDLE")).unwrap();
    assert_eq!(insp.format, "plist");
    assert_eq!(insp.detail["path"], "$.Account.Username");
}

#[test]
fn xml_plist_resolves_array_index() {
    let insp = inspect("sample.plist", XML, at(XML, "ARRAY_NEEDLE")).unwrap();
    assert_eq!(insp.detail["path"], "$.Account.Servers[1]");
}

#[test]
fn binary_plist_resolves_nested_key_path() {
    let insp = inspect("sample.bplist", BIN, at(BIN, "XML_NEEDLE")).unwrap();
    assert_eq!(insp.format, "bplist");
    assert_eq!(insp.detail["path"], "$.Account.Username");
}

#[test]
fn binary_plist_resolves_array_index() {
    let insp = inspect("sample.bplist", BIN, at(BIN, "ARRAY_NEEDLE")).unwrap();
    assert_eq!(insp.format, "bplist");
    assert_eq!(insp.detail["path"], "$.Account.Servers[1]");
}

#[test]
fn binary_plist_detected_by_magic_despite_extension() {
    // Wrong extension, but the bplist00 magic wins.
    let insp = inspect("note.txt", BIN, at(BIN, "ARRAY_NEEDLE")).unwrap();
    assert_eq!(insp.format, "bplist");
}

/// A minimal XML plist with the given count and an optional extra key.
fn plist_doc(count: u32, extra: bool) -> Vec<u8> {
    let extra = if extra { "<key>extra</key><true/>" } else { "" };
    format!(
        r#"<?xml version="1.0"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict>
          <key>name</key><string>alice</string>
          <key>count</key><integer>{count}</integer>
          {extra}
        </dict></plist>"#
    )
    .into_bytes()
}

#[test]
fn diff_reports_changed_and_added_plist_keys() {
    let a = plist_doc(3, false);
    let b = plist_doc(5, true); // count changed, `extra` added
    let d = diff("settings.plist", &a, &b).expect("a plist content diff");
    assert_eq!(d.format, "plist");
    assert_eq!(d.detail["counts"]["added"], 1); // $.extra
    assert_eq!(d.detail["counts"]["removed"], 0);
    assert_eq!(d.detail["counts"]["changed"], 1); // $.count
}

/// Crafted-input DoS guard (review finding S3): a binary-plist trailer claiming
/// 2^60 objects once made every offset lookup iterate effectively forever.
/// The trailer counts are now validated against the bytes actually available,
/// so the inspector must degrade to `None` immediately.
#[test]
fn crafted_bplist_trailer_with_bogus_counts_degrades_fast() {
    let mut content = b"bplist00".to_vec();
    content.extend_from_slice(&[0u8; 16]); // a token body
    let mut trailer = [0u8; 32];
    trailer[6] = 8; // offset_size
    trailer[7] = 8; // ref_size
    trailer[8..16].copy_from_slice(&(1u64 << 60).to_be_bytes()); // num_objects: absurd
    trailer[24..32].copy_from_slice(&8u64.to_be_bytes()); // offset_table
    content.extend_from_slice(&trailer);

    assert!(inspect("x.plist", &content, 10).is_none());
}

// ── NSKeyedArchiver integration tests ────────────────────────────────────────

/// A deeply nested string (`$objects[8]`, reached via root → nested → inner)
/// must resolve to the logical path `$.root.nested.inner` and the detail must
/// carry `archiver == "NSKeyedArchiver"` to confirm the correct resolver ran.
#[test]
fn nskeyed_resolves_deep_nested_path() {
    let insp = inspect("archive.bplist", NK, at(NK, "DEEP-needle-xyz")).unwrap();
    assert_eq!(insp.format, "bplist");
    assert_eq!(
        insp.detail["path"], "$.root.nested.inner",
        "expected logical NSKeyedArchiver path"
    );
    assert_eq!(
        insp.detail["archiver"], "NSKeyedArchiver",
        "archiver label must confirm the NSKeyedArchiver resolver ran"
    );
}

/// A top-level string (`$objects[10]`, reached via root → title`) must resolve
/// to `$.root.title`.
#[test]
fn nskeyed_resolves_top_level_key() {
    let insp = inspect("archive.bplist", NK, at(NK, "FINDME-needle")).unwrap();
    assert_eq!(insp.format, "bplist");
    assert_eq!(insp.detail["path"], "$.root.title");
}

/// Regression: a plain binary plist (`sample.bplist`) must still go through the
/// ordinary `path_to` walk — the NSKeyedArchiver resolver must not intercept it.
/// We check that the summary does NOT start with `"nskeyed key:"`, i.e. the
/// archiver path was not triggered by a non-archiver plist.
#[test]
fn plain_bplist_does_not_use_nskeyed_resolver() {
    let insp = inspect("sample.bplist", BIN, at(BIN, "XML_NEEDLE")).unwrap();
    assert_eq!(insp.format, "bplist");
    assert!(
        !insp.summary.starts_with("nskeyed key:"),
        "plain bplist summary must not start with 'nskeyed key:' — got: {}",
        insp.summary
    );
}
