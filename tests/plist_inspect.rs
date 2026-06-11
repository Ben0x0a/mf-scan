//! Tests for the plist inspector (XML plists and binary plists).
//!
//! Defines: tests that a match offset resolves to a dict-key / array-index path
//! in both encodings, and that detection is header-first.
//! Uses: `mf_scan::inspect` and the committed `fixtures/sample.plist`
//! (XML) and `fixtures/sample.bplist` (binary, produced by `plutil`). Both
//! encode `{ Account: { Username: "XML_NEEDLE", Servers: ["first",
//! "ARRAY_NEEDLE"] } }`.

use mf_scan::inspect::{diff, inspect};

const XML: &[u8] = include_bytes!("fixtures/sample.plist");
const BIN: &[u8] = include_bytes!("fixtures/sample.bplist");

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
