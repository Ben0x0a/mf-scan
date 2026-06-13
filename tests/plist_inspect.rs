//! Tests for the plist inspector (XML plists and binary plists).
//!
//! Defines: tests that a match offset resolves to a dict-key / array-index path
//! in both encodings, and that detection is header-first.  Also covers the
//! NSKeyedArchiver resolver (`inspect::nskeyed`) against several committed
//! fixtures:
//!
//! - `fixtures/nskeyed.bplist` — plain nested dict/string:
//!   `{ root: { count: 42, nested: { inner: "DEEP-needle-xyz" }, title: "FINDME-needle" } }`
//! - `fixtures/nskeyed_array.bplist` — NSArray value:
//!   `{ root: { items: ["alpha", "BRAVO-needle-xyz", "charlie"] } }`
//! - `fixtures/nskeyed_wrapped.bplist` — wrapped scalar (NSMutableString + NSData):
//!   `{ root: { s: NSMutableString("WRAPPED-needle-xyz"), blob: Data("BLOBDATA-needle") } }`
//! - `fixtures/nskeyed_dictkey.bplist` — dict key-name hit:
//!   `{ root: { NEEDLEKEY: "some-value-xyz", other: "other-value" } }`
//!
//! Uses: `mf_scan::inspect` and the committed `fixtures/sample.plist`
//! (XML) and `fixtures/sample.bplist` (binary, produced by `plutil`). Both
//! encode `{ Account: { Username: "XML_NEEDLE", Servers: ["first",
//! "ARRAY_NEEDLE"] } }`.

use mf_scan::inspect::{diff, inspect};

const XML: &[u8] = include_bytes!("fixtures/sample.plist");
const BIN: &[u8] = include_bytes!("fixtures/sample.bplist");
const NK: &[u8] = include_bytes!("fixtures/nskeyed.bplist");
const NK_ARRAY: &[u8] = include_bytes!("fixtures/nskeyed_array.bplist");
const NK_WRAPPED: &[u8] = include_bytes!("fixtures/nskeyed_wrapped.bplist");
const NK_DICTKEY: &[u8] = include_bytes!("fixtures/nskeyed_dictkey.bplist");

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

// ── NSKeyedArchiver — new fixture tests ───────────────────────────────────────

/// An NSArray value: `{ root: { items: ["alpha", "BRAVO-needle-xyz", "charlie"] } }`.
/// The string at index 1 must resolve to `$.root.items[1]`, and the container
/// class must be `"NSArray"` (the class of the array that holds the value).
///
/// plutil -p nskeyed_array.bplist shows $objects[3]=NSArray($objects[4..6]).
#[test]
fn nskeyed_resolves_nsarray_element_by_index() {
    let insp = inspect("archive.bplist", NK_ARRAY, at(NK_ARRAY, "BRAVO-needle-xyz")).unwrap();
    assert_eq!(insp.format, "bplist");
    assert_eq!(
        insp.detail["path"], "$.root.items[1]",
        "NSArray element must resolve to its positional index path"
    );
    assert_eq!(insp.detail["archiver"], "NSKeyedArchiver");
    assert_eq!(
        insp.detail["class"], "NSArray",
        "class of the NSArray container must appear in detail"
    );
}

/// A wrapped NSMutableString value: `{ root: { s: NSMutableString("WRAPPED-needle-xyz"), … } }`.
/// The bytes of the inner string live inside the wrapper object; the resolver
/// must report the *wrapper's* logical path (`$.root.s`) and class
/// (`"NSMutableString"`).
///
/// WHY: without the wrapped-scalar check, `walk_logical` reaches the wrapper
/// dict (no NS.keys/NS.objects), treats it as a leaf, and never matches the
/// inner string oid — the result would be `None` / fallback to raw offset.
#[test]
fn nskeyed_resolves_wrapped_mutable_string() {
    let insp = inspect(
        "archive.bplist",
        NK_WRAPPED,
        at(NK_WRAPPED, "WRAPPED-needle-xyz"),
    )
    .unwrap();
    assert_eq!(insp.format, "bplist");
    assert_eq!(
        insp.detail["path"], "$.root.s",
        "wrapped NSMutableString must resolve to the owning key path"
    );
    assert_eq!(insp.detail["archiver"], "NSKeyedArchiver");
    assert_eq!(
        insp.detail["class"], "NSMutableString",
        "class of the wrapper object must appear in detail"
    );
}

/// An NSData value: `{ root: { …, blob: Data("BLOBDATA-needle") } }`.
/// NSData is stored as a bplist data object (marker 0x4x) directly in
/// `$objects`; it is a direct value hit, not a wrapped scalar.  The resolver
/// must reach it via the ordinary dict-value path and report `$.root.blob`.
/// The container class is the root `NSDictionary`.
#[test]
fn nskeyed_resolves_nsdata_value() {
    let insp = inspect(
        "archive.bplist",
        NK_WRAPPED,
        at(NK_WRAPPED, "BLOBDATA-needle"),
    )
    .unwrap();
    assert_eq!(insp.format, "bplist");
    assert_eq!(
        insp.detail["path"], "$.root.blob",
        "NSData value must resolve to its owning key path"
    );
    assert_eq!(insp.detail["archiver"], "NSKeyedArchiver");
    assert_eq!(
        insp.detail["class"], "NSDictionary",
        "class of the containing NSDictionary must appear in detail"
    );
}

/// A dict key-name hit: `{ root: { NEEDLEKEY: "some-value-xyz", … } }`.
/// When the search pattern matches the KEY string rather than a value, the
/// resolver must report the key's own logical path (`$.root.NEEDLEKEY`).
///
/// WHY: without the key-name check, the resolver skips the key oid entirely
/// (only value oids are compared) and returns `None`.
#[test]
fn nskeyed_resolves_dict_key_name_hit() {
    let insp = inspect("archive.bplist", NK_DICTKEY, at(NK_DICTKEY, "NEEDLEKEY")).unwrap();
    assert_eq!(insp.format, "bplist");
    assert_eq!(
        insp.detail["path"], "$.root.NEEDLEKEY",
        "a match on a dict key name must resolve to that key's logical path"
    );
    assert_eq!(insp.detail["archiver"], "NSKeyedArchiver");
    assert_eq!(
        insp.detail["class"], "NSDictionary",
        "class of the containing NSDictionary must appear in detail"
    );
}

/// Regression: existing deep-nested path test must still report a class now.
/// The root NSKeyedArchiver dict is an NSDictionary, so `class == "NSDictionary"`.
#[test]
fn nskeyed_deep_nested_path_includes_class() {
    let insp = inspect("archive.bplist", NK, at(NK, "DEEP-needle-xyz")).unwrap();
    // The value is held by a nested NSDictionary container.
    assert_eq!(
        insp.detail["class"], "NSDictionary",
        "deep nested path must now carry the containing NSDictionary class"
    );
}
