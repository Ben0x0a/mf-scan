//! Tests for the SQLite inspector against a real database fixture.
//!
//! Defines: tests that a match offset resolves to table/rowid/column for live
//! table-leaf cells, falls back to page+offset elsewhere, and that header-first
//! detection works on a misnamed file.
//! Uses: `mf_scan::inspect` and the committed `fixtures/messages.sqlite`
//! (built with sqlite3: tables `messages(id,sender,body)` and
//! `notes(note_id,content)`).

use mf_scan::inspect::{diff, inspect};

const DB: &[u8] = include_bytes!("fixtures/messages.sqlite");
/// A database whose `items.payload` BLOB holds an Apple binary plist.
const BLOB_DB: &[u8] = include_bytes!("fixtures/blob.sqlite");

/// Byte offset of the first occurrence of `needle` in the database.
fn at(needle: &str) -> usize {
    at_in(DB, needle)
}

/// Byte offset of the first occurrence of `needle` in `hay`.
fn at_in(hay: &[u8], needle: &str) -> usize {
    hay.windows(needle.len())
        .position(|w| w == needle.as_bytes())
        .expect("needle not found in fixture")
}

#[test]
fn resolves_text_value_to_table_rowid_column() {
    let insp = inspect("messages.sqlite", DB, at("UNIQUE_NEEDLE_42")).unwrap();
    assert_eq!(insp.format, "sqlite");
    assert_eq!(insp.detail["table"], "messages");
    assert_eq!(insp.detail["rowid"], 3);
    assert_eq!(insp.detail["column"], "body");
    // The decoded cell content is included (text-safe), not raw bytes.
    assert!(
        insp.detail["cell"]
            .as_str()
            .unwrap()
            .contains("UNIQUE_NEEDLE_42")
    );
}

#[test]
fn resolves_a_different_column() {
    let insp = inspect("messages.sqlite", DB, at("FINDSENDER")).unwrap();
    assert_eq!(insp.detail["table"], "messages");
    assert_eq!(insp.detail["rowid"], 2);
    assert_eq!(insp.detail["column"], "sender");
}

#[test]
fn resolves_a_second_table() {
    let insp = inspect("notes.sqlite", DB, at("MARKER_NOTE")).unwrap();
    assert_eq!(insp.detail["table"], "notes");
    assert_eq!(insp.detail["rowid"], 1);
    assert_eq!(insp.detail["column"], "content");
}

#[test]
fn non_cell_region_falls_back_to_page_and_offset() {
    // Offset 50 is inside the 100-byte database header on page 1.
    let insp = inspect("messages.sqlite", DB, 50).unwrap();
    assert_eq!(insp.format, "sqlite");
    assert_eq!(insp.detail["page"], 1);
    assert_eq!(insp.detail["page_offset"], 50);
    assert!(insp.detail.get("table").is_none());
}

#[test]
fn detection_uses_header_over_extension() {
    // Misnamed .txt, but the SQLite magic header wins.
    let insp = inspect("evidence.txt", DB, at("UNIQUE_NEEDLE_42")).unwrap();
    assert_eq!(insp.format, "sqlite");
    assert_eq!(insp.detail["table"], "messages");
}

#[test]
fn reports_column_storage_type() {
    // The matched value is text, so the column's type is reported as TEXT, in
    // both the structured detail and the labelled summary (`column [TYPE]`).
    let insp = inspect("messages.sqlite", DB, at("UNIQUE_NEEDLE_42")).unwrap();
    assert_eq!(insp.detail["type"], "TEXT");
    assert!(insp.summary.contains("[TEXT]"), "summary: {}", insp.summary);
}

#[test]
fn blob_cell_is_classified_and_inspected_by_signature() {
    // A match inside the BLOB column lands in an embedded binary plist; the blob
    // is recognised by signature and resolved by the plist inspector.
    let insp = inspect("blob.sqlite", BLOB_DB, at_in(BLOB_DB, "Servers")).unwrap();
    assert_eq!(insp.format, "sqlite");
    assert_eq!(insp.detail["column"], "payload");
    assert_eq!(insp.detail["type"], "BLOB");
    assert_eq!(insp.detail["blob_format"], "bplist");
    // The nested plist context resolves a key path inside the blob.
    let path = insp.detail["blob_context"]["path"].as_str().unwrap();
    assert!(path.contains("Servers"), "blob path: {path}");
    // The txt summary surfaces the same: `... [BLOB] ... blob: bplist ...`.
    assert!(insp.summary.contains("[BLOB]"), "summary: {}", insp.summary);
    assert!(
        insp.summary.contains("blob: bplist"),
        "summary: {}",
        insp.summary
    );
}

#[test]
fn diff_reports_table_changes_between_databases() {
    // messages.sqlite has `messages`+`notes`; blob.sqlite has `items`.
    let d = diff("messages.sqlite", DB, BLOB_DB).expect("a sqlite content diff");
    assert_eq!(d.format, "sqlite");
    let removed = d.detail["tables_removed"].as_array().unwrap();
    let added = d.detail["tables_added"].as_array().unwrap();
    assert!(removed.iter().any(|t| t == "messages"));
    assert!(removed.iter().any(|t| t == "notes"));
    assert!(added.iter().any(|t| t == "items"));
}

#[test]
fn diff_of_identical_databases_reports_no_changes() {
    let d = diff("messages.sqlite", DB, DB).unwrap();
    assert_eq!(d.format, "sqlite");
    assert!(d.summary.contains("no table or row-count changes"));
}
