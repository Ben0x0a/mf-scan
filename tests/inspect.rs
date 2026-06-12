//! Tests for the in-file inspectors (`--inspect`).
//!
//! Defines: tests for TXT line/column, JSON key-path, XML element-path, and
//! format detection (extension + header-first magic).
//! Uses: `mf_scan::inspect`.

use mf_scan::inspect::inspect;

/// Byte offset of the first occurrence of `needle` in `hay`.
fn at(hay: &[u8], needle: &str) -> usize {
    hay.windows(needle.len())
        .position(|w| w == needle.as_bytes())
        .expect("needle not found")
}

#[test]
fn txt_reports_line_and_column() {
    // "line1\n" is 6 bytes, so offset 6 is the first byte of line 2.
    let insp = inspect("a.txt", b"line1\nXY", 6).unwrap();
    assert_eq!(insp.format, "txt");
    assert_eq!(insp.detail["line"], 2);
    assert_eq!(insp.detail["col"], 1);
    assert_eq!(insp.summary, "line: 2  col: 1");
}

#[test]
fn txt_column_is_within_line() {
    let insp = inspect("a.log", b"abcdef", 3).unwrap();
    assert_eq!(insp.detail["line"], 1);
    assert_eq!(insp.detail["col"], 4); // bytes a,b,c precede offset 3
}

#[test]
fn unknown_extension_is_not_inspected() {
    assert!(inspect("blob.bin", b"abc", 1).is_none());
    assert!(inspect("noext", b"abc", 1).is_none());
}

#[test]
fn offset_past_end_returns_none() {
    assert!(inspect("a.txt", b"abc", 99).is_none());
}

#[test]
fn json_resolves_nested_path() {
    let content = br#"{"users":[{"id":"AAA"},{"id":"TARGET"}]}"#;
    let insp = inspect("d.json", content, at(content, "TARGET")).unwrap();
    assert_eq!(insp.format, "json");
    assert_eq!(insp.detail["path"], "$.users[1].id");
}

#[test]
fn json_match_in_key_points_at_that_key() {
    let content = br#"{"a":{"token":"x"}}"#;
    let insp = inspect("d.json", content, at(content, "token")).unwrap();
    assert_eq!(insp.detail["path"], "$.a.token");
}

#[test]
fn json_top_level_array_index() {
    let content = br#"["xx","yy"]"#;
    let insp = inspect("d.json", content, at(content, "yy")).unwrap();
    assert_eq!(insp.detail["path"], "$[1]");
}

/// Crafted-input DoS guard (review finding S2): a file that is nothing but
/// 100 000 `[` characters once overflowed the scanner's recursion and crashed
/// the whole process. Past the depth cap, inspection must degrade to `None`.
#[test]
fn json_pathological_nesting_does_not_overflow_the_stack() {
    let content = vec![b'['; 100_000];
    assert!(inspect("bomb.json", &content, 50_000).is_none());
}

#[test]
fn xml_resolves_element_path() {
    // Non-plist XML, so it is handled by the generic XML inspector (element
    // path) rather than the plist inspector (key path).
    let content =
        br#"<?xml version="1.0"?><config><section><value>TARGET</value></section></config>"#;
    let insp = inspect("d.xml", content, at(content, "TARGET")).unwrap();
    assert_eq!(insp.format, "xml");
    assert_eq!(insp.detail["path"], "/config/section/value");
}

#[test]
fn csv_resolves_row_column_and_header() {
    let content = b"name,sender,body\nalice,bob,hello\ncarol,dave,TARGET\n";
    let insp = inspect("d.csv", content, at(content, "TARGET")).unwrap();
    assert_eq!(insp.format, "csv");
    assert_eq!(insp.detail["row"], 3);
    assert_eq!(insp.detail["col"], 3);
    assert_eq!(insp.detail["header"], "body");
}

#[test]
fn csv_quoted_field_does_not_miscount_columns() {
    // The comma inside the quoted field must not advance the column count.
    let content = b"id,note\n1,\"has, comma and TARGET\"\n";
    let insp = inspect("d.csv", content, at(content, "TARGET")).unwrap();
    assert_eq!(insp.detail["row"], 2);
    assert_eq!(insp.detail["col"], 2);
    assert_eq!(insp.detail["header"], "note");
}

#[test]
fn detection_prefers_header_over_extension() {
    // A misleading .txt name, but the content is clearly XML.
    let content = br#"<?xml version="1.0"?><root><item>TARGET</item></root>"#;
    let insp = inspect("evidence.txt", content, at(content, "TARGET")).unwrap();
    assert_eq!(insp.format, "xml"); // header wins over the .txt extension
    assert_eq!(insp.detail["path"], "/root/item");
}
