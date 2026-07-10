//! Integration tests for the byte-regex search over entry data.
//!
//! Defines: tests covering match offset/line reporting, the match's position
//! within its line (for highlighting), case-insensitive matching, multiple
//! matches, no-match, regex (vs literal) behaviour, and DEFLATE search.
//! Uses: `common` (fixture builder), `mf_scan::{zip, search}`, `regex::bytes`
//! to compile patterns the way `main.rs` does, and `flate2` to compress.

mod common;

use std::io::Write;

use common::{FileSpec, build_zip};
use flate2::Compression;
use flate2::write::DeflateEncoder;
use mf_scan::core::models::SearchHit;
use mf_scan::core::source::zip::parse_entries;
use mf_scan::ops::search::search_entry;
use regex::bytes::{Regex, RegexBuilder};

fn compile(pattern: &str, ignore_case: bool) -> Regex {
    RegexBuilder::new(pattern)
        .case_insensitive(ignore_case)
        .build()
        .unwrap()
}

/// The single-file STORED archive search used by most tests below.
fn search_single(data: &[u8], re: &Regex) -> Vec<SearchHit> {
    let files = [FileSpec::stored("f.txt", data)];
    let zip = build_zip(&files, false);
    let entries = parse_entries(&zip).unwrap();
    search_entry(&zip, &entries[0], re).unwrap()
}

fn line_str(hit: &SearchHit) -> String {
    String::from_utf8_lossy(&hit.line).into_owned()
}

#[test]
fn reports_offset_line_and_match_span() {
    let hits = search_single(
        b"first line\nhas SECRET here\nlast\n",
        &compile("SECRET", false),
    );

    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].offset, 15); // index of "SECRET" within the file
    assert_eq!(line_str(&hits[0]), "has SECRET here");
    // The recorded span must point exactly at the matched text within the line.
    let r = &hits[0].match_in_line;
    assert_eq!(&hits[0].line[r.start..r.end], b"SECRET");
}

#[test]
fn case_insensitive_matches_mixed_case() {
    let sensitive = search_single(b"value: SeCrEt\n", &compile("secret", false));
    let insensitive = search_single(b"value: SeCrEt\n", &compile("secret", true));

    assert!(sensitive.is_empty());
    assert_eq!(insensitive.len(), 1);
}

#[test]
fn finds_all_matches_in_a_file() {
    let hits = search_single(b"aXbXc", &compile("X", false));

    let offsets: Vec<u64> = hits.iter().map(|h| h.offset).collect();
    assert_eq!(offsets, vec![1, 3]);
}

#[test]
fn no_match_returns_empty() {
    let hits = search_single(b"nothing of interest here\n", &compile("absent", false));

    assert!(hits.is_empty());
}

#[test]
fn matches_regex_not_just_literals() {
    let hits = search_single(b"id=42\nid=7\n", &compile(r"id=\d+", false));

    assert_eq!(hits.len(), 2);
    assert_eq!(line_str(&hits[0]), "id=42");
    assert_eq!(line_str(&hits[1]), "id=7");
}

#[test]
fn strips_trailing_cr_from_crlf_lines() {
    let hits = search_single(
        b"alpha\r\nMATCH here\r\nomega\r\n",
        &compile("MATCH", false),
    );

    assert_eq!(hits.len(), 1);
    assert_eq!(line_str(&hits[0]), "MATCH here"); // no trailing '\r'
}

#[test]
fn long_line_is_capped_with_ellipsis() {
    // A 500-byte "line" with no newlines (typical of binary data); the match
    // sits in the middle.
    let mut data = vec![b'x'; 500];
    data.splice(250..250, *b"NEEDLE");

    let hits = search_single(&data, &compile("NEEDLE", false));

    assert_eq!(hits.len(), 1);
    let hit = &hits[0];
    // Preview is bounded, not the whole 500+ byte line.
    assert!(
        hit.line.len() <= 220,
        "preview not capped: {}",
        hit.line.len()
    );
    // The match is still present and correctly located within the preview.
    let r = &hit.match_in_line;
    assert_eq!(&hit.line[r.start..r.end], b"NEEDLE");
    // Both edges were truncated, so ellipsis markers appear.
    assert!(line_str(hit).contains('…'));
    // The exact offset is unaffected by the preview cap.
    assert_eq!(hit.offset, 250);
}

/// Raw DEFLATE stream — the form ZIP method 8 stores (no zlib header).
fn deflate(plain: &[u8]) -> Vec<u8> {
    let mut enc = DeflateEncoder::new(Vec::new(), Compression::default());
    enc.write_all(plain).unwrap();
    enc.finish().unwrap()
}

#[test]
fn searches_inside_deflate_entry() {
    let plain = b"alpha\nthe NEEDLE is compressed\nomega\n";
    let compressed = deflate(plain);
    let files = [FileSpec::deflate("c.bin", &compressed, plain.len() as u32)];
    let zip = build_zip(&files, false);
    let entries = parse_entries(&zip).unwrap();

    let hits = search_entry(&zip, &entries[0], &compile("NEEDLE", false)).unwrap();

    assert_eq!(hits.len(), 1);
    assert_eq!(line_str(&hits[0]), "the NEEDLE is compressed");
    // Offset is the position within the DECOMPRESSED stream ("alpha\n" = 6).
    assert_eq!(hits[0].offset, 10);
}
