//! End-to-end test for the search engine (parse + parallel search + records).
//!
//! Defines: a test that searches an archive containing both a STORED and a
//! DEFLATE entry and checks ordering, offsets, and the compressed flag.
//! Uses: `common` (fixture builder), `flate2` (compress), `mf_scan::engine`,
//! `regex::bytes`.

mod common;

use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};

use common::{FileSpec, build_zip};
use flate2::Compression;
use flate2::write::DeflateEncoder;
use mf_scan::engine::{NoProgress, Progress, search_archive, search_with_progress};
use mf_scan::filter::EntryFilter;
use regex::bytes::Regex;

/// A filter that searches everything.
fn no_filter() -> EntryFilter {
    EntryFilter::all()
}

fn deflate(plain: &[u8]) -> Vec<u8> {
    let mut enc = DeflateEncoder::new(Vec::new(), Compression::default());
    enc.write_all(plain).unwrap();
    enc.finish().unwrap()
}

#[test]
fn searches_stored_and_deflate_in_order() {
    let deflate_plain = b"zz TARGET zz";
    let compressed = deflate(deflate_plain);
    let files = [
        FileSpec::stored("a.txt", b"x TARGET y"),
        FileSpec::deflate("c.bin", &compressed, deflate_plain.len() as u32),
    ];
    let zip = build_zip(&files, false);

    let findings =
        search_archive(&zip, &Regex::new("TARGET").unwrap(), false, &no_filter()).unwrap();
    let records = &findings.records;

    assert_eq!(records.len(), 2);
    // Two distinct files matched (one per entry), for extraction.
    assert_eq!(findings.files.len(), 2);
    assert_eq!(findings.files[0].entry.name, "a.txt");
    assert_eq!(findings.files[1].offsets, vec![3]);

    // Entry order is preserved: STORED first.
    let stored = &records[0];
    assert_eq!(stored.path, "a.txt");
    assert!(!stored.compressed);
    assert_eq!(stored.file_offset, 2);
    // STORED archive offset is exact.
    assert_eq!(
        stored.archive_offset,
        Some(stored.file_start + stored.file_offset)
    );

    // DEFLATE second: offset is into the decompressed stream, archive offset is
    // the blob start (flagged compressed).
    let deflated = &records[1];
    assert_eq!(deflated.path, "c.bin");
    assert!(deflated.compressed);
    assert_eq!(deflated.file_offset, 3);
    assert_eq!(deflated.archive_offset, Some(deflated.file_start));
}

#[test]
fn deep_inspects_recognised_formats_only() {
    let files = [
        FileSpec::stored("notes.txt", b"a\nb TARGET c\n"),
        FileSpec::stored("blob.bin", b"x TARGET y"), // unknown extension
    ];
    let zip = build_zip(&files, false);

    let records = search_archive(&zip, &Regex::new("TARGET").unwrap(), true, &no_filter())
        .unwrap()
        .records;

    // .txt is inspected (line 2, after the first '\n'); .bin is not recognised.
    let txt = &records[0];
    let insp = txt.inspection.as_ref().expect("txt should be inspected");
    assert_eq!(insp.format, "txt");
    assert_eq!(insp.detail["line"], 2);

    assert!(records[1].inspection.is_none());
}

#[test]
fn path_filter_restricts_searched_entries() {
    let files = [
        FileSpec::stored("a/keep.db", b"x TARGET y"),
        FileSpec::stored("a/skip.txt", b"x TARGET y"),
    ];
    let zip = build_zip(&files, false);
    let filter = EntryFilter::new(&["*.db".to_string()], &[], &[], false);

    let findings = search_archive(&zip, &Regex::new("TARGET").unwrap(), false, &filter).unwrap();

    // Only the .db file is searched, so only it matches.
    assert_eq!(findings.files.len(), 1);
    assert_eq!(findings.records.len(), 1);
    assert_eq!(findings.records[0].path, "a/keep.db");
}

#[test]
fn type_filter_keeps_only_requested_category() {
    // A real SQLite header (detected as database) and a plain text file.
    let mut db = b"SQLite format 3\x00".to_vec();
    db.extend_from_slice(b" ... TARGET ...");
    let files = [
        FileSpec::stored("a.db", &db),
        FileSpec::stored("b.txt", b"x TARGET y"),
    ];
    let zip = build_zip(&files, false);

    // --type database keeps only the SQLite file (header-detected).
    let only_db = EntryFilter::new(&[], &[], &["database".to_string()], false);
    let findings = search_archive(&zip, &Regex::new("TARGET").unwrap(), false, &only_db).unwrap();
    assert_eq!(findings.files.len(), 1);
    assert_eq!(findings.records[0].path, "a.db");
}

#[test]
fn skip_media_drops_media_files_by_signature() {
    // A JPEG (magic, no media extension) is recognised by header and skipped
    // even though its name does not say "image".
    let mut jpg = vec![0xFF, 0xD8, 0xFF];
    jpg.extend_from_slice(b" TARGET trailing");
    let files = [
        FileSpec::stored("notes.txt", b"x TARGET y"),
        FileSpec::stored("blob.dat", &jpg),
    ];
    let zip = build_zip(&files, false);

    let skip_media = EntryFilter::new(&[], &[], &[], true);
    let findings =
        search_archive(&zip, &Regex::new("TARGET").unwrap(), false, &skip_media).unwrap();
    assert_eq!(findings.files.len(), 1);
    assert_eq!(findings.records[0].path, "notes.txt");
}

#[test]
fn match_path_lists_files_whose_path_matches() {
    let files = [
        FileSpec::stored("app/banking/creds.db", b"no hit in content"),
        FileSpec::stored("app/photos/img.jpg", b"banking is only in this content"),
        FileSpec::stored("notes.txt", b"banking"),
    ];
    let zip = build_zip(&files, false);
    let re = Regex::new("banking").unwrap();

    let findings =
        search_with_progress(&zip, &re, false, true, &EntryFilter::all(), &NoProgress).unwrap();

    // Only the file with "banking" in its PATH is reported (content ignored).
    assert_eq!(findings.records.len(), 1);
    assert_eq!(findings.records[0].path, "app/banking/creds.db");
    // The displayed line is the path itself, with the matched span recorded.
    assert_eq!(findings.records[0].line, b"app/banking/creds.db");
    let r = &findings.records[0].match_in_line;
    assert_eq!(&findings.records[0].line[r.start..r.end], b"banking");
    // The matched file is available for export.
    assert_eq!(findings.files.len(), 1);
}

#[derive(Default)]
struct CountProgress {
    total: AtomicUsize,
    done: AtomicUsize,
}

impl Progress for CountProgress {
    fn set_total(&self, total: usize) {
        self.total.store(total, Ordering::Relaxed);
    }
    fn inc(&self) {
        self.done.fetch_add(1, Ordering::Relaxed);
    }
}

#[test]
fn progress_counts_every_searched_entry() {
    let files = [
        FileSpec::stored("a.txt", b"x TARGET"),
        FileSpec::stored("b.txt", b"no hit here"), // searched but no match
        FileSpec::stored("c.db", b"x TARGET"),
    ];
    let zip = build_zip(&files, false);
    let re = Regex::new("TARGET").unwrap();

    // No filter: total and inc count all three entries (matching or not).
    let all = CountProgress::default();
    search_with_progress(&zip, &re, false, false, &no_filter(), &all).unwrap();
    assert_eq!(all.total.load(Ordering::Relaxed), 3);
    assert_eq!(all.done.load(Ordering::Relaxed), 3);

    // With a filter, the total reflects only the entries actually searched.
    let filtered = CountProgress::default();
    let only_db = EntryFilter::new(&["*.db".to_string()], &[], &[], false);
    search_with_progress(&zip, &re, false, false, &only_db, &filtered).unwrap();
    assert_eq!(filtered.total.load(Ordering::Relaxed), 1);
    assert_eq!(filtered.done.load(Ordering::Relaxed), 1);
}
