//! Tests for the positioned-read [`RangedZipSource`] (the network-drive path).
//!
//! The ranged source reads an on-disk archive with `pread` instead of a memory
//! map. These tests write a fabricated archive to a temp file and assert the
//! ranged source produces exactly the same entries and bytes as the mmap
//! [`ZipSource`] — including the ZIP64 path that a >4 GB FFS needs — plus the
//! header-prefix read and the CRC-32 integrity check.

mod common;

use std::io::Write;

use common::{FileSpec, build_zip};
use mf_scan::source::ranged::RangedZipSource;
use mf_scan::source::zip::ZipSource;
use mf_scan::source::{IntegrityCheck, Source};

/// Write archive bytes to a temp file and open a ranged source over it.
fn ranged(bytes: &[u8]) -> (tempfile::NamedTempFile, RangedZipSource) {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(bytes).unwrap();
    f.flush().unwrap();
    let src = RangedZipSource::open(f.path()).unwrap();
    (f, src)
}

/// The (name, content) pairs a source exposes, sorted by name.
fn dump(src: &dyn Source) -> Vec<(String, Vec<u8>)> {
    let mut out: Vec<(String, Vec<u8>)> = src
        .entries()
        .iter()
        .map(|e| (e.name.clone(), src.content(e).unwrap().to_vec()))
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

#[test]
fn ranged_matches_mmap_stored_and_deflate() {
    // A STORED entry and a DEFLATE entry (deflate stream of "DEFLATED token").
    let raw = b"DEFLATED token=ABC123 here";
    let compressed = deflate(raw);
    let files = [
        FileSpec::stored("dir/a.txt", b"stored token=ABC123 body"),
        FileSpec::deflate("dir/b.txt", &compressed, raw.len() as u32),
    ];
    let bytes = build_zip(&files, false);

    let mmap = ZipSource::open(&bytes).unwrap();
    let (_tmp, rng) = ranged(&bytes);

    // Same entries and same decompressed/stored bytes via both access paths.
    assert_eq!(dump(&rng), dump(&mmap));
    // The DEFLATE entry really round-trips to the original.
    let b = rng
        .entries()
        .iter()
        .find(|e| e.name == "dir/b.txt")
        .unwrap();
    assert_eq!(&*rng.content(b).unwrap(), raw);
}

#[test]
fn ranged_matches_mmap_zip64() {
    // The same archive in ZIP64 form (saturated offsets + ZIP64 EOCD records) —
    // the layout a >4 GB FFS uses, which the ranged source must parse from the tail.
    let files = [
        FileSpec::stored("x/one.bin", b"one token=ABC123"),
        FileSpec::stored("x/two.bin", b"two token=ABC123 two"),
    ];
    let bytes = build_zip(&files, true);

    let mmap = ZipSource::open(&bytes).unwrap();
    let (_tmp, rng) = ranged(&bytes);
    assert_eq!(dump(&rng), dump(&mmap));
}

#[test]
fn ranged_content_prefix_reads_only_the_header() {
    let files = [FileSpec::stored(
        "big.bin",
        b"HEADERMAGIC and then a long tail of bytes",
    )];
    let bytes = build_zip(&files, false);
    let (_tmp, rng) = ranged(&bytes);

    let e = &rng.entries()[0];
    let prefix = rng.content_prefix(e, 6).unwrap();
    assert_eq!(&*prefix, b"HEADER"); // exactly `max` bytes, not the whole file
    assert!(rng.prefers_prefix_classification());
}

#[test]
fn ranged_integrity_check_verifies_and_detects_corruption() {
    let files = [FileSpec::stored("c.txt", b"crc me please")];
    let bytes = build_zip(&files, false);

    // Intact: the CD CRC-32 matches the bytes on disk.
    let (_tmp, rng) = ranged(&bytes);
    assert!(matches!(
        rng.integrity_check(&rng.entries()[0]),
        IntegrityCheck::Verified { algorithm: "crc32" }
    ));

    // Corrupt one payload byte: the recomputed CRC must diverge.
    let mut corrupt = bytes.clone();
    let at = corrupt
        .windows(13)
        .position(|w| w == b"crc me please")
        .unwrap();
    corrupt[at + 1] ^= 0xFF;
    let (_tmp2, rng2) = ranged(&corrupt);
    assert!(matches!(
        rng2.integrity_check(&rng2.entries()[0]),
        IntegrityCheck::Mismatch {
            algorithm: "crc32",
            ..
        }
    ));
}

/// Raw-DEFLATE compress `data` (ZIP method 8 carries no zlib header).
fn deflate(data: &[u8]) -> Vec<u8> {
    use flate2::Compression;
    use flate2::write::DeflateEncoder;
    let mut e = DeflateEncoder::new(Vec::new(), Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}
