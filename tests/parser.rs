//! Integration tests for the ZIP central-directory parser.
//!
//! Defines: tests covering entry enumeration, exact data-offset resolution,
//! ZIP64 offset recovery, method detection (STORED/DEFLATE), skipping of
//! unsupported methods, and truncation errors.
//! Uses: `common` (fixture builder) and `mf_scan::{source, models}`.

mod common;

use common::{FileSpec, build_zip};
use mf_scan::models::{Entry, Location, Method};
use mf_scan::source::zip::parse_entries;

/// The bytes the parser points at must be exactly the file's stored data.
fn entry_bytes<'a>(archive: &'a [u8], e: &Entry) -> &'a [u8] {
    let Location::Zip {
        data_offset,
        data_len,
        ..
    } = &e.location
    else {
        panic!("expected a ZIP entry");
    };
    &archive[*data_offset as usize..(*data_offset + *data_len) as usize]
}

/// The compression method of a (ZIP) entry.
fn method(e: &Entry) -> Method {
    let Location::Zip { method, .. } = &e.location else {
        panic!("expected a ZIP entry");
    };
    *method
}

#[test]
fn enumerates_all_stored_entries() {
    let files = [
        FileSpec::stored("a.txt", b"hello"),
        FileSpec::stored("sub/b.log", b"world!!"),
    ];
    let zip = build_zip(&files, false);

    let entries = parse_entries(&zip).unwrap();

    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].name, "a.txt");
    assert_eq!(entries[1].name, "sub/b.log");
}

#[test]
fn resolves_data_offset_and_method() {
    let files = [
        FileSpec::stored("a.txt", b"hello"),
        FileSpec::deflate("z.bin", b"\x01\x02\x03", 9),
    ];
    let zip = build_zip(&files, false);

    let entries = parse_entries(&zip).unwrap();

    assert_eq!(method(&entries[0]), Method::Stored);
    assert_eq!(entry_bytes(&zip, &entries[0]), b"hello");
    assert_eq!(method(&entries[1]), Method::Deflate);
    assert_eq!(entries[1].uncompressed_size, 9);
    assert_eq!(entry_bytes(&zip, &entries[1]), b"\x01\x02\x03");
}

#[test]
fn skips_unsupported_methods() {
    let files = [
        FileSpec::stored("keep.txt", b"keep me"),
        // Method 99 (e.g. AES/other) is neither STORED nor DEFLATE -> skipped.
        FileSpec {
            name: "drop.bin",
            data: b"\x00\x00",
            method: 99,
            uncompressed_size: 2,
        },
    ];
    let zip = build_zip(&files, false);

    let entries = parse_entries(&zip).unwrap();

    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "keep.txt");
}

#[test]
fn recovers_zip64_local_offset() {
    let files = [FileSpec::stored("big.bin", b"ZIP64 payload")];
    let zip = build_zip(&files, true);

    let entries = parse_entries(&zip).unwrap();

    assert_eq!(entries.len(), 1);
    assert_eq!(entry_bytes(&zip, &entries[0]), b"ZIP64 payload");
}

#[test]
fn errors_on_truncated_archive() {
    let files = [FileSpec::stored("a.txt", b"hello")];
    let zip = build_zip(&files, false);
    // Drop the EOCD so the archive can no longer be located.
    let truncated = &zip[..zip.len() - 10];

    assert!(parse_entries(truncated).is_err());
}

/// Crafted-input DoS guards (review finding S1): the Central Directory's
/// declared uncompressed size is untrusted. A huge claimed size must produce a
/// clean error (capped allocation hint, size mismatch) — not an allocation
/// abort — and an entry inflating to MORE than its claim must error rather
/// than balloon without bound (zip-bomb ceiling).
#[test]
fn deflate_entry_lying_about_its_size_errors_cleanly() {
    use std::io::Write;

    use flate2::{Compression, write::DeflateEncoder};
    use mf_scan::source::zip::content;

    let plain = b"tiny but honest content";
    let mut enc = DeflateEncoder::new(Vec::new(), Compression::default());
    enc.write_all(plain).unwrap();
    let compressed = enc.finish().unwrap();

    // Claims ~4 GiB but inflates to 23 bytes: must error, not abort or accept.
    // (u32::MAX itself is the ZIP64 saturation sentinel, so stay just under it.)
    let oversize = build_zip(
        &[FileSpec::deflate("liar.bin", &compressed, u32::MAX - 1)],
        false,
    );
    let entries = parse_entries(&oversize).unwrap();
    assert!(content(&oversize, &entries[0]).is_err());

    // Claims 4 bytes but inflates past it: the ceiling must stop and reject it.
    let bomb = build_zip(&[FileSpec::deflate("bomb.bin", &compressed, 4)], false);
    let entries = parse_entries(&bomb).unwrap();
    assert!(content(&bomb, &entries[0]).is_err());

    // The honest declaration still round-trips.
    let honest = build_zip(
        &[FileSpec::deflate("ok.bin", &compressed, plain.len() as u32)],
        false,
    );
    let entries = parse_entries(&honest).unwrap();
    assert_eq!(&*content(&honest, &entries[0]).unwrap(), plain);
}
