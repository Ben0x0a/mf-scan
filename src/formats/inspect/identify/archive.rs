//! Identify-only archive and compression formats.
//!
//! Defines: [`Zip`], [`Gzip`], [`Bzip2`], [`Xz`], [`Zstd`], [`SevenZip`], [`Tar`],
//! [`Lz4`], [`Lzfse`], [`Aea`].
//! Used by: `identify` (re-export) → `inspect::mod` registry.
//! Uses: `identify::has_at`, the `classify_inspector!` macro.

use super::has_at;

// ZIP (also APK, JAR, IPA, DOCX, …): a local file header, or the end record of an
// empty archive.
classify_inspector!(Zip, "zip", "archive", [], |c: &[u8]| has_at(
    c,
    0,
    b"PK\x03\x04"
) || has_at(
    c,
    0,
    b"PK\x05\x06"
));

// gzip (RFC 1952): ID1 ID2, then compression method 8 (deflate, the only one defined).
classify_inspector!(Gzip, "gzip", "archive", [], |c: &[u8]| has_at(
    c,
    0,
    &[0x1F, 0x8B, 0x08]
));

// bzip2: "BZh", the block size digit, then a block's magic (pi) or the empty
// stream's end magic (sqrt(pi)).
classify_inspector!(Bzip2, "bzip2", "archive", [], |c: &[u8]| has_at(
    c, 0, b"BZh"
) && c
    .get(3)
    .is_some_and(|d| (b'1'..=b'9').contains(d))
    && (has_at(c, 4, &[0x31, 0x41, 0x59, 0x26, 0x53, 0x59])
        || has_at(c, 4, &[0x17, 0x72, 0x45, 0x38, 0x50, 0x90])));

// xz: the 6-byte stream header magic. Not found in the test file systems.
classify_inspector!(Xz, "xz", "archive", [], |c: &[u8]| has_at(
    c,
    0,
    &[0xFD, b'7', b'z', b'X', b'Z', 0x00]
));

// Zstandard: the frame magic 0xFD2FB528.
classify_inspector!(Zstd, "zstd", "archive", [], |c: &[u8]| has_at(
    c,
    0,
    &[0x28, 0xB5, 0x2F, 0xFD]
));

// 7-Zip: the 6-byte signature header. Not found in the test file systems.
classify_inspector!(SevenZip, "7z", "archive", [], |c: &[u8]| has_at(
    c,
    0,
    &[b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C]
));

// tar (POSIX ustar, and GNU tar's "ustar  "): the magic in the first header block.
classify_inspector!(Tar, "tar", "archive", [], |c: &[u8]| has_at(
    c, 257, b"ustar"
));

// LZ4 frame format: the frame magic 0x184D2204. Not found in the test file systems.
classify_inspector!(Lz4, "lz4", "archive", [], |c: &[u8]| has_at(
    c,
    0,
    &[0x04, 0x22, 0x4D, 0x18]
));

// Apple LZFSE: a block header magic "bvx1", "bvx2", "bvxn" (LZVN) or "bvx-"
// (uncompressed).
classify_inspector!(Lzfse, "lzfse", "archive", [], |c: &[u8]| has_at(
    c, 0, b"bvx"
) && matches!(
    c.get(3),
    Some(b'1' | b'2' | b'n' | b'-')
));

// Apple Encrypted Archive: the "AEA1" magic.
classify_inspector!(Aea, "aea", "archive", [], |c: &[u8]| has_at(c, 0, b"AEA1"));
