//! Identify-only archive and compression formats.
//!
//! Defines: [`Zip`], [`Gzip`], [`Bzip2`], [`Xz`], [`Zstd`], [`SevenZip`], [`Tar`],
//! [`Lz4`], [`Lzfse`], [`Aea`].
//! Used by: `identify` (re-export) → `inspect::mod` registry.
//! Uses: `identify::has_at`, the `classify_inspector!` macro, and
//! `core::source::compressed::Compression` (the one table of compression magics).

use super::has_at;
use crate::core::source::compressed::Compression;

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

// gzip, bzip2, xz and Zstandard: by the magics the compressed-tar reader uses (see
// `Compression::of`), so a file named one is a file that reader can decode. xz was
// not found in the test file systems.
classify_inspector!(Gzip, "gzip", "archive", [], |c: &[u8]| Compression::of(c)
    == Some(Compression::Gzip));
classify_inspector!(Bzip2, "bzip2", "archive", [], |c: &[u8]| Compression::of(c)
    == Some(Compression::Bzip2));
classify_inspector!(Xz, "xz", "archive", [], |c: &[u8]| Compression::of(c)
    == Some(Compression::Xz));
classify_inspector!(Zstd, "zstd", "archive", [], |c: &[u8]| Compression::of(c)
    == Some(Compression::Zstd));

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
