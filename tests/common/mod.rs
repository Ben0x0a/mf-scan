//! Test fixtures: build in-memory ZIP archives byte-by-byte.
//!
//! Defines: `FileSpec` plus `build_zip`, which assembles a complete ZIP archive
//! (local headers, central directory, EOCD, optionally ZIP64 records) in a
//! `Vec<u8>`.
//! Used by: the integration tests under `tests/`.
//! Uses: only the standard library.
//!
//! Why hand-build instead of shelling out to the `zip` tool: it keeps tests
//! deterministic and dependency-free, and lets us fabricate exact ZIP64 and
//! DEFLATE layouts that would otherwise be awkward to produce on demand.

// This module is included via `mod common;` into each integration-test binary
// separately, so a helper used by only one binary looks "dead" to the others.
// The dead-code warning here is therefore a false positive of per-binary
// compilation, not genuinely unused code.
#![allow(dead_code)]

pub const METHOD_STORED: u16 = 0;
pub const METHOD_DEFLATE: u16 = 8;

/// The CRC-32 a fabricated entry should record in its headers.
///
/// For a STORED entry the on-disk bytes ARE the uncompressed data, so we record
/// their real CRC-32 (matching what a real producer writes) — this exercises the
/// `ZipSource` integrity attestation. For a DEFLATE entry the builder only holds
/// the already-compressed stream, not the original, so it records 0 ("not
/// recorded"), which the parser/integrity check treats as un-attestable.
fn entry_crc32(f: &FileSpec) -> u32 {
    if f.method == METHOD_STORED {
        crc32fast::hash(f.data)
    } else {
        0
    }
}

/// One file to place into a fabricated archive.
pub struct FileSpec<'a> {
    pub name: &'a str,
    /// Bytes exactly as stored on disk (already-compressed for DEFLATE).
    pub data: &'a [u8],
    pub method: u16,
    /// Logical uncompressed size; equals `data.len()` for STORED entries.
    pub uncompressed_size: u32,
}

impl<'a> FileSpec<'a> {
    /// A STORED (uncompressed) entry: on-disk bytes are the content itself.
    pub fn stored(name: &'a str, data: &'a [u8]) -> Self {
        Self {
            name,
            data,
            method: METHOD_STORED,
            uncompressed_size: data.len() as u32,
        }
    }

    /// A DEFLATE entry: `compressed` is the on-disk stream, `uncompressed_size`
    /// the original length.
    pub fn deflate(name: &'a str, compressed: &'a [u8], uncompressed_size: u32) -> Self {
        Self {
            name,
            data: compressed,
            method: METHOD_DEFLATE,
            uncompressed_size,
        }
    }
}

fn push_u16(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_le_bytes());
}
fn push_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}
fn push_u64(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_le_bytes());
}

/// Build a complete ZIP archive in memory.
///
/// When `zip64` is set, the central directory stores each entry's local-header
/// offset as the 0xFFFFFFFF sentinel with the real value in a ZIP64 extra
/// field, and the EOCD points to a ZIP64 EOCD record + locator — exercising the
/// parser's ZIP64 path even for tiny archives.
pub fn build_zip(files: &[FileSpec], zip64: bool) -> Vec<u8> {
    const SENTINEL32: u32 = 0xFFFF_FFFF;
    let mut buf = Vec::new();
    let mut local_offsets = Vec::new();

    // --- Local file headers + data ---
    for f in files {
        local_offsets.push(buf.len() as u64);
        push_u32(&mut buf, 0x0403_4b50); // local file header signature
        push_u16(&mut buf, 20); // version needed
        push_u16(&mut buf, 0); // flags
        push_u16(&mut buf, f.method);
        push_u16(&mut buf, 0); // mod time
        push_u16(&mut buf, 0); // mod date
        push_u32(&mut buf, entry_crc32(f)); // crc32 of the uncompressed data
        push_u32(&mut buf, f.data.len() as u32); // compressed size
        push_u32(&mut buf, f.uncompressed_size); // uncompressed size
        push_u16(&mut buf, f.name.len() as u16);
        push_u16(&mut buf, 0); // extra length
        buf.extend_from_slice(f.name.as_bytes());
        buf.extend_from_slice(f.data);
    }

    // --- Central directory ---
    let cd_start = buf.len() as u64;
    for (i, f) in files.iter().enumerate() {
        push_u32(&mut buf, 0x0201_4b50); // central directory header signature
        push_u16(&mut buf, 20); // version made by
        push_u16(&mut buf, 20); // version needed
        push_u16(&mut buf, 0); // flags
        push_u16(&mut buf, f.method);
        push_u16(&mut buf, 0); // mod time
        push_u16(&mut buf, 0); // mod date
        push_u32(&mut buf, entry_crc32(f)); // crc32 of the uncompressed data
        push_u32(&mut buf, f.data.len() as u32); // compressed size
        push_u32(&mut buf, f.uncompressed_size); // uncompressed size
        push_u16(&mut buf, f.name.len() as u16);
        push_u16(&mut buf, if zip64 { 12 } else { 0 }); // extra length
        push_u16(&mut buf, 0); // comment length
        push_u16(&mut buf, 0); // disk number start
        push_u16(&mut buf, 0); // internal attributes
        push_u32(&mut buf, 0); // external attributes
        if zip64 {
            push_u32(&mut buf, SENTINEL32); // local offset -> see ZIP64 extra
        } else {
            push_u32(&mut buf, local_offsets[i] as u32);
        }
        buf.extend_from_slice(f.name.as_bytes());
        if zip64 {
            // ZIP64 extended-information extra field carrying only the offset.
            push_u16(&mut buf, 0x0001); // header id
            push_u16(&mut buf, 8); // data size
            push_u64(&mut buf, local_offsets[i]);
        }
    }
    let cd_size = buf.len() as u64 - cd_start;

    // --- ZIP64 EOCD record + locator (only when requested) ---
    if zip64 {
        let z64_off = buf.len() as u64;
        push_u32(&mut buf, 0x0606_4b50); // ZIP64 EOCD record signature
        push_u64(&mut buf, 44); // size of remaining record
        push_u16(&mut buf, 20); // version made by
        push_u16(&mut buf, 20); // version needed
        push_u32(&mut buf, 0); // disk number
        push_u32(&mut buf, 0); // disk with central directory
        push_u64(&mut buf, files.len() as u64); // entries on this disk
        push_u64(&mut buf, files.len() as u64); // total entries
        push_u64(&mut buf, cd_size);
        push_u64(&mut buf, cd_start);

        push_u32(&mut buf, 0x0706_4b50); // ZIP64 EOCD locator signature
        push_u32(&mut buf, 0); // disk with ZIP64 EOCD
        push_u64(&mut buf, z64_off);
        push_u32(&mut buf, 1); // total number of disks
    }

    // --- End of central directory ---
    push_u32(&mut buf, 0x0605_4b50); // EOCD signature
    push_u16(&mut buf, 0); // disk number
    push_u16(&mut buf, 0); // disk with central directory
    push_u16(&mut buf, files.len() as u16); // entries on this disk
    push_u16(&mut buf, files.len() as u16); // total entries
    push_u32(&mut buf, cd_size as u32);
    if zip64 {
        push_u32(&mut buf, SENTINEL32); // central directory offset -> ZIP64
    } else {
        push_u32(&mut buf, cd_start as u32);
    }
    push_u16(&mut buf, 0); // comment length

    buf
}
