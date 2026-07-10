//! Shared test-only helpers for the library's own unit tests.
//!
//! Defines: [`stored_zip`], a byte-by-byte builder for a STORED (uncompressed) ZIP
//! archive from `(name, bytes)` pairs — the single canonical builder the in-crate
//! unit tests use, so a second copy cannot drift.
//! Used by: the `ops::search` and `core::source::nested` unit tests.
//!
//! WHY separate from `tests/common::build_zip`: that richer builder (DEFLATE/ZIP64)
//! lives in a different crate (the integration-test binaries) and cannot see this
//! `pub(crate)` module, so the two intentionally stay apart. STORED-only keeps this
//! one tiny — the parser reads the local header, central directory and EOCD the
//! same way regardless of method, so STORED exercises the path the unit tests care
//! about.

/// Build a minimal STORED-only ZIP archive in memory from `(name, bytes)` pairs.
pub(crate) fn stored_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    fn pu16(buf: &mut Vec<u8>, v: u16) {
        buf.extend_from_slice(&v.to_le_bytes());
    }
    fn pu32(buf: &mut Vec<u8>, v: u32) {
        buf.extend_from_slice(&v.to_le_bytes());
    }

    let mut buf = Vec::new();
    let mut offsets = Vec::new();
    // Local file headers + data.
    for (name, data) in entries {
        offsets.push(buf.len() as u32);
        pu32(&mut buf, 0x0403_4b50); // local file header signature
        pu16(&mut buf, 20); // version needed
        pu16(&mut buf, 0); // flags
        pu16(&mut buf, 0); // method 0 = STORED
        pu16(&mut buf, 0); // mod time
        pu16(&mut buf, 0); // mod date
        pu32(&mut buf, 0); // crc32 (parser ignores it)
        pu32(&mut buf, data.len() as u32); // compressed size
        pu32(&mut buf, data.len() as u32); // uncompressed size
        pu16(&mut buf, name.len() as u16);
        pu16(&mut buf, 0); // extra length
        buf.extend_from_slice(name.as_bytes());
        buf.extend_from_slice(data);
    }
    // Central directory.
    let cd_start = buf.len() as u32;
    for (i, (name, data)) in entries.iter().enumerate() {
        pu32(&mut buf, 0x0201_4b50); // central directory header signature
        pu16(&mut buf, 20); // version made by
        pu16(&mut buf, 20); // version needed
        pu16(&mut buf, 0); // flags
        pu16(&mut buf, 0); // method 0 = STORED
        pu16(&mut buf, 0); // mod time
        pu16(&mut buf, 0); // mod date
        pu32(&mut buf, 0); // crc32
        pu32(&mut buf, data.len() as u32); // compressed size
        pu32(&mut buf, data.len() as u32); // uncompressed size
        pu16(&mut buf, name.len() as u16);
        pu16(&mut buf, 0); // extra length
        pu16(&mut buf, 0); // comment length
        pu16(&mut buf, 0); // disk number start
        pu16(&mut buf, 0); // internal attributes
        pu32(&mut buf, 0); // external attributes
        pu32(&mut buf, offsets[i]); // local header offset
        buf.extend_from_slice(name.as_bytes());
    }
    let cd_size = buf.len() as u32 - cd_start;
    // End of central directory.
    pu32(&mut buf, 0x0605_4b50); // EOCD signature
    pu16(&mut buf, 0); // disk number
    pu16(&mut buf, 0); // disk with CD
    pu16(&mut buf, entries.len() as u16); // entries on this disk
    pu16(&mut buf, entries.len() as u16); // total entries
    pu32(&mut buf, cd_size);
    pu32(&mut buf, cd_start);
    pu16(&mut buf, 0); // comment length
    buf
}
