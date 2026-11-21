//! ZIP archive source: central-directory parser + the [`ZipSource`] container.
//!
//! Defines: `parse_entries`, which reads a ZIP archive's Central Directory and
//! resolves every file's byte range, compression method and encryption; `content`,
//! which borrows a STORED entry's bytes from the archive or inflates a DEFLATE one,
//! decrypting it first when it is encrypted; [`ZipSource`], the
//! [`crate::core::source::Source`] over a memory-mapped archive; and
//! [`not_searched_notes`], what an archive holds that cannot be searched.
//! Used by: `source` (the open helpers), `ranged` and `folder`/`nested` (the shared
//! directory walk and `decode`), `engine` (search over a `Source`) and
//! `report::export` (re-reads matched files' bytes).
//! Uses: `crate::core::models::{Encryption, Entry, Location, Method}`, `zip_crypto`
//! (ZipCrypto and WinZip AES), `flate2` (inflate), `anyhow`.
//!
//! Every entry the Central Directory lists is kept. One whose method is not read
//! (bzip2, LZMA, …) or whose encryption cannot be opened fails when it is read, so
//! the engine counts it as not searched and the run says so; it is never left out.
//! All integer decoding is done by hand so the parsing flow stays explicit.
//!
//! Why CD-first instead of a blind linear scan: the Central Directory is the
//! authoritative record of every entry (local headers may carry zeroed sizes
//! when a data descriptor is used). Parsing it first gives exact data ranges,
//! lets us skip header bytes, and tells us each entry's method.

use std::io::Read;

use anyhow::{Context, Result, bail, ensure};
use flate2::read::DeflateDecoder;
use rayon::prelude::*;

use crate::core::models::{Encryption, Entry, Location, Method};
use crate::core::source::zip_crypto::{self, ZipPassword};
use crate::core::source::{Content, IntegrityCheck, Source};
use crate::core::util::unix_from_civil;

// --- ZIP record signatures (little-endian on disk) ---------------------------
// These are fixed by the ZIP specification (APPNOTE.TXT), not operator-tunable,
// so they live here as format constants rather than in any config.
pub(crate) const SIG_EOCD: u32 = 0x0605_4b50; // End Of Central Directory
const SIG_ZIP64_EOCD_LOCATOR: u32 = 0x0706_4b50; // ZIP64 EOCD locator
const SIG_ZIP64_EOCD: u32 = 0x0606_4b50; // ZIP64 EOCD record
pub(crate) const SIG_CDFH: u32 = 0x0201_4b50; // Central Directory File Header
pub(crate) const SIG_LFH: u32 = 0x0403_4b50; // Local File Header

const METHOD_STORED: u16 = 0; // compression method 0 = no compression
const METHOD_DEFLATE: u16 = 8; // compression method 8 = DEFLATE
const ZIP64_EXTRA_ID: u16 = 0x0001; // header id of the ZIP64 extended-info field
const TIMESTAMP_EXTRA_ID: u16 = 0x5455; // Info-ZIP extended timestamp (exact UTC seconds)
const METHOD_AES: u16 = 99; // WinZip AES: the real method is in the AES extra field
const AES_EXTRA_ID: u16 = 0x9901; // WinZip AES extra field (AE-1 / AE-2)
const FLAG_ENCRYPTED: u16 = 1 << 0; // general-purpose flag: the data is encrypted
const FLAG_DESCRIPTOR: u16 = 1 << 3; // sizes and CRC follow the data (data descriptor)
const FLAG_STRONG: u16 = 1 << 6; // PKWARE strong encryption

/// One decoded Central Directory record, *before* its on-disk data offset is
/// resolved from the Local File Header.
///
/// This is the shared product of the central-directory walk: a memory-mapped
/// [`ZipSource`] turns each into an [`Entry`] by resolving `local_offset` through
/// [`local_data_offset`], while the positioned-read [`super::ranged::RangedZipSource`]
/// keeps `local_offset` and resolves it lazily, per file, at read time — so the
/// directory walk itself is identical for both and lives only here.
pub(crate) struct CdEntry {
    pub(crate) name: String,
    pub(crate) method: Method,
    pub(crate) encryption: Encryption,
    /// Compressed (on-disk) data length.
    pub(crate) comp_size: u64,
    /// Uncompressed (logical) data length.
    pub(crate) uncomp_size: u64,
    pub(crate) mtime: Option<u64>,
    /// CRC-32 of the uncompressed data, as recorded by the producer.
    pub(crate) crc32: u32,
    /// Absolute offset of the entry's Local File Header in the archive.
    pub(crate) local_offset: u64,
}

/// Parse the archive and return every entry its Central Directory lists.
pub fn parse_entries(data: &[u8]) -> Result<Vec<Entry>> {
    Ok(parse_entries_with_crc(data)?
        .into_iter()
        .map(|(entry, _crc)| entry)
        .collect())
}

/// Like [`parse_entries`], but also returns each entry's Central-Directory
/// CRC-32 (over the uncompressed data), parallel to the entries. The
/// [`ZipSource`] keeps these so it can attest an entry's bytes on export; plain
/// search callers use [`parse_entries`] and ignore them.
///
/// HOW:
///   1. locate the central directory via the EOCD (and ZIP64 records),
///   2. walk it into `CdEntry` records (`parse_cd_headers`),
///   3. resolve each entry's real data offset from its Local File Header.
pub fn parse_entries_with_crc(data: &[u8]) -> Result<Vec<(Entry, u32)>> {
    let loc = find_cd_location(data, 0)?;
    let cd = slice(data, loc.cd_offset as usize, loc.cd_size as usize)
        .context("central directory range is out of bounds")?;
    let records = parse_cd_headers(cd, loc.total_entries)?;

    // Resolve each entry's real data offset from its Local File Header. WHY in
    // parallel: the LFHs are scattered across the whole archive (each sits just
    // before its file's data), so on a multi-hundred-thousand-entry FFS this is
    // hundreds of thousands of random reads spanning the map — cold, the dominant
    // cost of merely *opening* the archive. The reads are independent and `data`
    // is read-only, so spreading them across the rayon pool lets the OS service
    // the faults concurrently. Order is preserved (`collect` keeps input order),
    // so the entries stay deterministic. The offset stays resolved here (not
    // deferred), so every downstream forensic field — the exact archive offset of
    // a STORED match, the export manifest's `file_start`, `--match-path` — is
    // unchanged from the sequential version.
    records
        .into_par_iter()
        .map(|ce| {
            let data_offset = local_data_offset(data, ce.local_offset)?;
            Ok((
                Entry {
                    name: ce.name,
                    uncompressed_size: ce.uncomp_size,
                    mtime: ce.mtime,
                    location: Location::Zip {
                        method: ce.method,
                        encryption: ce.encryption,
                        data_offset,
                        data_len: ce.comp_size,
                    },
                },
                ce.crc32,
            ))
        })
        .collect()
}

/// Where the central directory lives, resolved from the EOCD (upgraded by the
/// ZIP64 records when the 32-bit fields are saturated).
pub(crate) struct CdLocation {
    pub(crate) cd_offset: u64,
    pub(crate) cd_size: u64,
    pub(crate) total_entries: u64,
}

/// Locate the central directory within `buf`, whose first byte is at absolute
/// file offset `base`.
///
/// `base` is `0` when `buf` is the whole archive (the mmap source) and the
/// archive size minus the tail length when `buf` is only the tail read by the
/// positioned-read source — so the absolute offsets the records carry can be
/// translated back into the buffer. The EOCD (and any ZIP64 EOCD record) sit at
/// the very end, so a tail that reaches them is enough.
pub(crate) fn find_cd_location(buf: &[u8], base: u64) -> Result<CdLocation> {
    let eocd = find_eocd(buf, base).context("could not locate End Of Central Directory record")?;

    let mut cd_offset = read_u32(buf, eocd + 16)? as u64;
    let mut cd_size = read_u32(buf, eocd + 12)? as u64;
    let mut total_entries = read_u16(buf, eocd + 10)? as u64;

    // A saturated (all-ones) field means the real value lives in the ZIP64
    // records; reading the 32-bit field as truth would point us at the wrong
    // offset and corrupt the whole parse, so we must redirect.
    if cd_offset == u32::MAX as u64
        || cd_size == u32::MAX as u64
        || total_entries == u16::MAX as u64
    {
        let z = read_zip64_eocd(buf, base, eocd)?;
        cd_offset = z.cd_offset;
        cd_size = z.cd_size;
        total_entries = z.total_entries;
    }

    Ok(CdLocation {
        cd_offset,
        cd_size,
        total_entries,
    })
}

/// Walk `total_entries` Central Directory File Headers from the start of `cd`.
///
/// `cd` is the central-directory byte range only (its first byte is the first
/// `CDFH` signature), so positions here are relative to it; the `local_offset`
/// each record carries stays absolute (it indexes the whole archive).
pub(crate) fn parse_cd_headers(cd: &[u8], total_entries: u64) -> Result<Vec<CdEntry>> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    for _ in 0..total_entries {
        let (record, next) = decode_cd_header(cd, pos)?;
        out.push(record);
        pos = next;
    }
    Ok(out)
}

/// Resolved ZIP64 central-directory location.
struct Zip64Eocd {
    cd_offset: u64,
    cd_size: u64,
    total_entries: u64,
}

/// Read the ZIP64 EOCD via the locator that sits 20 bytes before the EOCD.
///
/// HOW: the 20-byte locator immediately precedes the EOCD and stores the
/// *absolute* offset of the ZIP64 EOCD record, which holds the real 64-bit
/// central-directory size/offset and entry count. `base` translates that
/// absolute offset into an index within `buf` (see [`find_cd_location`]).
fn read_zip64_eocd(buf: &[u8], base: u64, eocd: usize) -> Result<Zip64Eocd> {
    // If the EOCD claimed ZIP64 but no locator fits before it, the archive is
    // malformed and any offset we compute would be garbage — fail loudly.
    let locator = eocd
        .checked_sub(20)
        .context("file too small for a ZIP64 EOCD locator")?;
    ensure!(
        read_u32(buf, locator)? == SIG_ZIP64_EOCD_LOCATOR,
        "expected ZIP64 EOCD locator signature before EOCD"
    );

    let z64_abs = read_u64(buf, locator + 8)?; // absolute offset of the ZIP64 EOCD record
    let z64 = z64_abs
        .checked_sub(base)
        .context("ZIP64 EOCD record lies before the read window")? as usize;
    ensure!(
        read_u32(buf, z64)? == SIG_ZIP64_EOCD,
        "expected ZIP64 EOCD record signature"
    );

    Ok(Zip64Eocd {
        total_entries: read_u64(buf, z64 + 32)?,
        cd_size: read_u64(buf, z64 + 40)?,
        cd_offset: read_u64(buf, z64 + 48)?,
    })
}

/// Decode one Central Directory File Header at `pos` within the CD buffer.
///
/// Returns the decoded record plus the offset of the next header. Does NOT resolve
/// the data offset — that needs the Local File Header, which the two sources reach
/// differently.
fn decode_cd_header(cd: &[u8], pos: usize) -> Result<(CdEntry, usize)> {
    // A wrong signature here means we have lost sync with the directory; every
    // subsequent field would be misread, so stop rather than emit junk.
    ensure!(
        read_u32(cd, pos)? == SIG_CDFH,
        "bad central-directory header signature at offset {pos}"
    );

    let flags = read_u16(cd, pos + 8)?;
    let method_code = read_u16(cd, pos + 10)?;
    // Last-modified DOS time/date (2 bytes each), decoded for `diff`'s mtime compare.
    let dos_time = read_u16(cd, pos + 12)?;
    let dos_date = read_u16(cd, pos + 14)?;
    // CRC-32 of the uncompressed data, as recorded by the producer.
    let crc32 = read_u32(cd, pos + 16)?;
    let mut comp_size = read_u32(cd, pos + 20)? as u64;
    let mut uncomp_size = read_u32(cd, pos + 24)? as u64;
    let name_len = read_u16(cd, pos + 28)? as usize;
    let extra_len = read_u16(cd, pos + 30)? as usize;
    let comment_len = read_u16(cd, pos + 32)? as usize;
    let mut local_offset = read_u32(cd, pos + 42)? as u64;

    // HOW: the variable-length name/extra/comment fields follow the 46-byte
    // fixed header in that order; summing them gives the next header's offset.
    let name_start = pos + 46;
    let extra_start = name_start + name_len;
    let comment_start = extra_start + extra_len;
    let next = comment_start + comment_len;

    // Saturated 32-bit fields are carried in the ZIP64 extra field (id 0x0001),
    // in a fixed order: uncompressed, compressed, local-offset, disk. We must
    // read the real values from there or we would scan the wrong byte range.
    let uncomp_saturated = uncomp_size == u32::MAX as u64;
    let comp_saturated = comp_size == u32::MAX as u64;
    let offset_saturated = local_offset == u32::MAX as u64;
    if uncomp_saturated || comp_saturated || offset_saturated {
        let z = read_zip64_extra(
            cd,
            extra_start,
            extra_len,
            uncomp_saturated,
            comp_saturated,
            offset_saturated,
        )?;
        if let Some(v) = z.uncompressed {
            uncomp_size = v;
        }
        if let Some(v) = z.compressed {
            comp_size = v;
        }
        if let Some(v) = z.local_offset {
            local_offset = v;
        }
    }

    // WinZip AES names method 99 and keeps the real one in its extra field. An AES
    // entry without that field cannot be opened, but is still listed.
    let (method_code, encryption) = if method_code == METHOD_AES {
        match read_aes_extra(cd, extra_start, extra_len) {
            Some((strength, method)) => (method, Encryption::Aes { strength }),
            None => (method_code, Encryption::Unsupported),
        }
    } else if flags & FLAG_ENCRYPTED == 0 {
        (method_code, Encryption::None)
    } else if flags & FLAG_STRONG != 0 {
        (method_code, Encryption::Unsupported)
    } else {
        // APPNOTE 6.1.6: the header's check byte is the CRC's high byte, or, when a
        // data descriptor follows (the CRC was unknown while writing), the high byte
        // of the DOS time.
        let check = if flags & FLAG_DESCRIPTOR != 0 {
            (dos_time >> 8) as u8
        } else {
            (crc32 >> 24) as u8
        };
        (method_code, Encryption::ZipCrypto { check, crc32 })
    };
    let method = match method_code {
        METHOD_STORED => Method::Stored,
        METHOD_DEFLATE => Method::Deflate,
        other => Method::Other(other),
    };

    let name = String::from_utf8_lossy(slice(cd, name_start, name_len)?).into_owned();

    Ok((
        CdEntry {
            name,
            method,
            encryption,
            comp_size,
            uncomp_size,
            // The extended timestamp, when present, is exact and in UTC; the DOS field
            // has 2-second resolution and no time zone.
            mtime: read_timestamp_extra(cd, extra_start, extra_len)
                .or_else(|| dos_to_unix(dos_date, dos_time)),
            crc32,
            local_offset,
        },
        next,
    ))
}

/// The modification time in an entry's extended-timestamp extra field, if it has one.
///
/// HOW: the extra area is a sequence of `(id: u16, size: u16, body)` blocks; this
/// field's body is a flags byte (bit 0: a modification time follows) and a signed
/// 32-bit time. A malformed or negative value yields `None`, and the DOS field is used.
fn read_timestamp_extra(data: &[u8], extra_start: usize, extra_len: usize) -> Option<u64> {
    let body = find_extra(data, extra_start, extra_len, TIMESTAMP_EXTRA_ID)?;
    let (&flags, rest) = body.split_first()?;
    if flags & 1 == 0 {
        return None;
    }
    let bytes: [u8; 4] = rest.get(..4)?.try_into().ok()?;
    u64::try_from(i32::from_le_bytes(bytes)).ok()
}

/// The AES strength (1, 2, 3) and real compression method in an entry's WinZip AES
/// extra field: vendor version (AE-1 or AE-2), vendor id `AE`, strength, method.
fn read_aes_extra(data: &[u8], extra_start: usize, extra_len: usize) -> Option<(u8, u16)> {
    let body = find_extra(data, extra_start, extra_len, AES_EXTRA_ID)?;
    let [_, _, b'A', b'E', strength, m0, m1, ..] = *body else {
        return None;
    };
    Some((strength, u16::from_le_bytes([m0, m1])))
}

/// The body of the extra-area block `id`, if the entry has one.
///
/// HOW: the extra area is a sequence of `(id: u16, size: u16, body)` blocks. A block
/// running past the area ends the walk.
fn find_extra(data: &[u8], extra_start: usize, extra_len: usize, id: u16) -> Option<&[u8]> {
    let extra = data.get(extra_start..extra_start.checked_add(extra_len)?)?;
    let mut pos = 0;
    while let Some(block) = extra.get(pos..pos + 4) {
        let size = u16::from_le_bytes([block[2], block[3]]) as usize;
        let body = extra.get(pos + 4..pos + 4 + size)?;
        if u16::from_le_bytes([block[0], block[1]]) == id {
            return Some(body);
        }
        pos += 4 + size;
    }
    None
}

/// Values recovered from a ZIP64 extended-information extra field.
struct Zip64Extra {
    uncompressed: Option<u64>,
    compressed: Option<u64>,
    local_offset: Option<u64>,
}

/// Decode the ZIP64 extra field (header id 0x0001) within an entry's extra
/// area.
///
/// HOW: the extra area is a sequence of `(id: u16, size: u16, body)` blocks; we
/// walk it until we find id 0x0001, then read the 8-byte fields that are
/// present. A field is present only when its 32-bit counterpart was saturated,
/// always in the order uncompressed, compressed, local-offset — so we skip or
/// read each in turn driven by the `want_*` flags.
fn read_zip64_extra(
    data: &[u8],
    extra_start: usize,
    extra_len: usize,
    want_uncomp: bool,
    want_comp: bool,
    want_offset: bool,
) -> Result<Zip64Extra> {
    let mut p = extra_start;
    let end = extra_start + extra_len;
    while p + 4 <= end {
        let id = read_u16(data, p)?;
        let size = read_u16(data, p + 2)? as usize;
        let body = p + 4;
        if id == ZIP64_EXTRA_ID {
            let mut q = body;
            let uncompressed = if want_uncomp {
                let v = read_u64(data, q)?;
                q += 8;
                Some(v)
            } else {
                None
            };
            let compressed = if want_comp {
                let v = read_u64(data, q)?;
                q += 8;
                Some(v)
            } else {
                None
            };
            let local_offset = if want_offset {
                Some(read_u64(data, q)?)
            } else {
                None
            };
            return Ok(Zip64Extra {
                uncompressed,
                compressed,
                local_offset,
            });
        }
        p = body + size;
    }
    // We only call this when a field was saturated, so a missing 0x0001 block
    // means the archive contradicts itself; refuse rather than guess an offset.
    bail!("ZIP64 extra field expected but not found");
}

/// Compute where an entry's data actually starts.
///
/// WHY this reads the Local File Header rather than reusing the Central
/// Directory's extra length: the LFH carries its *own* name/extra lengths,
/// which may differ from the CD's. Using the CD's extra length here is a
/// classic ZIP-parsing bug that lands the data offset in the wrong place.
fn local_data_offset(data: &[u8], local_offset: u64) -> Result<u64> {
    let p = local_offset as usize;
    ensure!(
        read_u32(data, p)? == SIG_LFH,
        "bad local file header signature at offset {p}"
    );
    let name_len = read_u16(data, p + 26)? as u64;
    let extra_len = read_u16(data, p + 28)? as u64;
    Ok(local_offset + 30 + name_len + extra_len)
}

/// Whether `tail`, the end of a file starting at file offset `base`, holds a
/// consistent end-of-central-directory record.
pub(crate) fn has_end_record(tail: &[u8], base: u64) -> bool {
    find_eocd(tail, base).is_ok()
}

/// Scan backwards from the file tail for the EOCD signature.
///
/// HOW: the EOCD can be followed by a comment of up to 65535 bytes, so we search
/// the last (22 + 65535) bytes from the end and, on each candidate, confirm the
/// stored comment length is consistent with the distance to end-of-file.
/// WHY the consistency check: the signature bytes can legitimately appear
/// inside a comment; the length check rejects those false positives.
///
/// A record whose comment ends before the file does is also accepted when every
/// byte after it is zero. WHY: some acquisition tools pad a small zip to a block
/// size (a 64 KiB Android-Keystore dump zip, seen on a real extraction, ends in
/// 32 KiB of zeros), and `unzip` reads such files. Zeros cannot hide a later
/// record, and the nearest candidate to the end is taken first, so an exact match
/// still wins over a padded one.
///
/// Failing both, a record followed by other bytes is accepted when the archive's own
/// structure confirms it: a ZIP64 locator sits right before it, or the central
/// directory it describes ends exactly where it starts. WHY: a Cellebrite `.ufdr`
/// report appends a trailer of its own after the record (528 bytes on a real one),
/// which Python's `zipfile` and 7-Zip accept. A stray signature inside such a
/// trailer would fail both checks. `base` is the file offset of `data[0]`, needed
/// to compare the directory's end, an absolute offset, with the record's position.
fn find_eocd(data: &[u8], base: u64) -> Result<usize> {
    const EOCD_MIN: usize = 22;
    ensure!(data.len() >= EOCD_MIN, "file smaller than an EOCD record");

    let max_back = (EOCD_MIN + u16::MAX as usize).min(data.len());
    let start = data.len() - max_back;
    let candidates = || {
        (start..=data.len() - EOCD_MIN)
            .rev()
            .filter(|&pos| read_u32(data, pos).is_ok_and(|sig| sig == SIG_EOCD))
    };
    for pos in candidates() {
        let comment_len = read_u16(data, pos + 20)? as usize;
        let end = pos + EOCD_MIN + comment_len;
        let zero_padded = || {
            data.get(end..)
                .is_some_and(|rest| rest.iter().all(|&b| b == 0))
        };
        if end == data.len() || (end < data.len() && zero_padded()) {
            return Ok(pos);
        }
    }
    for pos in candidates() {
        if structurally_confirmed(data, base, pos)? {
            return Ok(pos);
        }
    }
    bail!("no EOCD signature found in tail of file");
}

/// Whether the end record at `pos` is confirmed by the structure around it, not
/// only by its signature (see [`find_eocd`]).
fn structurally_confirmed(data: &[u8], base: u64, pos: usize) -> Result<bool> {
    const ZIP64_LOCATOR_LEN: usize = 20;
    if pos >= ZIP64_LOCATOR_LEN
        && read_u32(data, pos - ZIP64_LOCATOR_LEN)? == SIG_ZIP64_EOCD_LOCATOR
    {
        return Ok(true);
    }
    let cd_size = u64::from(read_u32(data, pos + 12)?);
    let cd_offset = u64::from(read_u32(data, pos + 16)?);
    Ok(cd_offset.checked_add(cd_size) == Some(base + pos as u64))
}

// --- Bounds-checked little-endian readers ------------------------------------
// Every multi-byte read goes through these so an out-of-bounds offset becomes a
// clean error instead of a panic — important when parsing untrusted evidence.

pub(crate) fn slice(data: &[u8], off: usize, len: usize) -> Result<&[u8]> {
    // checked_add keeps debug and release behaviour identical on absurd
    // offsets: an overflowing `off + len` must error like any other
    // out-of-bounds read, not panic in debug builds.
    off.checked_add(len)
        .and_then(|end| data.get(off..end))
        .with_context(|| format!("read of {len} bytes at offset {off} is out of bounds"))
}

pub(crate) fn read_u16(data: &[u8], off: usize) -> Result<u16> {
    let b = slice(data, off, 2)?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

pub(crate) fn read_u32(data: &[u8], off: usize) -> Result<u32> {
    let b = slice(data, off, 4)?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_u64(data: &[u8], off: usize) -> Result<u64> {
    let b = slice(data, off, 8)?;
    Ok(u64::from_le_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

/// Convert a ZIP DOS date+time pair into Unix epoch seconds (UTC-interpreted).
///
/// DOS date packs `(year-1980):7 | month:4 | day:5`; DOS time packs
/// `hour:5 | minute:6 | (second/2):5` (2-second resolution). The timestamp has no
/// timezone, so it is read as UTC — fine for `diff`, where both sides are decoded
/// the same way. Returns `None` for an unset (zero) or out-of-range date.
fn dos_to_unix(date: u16, time: u16) -> Option<u64> {
    if date == 0 {
        return None;
    }
    let day = (date & 0x1f) as i64;
    let month = ((date >> 5) & 0x0f) as i64;
    let year = 1980 + ((date >> 9) & 0x7f) as i64;
    let second = ((time & 0x1f) * 2) as i64;
    let minute = ((time >> 5) & 0x3f) as i64;
    let hour = ((time >> 11) & 0x1f) as i64;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    u64::try_from(unix_from_civil(year, month, day, hour, minute, second)).ok()
}

// --- Byte access + the Source container --------------------------------------

/// Return a ZIP entry's logical content: a borrowed slice of the archive for
/// STORED, or an owned decompressed buffer for DEFLATE.
///
/// Exposed so callers (the engine, the export step) can search *and* inspect the
/// same content without decompressing a DEFLATE entry twice. STORED entries are
/// returned in place over the memory-mapped archive (no copy); DEFLATE entries are
/// decompressed into an owned buffer, so reported offsets are positions within the
/// *decompressed* stream. A non-ZIP entry is a caller bug and errors.
pub fn content<'a>(archive: &'a [u8], entry: &Entry) -> Result<Content<'a>> {
    content_with(archive, entry, ZipPassword::Missing)
}

/// [`content`], with what is known of the password for an encrypted entry.
pub(crate) fn content_with<'a>(
    archive: &'a [u8],
    entry: &Entry,
    password: ZipPassword,
) -> Result<Content<'a>> {
    let Location::Zip {
        method,
        encryption,
        data_offset,
        data_len,
    } = &entry.location
    else {
        bail!("zip::content called on a non-ZIP entry: {}", entry.name);
    };
    read_range(
        archive,
        Coding {
            method: *method,
            encryption: *encryption,
            password,
        },
        *data_offset,
        *data_len,
        entry.uncompressed_size,
        &entry.name,
    )
}

/// How an entry's data is coded: its compression, its encryption, and what is known
/// of the password.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Coding<'p> {
    pub(crate) method: Method,
    pub(crate) encryption: Encryption,
    pub(crate) password: ZipPassword<'p>,
}

/// Read a ZIP data range from `archive` by explicit fields: borrow the slice for
/// STORED, inflate it for DEFLATE.
///
/// The lower-level twin of [`content`], used to read an entry that lives inside an
/// in-memory *nested* archive (where the offsets are into a folder source's blob, not
/// a top-level `Entry`'s mmap). `uncompressed_size` is the inflate capacity hint and
/// `name` only labels errors.
pub(crate) fn read_range<'a>(
    archive: &'a [u8],
    coding: Coding,
    data_offset: u64,
    data_len: u64,
    uncompressed_size: u64,
    name: &str,
) -> Result<Content<'a>> {
    let start = data_offset as usize;
    // A data range outside the file means the Central Directory disagreed with
    // the archive's real size; bailing here surfaces a corrupt/truncated image
    // rather than silently searching the wrong bytes. checked_add: an
    // overflowing range is the same lie and must error identically in debug.
    let raw = start
        .checked_add(data_len as usize)
        .and_then(|end| archive.get(start..end))
        .with_context(|| format!("data range of {name} is out of bounds"))?;
    decode(raw, coding, uncompressed_size, name)
}

/// An entry's content from its raw data as stored: decrypted, then decompressed.
///
/// Shared by the mapped, ranged and nested ZIP readers, so an entry is decoded the
/// same way whichever read it. Unencrypted STORED data is borrowed, not copied. A
/// ZipCrypto entry's CRC-32 is checked here: its 12-byte header carries one check
/// byte, so a wrong password passes it 1 time in 256, and its output would be
/// searched as garbage; the CRC catches that (WinZip AES has its own HMAC).
pub(crate) fn decode<'a>(
    raw: &'a [u8],
    coding: Coding,
    uncompressed_size: u64,
    name: &str,
) -> Result<Content<'a>> {
    let Coding {
        method,
        encryption,
        password,
    } = coding;
    // Before decrypting: a method that cannot be read fails the same way whether or
    // not the entry is encrypted, and costs no key derivation.
    if let Method::Other(code) = method {
        bail!(
            "{name} uses compression method {code} ({}), which mf-scan does not read",
            method_name(code)
        );
    }
    let content = if encryption == Encryption::None {
        match method {
            Method::Stored => Content::Borrowed(raw),
            _ => Content::Owned(
                inflate(raw, uncompressed_size)
                    .with_context(|| format!("failed to inflate {name}"))?,
            ),
        }
    } else {
        let plain = zip_crypto::decrypt(raw, encryption, password)
            .with_context(|| format!("cannot decrypt {name}"))?;
        Content::Owned(match method {
            Method::Stored => plain,
            _ => inflate(&plain, uncompressed_size).with_context(|| {
                format!(
                    "failed to inflate {name} after decryption (a wrong password, or damaged data)"
                )
            })?,
        })
    };
    if let Encryption::ZipCrypto { crc32, .. } = encryption {
        let actual = crc32fast::hash(&content);
        ensure!(
            actual == crc32,
            "{name}: the CRC-32 after decryption is {actual:08x}, not the recorded \
             {crc32:08x} (a wrong password, or damaged data)"
        );
    }
    Ok(content)
}

/// A ZIP compression method's name (APPNOTE 4.4.5), for messages.
fn method_name(code: u16) -> &'static str {
    match code {
        1 => "shrunk",
        2..=5 => "reduced",
        6 => "imploded",
        9 => "Deflate64",
        10 => "PKWARE DCL imploded",
        12 => "bzip2",
        14 => "LZMA",
        18 => "IBM TERSE",
        19 => "IBM LZ77",
        93 => "Zstandard",
        94 => "MP3",
        95 => "xz",
        96 => "JPEG",
        97 => "WavPack",
        98 => "PPMd",
        99 => "AES without its extra field",
        _ => "unknown",
    }
}

/// What in `entries` cannot be searched as the archive is opened, one line each for
/// stderr: encrypted entries (and whether a password was given), encryption not read,
/// compression methods not read. Empty when everything can be read.
///
/// WHY at open, not only in the end-of-run count: the count says how many files
/// could not be read, these lines say why, and what would open them.
pub fn not_searched_notes(entries: &[Entry], password_given: bool) -> Vec<String> {
    use std::collections::BTreeMap;
    let mut aes = BTreeMap::new();
    let mut zipcrypto = 0usize;
    let mut unsupported = 0usize;
    let mut methods: BTreeMap<u16, usize> = BTreeMap::new();
    for entry in entries {
        let (Location::Zip {
            method, encryption, ..
        }
        | Location::RangedZip {
            method, encryption, ..
        }
        | Location::Nested {
            method, encryption, ..
        }) = &entry.location
        else {
            continue;
        };
        match encryption {
            Encryption::None => {}
            Encryption::ZipCrypto { .. } => zipcrypto += 1,
            Encryption::Aes { strength } => *aes.entry(*strength).or_insert(0usize) += 1,
            Encryption::Unsupported => unsupported += 1,
        }
        if let Method::Other(code) = method {
            *methods.entry(*code).or_insert(0) += 1;
        }
    }
    let mut notes = Vec::new();
    let mut schemes: Vec<String> = aes
        .iter()
        .map(|(strength, n)| format!("{n} AES-{}", 64 + 64 * u32::from(*strength)))
        .collect();
    if zipcrypto > 0 {
        schemes.push(format!("{zipcrypto} ZipCrypto"));
    }
    if !schemes.is_empty() {
        let total = zipcrypto + aes.values().sum::<usize>();
        notes.push(if password_given {
            format!(
                "{total} encrypted file(s) ({}), decrypted with the supplied password",
                schemes.join(", ")
            )
        } else {
            format!(
                "⚠ {total} encrypted file(s) ({}) NOT searched: pass --archive-password to \
                 be asked for the password (or set MFSCAN_ARCHIVE_PASSWORD)",
                schemes.join(", ")
            )
        });
    }
    if unsupported > 0 {
        notes.push(format!(
            "⚠ {unsupported} file(s) NOT searched: an encryption mf-scan does not read \
             (PKWARE strong encryption, or a malformed AES field)"
        ));
    }
    if !methods.is_empty() {
        let list: Vec<String> = methods
            .iter()
            .map(|(code, n)| format!("{n} {} ({code})", method_name(*code)))
            .collect();
        notes.push(format!(
            "⚠ {} file(s) NOT searched: a compression method mf-scan does not read: {}",
            methods.values().sum::<usize>(),
            list.join(", ")
        ));
    }
    notes
}

/// Cap on the inflate pre-allocation hint. `expected_size` comes from the
/// untrusted Central Directory: a crafted entry claiming an absurd size must
/// not abort on allocation before a single byte is inflated. `read_to_end`
/// grows the buffer as needed, so capping the hint costs only reallocations.
const INFLATE_HINT_CAP: u64 = 64 * 1024 * 1024;

/// Inflate a raw DEFLATE stream (ZIP method 8 stores no zlib header).
///
/// `expected_size` is the Central Directory's declared uncompressed size. It is
/// enforced as a ceiling and an exact target: DEFLATE can legally expand ~1000×,
/// so without the ceiling a small crafted entry could balloon without bound
/// (zip bomb); a mismatch in either direction means the archive lies about the
/// entry and the bytes cannot be trusted.
pub(crate) fn inflate(compressed: &[u8], expected_size: u64) -> Result<Vec<u8>> {
    let mut decoder = DeflateDecoder::new(compressed).take(expected_size.saturating_add(1));
    let mut out = Vec::with_capacity(expected_size.min(INFLATE_HINT_CAP) as usize);
    decoder.read_to_end(&mut out)?;
    ensure!(
        out.len() as u64 == expected_size,
        "inflated size {} does not match the declared {expected_size} bytes",
        out.len()
    );
    Ok(out)
}

/// The first `max` bytes a raw DEFLATE stream inflates to (fewer when it is shorter).
pub(crate) fn inflate_head(compressed: &[u8], max: usize) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(max);
    DeflateDecoder::new(compressed)
        .take(max as u64)
        .read_to_end(&mut out)?;
    Ok(out)
}

/// A [`Source`] backed by a memory-mapped ZIP archive.
///
/// Parses the central directory once on [`ZipSource::open`] and then serves each
/// entry's bytes straight from the mapped archive (zero-copy for STORED). The
/// borrowed `data` is the read-only mmap held by the caller for the source's life.
pub struct ZipSource<'d> {
    data: &'d [u8],
    /// The password for encrypted entries, when one was given.
    password: Option<String>,
    entries: Vec<Entry>,
    /// Central-Directory CRC-32 per entry, parallel to `entries`. Kept so
    /// [`Source::integrity_check`] can attest an entry's bytes against the value
    /// the archive producer recorded.
    crcs: Vec<u32>,
}

impl<'d> ZipSource<'d> {
    /// Parse `data`'s central directory and build the source.
    pub fn open(data: &'d [u8]) -> Result<Self> {
        Self::open_with_password(data, None)
    }

    /// [`ZipSource::open`], with the password of its encrypted entries. A password
    /// that does not open the smallest encrypted entry is an error here, before any
    /// search (see `check_password`).
    pub fn open_with_password(data: &'d [u8], password: Option<&str>) -> Result<Self> {
        let (entries, crcs): (Vec<Entry>, Vec<u32>) =
            parse_entries_with_crc(data)?.into_iter().unzip();
        let source = Self {
            data,
            password: password.map(str::to_string),
            entries,
            crcs,
        };
        check_password(&source, password.is_some())?;
        Ok(source)
    }

    fn password(&self) -> ZipPassword<'_> {
        match &self.password {
            Some(password) => ZipPassword::Given(password),
            None => ZipPassword::Missing,
        }
    }
}

/// With a password given, decode the smallest entry it should open, whole.
///
/// WHY: a wrong password must stop the run with that reason, not turn every
/// encrypted file into an "unreadable" count the examiner has to explain. The whole
/// entry is decoded because only the CRC (ZipCrypto) or the HMAC (AES) tells a wrong
/// password for sure; the smallest keeps that cheap. An archive whose files have
/// different passwords opens with the smallest one's: the others are then counted as
/// not searched, each failing its own check.
pub(crate) fn check_password(source: &dyn Source, password_given: bool) -> Result<()> {
    if !password_given {
        return Ok(());
    }
    let smallest = source
        .entries()
        .iter()
        .filter(|e| {
            e.is_encrypted()
                && !matches!(
                    &e.location,
                    Location::Zip {
                        encryption: Encryption::Unsupported,
                        ..
                    } | Location::Zip {
                        method: Method::Other(_),
                        ..
                    } | Location::RangedZip {
                        encryption: Encryption::Unsupported,
                        ..
                    } | Location::RangedZip {
                        method: Method::Other(_),
                        ..
                    }
                )
        })
        .min_by_key(|e| e.uncompressed_size);
    if let Some(entry) = smallest {
        source.content(entry).with_context(|| {
            format!(
                "the password given does not open {} (the smallest encrypted file, checked first)",
                entry.name
            )
        })?;
    }
    Ok(())
}

impl Source for ZipSource<'_> {
    fn entries(&self) -> &[Entry] {
        &self.entries
    }

    fn content(&self, entry: &Entry) -> Result<Content<'_>> {
        content_with(self.data, entry, self.password())
    }

    /// A plain STORED entry is a slice of the mapped archive.
    fn reads_in_place(&self, entry: &Entry) -> bool {
        matches!(
            entry.location,
            Location::Zip {
                method: Method::Stored,
                encryption: Encryption::None,
                ..
            }
        )
    }

    /// The start of a plain DEFLATE entry is inflated alone; anything else (STORED
    /// is borrowed anyway, encrypted data is checked whole) is read whole.
    fn content_head(&self, entry: &Entry, max: usize) -> Result<Content<'_>> {
        if let Location::Zip {
            method: Method::Deflate,
            encryption: Encryption::None,
            data_offset,
            data_len,
        } = entry.location
        {
            let start = usize::try_from(data_offset)?;
            let raw = start
                .checked_add(usize::try_from(data_len)?)
                .and_then(|end| self.data.get(start..end))
                .with_context(|| format!("data range of {} is out of bounds", entry.name))?;
            return inflate_head(raw, max)
                .map(Content::Owned)
                .with_context(|| format!("failed to inflate the start of {}", entry.name));
        }
        self.content(entry)
    }

    fn byte_size(&self) -> u64 {
        self.data.len() as u64
    }

    /// Attest an entry's bytes against the CRC-32 the Central Directory records.
    ///
    /// WHY this is a real integrity check, not a tautology: the recorded CRC-32
    /// was written by the *producer* of the archive (the acquisition tool), so
    /// recomputing it from the bytes on disk detects a STORED entry whose data
    /// was truncated or corrupted in storage/transit — independent of anything
    /// this tool computed. The CRC covers the uncompressed data for both STORED
    /// and DEFLATE. A CRC of 0 is treated as "not recorded" (some producers leave
    /// it zero, e.g. streamed entries with a data descriptor we don't resolve),
    /// degrading to `Unrecorded` rather than a false mismatch.
    fn integrity_check(&self, entry: &Entry) -> IntegrityCheck {
        let Some(idx) = self.entries.iter().position(|e| e.name == entry.name) else {
            return IntegrityCheck::Unrecorded;
        };
        let expected = self.crcs[idx];
        if expected == 0 {
            return IntegrityCheck::Unrecorded;
        }
        let Ok(content) = self.content(entry) else {
            return IntegrityCheck::Unrecorded;
        };
        let actual = crc32fast::hash(&content);
        if actual == expected {
            IntegrityCheck::Verified { algorithm: "crc32" }
        } else {
            IntegrityCheck::Mismatch {
                algorithm: "crc32",
                expected: format!("{expected:08x}"),
                actual: format!("{actual:08x}"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{SIG_EOCD, dos_to_unix, find_eocd};

    /// An empty archive: a bare end-of-central-directory record.
    fn bare_eocd() -> Vec<u8> {
        let mut eocd = SIG_EOCD.to_le_bytes().to_vec();
        eocd.extend_from_slice(&[0u8; 18]);
        eocd
    }

    #[test]
    fn end_record_followed_by_zero_padding_is_found() {
        let mut data = bare_eocd();
        assert_eq!(find_eocd(&data, 0).unwrap(), 0);
        data.extend_from_slice(&[0u8; 4096]);
        assert_eq!(find_eocd(&data, 0).unwrap(), 0, "zero padding is tolerated");
    }

    #[test]
    fn a_trailer_after_a_consistent_end_record_is_accepted() {
        // An empty archive's record says its (empty) directory ends at offset 0,
        // which is where the record starts: confirmed, so a trailer may follow.
        let mut data = bare_eocd();
        data.extend_from_slice(b"\x00\x00a report tool's trailer");
        assert_eq!(find_eocd(&data, 0).unwrap(), 0);
    }

    #[test]
    fn a_trailer_after_an_unconfirmed_end_record_is_rejected() {
        // A record whose directory would end elsewhere is a stray signature.
        let mut data = vec![0u8; 8];
        data.extend_from_slice(&bare_eocd());
        data.extend_from_slice(b"\x00\x00trailing garbage");
        assert!(find_eocd(&data, 0).is_err());
    }

    /// Pack a DOS date/time the way a ZIP central directory stores them.
    fn dos(y: u16, mo: u16, d: u16, h: u16, mi: u16, s: u16) -> (u16, u16) {
        let date = ((y - 1980) << 9) | (mo << 5) | d;
        let time = (h << 11) | (mi << 5) | (s / 2);
        (date, time)
    }

    #[test]
    fn decodes_known_dos_timestamps() {
        // 2021-01-01 00:00:00 UTC == 1609459200.
        let (date, time) = dos(2021, 1, 1, 0, 0, 0);
        assert_eq!(dos_to_unix(date, time), Some(1_609_459_200));

        // The DOS epoch, 1980-01-01 00:00:00 UTC == 315532800.
        let (date, time) = dos(1980, 1, 1, 0, 0, 0);
        assert_eq!(dos_to_unix(date, time), Some(315_532_800));

        // 2s resolution: an odd second is rounded down to the even slot.
        let (date, time) = dos(2000, 6, 15, 12, 30, 44);
        assert_eq!(dos_to_unix(date, time), Some(961_072_244));
    }

    #[test]
    fn rejects_unset_or_invalid_dates() {
        assert_eq!(dos_to_unix(0, 0), None); // unset
        // A date with month 13 (year 1990, day 1) is out of range.
        assert_eq!(dos_to_unix((10u16 << 9) | (13 << 5) | 1, 0), None);
    }
}
