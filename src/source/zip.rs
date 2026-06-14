//! ZIP archive source: central-directory parser + the [`ZipSource`] container.
//!
//! Defines: `parse_entries`, which reads a ZIP archive's Central Directory and
//! resolves every searchable file's byte range and compression method; `content`,
//! which borrows a STORED entry's bytes from the archive or inflates a DEFLATE one;
//! and [`ZipSource`], the [`crate::source::Source`] over a memory-mapped archive.
//! Used by: `source` (the open helpers), `engine` (search over a `Source`) and
//! `report::export` (re-reads matched files' bytes).
//! Uses: `crate::models::{Entry, Location, Method}`, `flate2` (inflate), `anyhow`.
//! All integer decoding is done by hand so the parsing flow stays explicit.
//!
//! Why CD-first instead of a blind linear scan: the Central Directory is the
//! authoritative record of every entry (local headers may carry zeroed sizes
//! when a data descriptor is used). Parsing it first gives exact data ranges,
//! lets us skip header bytes, and tells us each entry's method.

use std::io::Read;

use anyhow::{Context, Result, bail, ensure};
use flate2::read::DeflateDecoder;

use crate::models::{Entry, Location, Method};
use crate::source::{Content, IntegrityCheck, Source};

// --- ZIP record signatures (little-endian on disk) ---------------------------
// These are fixed by the ZIP specification (APPNOTE.TXT), not operator-tunable,
// so they live here as format constants rather than in any config.
const SIG_EOCD: u32 = 0x0605_4b50; // End Of Central Directory
const SIG_ZIP64_EOCD_LOCATOR: u32 = 0x0706_4b50; // ZIP64 EOCD locator
const SIG_ZIP64_EOCD: u32 = 0x0606_4b50; // ZIP64 EOCD record
const SIG_CDFH: u32 = 0x0201_4b50; // Central Directory File Header
const SIG_LFH: u32 = 0x0403_4b50; // Local File Header

const METHOD_STORED: u16 = 0; // compression method 0 = no compression
const METHOD_DEFLATE: u16 = 8; // compression method 8 = DEFLATE
const ZIP64_EXTRA_ID: u16 = 0x0001; // header id of the ZIP64 extended-info field

/// Outcome of decoding one Central Directory header.
///
/// Modelled as an enum (rather than `Option<Entry>`) because "this entry uses a
/// method we do not search" is an *expected* outcome, not an error: only STORED
/// and DEFLATE are kept, and a named variant says so at the call site.
enum CdScan {
    /// A searchable entry plus the CRC-32 the Central Directory records for its
    /// uncompressed bytes (used for export integrity attestation).
    Searchable(Entry, u32),
    Skipped,
}

/// Parse the archive and return every searchable (STORED or DEFLATE) entry.
///
/// HOW:
///   1. locate the EOCD at the tail of the file,
///   2. follow the ZIP64 records if the EOCD fields are saturated,
///   3. walk the Central Directory, decoding one header per entry,
///   4. keep the STORED and DEFLATE entries.
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
pub fn parse_entries_with_crc(data: &[u8]) -> Result<Vec<(Entry, u32)>> {
    let eocd = find_eocd(data).context("could not locate End Of Central Directory record")?;

    // Central-directory location/count, possibly upgraded by ZIP64 below.
    let mut cd_offset = read_u32(data, eocd + 16)? as u64;
    let mut total_entries = read_u16(data, eocd + 10)? as u64;

    // A saturated (all-ones) field means the real value lives in the ZIP64
    // records; reading the 32-bit field as the truth would point us at the
    // wrong offset and corrupt the whole parse, so we must redirect.
    let cd_offset_saturated = read_u32(data, eocd + 16)? == u32::MAX;
    let entries_saturated = read_u16(data, eocd + 10)? == u16::MAX;
    if cd_offset_saturated || entries_saturated {
        let z = read_zip64_eocd(data, eocd)?;
        cd_offset = z.cd_offset;
        total_entries = z.total_entries;
    }

    let mut entries = Vec::new();
    let mut pos = cd_offset as usize;
    for _ in 0..total_entries {
        let (scan, next) = parse_cd_header(data, pos)?;
        if let CdScan::Searchable(entry, crc) = scan {
            entries.push((entry, crc));
        }
        pos = next;
    }

    Ok(entries)
}

/// Resolved ZIP64 central-directory location.
struct Zip64Eocd {
    cd_offset: u64,
    total_entries: u64,
}

/// Read the ZIP64 EOCD via the locator that sits 20 bytes before the EOCD.
///
/// HOW: the 20-byte locator immediately precedes the EOCD and stores the
/// absolute offset of the ZIP64 EOCD record, which in turn holds the real
/// 64-bit central-directory offset and entry count.
fn read_zip64_eocd(data: &[u8], eocd: usize) -> Result<Zip64Eocd> {
    // If the EOCD claimed ZIP64 but no locator fits before it, the archive is
    // malformed and any offset we compute would be garbage — fail loudly.
    let locator = eocd
        .checked_sub(20)
        .context("file too small for a ZIP64 EOCD locator")?;
    ensure!(
        read_u32(data, locator)? == SIG_ZIP64_EOCD_LOCATOR,
        "expected ZIP64 EOCD locator signature before EOCD"
    );

    let z64 = read_u64(data, locator + 8)? as usize; // offset of ZIP64 EOCD record
    ensure!(
        read_u32(data, z64)? == SIG_ZIP64_EOCD,
        "expected ZIP64 EOCD record signature"
    );

    Ok(Zip64Eocd {
        total_entries: read_u64(data, z64 + 32)?,
        cd_offset: read_u64(data, z64 + 48)?,
    })
}

/// Parse one Central Directory File Header at `pos`.
///
/// Returns the scan outcome plus the offset of the next header, so the caller
/// can keep walking the directory regardless of whether this entry was kept.
fn parse_cd_header(data: &[u8], pos: usize) -> Result<(CdScan, usize)> {
    // A wrong signature here means we have lost sync with the directory; every
    // subsequent field would be misread, so stop rather than emit junk.
    ensure!(
        read_u32(data, pos)? == SIG_CDFH,
        "bad central-directory header signature at offset {pos}"
    );

    let method_code = read_u16(data, pos + 10)?;
    // Last-modified DOS time/date (2 bytes each), decoded for `diff`'s mtime compare.
    let dos_time = read_u16(data, pos + 12)?;
    let dos_date = read_u16(data, pos + 14)?;
    // CRC-32 of the uncompressed data, as recorded by the producer.
    let crc32 = read_u32(data, pos + 16)?;
    let mut comp_size = read_u32(data, pos + 20)? as u64;
    let mut uncomp_size = read_u32(data, pos + 24)? as u64;
    let name_len = read_u16(data, pos + 28)? as usize;
    let extra_len = read_u16(data, pos + 30)? as usize;
    let comment_len = read_u16(data, pos + 32)? as usize;
    let mut local_offset = read_u32(data, pos + 42)? as u64;

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
            data,
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

    // Only STORED and DEFLATE are searchable; any other method is skipped.
    let method = match method_code {
        METHOD_STORED => Method::Stored,
        METHOD_DEFLATE => Method::Deflate,
        _ => return Ok((CdScan::Skipped, next)),
    };

    let name = String::from_utf8_lossy(slice(data, name_start, name_len)?).into_owned();
    let data_offset = local_data_offset(data, local_offset)?;

    Ok((
        CdScan::Searchable(
            Entry {
                name,
                uncompressed_size: uncomp_size,
                mtime: dos_to_unix(dos_date, dos_time),
                location: Location::Zip {
                    method,
                    data_offset,
                    data_len: comp_size,
                },
            },
            crc32,
        ),
        next,
    ))
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

/// Scan backwards from the file tail for the EOCD signature.
///
/// HOW: the EOCD can be followed by a comment of up to 65535 bytes, so we search
/// the last (22 + 65535) bytes from the end and, on each candidate, confirm the
/// stored comment length is consistent with the distance to end-of-file.
/// WHY the consistency check: the signature bytes can legitimately appear
/// inside a comment; the length check rejects those false positives.
fn find_eocd(data: &[u8]) -> Result<usize> {
    const EOCD_MIN: usize = 22;
    ensure!(data.len() >= EOCD_MIN, "file smaller than an EOCD record");

    let max_back = (EOCD_MIN + u16::MAX as usize).min(data.len());
    let start = data.len() - max_back;
    for pos in (start..=data.len() - EOCD_MIN).rev() {
        if read_u32(data, pos)? == SIG_EOCD {
            let comment_len = read_u16(data, pos + 20)? as usize;
            if pos + EOCD_MIN + comment_len == data.len() {
                return Ok(pos);
            }
        }
    }
    bail!("no EOCD signature found in tail of file");
}

// --- Bounds-checked little-endian readers ------------------------------------
// Every multi-byte read goes through these so an out-of-bounds offset becomes a
// clean error instead of a panic — important when parsing untrusted evidence.

fn slice(data: &[u8], off: usize, len: usize) -> Result<&[u8]> {
    // checked_add keeps debug and release behaviour identical on absurd
    // offsets: an overflowing `off + len` must error like any other
    // out-of-bounds read, not panic in debug builds.
    off.checked_add(len)
        .and_then(|end| data.get(off..end))
        .with_context(|| format!("read of {len} bytes at offset {off} is out of bounds"))
}

fn read_u16(data: &[u8], off: usize) -> Result<u16> {
    let b = slice(data, off, 2)?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

fn read_u32(data: &[u8], off: usize) -> Result<u32> {
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
    // Days since the Unix epoch via Howard Hinnant's days_from_civil algorithm.
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    let days = era * 146097 + doe - 719468;
    let secs = days * 86400 + hour * 3600 + minute * 60 + second;
    u64::try_from(secs).ok()
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
    let Location::Zip {
        method,
        data_offset,
        data_len,
    } = &entry.location
    else {
        bail!("zip::content called on a non-ZIP entry: {}", entry.name);
    };
    read_range(
        archive,
        *method,
        *data_offset,
        *data_len,
        entry.uncompressed_size,
        &entry.name,
    )
}

/// Read a ZIP data range from `archive` by explicit fields: borrow the slice for
/// STORED, inflate it for DEFLATE.
///
/// The lower-level twin of [`content`], used to read an entry that lives inside an
/// in-memory *nested* archive (where the offsets are into a folder source's blob, not
/// a top-level `Entry`'s mmap). `uncompressed_size` is the inflate capacity hint and
/// `name` only labels errors.
pub fn read_range<'a>(
    archive: &'a [u8],
    method: Method,
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

    match method {
        Method::Stored => Ok(Content::Borrowed(raw)),
        Method::Deflate => {
            let inflated = inflate(raw, uncompressed_size)
                .with_context(|| format!("failed to inflate {name}"))?;
            Ok(Content::Owned(inflated))
        }
    }
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
fn inflate(compressed: &[u8], expected_size: u64) -> Result<Vec<u8>> {
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

/// A [`Source`] backed by a memory-mapped ZIP archive.
///
/// Parses the central directory once on [`ZipSource::open`] and then serves each
/// entry's bytes straight from the mapped archive (zero-copy for STORED). The
/// borrowed `data` is the read-only mmap held by the caller for the source's life.
pub struct ZipSource<'d> {
    data: &'d [u8],
    entries: Vec<Entry>,
    /// Central-Directory CRC-32 per entry, parallel to `entries`. Kept so
    /// [`Source::integrity_check`] can attest an entry's bytes against the value
    /// the archive producer recorded.
    crcs: Vec<u32>,
}

impl<'d> ZipSource<'d> {
    /// Parse `data`'s central directory and build the source.
    pub fn open(data: &'d [u8]) -> Result<Self> {
        let (entries, crcs): (Vec<Entry>, Vec<u32>) =
            parse_entries_with_crc(data)?.into_iter().unzip();
        Ok(Self {
            data,
            entries,
            crcs,
        })
    }
}

impl Source for ZipSource<'_> {
    fn entries(&self) -> &[Entry] {
        &self.entries
    }

    fn content(&self, entry: &Entry) -> Result<Content<'_>> {
        content(self.data, entry)
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
    use super::dos_to_unix;

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
