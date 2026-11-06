//! A streaming writer for STORED ZIP archives that keeps each member's timestamp.
//!
//! Defines: [`ZipWriter`] (add files and directories, read a member back, finish), and
//! [`ZipWriter::extend`] (an existing archive, kept verbatim, plus new members).
//! Used by: `report::rebuild_zip` (the one archive a backup rebuild writes) and
//! `report::decrypted_zip` (an acquisition with decrypted databases added).
//! Uses: `crc32fast`, `sha2`, and `core::util` (the UTC calendar); the format follows
//! PKWARE APPNOTE.TXT, with the extended-timestamp extra field from Info-ZIP's
//! `extrafld.txt`.
//!
//! WHY by hand, not the `zip` crate: the codebase reads ZIP by hand for full control
//! (see `core::source::zip`), and writing STORED members is a small, fixed layout, so
//! a dependency would add more audited surface than the code it replaces.
//!
//! WHY STORED: a member's bytes then sit in the archive unchanged, so `mf-scan` reads
//! a rebuilt archive zero-copy and reports exact archive offsets, as it does for a
//! real acquisition, and any carving tool sees the original bytes.
//!
//! ── How a timestamp survives ─────────────────────────────────────────────────
//! Each member records its modification time twice, because the two fields fail
//! differently:
//!   • the DOS field every tool reads has 2-second resolution, no time zone and no
//!     dates before 1980. It is written in UTC, so it displays the same on any
//!     machine (and matches the Python reconstructor).
//!   • the Info-ZIP extended timestamp (extra field 0x5455) holds exact UTC seconds.
//!     Tools that understand it (`unzip`, 7-Zip, `mf-scan` itself) restore the true
//!     time in every time zone, whatever the DOS field says.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};

use crate::core::util::UtcTime;

const SIG_LFH: u32 = 0x0403_4b50;
const SIG_CDFH: u32 = 0x0201_4b50;
const SIG_EOCD: u32 = 0x0605_4b50;
const SIG_ZIP64_EOCD: u32 = 0x0606_4b50;
const SIG_ZIP64_LOCATOR: u32 = 0x0706_4b50;

/// General-purpose flag bit 11: the member name is UTF-8.
const FLAG_UTF8: u16 = 1 << 11;
const VERSION_DEFAULT: u16 = 20;
const VERSION_ZIP64: u16 = 45;
/// "Version made by": host 3 (Unix), so the external attributes below are read as
/// permission bits, on every platform that writes the archive.
const VERSION_MADE_BY: u16 = (3 << 8) | VERSION_ZIP64;

/// `-rw-r--r--`, in the high half of the external attributes.
const ATTR_FILE: u32 = 0o100_644 << 16;
/// `drwxr-xr-x`, plus the DOS directory bit (0x10) that Windows tools read.
const ATTR_DIR: u32 = (0o040_755 << 16) | 0x10;

const EXTRA_ZIP64: u16 = 0x0001;
const EXTRA_TIMESTAMP: u16 = 0x5455;
/// Extended-timestamp flag: the modification time is present.
const TIMESTAMP_HAS_MTIME: u8 = 1;

/// The DOS date for 1980-01-01, the earliest time the field can hold.
const DOS_EPOCH_DATE: u16 = (1 << 5) | 1;
/// The latest year the 7-bit DOS year field can hold.
const DOS_MAX_YEAR: u64 = 2107;

/// A size or offset at or above this needs ZIP64.
const ZIP64_LIMIT: u64 = u32::MAX as u64;
/// A member count at or above this needs ZIP64.
const ZIP64_COUNT_LIMIT: u64 = u16::MAX as u64;

/// Chunk size for reading a written member back.
const READ_BACK_CHUNK: usize = 1024 * 1024;
/// Chunk size for copying an extended archive's members.
const COPY_CHUNK: usize = 8 * 1024 * 1024;

/// What the central directory needs to know about one written member.
struct CentralRecord {
    name: String,
    crc32: u32,
    size: u64,
    dos_date: u16,
    dos_time: u16,
    mtime: Option<u64>,
    header_offset: u64,
    external_attrs: u32,
}

/// Where a member's bytes landed, for [`ZipWriter::sha256_of`].
#[derive(Debug, Clone, Copy)]
pub struct WrittenMember {
    data_offset: u64,
    size: u64,
}

/// Writes a ZIP archive member by member. Nothing is valid until [`finish`] writes
/// the central directory, which is what lets a caller abandon a failed archive.
///
/// [`finish`]: ZipWriter::finish
pub struct ZipWriter {
    file: File,
    offset: u64,
    central: Vec<CentralRecord>,
    /// The central directory of the archive this one extends, written verbatim
    /// before the new members' records, and how many records it holds.
    prior_directory: Vec<u8>,
    prior_count: u64,
    /// Sizes and offsets at or above this use ZIP64. Always [`ZIP64_LIMIT`] outside
    /// tests, which lower it because exercising ZIP64 for real needs a 4 GiB member.
    zip64_limit: u64,
    zip64_count_limit: u64,
}

impl ZipWriter {
    /// Create the archive at `path`, failing if a file is already there.
    pub fn create(path: &Path) -> Result<Self> {
        let file = File::options()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)
            .with_context(|| format!("cannot create {}", path.display()))?;
        Ok(Self {
            file,
            offset: 0,
            central: Vec::new(),
            prior_directory: Vec::new(),
            prior_count: 0,
            zip64_limit: ZIP64_LIMIT,
            zip64_count_limit: ZIP64_COUNT_LIMIT,
        })
    }

    /// Create the archive at `path` as a copy of the archive at `original`, to which
    /// new members are then added.
    ///
    /// HOW: every byte before the original's central directory (its members, with
    /// their local headers and data, compressed or not) is copied unchanged, and its
    /// central-directory records are kept verbatim; new members go after, and
    /// [`finish`](Self::finish) writes the old records, then the new ones. WHY not
    /// re-pack: the original members stay bit-identical, at the same offsets, with
    /// their own timestamps and compression, so the evidence inside is the
    /// acquisition's own bytes, and nothing is decompressed or recompressed.
    pub fn extend(original: &Path, path: &Path) -> Result<Self> {
        let source =
            File::open(original).with_context(|| format!("cannot open {}", original.display()))?;
        // SAFETY: the map is read-only and only read while this function runs; as with
        // every mapped source, a concurrent truncation of the evidence file would be an
        // operator error outside what the tool can guard against.
        let map = unsafe { memmap2::Mmap::map(&source) }
            .with_context(|| format!("cannot map {}", original.display()))?;
        let cd = crate::core::source::zip::find_cd_location(&map, 0)
            .with_context(|| format!("{} is not a readable zip", original.display()))?;
        let cd_start = usize::try_from(cd.cd_offset)?;
        let cd_end = cd_start
            .checked_add(usize::try_from(cd.cd_size)?)
            .filter(|&end| end <= map.len())
            .context("the original's central directory lies outside the file")?;

        let mut writer = Self::create(path)?;
        for chunk in map[..cd_start].chunks(COPY_CHUNK) {
            writer.write_all(chunk)?;
        }
        writer.prior_directory = map[cd_start..cd_end].to_vec();
        writer.prior_count = cd.total_entries;
        Ok(writer)
    }

    /// Add a file holding `data`, modified at `mtime` (Unix seconds, if known).
    pub fn add_file(
        &mut self,
        name: &str,
        mtime: Option<u64>,
        data: &[u8],
    ) -> Result<WrittenMember> {
        let mut crc = crc32fast::Hasher::new();
        crc.update(data);
        self.write_member(name, mtime, data, crc.finalize(), ATTR_FILE)
    }

    /// Add a directory entry, kept with its own timestamp: when a directory last
    /// changed on the device is itself evidence.
    pub fn add_directory(&mut self, name: &str, mtime: Option<u64>) -> Result<()> {
        let dir_name = if name.ends_with('/') {
            name.to_string()
        } else {
            format!("{name}/")
        };
        self.write_member(&dir_name, mtime, &[], 0, ATTR_DIR)?;
        Ok(())
    }

    /// SHA-256 of a member's bytes as they now sit in the archive.
    ///
    /// Read back from the file rather than taken from the buffer that was written, so
    /// the hash is of what landed: this is the export's silent-copy-error check.
    pub fn sha256_of(&mut self, member: WrittenMember) -> Result<String> {
        self.file
            .seek(SeekFrom::Start(member.data_offset))
            .context("cannot seek in the archive being written")?;
        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; READ_BACK_CHUNK];
        let mut remaining = member.size;
        while remaining > 0 {
            let want = remaining.min(READ_BACK_CHUNK as u64) as usize;
            self.file
                .read_exact(&mut buffer[..want])
                .context("cannot read back the archive being written")?;
            hasher.update(&buffer[..want]);
            remaining -= want as u64;
        }
        self.file
            .seek(SeekFrom::Start(self.offset))
            .context("cannot seek in the archive being written")?;
        Ok(hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect())
    }

    fn write_member(
        &mut self,
        name: &str,
        mtime: Option<u64>,
        data: &[u8],
        crc32: u32,
        external_attrs: u32,
    ) -> Result<WrittenMember> {
        ensure!(
            name.len() <= u16::MAX as usize,
            "member name is longer than a ZIP entry can hold: {name}"
        );
        let header_offset = self.offset;
        let size = data.len() as u64;
        let (dos_date, dos_time) = dos_datetime(mtime);
        let zip64 = size >= self.zip64_limit;

        let mut extra = Vec::new();
        if zip64 {
            push_u16(&mut extra, EXTRA_ZIP64);
            push_u16(&mut extra, 16);
            push_u64(&mut extra, size);
            push_u64(&mut extra, size);
        }
        push_timestamp_extra(&mut extra, mtime);

        let mut header = Vec::with_capacity(30 + name.len() + extra.len());
        push_u32(&mut header, SIG_LFH);
        push_u16(
            &mut header,
            if zip64 {
                VERSION_ZIP64
            } else {
                VERSION_DEFAULT
            },
        );
        push_u16(&mut header, FLAG_UTF8);
        push_u16(&mut header, 0); // method: STORED
        push_u16(&mut header, dos_time);
        push_u16(&mut header, dos_date);
        push_u32(&mut header, crc32);
        let stored = if zip64 { u32::MAX } else { size as u32 };
        push_u32(&mut header, stored); // compressed size
        push_u32(&mut header, stored); // uncompressed size
        push_u16(&mut header, name.len() as u16);
        push_u16(&mut header, extra.len() as u16);
        header.extend_from_slice(name.as_bytes());
        header.extend_from_slice(&extra);

        self.write_all(&header)?;
        let data_offset = self.offset;
        self.write_all(data)?;

        self.central.push(CentralRecord {
            name: name.to_string(),
            crc32,
            size,
            dos_date,
            dos_time,
            mtime,
            header_offset,
            external_attrs,
        });
        Ok(WrittenMember { data_offset, size })
    }

    /// Write the central directory, which is the point the archive becomes valid.
    pub fn finish(mut self) -> Result<()> {
        let cd_offset = self.offset;
        let records = std::mem::take(&mut self.central);
        let count = self.prior_count + records.len() as u64;
        // An extended archive's own records come first, unchanged: their offsets
        // still point at its members, which were copied to the same place.
        let mut directory = std::mem::take(&mut self.prior_directory);
        for record in &records {
            self.push_central_record(&mut directory, record);
        }
        self.write_all(&directory)?;
        let cd_size = directory.len() as u64;
        let eocd64_offset = self.offset;

        let mut tail = Vec::new();
        let zip64 = count >= self.zip64_count_limit
            || cd_offset >= self.zip64_limit
            || cd_size >= self.zip64_limit;
        if zip64 {
            push_u32(&mut tail, SIG_ZIP64_EOCD);
            push_u64(&mut tail, 44); // size of this record after this field
            push_u16(&mut tail, VERSION_MADE_BY);
            push_u16(&mut tail, VERSION_ZIP64);
            push_u32(&mut tail, 0); // this disk
            push_u32(&mut tail, 0); // disk holding the central directory
            push_u64(&mut tail, count);
            push_u64(&mut tail, count);
            push_u64(&mut tail, cd_size);
            push_u64(&mut tail, cd_offset);

            push_u32(&mut tail, SIG_ZIP64_LOCATOR);
            push_u32(&mut tail, 0); // disk holding the ZIP64 record
            push_u64(&mut tail, eocd64_offset);
            push_u32(&mut tail, 1); // total disks
        }
        let saturated = |value: u64, limit: u64, max: u64| if value >= limit { max } else { value };
        let short_count = saturated(count, self.zip64_count_limit, u16::MAX as u64) as u16;
        push_u32(&mut tail, SIG_EOCD);
        push_u16(&mut tail, 0); // this disk
        push_u16(&mut tail, 0); // disk holding the central directory
        push_u16(&mut tail, short_count);
        push_u16(&mut tail, short_count);
        push_u32(
            &mut tail,
            saturated(cd_size, self.zip64_limit, u32::MAX as u64) as u32,
        );
        push_u32(
            &mut tail,
            saturated(cd_offset, self.zip64_limit, u32::MAX as u64) as u32,
        );
        push_u16(&mut tail, 0); // comment length
        self.write_all(&tail)?;
        self.file.sync_all().context("cannot flush the archive")?;
        Ok(())
    }

    fn push_central_record(&self, out: &mut Vec<u8>, record: &CentralRecord) {
        let zip64_size = record.size >= self.zip64_limit;
        let zip64_offset = record.header_offset >= self.zip64_limit;

        let mut extra = Vec::new();
        if zip64_size || zip64_offset {
            let fields = u16::from(zip64_size) * 2 + u16::from(zip64_offset);
            push_u16(&mut extra, EXTRA_ZIP64);
            push_u16(&mut extra, fields * 8);
            if zip64_size {
                push_u64(&mut extra, record.size);
                push_u64(&mut extra, record.size);
            }
            if zip64_offset {
                push_u64(&mut extra, record.header_offset);
            }
        }
        push_timestamp_extra(&mut extra, record.mtime);

        push_u32(out, SIG_CDFH);
        push_u16(out, VERSION_MADE_BY);
        push_u16(
            out,
            if zip64_size || zip64_offset {
                VERSION_ZIP64
            } else {
                VERSION_DEFAULT
            },
        );
        push_u16(out, FLAG_UTF8);
        push_u16(out, 0); // method: STORED
        push_u16(out, record.dos_time);
        push_u16(out, record.dos_date);
        push_u32(out, record.crc32);
        let stored = if zip64_size {
            u32::MAX
        } else {
            record.size as u32
        };
        push_u32(out, stored); // compressed size
        push_u32(out, stored); // uncompressed size
        push_u16(out, record.name.len() as u16);
        push_u16(out, extra.len() as u16);
        push_u16(out, 0); // comment length
        push_u16(out, 0); // disk number
        push_u16(out, 0); // internal attributes
        push_u32(out, record.external_attrs);
        push_u32(
            out,
            if zip64_offset {
                u32::MAX
            } else {
                record.header_offset as u32
            },
        );
        out.extend_from_slice(record.name.as_bytes());
        out.extend_from_slice(&extra);
    }

    fn write_all(&mut self, bytes: &[u8]) -> Result<()> {
        self.file
            .write_all(bytes)
            .context("cannot write to the archive")?;
        self.offset += bytes.len() as u64;
        Ok(())
    }
}

/// The DOS date and time fields for `mtime`, in UTC.
///
/// An unknown time, or one before 1980, becomes 1980-01-01, and one after 2107 the
/// last time the field can hold: the fields cannot represent them, and a bogus device
/// timestamp must not fail the file. The extended timestamp still carries the true
/// value where it can.
fn dos_datetime(mtime: Option<u64>) -> (u16, u16) {
    let Some(time) = mtime.map(UtcTime::from_unix) else {
        return (DOS_EPOCH_DATE, 0);
    };
    if time.year < 1980 {
        return (DOS_EPOCH_DATE, 0);
    }
    if time.year > DOS_MAX_YEAR {
        let date = ((DOS_MAX_YEAR - 1980) << 9) | (12 << 5) | 31;
        return (date as u16, (23 << 11) | (59 << 5) | 29);
    }
    let date = ((time.year - 1980) << 9) | (time.month << 5) | time.day;
    let dos_time = (time.hour << 11) | (time.minute << 5) | (time.second / 2);
    (date as u16, dos_time as u16)
}

/// Append the extended-timestamp field. The local and central forms are identical when
/// only the modification time is present. It holds a signed 32-bit time, so a time
/// past 2038 is left to the DOS field rather than stored wrong.
fn push_timestamp_extra(extra: &mut Vec<u8>, mtime: Option<u64>) {
    if let Some(mtime) = mtime.and_then(|m| i32::try_from(m).ok()) {
        push_u16(extra, EXTRA_TIMESTAMP);
        push_u16(extra, 5);
        extra.push(TIMESTAMP_HAS_MTIME);
        extra.extend_from_slice(&mtime.to_le_bytes());
    }
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::source::Source;
    use crate::core::source::zip::{ZipSource, parse_entries_with_crc};
    use crate::core::util::sha256_hex;

    /// 2026-10-26T07:33:21Z: an odd second, which the DOS field cannot hold.
    const ODD_SECOND: u64 = 1_793_000_001;

    fn write(path: &Path, limit: u64, count_limit: u64) {
        let mut zip = ZipWriter::create(path).unwrap();
        zip.zip64_limit = limit;
        zip.zip64_count_limit = count_limit;
        zip.add_directory("empty", Some(ODD_SECOND)).unwrap();
        let member = zip
            .add_file("data/hello.txt", Some(ODD_SECOND), b"hello")
            .unwrap();
        assert_eq!(zip.sha256_of(member).unwrap(), sha256_hex(b"hello"));
        // Reading back must leave the writer positioned to keep appending.
        zip.add_file("no-time.bin", None, b"xyz").unwrap();
        zip.finish().unwrap();
    }

    fn check(path: &Path) {
        let bytes = std::fs::read(path).unwrap();
        let source = ZipSource::open(&bytes).unwrap();
        let names: Vec<&str> = source.entries().iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["empty/", "data/hello.txt", "no-time.bin"]);

        // The odd second survives through the extended timestamp, for a directory too.
        assert_eq!(source.entries()[0].mtime, Some(ODD_SECOND));
        assert_eq!(source.entries()[1].mtime, Some(ODD_SECOND));
        assert_eq!(&*source.content(&source.entries()[1]).unwrap(), b"hello");
        assert_eq!(&*source.content(&source.entries()[2]).unwrap(), b"xyz");

        let (_, crc) = &parse_entries_with_crc(&bytes).unwrap()[1];
        assert_eq!(*crc, crc32fast::hash(b"hello"));
    }

    #[test]
    fn a_plain_archive_reads_back() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.zip");
        write(&path, ZIP64_LIMIT, ZIP64_COUNT_LIMIT);
        check(&path);
    }

    /// Lowering the limits exercises every ZIP64 record without a 4 GiB member.
    #[test]
    fn a_zip64_archive_reads_back() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.zip");
        write(&path, 1, 1);
        check(&path);
    }

    #[test]
    fn dos_field_is_utc_and_clamped_to_what_it_can_hold() {
        // 2026-10-26 07:33:21 UTC, seconds floored to the 2-second field.
        let (date, time) = dos_datetime(Some(ODD_SECOND));
        assert_eq!(date, (46 << 9) | (10 << 5) | 26);
        assert_eq!(time, (7 << 11) | (33 << 5) | 10);

        assert_eq!(dos_datetime(None), (DOS_EPOCH_DATE, 0));
        assert_eq!(dos_datetime(Some(0)), (DOS_EPOCH_DATE, 0));
        let far_future = 7_000_000_000; // the year 2191
        assert_eq!(dos_datetime(Some(far_future)).0 >> 9, 127);
    }

    #[test]
    fn an_existing_archive_is_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.zip");
        std::fs::write(&path, b"keep").unwrap();
        assert!(ZipWriter::create(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"keep");
    }
}
