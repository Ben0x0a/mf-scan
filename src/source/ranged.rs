//! Positioned-read ZIP source for remote (SMB/NFS) archives.
//!
//! Defines: [`RangedZipSource`], a [`Source`] over a ZIP archive that reads it
//! with positioned reads (`pread`) instead of a memory map. It is the answer to a
//! ~1 TB acquisition on a network share: memory-mapping it would turn every search
//! into a storm of single-page faults pulled over the network, whereas listing
//! only needs the tail (EOCD + central directory) and each searched file only its
//! own byte range.
//! Used by: `support::sources` (built instead of [`ZipSource`](super::zip::ZipSource)
//! when the source is remote — auto-detected or forced with `--io-mode ranged`).
//! Uses: the shared ZIP-format decoders in [`super::zip`] (so the central-directory
//! parsing is identical to the mmap source), `std::os::unix::fs::FileExt` for
//! positioned reads, `crc32fast` for the integrity check.
//!
//! ── How it differs from [`ZipSource`](super::zip::ZipSource) ─────────────────
//! Same central-directory walk (one `super::zip::parse_cd_headers` over the CD
//! bytes), but:
//!   • the EOCD + central directory are read by two positioned reads at open, not
//!     mapped;
//!   • each entry keeps its Local File Header offset and resolves its real data
//!     start lazily, the first time the entry is read — so listing a 23 GB archive
//!     never reads every header;
//!   • [`Source::content`] reads exactly the entry's data range (in 256 MiB chunks
//!     for the rare huge file), and [`Source::content_prefix`] reads only a header
//!     slice, so a media file excluded by `--type`/`--fast` is never fetched whole.

use std::fs::File;
use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::FileExt;
use std::path::Path;

use anyhow::{Context, Result, ensure};

use crate::models::{Entry, Location, Method};
use crate::source::zip::{self, SIG_LFH};
use crate::source::{Content, IntegrityCheck, Source};

/// Bytes read from the tail to locate the EOCD + ZIP64 records. The EOCD may be
/// followed by a comment of up to 65535 bytes, and the tiny ZIP64 records sit just
/// before it, so this window always reaches them.
const TAIL_LEN: u64 = 64 * 1024 + 128;
/// Chunk size for reading a single (possibly multi-GB) entry's data, so one huge
/// file never forces one enormous positioned read.
const CHUNK: usize = 256 * 1024 * 1024;
/// Local File Header fixed size, before the variable name/extra fields.
const LFH_FIXED: u64 = 30;

/// Per-entry data needed to read a file's bytes, parallel to the public entries.
struct RangedEntry {
    method: Method,
    /// Absolute offset of the entry's Local File Header.
    header_offset: u64,
    /// On-disk (compressed) data length.
    data_len: u64,
    /// Uncompressed length (the inflate target / STORED length).
    uncomp_size: u64,
    /// CRC-32 of the uncompressed data, from the central directory.
    crc32: u32,
}

/// A [`Source`] over a ZIP archive backed by positioned reads.
pub struct RangedZipSource {
    file: File,
    entries: Vec<Entry>,
    /// Per-entry read metadata, indexed parallel to `entries`.
    meta: Vec<RangedEntry>,
}

impl RangedZipSource {
    /// Open `path` and parse its central directory with two positioned reads
    /// (the tail, then the central-directory range) — without mapping the file.
    pub fn open(path: &Path) -> Result<Self> {
        let file =
            File::open(path).with_context(|| format!("cannot open archive {}", path.display()))?;
        let size = file
            .metadata()
            .with_context(|| format!("cannot stat {}", path.display()))?
            .len();

        // 1) Read the tail and locate the central directory.
        let tail_len = TAIL_LEN.min(size);
        let tail_base = size - tail_len;
        let tail = read_at(&file, tail_base, tail_len as usize)?;
        let loc = zip::find_cd_location(&tail, tail_base)?;

        // 2) Read the central-directory range and walk it (shared with the mmap
        //    source, so the parsing can never drift).
        let cd = read_at(&file, loc.cd_offset, loc.cd_size as usize)
            .context("cannot read the central directory")?;
        let records = zip::parse_cd_headers(&cd, loc.total_entries)?;

        let mut entries = Vec::with_capacity(records.len());
        let mut meta = Vec::with_capacity(records.len());
        for ce in records {
            entries.push(Entry {
                name: ce.name,
                uncompressed_size: ce.uncomp_size,
                mtime: ce.mtime,
                location: Location::RangedZip {
                    method: ce.method,
                    header_offset: ce.local_offset,
                    data_len: ce.comp_size,
                },
            });
            meta.push(RangedEntry {
                method: ce.method,
                header_offset: ce.local_offset,
                data_len: ce.comp_size,
                uncomp_size: ce.uncomp_size,
                crc32: ce.crc32,
            });
        }
        Ok(Self {
            file,
            entries,
            meta,
        })
    }

    /// The metadata index for `entry` (entries/meta are built together, in order).
    fn meta_for(&self, entry: &Entry) -> Result<&RangedEntry> {
        let idx = self
            .entries
            .iter()
            .position(|e| e.name == entry.name)
            .with_context(|| format!("unknown ranged entry {}", entry.name))?;
        Ok(&self.meta[idx])
    }

    /// Resolve an entry's real data start by reading its Local File Header.
    ///
    /// WHY read the LFH and not reuse the CD's extra length: the LFH carries its
    /// own name/extra lengths, which may differ from the central directory's —
    /// assuming they are equal is a classic ZIP-parsing bug. This is one small
    /// positioned read, done only when the entry is actually read.
    fn data_start(&self, meta: &RangedEntry) -> Result<u64> {
        let header = read_at(&self.file, meta.header_offset, LFH_FIXED as usize)?;
        ensure!(
            zip::read_u32(&header, 0)? == SIG_LFH,
            "bad local file header signature at offset {}",
            meta.header_offset
        );
        let name_len = zip::read_u16(&header, 26)? as u64;
        let extra_len = zip::read_u16(&header, 28)? as u64;
        Ok(meta.header_offset + LFH_FIXED + name_len + extra_len)
    }

    /// Read an entry's raw on-disk (compressed) bytes, in chunks for huge files.
    fn read_raw(&self, meta: &RangedEntry) -> Result<Vec<u8>> {
        let start = self.data_start(meta)?;
        read_range_chunked(&self.file, start, meta.data_len)
    }
}

impl Source for RangedZipSource {
    fn entries(&self) -> &[Entry] {
        &self.entries
    }

    fn content(&self, entry: &Entry) -> Result<Content<'_>> {
        let meta = self.meta_for(entry)?;
        let raw = self.read_raw(meta)?;
        match meta.method {
            Method::Stored => Ok(Content::Owned(raw)),
            Method::Deflate => {
                let inflated = zip::inflate(&raw, meta.uncomp_size)
                    .with_context(|| format!("failed to inflate {}", entry.name))?;
                Ok(Content::Owned(inflated))
            }
        }
    }

    fn byte_size(&self) -> u64 {
        // The archive's on-disk size, matching ZipSource's coverage figure.
        self.file.metadata().map(|m| m.len()).unwrap_or(0)
    }

    fn prefers_prefix_classification(&self) -> bool {
        true
    }

    /// Read only the first `max` uncompressed bytes, so a media file excluded by
    /// `--type`/`--fast` is classified without fetching its whole body. For a
    /// STORED entry that is a single small positioned read; a DEFLATE entry reads
    /// its (compressed) range and inflates just the prefix.
    fn content_prefix(&self, entry: &Entry, max: usize) -> Result<Content<'_>> {
        let meta = self.meta_for(entry)?;
        let start = self.data_start(meta)?;
        match meta.method {
            Method::Stored => {
                let want = (meta.data_len as usize).min(max);
                Ok(Content::Owned(read_at(&self.file, start, want)?))
            }
            Method::Deflate => {
                let raw = read_range_chunked(&self.file, start, meta.data_len)?;
                let mut out = Vec::new();
                flate2::read::DeflateDecoder::new(&raw[..])
                    .take(max as u64)
                    .read_to_end(&mut out)
                    .with_context(|| format!("failed to inflate prefix of {}", entry.name))?;
                Ok(Content::Owned(out))
            }
        }
    }

    /// Attest an entry's uncompressed bytes against the central-directory CRC-32,
    /// exactly as [`ZipSource`](super::zip::ZipSource) does (STORED and DEFLATE
    /// alike). A recorded CRC of 0 is treated as "not recorded".
    fn integrity_check(&self, entry: &Entry) -> IntegrityCheck {
        let Ok(meta) = self.meta_for(entry) else {
            return IntegrityCheck::Unrecorded;
        };
        if meta.crc32 == 0 {
            return IntegrityCheck::Unrecorded;
        }
        let Ok(content) = self.content(entry) else {
            return IntegrityCheck::Unrecorded;
        };
        let actual = crc32fast::hash(&content);
        if actual == meta.crc32 {
            IntegrityCheck::Verified { algorithm: "crc32" }
        } else {
            IntegrityCheck::Mismatch {
                algorithm: "crc32",
                expected: format!("{:08x}", meta.crc32),
                actual: format!("{actual:08x}"),
            }
        }
    }
}

/// Read exactly `len` bytes at absolute `offset` into a fresh buffer.
fn read_at(file: &File, offset: u64, len: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    read_exact_at(file, &mut buf, offset)
        .with_context(|| format!("positioned read of {len} bytes at offset {offset} failed"))?;
    Ok(buf)
}

/// Read `total` bytes at `start` in [`CHUNK`]-sized positioned reads, so one
/// multi-GB entry never forces a single enormous read.
fn read_range_chunked(file: &File, start: u64, total: u64) -> Result<Vec<u8>> {
    let mut out = vec![0u8; total as usize];
    let mut done: u64 = 0;
    while done < total {
        let end = (done + CHUNK as u64).min(total);
        let slice = &mut out[done as usize..end as usize];
        read_exact_at(file, slice, start + done)
            .with_context(|| format!("positioned read at offset {} failed", start + done))?;
        done = end;
    }
    Ok(out)
}

/// Positioned `read_exact` at an absolute offset. Unix uses `pread`; the fallback
/// (other platforms) seeks a cloned handle so the shared `File` is left alone.
#[cfg(unix)]
fn read_exact_at(file: &File, buf: &mut [u8], offset: u64) -> std::io::Result<()> {
    file.read_exact_at(buf, offset)
}

#[cfg(not(unix))]
fn read_exact_at(file: &File, buf: &mut [u8], offset: u64) -> std::io::Result<()> {
    use std::io::{Read, Seek, SeekFrom};
    let mut handle = file.try_clone()?;
    handle.seek(SeekFrom::Start(offset))?;
    handle.read_exact(buf)
}
