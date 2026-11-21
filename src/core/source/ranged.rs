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
//!     slice, so a media file excluded by `--type`/`--fast` is never fetched whole;
//!     [`Source::content_suffix`] reads only the end of a STORED entry (cheap, see
//!     [`Source::cheap_suffix`]), for a format signed at its end.

use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::FileExt;
use std::path::Path;

use anyhow::{Context, Result, ensure};

use crate::core::models::{Encryption, Entry, Location, Method};
use crate::core::source::zip::{self, Coding, SIG_LFH};
use crate::core::source::zip_crypto::ZipPassword;
use crate::core::source::{Content, IntegrityCheck, Source};

/// Bytes read from the tail to locate the EOCD + ZIP64 records. The EOCD may be
/// followed by a comment of up to 65535 bytes, and the tiny ZIP64 records sit just
/// before it, so this window always reaches them.
const TAIL_LEN: u64 = 64 * 1024 + 128;
/// Chunk size for reading a single (possibly multi-GB) entry's data, so one huge
/// file never forces one enormous positioned read.
const CHUNK: usize = 256 * 1024 * 1024;
/// Local File Header fixed size, before the variable name/extra fields.
const LFH_FIXED: u64 = 30;

/// A [`Source`] over a ZIP archive backed by positioned reads.
pub struct RangedZipSource {
    file: File,
    /// The password for encrypted entries, when one was given.
    password: Option<String>,
    /// Public entries. Each [`Location::RangedZip`] carries everything a read
    /// needs (method, LFH offset, compressed length), so [`Source::content`] reads
    /// straight from the entry — no per-call lookup, no O(N) scan over a parallel
    /// table — which matters for an archive with hundreds of thousands of entries.
    entries: Vec<Entry>,
    /// Name → CRC-32, consulted only by [`Source::integrity_check`] on export (not
    /// the search hot path), so a lookup here is rare.
    crc_by_name: HashMap<String, u32>,
}

impl RangedZipSource {
    /// Open `path` and parse its central directory with two positioned reads
    /// (the tail, then the central-directory range) — without mapping the file.
    pub fn open(path: &Path) -> Result<Self> {
        Self::open_with_password(path, None)
    }

    /// [`RangedZipSource::open`], with the password of its encrypted entries,
    /// checked on the smallest one as for a mapped archive.
    pub fn open_with_password(path: &Path, password: Option<&str>) -> Result<Self> {
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
        let mut crc_by_name = HashMap::with_capacity(records.len());
        for ce in records {
            crc_by_name.insert(ce.name.clone(), ce.crc32);
            entries.push(Entry {
                name: ce.name,
                uncompressed_size: ce.uncomp_size,
                mtime: ce.mtime,
                location: Location::RangedZip {
                    method: ce.method,
                    encryption: ce.encryption,
                    header_offset: ce.local_offset,
                    data_len: ce.comp_size,
                },
            });
        }
        let source = Self {
            file,
            password: password.map(str::to_string),
            entries,
            crc_by_name,
        };
        zip::check_password(&source, password.is_some())?;
        Ok(source)
    }

    fn coding(&self, method: Method, encryption: Encryption) -> Coding<'_> {
        Coding {
            method,
            encryption,
            password: match &self.password {
                Some(password) => ZipPassword::Given(password),
                None => ZipPassword::Missing,
            },
        }
    }

    /// Resolve an entry's real data start by reading its Local File Header.
    ///
    /// WHY read the LFH and not reuse the CD's extra length: the LFH carries its
    /// own name/extra lengths, which may differ from the central directory's —
    /// assuming they are equal is a classic ZIP-parsing bug. This is one small
    /// positioned read, done only when the entry is actually read.
    fn data_start(&self, header_offset: u64) -> Result<u64> {
        let header = read_at(&self.file, header_offset, LFH_FIXED as usize)?;
        ensure!(
            zip::read_u32(&header, 0)? == SIG_LFH,
            "bad local file header signature at offset {header_offset}"
        );
        let name_len = zip::read_u16(&header, 26)? as u64;
        let extra_len = zip::read_u16(&header, 28)? as u64;
        Ok(header_offset + LFH_FIXED + name_len + extra_len)
    }
}

/// Read the `Location::RangedZip` fields of an entry, or error if it is not one.
fn ranged_loc(entry: &Entry) -> Result<(Method, u64, u64)> {
    match entry.location {
        Location::RangedZip {
            method,
            header_offset,
            data_len,
            ..
        } => Ok((method, header_offset, data_len)),
        _ => anyhow::bail!(
            "RangedZipSource called on a non-ranged entry: {}",
            entry.name
        ),
    }
}

impl Source for RangedZipSource {
    fn entries(&self) -> &[Entry] {
        &self.entries
    }

    fn content(&self, entry: &Entry) -> Result<Content<'_>> {
        let (method, header_offset, data_len) = ranged_loc(entry)?;
        let encryption = match entry.location {
            Location::RangedZip { encryption, .. } => encryption,
            _ => Encryption::None,
        };
        let start = self.data_start(header_offset)?;
        let raw = read_range_chunked(&self.file, start, data_len)?;
        let content = zip::decode(
            &raw,
            self.coding(method, encryption),
            entry.uncompressed_size,
            &entry.name,
        )?;
        Ok(Content::Owned(content.into_owned()))
    }

    fn byte_size(&self) -> u64 {
        // The archive's on-disk size, matching ZipSource's coverage figure.
        self.file.metadata().map(|m| m.len()).unwrap_or(0)
    }

    /// Resolve the entry's data start by reading its Local File Header — the same
    /// lazy resolution [`Source::content`] does, exposed so a match can report its
    /// exact archive offset. Returns `None` if the entry is not a ranged ZIP entry
    /// or its header cannot be read (degrade to "no absolute offset", never abort).
    fn archive_data_start(&self, entry: &Entry) -> Option<u64> {
        let (_method, header_offset, _data_len) = ranged_loc(entry).ok()?;
        self.data_start(header_offset).ok()
    }

    fn prefers_prefix_classification(&self) -> bool {
        true
    }

    /// Read only the first `max` uncompressed bytes, so a media file excluded by
    /// `--type`/`--fast` is classified without fetching its whole body. For a
    /// STORED entry that is a single small positioned read; a DEFLATE entry reads
    /// its (compressed) range and inflates just the prefix.
    fn content_prefix(&self, entry: &Entry, max: usize) -> Result<Content<'_>> {
        let (method, header_offset, data_len) = ranged_loc(entry)?;
        // Encrypted, or a method not read: no cheap partial read, so the whole
        // entry is decoded (or fails, saying why) and its start kept.
        if entry.is_encrypted() || matches!(method, Method::Other(_)) {
            let mut whole = self.content(entry)?.into_owned();
            whole.truncate(max);
            return Ok(Content::Owned(whole));
        }
        let start = self.data_start(header_offset)?;
        match method {
            Method::Stored => {
                let want = (data_len as usize).min(max);
                Ok(Content::Owned(read_at(&self.file, start, want)?))
            }
            Method::Deflate => {
                let raw = read_range_chunked(&self.file, start, data_len)?;
                let mut out = Vec::new();
                flate2::read::DeflateDecoder::new(&raw[..])
                    .take(max as u64)
                    .read_to_end(&mut out)
                    .with_context(|| format!("failed to inflate prefix of {}", entry.name))?;
                Ok(Content::Owned(out))
            }
            // Decoded whole above.
            Method::Other(_) => unreachable!("an unread method is decoded whole above"),
        }
    }

    /// Only a STORED entry: a DEFLATE stream must be inflated from its start to
    /// reach its end.
    fn cheap_suffix(&self, entry: &Entry) -> bool {
        !entry.is_encrypted() && matches!(ranged_loc(entry), Ok((Method::Stored, _, _)))
    }

    /// Read only the last `max` uncompressed bytes. A STORED entry is one small
    /// positioned read. A DEFLATE stream cannot be entered mid-way, so its range is
    /// read (as [`Self::content_prefix`] does) and inflated as a stream, keeping only
    /// the last `max` bytes in memory, and refused past its declared size, as a full
    /// read (`zip::inflate`) would refuse it.
    fn content_suffix(&self, entry: &Entry, max: usize) -> Result<Content<'_>> {
        let (method, header_offset, data_len) = ranged_loc(entry)?;
        // As for the prefix: decoded whole, its end kept.
        if entry.is_encrypted() || matches!(method, Method::Other(_)) {
            let whole = self.content(entry)?.into_owned();
            let from = whole.len().saturating_sub(max);
            return Ok(Content::Owned(whole[from..].to_vec()));
        }
        let start = self.data_start(header_offset)?;
        match method {
            Method::Stored => {
                let want = (data_len as usize).min(max);
                Ok(Content::Owned(read_at(
                    &self.file,
                    start + data_len - want as u64,
                    want,
                )?))
            }
            Method::Deflate => {
                let raw = read_range_chunked(&self.file, start, data_len)?;
                let expected = entry.uncompressed_size;
                let mut decoder =
                    flate2::read::DeflateDecoder::new(&raw[..]).take(expected.saturating_add(1));
                let mut tail = Vec::with_capacity(max.saturating_mul(2));
                let mut chunk = vec![0u8; 64 * 1024];
                let mut total = 0u64;
                loop {
                    let n = decoder
                        .read(&mut chunk)
                        .with_context(|| format!("failed to inflate {}", entry.name))?;
                    if n == 0 {
                        break;
                    }
                    total += n as u64;
                    // Only the chunk's last `max` bytes can end the stream: copy
                    // just those, and trim what they push out.
                    let keep = &chunk[n.saturating_sub(max)..n];
                    tail.extend_from_slice(keep);
                    if tail.len() > max.saturating_mul(2) {
                        tail.drain(..tail.len() - max);
                    }
                }
                ensure!(
                    total == expected,
                    "inflated size {total} of {} does not match the declared {expected} bytes",
                    entry.name
                );
                tail.drain(..tail.len().saturating_sub(max));
                Ok(Content::Owned(tail))
            }
            // Decoded whole above.
            Method::Other(_) => unreachable!("an unread method is decoded whole above"),
        }
    }

    /// Attest an entry's uncompressed bytes against the central-directory CRC-32,
    /// exactly as [`ZipSource`](super::zip::ZipSource) does (STORED and DEFLATE
    /// alike). A recorded CRC of 0 is treated as "not recorded".
    fn integrity_check(&self, entry: &Entry) -> IntegrityCheck {
        let Some(&expected) = self.crc_by_name.get(&entry.name) else {
            return IntegrityCheck::Unrecorded;
        };
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

/// Positioned `read_exact` at an absolute offset, safe to call from several threads
/// at once on the one `File` (the engine reads entries in parallel).
///
/// Unix uses `pread`, which takes the offset with each call. Windows uses
/// `seek_read`, which does too (ReadFile with an explicit offset).
///
/// WHY not seek-then-read on a cloned handle, as before: a cloned `File` shares
/// its position with the original (Rust's `try_clone` documentation), so two
/// threads seeking and reading at once read at each other's offsets — wrong bytes,
/// found only when a check happened to cover them (a ZipCrypto CRC, on Windows CI).
#[cfg(unix)]
fn read_exact_at(file: &File, buf: &mut [u8], offset: u64) -> std::io::Result<()> {
    file.read_exact_at(buf, offset)
}

#[cfg(windows)]
fn read_exact_at(file: &File, mut buf: &mut [u8], mut offset: u64) -> std::io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !buf.is_empty() {
        match file.seek_read(buf, offset) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "the file ends before the range read",
                ));
            }
            Ok(n) => {
                buf = &mut buf[n..];
                offset += n as u64;
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Any other platform: seek then read, one thread at a time (the position is
/// shared, see above), so a read is never interleaved with another.
#[cfg(not(any(unix, windows)))]
fn read_exact_at(file: &File, buf: &mut [u8], offset: u64) -> std::io::Result<()> {
    use std::io::{Read, Seek, SeekFrom};
    static ONE_AT_A_TIME: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut handle = file;
    handle.seek(SeekFrom::Start(offset))?;
    handle.read_exact(buf)
}
