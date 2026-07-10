//! Tar source: read a `.tar` (or gzip-compressed `.tar.gz`/`.tgz`) as located files.
//!
//! Defines: [`TarSource`], a [`Source`] over a POSIX/USTAR tar archive. Each regular
//! file (and directory placeholder) becomes an [`Entry`] whose bytes are a contiguous
//! range in the backing buffer — the memory-mapped `.tar` (zero-copy) or the
//! decompressed stream of a `.tar.gz`. Gzip is detected by content magic (not
//! extension), so a gzipped tar with any name is handled.
//! Used by: the binary's `support::sources` (opens a `.tar`/`.tar.gz` operand) and,
//! through the [`Source`] trait, the search/diff/export engines.
//! Uses: `crate::core::models::{Entry, Location}`, `flate2` (gunzip), `memmap2`, `anyhow`.
//!
//! Why hand-rolled (not the `tar` crate): the codebase parses its containers by hand
//! (see `zip`) for full bounds-checking control and the forensic "degrade, don't die"
//! rule — a truncated or garbage header stops enumeration cleanly rather than aborting
//! the scan. A tar is a flat sequence of 512-byte-header + data blocks, so the reader
//! stays small. USTAR name+prefix, GNU long names (`L`), and PAX (`x`) `path`/`size`
//! overrides are handled — enough for real iOS/Android extractions with long paths.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result, bail};
use flate2::read::MultiGzDecoder;

use crate::core::models::{Entry, Location};
use crate::core::source::{Content, Source, nested};

/// A tar block: header and data are both padded to this size.
const BLOCK: usize = 512;

/// How a [`TarSource`]'s bytes are backed, which decides whether byte offsets are
/// true file offsets (a carve coordinate) or index a decompressed stream.
enum Backing {
    /// A memory map of a plain `.tar` — offsets are true offsets in the file.
    Mapped(memmap2::Mmap),
    /// The decompressed stream of a `.tar.gz`/`.tgz` — offsets index the stream,
    /// not the on-disk file, so they are not archive carve coordinates.
    Owned(Vec<u8>),
}

impl Backing {
    fn bytes(&self) -> &[u8] {
        match self {
            Backing::Mapped(m) => m,
            Backing::Owned(v) => v,
        }
    }

    /// Whether byte offsets into [`bytes`](Self::bytes) are true offsets in the
    /// on-disk file (a plain `.tar`) rather than into a decompressed stream.
    fn physical(&self) -> bool {
        matches!(self, Backing::Mapped(_))
    }
}

/// A [`Source`] backed by a tar archive (plain or gzip-compressed).
///
/// Parses the whole block sequence once on [`TarSource::open`], then serves each
/// entry's bytes straight from the backing buffer (always zero-copy — tar stores
/// files uncompressed and contiguous).
pub struct TarSource {
    backing: Backing,
    entries: Vec<Entry>,
}

impl TarSource {
    /// Open `path` as a tar source, transparently decompressing a gzip stream.
    ///
    /// Detection is by content (the gzip magic `1f 8b`), not extension, so a
    /// gzipped tar with any name is handled. A plain `.tar` is memory-mapped
    /// (zero-copy, physical offsets); a `.tar.gz` is decompressed into memory,
    /// bounded by the shared arena budget so a crafted gzip cannot exhaust RAM.
    pub fn open(path: &Path) -> Result<Self> {
        let file = File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
        // SAFETY: read-only map of evidence opened read-only — the same discipline
        // as the ZIP and large-loose-file mmap paths.
        let map = unsafe { memmap2::Mmap::map(&file) }
            .with_context(|| format!("cannot map {}", path.display()))?;
        let backing = if map.starts_with(&[0x1f, 0x8b]) {
            let bytes =
                gunzip(&map).with_context(|| format!("cannot decompress {}", path.display()))?;
            Backing::Owned(bytes)
        } else {
            Backing::Mapped(map)
        };
        let entries = parse_entries(backing.bytes());
        Ok(Self { backing, entries })
    }
}

impl Source for TarSource {
    fn entries(&self) -> &[Entry] {
        &self.entries
    }

    fn content(&self, entry: &Entry) -> Result<Content<'_>> {
        let Location::Tar {
            data_offset,
            data_len,
        } = &entry.location
        else {
            bail!(
                "TarSource::content called on a non-tar entry: {}",
                entry.name
            );
        };
        let bytes = self.backing.bytes();
        let start = *data_offset as usize;
        let end = start
            .checked_add(*data_len as usize)
            .filter(|&e| e <= bytes.len())
            .with_context(|| format!("tar entry {} data range out of bounds", entry.name))?;
        Ok(Content::Borrowed(&bytes[start..end]))
    }

    fn byte_size(&self) -> u64 {
        self.backing.bytes().len() as u64
    }

    /// A plain `.tar` entry's data offset is a true file offset (a real carve
    /// coordinate); a `.tar.gz` entry's offset indexes the decompressed stream, so
    /// no absolute archive byte can be reported (like a loose/nested entry).
    fn archive_data_start(&self, entry: &Entry) -> Option<u64> {
        match &entry.location {
            Location::Tar { data_offset, .. } if self.backing.physical() => Some(*data_offset),
            _ => None,
        }
    }
}

/// Decompress a gzip stream, bounded by the nested-archive arena budget so a
/// crafted `.tar.gz` cannot exhaust memory (a top-level tar.gz must be inflated
/// whole to random-access it, unlike a zip's per-entry inflate).
fn gunzip(compressed: &[u8]) -> Result<Vec<u8>> {
    let budget = nested::NESTED_ARENA_BUDGET;
    let mut out = Vec::new();
    // `MultiGzDecoder` handles a gzip made of several concatenated members (what
    // `gzip a b > out.gz` or some tar tools produce). `take(budget + 1)` lets us
    // detect an overrun: reading budget+1 bytes means it exceeds the cap.
    MultiGzDecoder::new(compressed)
        .take(budget + 1)
        .read_to_end(&mut out)?;
    if out.len() as u64 > budget {
        bail!(
            "decompressed tar exceeds the {} MiB budget",
            budget / (1024 * 1024)
        );
    }
    Ok(out)
}

/// Walk the tar block sequence, yielding one [`Entry`] per regular file and
/// directory placeholder. Stops cleanly at the end-of-archive marker (a zero
/// block), at EOF, or on the first header that fails its checksum (lost sync /
/// trailing garbage) — never panics on a malformed archive.
fn parse_entries(data: &[u8]) -> Vec<Entry> {
    let mut entries = Vec::new();
    let mut pos = 0usize;
    // Overrides carried from a preceding GNU long-name (`L`) or PAX (`x`) header;
    // each applies to the very next file/dir header, then is consumed.
    let mut long_name: Option<String> = None;
    let mut pax_path: Option<String> = None;
    let mut pax_size: Option<u64> = None;

    while pos + BLOCK <= data.len() {
        let header = &data[pos..pos + BLOCK];
        // A zero block marks the end of the archive (POSIX writes two; one is enough).
        if header.iter().all(|&b| b == 0) {
            break;
        }
        // A bad checksum means we have lost sync with the block stream; stop rather
        // than fabricate entries from garbage.
        if !checksum_ok(header) {
            break;
        }
        let size = match pax_size.take().or_else(|| parse_octal(&header[124..136])) {
            Some(s) => s,
            None => break, // unreadable size ⇒ we can't find the next header
        };
        let data_start = pos + BLOCK;
        // Data is `size` bytes padded up to the next block boundary.
        let Some(data_end) = data_start.checked_add(size as usize) else {
            break;
        };
        if data_end > data.len() {
            break; // truncated archive: the entry's data is not fully present
        }
        let next = data_start + (size as usize).next_multiple_of(BLOCK);
        let typeflag = header[156];

        match typeflag {
            // GNU long name: this entry's DATA is the full path for the NEXT header.
            b'L' => long_name = Some(read_cstr(&data[data_start..data_end])),
            // PAX extended header: records override the next entry's path/size.
            b'x' | b'g' => {
                let recs = &data[data_start..data_end];
                if let Some(p) = pax_value(recs, "path") {
                    pax_path = Some(p);
                }
                if let Some(s) = pax_value(recs, "size").and_then(|v| v.parse().ok()) {
                    pax_size = Some(s);
                }
            }
            // Regular file (`0`/NUL, or `7` contiguous treated as regular).
            b'0' | 0 | b'7' => {
                let name = take_name(&mut long_name, &mut pax_path, header);
                entries.push(Entry {
                    name,
                    uncompressed_size: size,
                    mtime: parse_octal(&header[136..148]),
                    location: Location::Tar {
                        data_offset: data_start as u64,
                        data_len: size,
                    },
                });
            }
            // Directory placeholder (name ends with `/`, like a ZIP dir entry).
            b'5' => {
                let mut name = take_name(&mut long_name, &mut pax_path, header);
                if !name.ends_with('/') {
                    name.push('/');
                }
                entries.push(Entry {
                    name,
                    uncompressed_size: 0,
                    mtime: parse_octal(&header[136..148]),
                    location: Location::Tar {
                        data_offset: data_start as u64,
                        data_len: 0,
                    },
                });
            }
            // Symlinks, hardlinks, devices, etc.: not searchable content. Consume
            // any pending overrides so they don't leak onto a later entry.
            _ => {
                long_name = None;
                pax_path = None;
            }
        }
        pos = next;
    }
    entries
}

/// Resolve an entry's name, preferring a pending GNU long name, then a PAX `path`,
/// then the USTAR `prefix` + `name` fields; consumes whichever override it used.
fn take_name(
    long_name: &mut Option<String>,
    pax_path: &mut Option<String>,
    header: &[u8],
) -> String {
    let raw = long_name
        .take()
        .or_else(|| pax_path.take())
        .unwrap_or_else(|| ustar_name(header));
    // Tars commonly prefix entries with `./`; drop it for names that read like the
    // zip/folder sources' relative paths.
    raw.strip_prefix("./").unwrap_or(&raw).to_string()
}

/// Join the USTAR `prefix` (bytes 345..500) and `name` (bytes 0..100) fields with
/// `/`, as the format specifies for paths longer than 100 bytes.
fn ustar_name(header: &[u8]) -> String {
    let name = read_cstr(&header[0..100]);
    let prefix = read_cstr(&header[345..500]);
    if prefix.is_empty() {
        name
    } else {
        format!("{prefix}/{name}")
    }
}

/// Read a NUL-terminated (or field-length) string, lossily decoded as UTF-8.
fn read_cstr(field: &[u8]) -> String {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    String::from_utf8_lossy(&field[..end]).into_owned()
}

/// Parse a tar numeric field: octal ASCII (space/NUL padded), or GNU base-256 when
/// the top bit of the first byte is set (used for sizes above 8 GiB).
fn parse_octal(field: &[u8]) -> Option<u64> {
    if let Some(&first) = field.first()
        && first & 0x80 != 0
    {
        // GNU base-256: the low 7 bits of the first byte, then big-endian bytes.
        let mut value: u64 = (first & 0x7f) as u64;
        for &b in &field[1..] {
            value = value.checked_shl(8)?.checked_add(b as u64)?;
        }
        return Some(value);
    }
    let s = read_cstr(field);
    let digits = s.trim();
    if digits.is_empty() {
        return Some(0);
    }
    u64::from_str_radix(digits, 8).ok()
}

/// Verify the header checksum: the sum of all 512 bytes with the 8 checksum bytes
/// (148..156) taken as spaces, matching the octal value stored in that field.
/// Accepts both the unsigned and (historic) signed-byte sums.
fn checksum_ok(header: &[u8]) -> bool {
    let Some(stored) = parse_octal(&header[148..156]) else {
        return false;
    };
    let mut unsigned: u64 = 0;
    let mut signed: i64 = 0;
    for (i, &b) in header.iter().enumerate() {
        let byte = if (148..156).contains(&i) { b' ' } else { b };
        unsigned += byte as u64;
        signed += byte as i8 as i64;
    }
    stored == unsigned || stored as i64 == signed
}

/// Extract a PAX record value by key. Records are `LENGTH KEY=VALUE\n`, where
/// `LENGTH` is the decimal byte length of the whole record including itself.
fn pax_value(mut recs: &[u8], key: &str) -> Option<String> {
    while !recs.is_empty() {
        // Split off the leading decimal length and the following space.
        let sp = recs.iter().position(|&b| b == b' ')?;
        let len: usize = std::str::from_utf8(&recs[..sp]).ok()?.parse().ok()?;
        if len == 0 || len > recs.len() {
            return None;
        }
        let record = &recs[sp + 1..len]; // `KEY=VALUE\n`
        if let Some(eq) = record.iter().position(|&b| b == b'=') {
            let k = std::str::from_utf8(&record[..eq]).ok()?;
            if k == key {
                let mut v = &record[eq + 1..];
                if v.last() == Some(&b'\n') {
                    v = &v[..v.len() - 1];
                }
                return Some(String::from_utf8_lossy(v).into_owned());
            }
        }
        recs = &recs[len..];
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// Build one USTAR 512-byte header with a valid checksum.
    fn header(name: &str, size: usize, typeflag: u8) -> [u8; BLOCK] {
        let mut h = [0u8; BLOCK];
        let nb = name.as_bytes();
        let n = nb.len().min(100);
        h[..n].copy_from_slice(&nb[..n]);
        h[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
        h[136..148].copy_from_slice(b"00000000000\0"); // mtime 0
        h[156] = typeflag;
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        set_checksum(&mut h);
        h
    }

    /// Compute and write the header checksum (bytes 148..156 taken as spaces).
    fn set_checksum(h: &mut [u8; BLOCK]) {
        for b in &mut h[148..156] {
            *b = b' ';
        }
        let sum: u64 = h.iter().map(|&b| b as u64).sum();
        h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    }

    /// Assemble a plain tar from `(name, data)` pairs, terminated by two zero blocks.
    fn build_tar(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (name, data) in files {
            out.extend_from_slice(&header(name, data.len(), b'0'));
            out.extend_from_slice(data);
            out.resize(out.len() + (BLOCK - data.len() % BLOCK) % BLOCK, 0);
        }
        out.resize(out.len() + 2 * BLOCK, 0); // end-of-archive marker
        out
    }

    #[test]
    fn parses_files_with_offsets_and_sizes() {
        let tar = build_tar(&[("a.txt", b"hello"), ("dir/b.bin", b"abcdef")]);
        let entries = parse_entries(&tar);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "a.txt");
        assert_eq!(entries[0].uncompressed_size, 5);
        assert_eq!(
            entries[0].location,
            Location::Tar {
                data_offset: 512, // first header at 0, data follows
                data_len: 5,
            }
        );
        // Second entry: 512 header + 512 (padded 5-byte data) = header at 1024, data 1536.
        assert_eq!(entries[1].name, "dir/b.bin");
        assert_eq!(
            entries[1].location,
            Location::Tar {
                data_offset: 1536,
                data_len: 6,
            }
        );
    }

    #[test]
    fn joins_ustar_prefix_and_name() {
        let mut h = header("name.txt", 0, b'0');
        let prefix = b"long/prefix/path";
        h[345..345 + prefix.len()].copy_from_slice(prefix);
        set_checksum(&mut h);
        let mut tar = h.to_vec();
        tar.resize(tar.len() + 2 * BLOCK, 0);
        let entries = parse_entries(&tar);
        assert_eq!(entries[0].name, "long/prefix/path/name.txt");
    }

    #[test]
    fn strips_leading_dot_slash() {
        let tar = build_tar(&[("./data/x.txt", b"y")]);
        assert_eq!(parse_entries(&tar)[0].name, "data/x.txt");
    }

    #[test]
    fn stops_on_bad_checksum_rather_than_emitting_junk() {
        let mut tar = build_tar(&[("a.txt", b"hi")]);
        tar[148] = b'9'; // corrupt the stored checksum (9 is not even octal)
        assert!(parse_entries(&tar).is_empty());
    }

    #[test]
    fn parses_octal_and_gnu_base256_sizes() {
        assert_eq!(parse_octal(b"0000000012\0 "), Some(0o12));
        assert_eq!(parse_octal(b"           "), Some(0)); // all spaces ⇒ 0
        // GNU base-256: 0x80 flag, then big-endian 0x00_00_01_00 = 256.
        assert_eq!(parse_octal(&[0x80, 0x00, 0x00, 0x01, 0x00]), Some(256));
    }

    /// Build one PAX record `LEN KEY=VALUE\n`, where `LEN` is the total record
    /// byte length including itself (solved by fixpoint since it is self-referential).
    fn pax_record(key: &str, value: &str) -> String {
        let body = format!("{key}={value}\n");
        let mut len = body.len() + 2;
        loop {
            let candidate = format!("{len} {body}");
            if candidate.len() == len {
                return candidate;
            }
            len = candidate.len();
        }
    }

    #[test]
    fn pax_path_override_is_used() {
        // A PAX 'x' header carrying a long path, followed by the real file header
        // whose name field is a short placeholder.
        let long = "a/very/long/pax/path/that/exceeds/the/ustar/name/field/limit.txt";
        let pax = pax_record("path", long);

        let mut tar = Vec::new();
        tar.extend_from_slice(&header("PaxHeaders/placeholder", pax.len(), b'x'));
        tar.extend_from_slice(pax.as_bytes());
        tar.resize(tar.len() + (BLOCK - pax.len() % BLOCK) % BLOCK, 0);
        tar.extend_from_slice(&header("placeholder", 3, b'0'));
        tar.extend_from_slice(b"abc");
        tar.resize(tar.len() + (BLOCK - 3) % BLOCK, 0);
        tar.resize(tar.len() + 2 * BLOCK, 0);

        let entries = parse_entries(&tar);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, long);
        assert_eq!(entries[0].uncompressed_size, 3);
    }

    #[test]
    fn content_and_physical_offset_through_a_real_file() {
        let dir = tempdir().unwrap();
        let tar = build_tar(&[("note.txt", b"needle-bytes")]);
        let path = dir.path().join("a.tar");
        std::fs::write(&path, &tar).unwrap();

        let src = TarSource::open(&path).unwrap();
        assert_eq!(src.entries().len(), 1);
        let e = &src.entries()[0];
        assert_eq!(&*src.content(e).unwrap(), b"needle-bytes");
        // A plain `.tar` is memory-mapped, so the data offset is a true file offset.
        assert_eq!(src.archive_data_start(e), Some(512));
    }
}
