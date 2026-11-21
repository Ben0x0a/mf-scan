//! 7z source: read a `.7z` archive, plain or AES-encrypted, as located files.
//!
//! Defines: [`SevenZSource`] (a [`Source`] over a 7z archive), [`is_seven_z`] (its
//! signature), [`Unlock`] (whether, and how, a password opened it).
//! Used by: `mod::sniff_container` (is a file a 7z?), the binary's `support::sources`
//! (opens a 7z operand), `formats::inspect::identify::archive` (the `7z` type name),
//! and, through the [`Source`] trait, the search/diff/export engines.
//! Uses: `sevenz-rust2` (the 7z reader: LZMA, LZMA2, PPMd, BZip2, the BCJ filters,
//! AES-256), `spool`, `memmap2`, `crate::core::models::{Entry, Location}`.
//!
//! HOW: the archive's header is read first without a password. A header that needs
//! one (`7z a -mhe=on`) is read again with the password given; data blocks that need
//! one are found from their coders before any is decoded. Then every block is decoded
//! once, in order, into the spool, and each member's range in that decoded stream
//! becomes its [`Location::SevenZ`].
//!
//! WHY decode it all up front: 7z compresses files together in "solid" blocks, so one
//! file can only be read by decoding every file before it in its block. Decoding each
//! block once, whole, makes every read afterwards a slice, as for a compressed tar.
//!
//! WHY a hand-made tar but a crate here: a tar is a flat list of headers; a 7z is a
//! graph of coders (compression, filters, encryption) over packed streams, with its
//! own LZMA, PPMd and AES key derivation. `sevenz-rust2` is pure Rust and verifies
//! what the format stores: every member's CRC-32 and every block's decoded size.
//!
//! Every failure is an error naming the file: a missing or wrong password, a CRC that
//! does not match, a method this build does not decode (Deflate, Deflate64, and the
//! zstd/brotli/lz4 methods only some 7-Zip forks write). A 7z is never read as a
//! smaller archive.

use std::fs::File;
use std::io::Cursor;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use sevenz_rust2::{Archive, ArchiveReader, EncoderMethod, EntryDecision, Error, Password};

use crate::core::models::{Entry, Location};
use crate::core::source::spool::Spool;
use crate::core::source::{Content, Source};

/// The 7z signature header's first six bytes.
const SEVEN_Z_MAGIC: [u8; 6] = [b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C];
/// How much is read from a member at a time.
const CHUNK: usize = 1024 * 1024;
/// 100-nanosecond intervals from 1601-01-01 (the NT epoch) to the Unix epoch.
const NT_TO_UNIX_TICKS: u64 = 116_444_736_000_000_000;
/// 100-nanosecond intervals in a second.
const TICKS_PER_SECOND: u64 = 10_000_000;

/// Whether `head`, a file's first bytes, is a 7z signature header.
pub fn is_seven_z(head: &[u8]) -> bool {
    head.starts_with(&SEVEN_Z_MAGIC)
}

/// What the password did for a 7z archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unlock {
    /// Nothing is encrypted; no password was used.
    NotEncrypted,
    /// The file data is encrypted, the list of files is not.
    Data,
    /// The list of files is encrypted too (`-mhe=on`).
    HeaderAndData,
}

/// A [`Source`] backed by a 7z archive, every block decoded once on open.
pub struct SevenZSource {
    /// The archive exactly as it is on disk, for `--verify` (which attests the
    /// evidence file, not the bytes it decodes to).
    raw: memmap2::Mmap,
    /// Every block's decoded bytes, in order; entries index into it.
    decoded: Content<'static>,
    entries: Vec<Entry>,
    unlock: Unlock,
}

impl SevenZSource {
    /// Open `path`, decoding every block. `password` is used only if something in the
    /// archive is encrypted.
    pub fn open(path: &Path, password: Option<&str>) -> Result<Self> {
        let file = File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
        // SAFETY: read-only map of evidence opened read-only — the same discipline
        // as the ZIP and tar mmap paths.
        let raw = unsafe { memmap2::Mmap::map(&file) }
            .with_context(|| format!("cannot map {}", path.display()))?;
        let (archive, header_encrypted) = read_header(&raw, password)
            .with_context(|| format!("cannot read the 7z {}", path.display()))?;

        let data_encrypted = archive.blocks.iter().any(|block| {
            block
                .coders
                .iter()
                .any(|coder| coder.encoder_method_id() == EncoderMethod::ID_AES256_SHA256)
        });
        let unlock = match (header_encrypted, data_encrypted) {
            (true, _) => Unlock::HeaderAndData,
            (false, true) => Unlock::Data,
            (false, false) => Unlock::NotEncrypted,
        };
        // Checked before decoding, so the message names the cause, not a decoder
        // failure deep in the first block.
        let password = match (unlock, password) {
            (Unlock::NotEncrypted, _) => Password::empty(),
            (_, Some(p)) => Password::from(p),
            (_, None) => bail!(
                "{} is an encrypted 7z: pass its password with --archive-password (or \
                 MFSCAN_ARCHIVE_PASSWORD)",
                path.display()
            ),
        };

        let reader = ArchiveReader::from_archive(archive, Cursor::new(&raw[..]), password);
        let (decoded, entries) = decode_all(reader, unlock)
            .with_context(|| format!("cannot decompress the 7z {}", path.display()))?;
        Ok(Self {
            raw,
            decoded,
            entries,
            unlock,
        })
    }

    /// What the password did, for the provenance line.
    pub fn unlock(&self) -> Unlock {
        self.unlock
    }

    /// The archive exactly as stored on disk, for `--verify` attestation.
    pub fn raw_bytes(&self) -> &[u8] {
        &self.raw
    }
}

impl Source for SevenZSource {
    fn entries(&self) -> &[Entry] {
        &self.entries
    }

    fn content(&self, entry: &Entry) -> Result<Content<'_>> {
        let Location::SevenZ {
            data_offset,
            data_len,
        } = &entry.location
        else {
            bail!(
                "SevenZSource::content called on a non-7z entry: {}",
                entry.name
            );
        };
        let bytes: &[u8] = &self.decoded;
        let start = usize::try_from(*data_offset)?;
        let end = start
            .checked_add(usize::try_from(*data_len)?)
            .filter(|&e| e <= bytes.len())
            .with_context(|| format!("7z entry {} data range out of bounds", entry.name))?;
        Ok(Content::Borrowed(&bytes[start..end]))
    }

    fn byte_size(&self) -> u64 {
        self.decoded.len() as u64
    }
}

/// The archive's header, and whether reading it needed the password.
///
/// HOW: read without a password; only a header that asks for one is read again
/// with `password`. WHY two reads: whether the header is encrypted is known only by
/// trying, and it decides the provenance reported.
fn read_header(raw: &[u8], password: Option<&str>) -> Result<(Archive, bool)> {
    match Archive::read(&mut Cursor::new(raw), &Password::empty()) {
        Ok(archive) => Ok((archive, false)),
        Err(Error::PasswordRequired) => {
            let Some(password) = password else {
                bail!(
                    "its list of files is encrypted: pass its password with \
                     --archive-password (or MFSCAN_ARCHIVE_PASSWORD)"
                );
            };
            let archive =
                Archive::read(&mut Cursor::new(raw), &Password::from(password)).map_err(|e| {
                    anyhow!(
                        "its list of files is encrypted, and the password given does not \
                         decrypt it ({})",
                        describe(&e)
                    )
                })?;
            Ok((archive, true))
        }
        Err(e) => Err(anyhow!(describe(&e))),
    }
}

/// Every block of `reader` decoded into the spool, and one [`Entry`] per member.
fn decode_all(
    mut reader: ArchiveReader<Cursor<&[u8]>>,
    unlock: Unlock,
) -> Result<(Content<'static>, Vec<Entry>)> {
    let mut spool = Spool::new("the 7z archive");
    let mut entries = Vec::new();
    // A spool write that failed: the crate's callback cannot carry it, so it stops
    // the walk and is returned below.
    let mut failure = None;
    let mut buffer = vec![0u8; CHUNK];
    let walked = reader.for_each_entries_with_decision(|member, data| {
        // An anti-item marks a file deleted by an update archive: it has no data.
        if member.is_anti_item {
            return Ok(EntryDecision::Continue);
        }
        let start = spool.len();
        loop {
            let n = data.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            if let Err(e) = spool.write(&buffer[..n]) {
                failure = Some(e);
                return Ok(EntryDecision::Stop);
            }
        }
        let mut name = member.name.clone();
        if member.is_directory && !name.ends_with('/') {
            name.push('/');
        }
        let data_len = spool.len() - start;
        entries.push(Entry {
            name,
            uncompressed_size: data_len,
            mtime: member
                .has_last_modified_date
                .then(|| unix_seconds(member.last_modified_date.into()))
                .flatten(),
            location: Location::SevenZ {
                data_offset: start,
                data_len,
            },
        });
        Ok(EntryDecision::Continue)
    });
    if let Some(e) = failure {
        return Err(e);
    }
    walked.map_err(|e| match unlock {
        Unlock::NotEncrypted => anyhow!(describe(&e)),
        _ => anyhow!(
            "{} (the archive is encrypted: a wrong password reads as damaged data)",
            describe(&e)
        ),
    })?;
    Ok((spool.finish()?, entries))
}

/// An NT file time (100 ns since 1601) as Unix seconds; `None` before 1970.
fn unix_seconds(ticks: u64) -> Option<u64> {
    ticks
        .checked_sub(NT_TO_UNIX_TICKS)
        .map(|t| t / TICKS_PER_SECOND)
}

/// A reader error in words. WHY: the crate prints its errors with `Debug`, which
/// nests the cause of a failed check inside an I/O error.
fn describe(error: &Error) -> String {
    let inner = |e: &std::io::Error| {
        e.get_ref()
            .and_then(|cause| cause.downcast_ref::<Error>())
            .map(describe)
            .unwrap_or_else(|| e.to_string())
    };
    match error {
        Error::BadSignature(_) => "not a 7z archive".to_string(),
        Error::ChecksumVerificationFailed => {
            "a member's CRC-32 does not match its data".to_string()
        }
        Error::NextHeaderCrcMismatch => "the header's CRC-32 does not match".to_string(),
        Error::PasswordRequired => "a password is needed".to_string(),
        Error::MaybeBadPassword(e) => format!("wrong password, or damaged data: {}", inner(e)),
        Error::UnsupportedCompressionMethod(method) => {
            format!("a compression method this build does not decode ({method})")
        }
        Error::Io(e, context) if context.is_empty() => inner(e),
        Error::Io(e, context) => format!("{context}: {}", inner(e)),
        Error::Other(message) | Error::Unsupported(message) => message.to_string(),
        other => format!("{other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nt_time_converts_to_unix_seconds() {
        // 2023-11-14T22:13:20Z, the fixtures' mtime.
        assert_eq!(
            unix_seconds(NT_TO_UNIX_TICKS + 1_700_000_000 * TICKS_PER_SECOND),
            Some(1_700_000_000)
        );
        assert_eq!(unix_seconds(0), None);
    }

    // Made by 7-Zip 26.06 from one tree: see `tests/fixtures/README.md`.
    const PASSWORD: &str = "fixture-password";

    fn fixture(name: &str) -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/sevenz")
            .join(name)
    }

    fn read(source: &SevenZSource, name: &str) -> Vec<u8> {
        let entry = source
            .entries()
            .iter()
            .find(|e| e.name == name)
            .unwrap_or_else(|| panic!("no {name}"));
        source.content(entry).unwrap().into_owned()
    }

    #[test]
    fn every_method_and_encryption_reads_every_member() {
        let filler: String = (0..2000)
            .map(|i| format!("line {i} of filler text\n"))
            .collect();
        for (name, password, unlock) in [
            ("note.7z", None, Unlock::NotEncrypted),
            ("note.ppmd.7z", None, Unlock::NotEncrypted),
            ("note.bzip2.7z", None, Unlock::NotEncrypted),
            ("note.aes.7z", Some(PASSWORD), Unlock::Data),
            ("note.aes-header.7z", Some(PASSWORD), Unlock::HeaderAndData),
        ] {
            let source = SevenZSource::open(&fixture(name), password).unwrap();
            assert_eq!(source.unlock(), unlock, "{name}");
            // Both members of the one solid block, each its own slice.
            assert_eq!(
                read(&source, "evidence/note.txt"),
                b"needle in a 7z\n",
                "{name}"
            );
            assert_eq!(
                read(&source, "evidence/filler.txt"),
                filler.as_bytes(),
                "{name}"
            );
            assert_eq!(read(&source, "evidence/empty.txt"), b"", "{name}");
            let names: Vec<&str> = source.entries().iter().map(|e| e.name.as_str()).collect();
            assert!(names.contains(&"evidence/empty-dir/"), "{name}: {names:?}");
            assert!(names.contains(&"evidence/"), "{name}: {names:?}");
            let note = source
                .entries()
                .iter()
                .find(|e| e.name == "evidence/note.txt");
            assert_eq!(note.unwrap().mtime, Some(1_700_000_000), "{name}");
            assert_eq!(source.raw_bytes(), std::fs::read(fixture(name)).unwrap());
        }
    }

    #[test]
    fn a_password_given_to_a_plain_archive_is_not_used() {
        let source = SevenZSource::open(&fixture("note.7z"), Some("unused")).unwrap();
        assert_eq!(source.unlock(), Unlock::NotEncrypted);
    }

    #[test]
    fn a_missing_or_wrong_password_fails_loudly() {
        for name in ["note.aes.7z", "note.aes-header.7z"] {
            let Err(e) = SevenZSource::open(&fixture(name), None) else {
                panic!("{name}: opened without its password");
            };
            assert!(
                format!("{e:#}").contains("--archive-password"),
                "{name}: {e:#}"
            );
            assert!(
                SevenZSource::open(&fixture(name), Some("not the password")).is_err(),
                "{name}: opened with a wrong password"
            );
        }
    }

    #[test]
    fn a_damaged_archive_or_an_unknown_method_fails_loudly() {
        let dir = tempfile::tempdir().unwrap();
        for name in ["note.7z", "note.ppmd.7z", "note.bzip2.7z", "note.aes.7z"] {
            // A byte in the packed data (which starts after the 32-byte signature
            // header), never a shorter or altered result.
            let mut bytes = std::fs::read(fixture(name)).unwrap();
            bytes[40] ^= 0x55;
            let path = dir.path().join(name);
            std::fs::write(&path, &bytes).unwrap();
            let password = name.contains("aes").then_some(PASSWORD);
            assert!(
                SevenZSource::open(&path, password).is_err(),
                "{name}: a damaged archive must fail"
            );
        }
        let Err(e) = SevenZSource::open(&fixture("note.deflate.7z"), None) else {
            panic!("a Deflate 7z must fail in a build without Deflate");
        };
        assert!(format!("{e:#}").contains("does not decode"), "{e:#}");
    }
}
