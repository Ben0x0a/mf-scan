//! Compressed streams: which compression a file uses, by its magic, and its decoding.
//!
//! Defines: `Compression` (gzip, bzip2, xz, zstd): `of` (recognise the magic), `decode`
//! (the whole stream, spooled) and `head` (its first bytes, to recognise what it holds).
//! Used by: `tar` (a compressed tar), `mod::sniff_container` (is a compressed file a
//! tar?), `formats::inspect::identify::archive` (the `--type` names of the four).
//! Uses: `flate2`, `bzip2`, `lzma-rust2` (xz), `ruzstd` (zstd), `spool`.
//!
//! WHY one place: the magic table and the decoders are needed both to decide what a
//! file is and to read it; two copies would drift (a format recognised but not read).
//! WHY pure-Rust decoders: no C toolchain on any release platform, and one audited
//! language for the code that reads evidence.
//!
//! Every decoder reads every concatenated stream or member (what parallel compressors
//! and `cat a.gz b.gz` produce), and verifies the checks the format carries: CRC-32
//! (gzip, bzip2), the xz block check, the zstd content checksum. A stream that fails
//! a check, or ends early, is an error, never a shorter result.

use std::io::{BufRead, BufReader, Read};

use anyhow::{Context, Result, bail};
use bzip2::read::MultiBzDecoder;
use flate2::read::MultiGzDecoder;
use lzma_rust2::XzReader;
use ruzstd::decoding::StreamingDecoder;
use ruzstd::decoding::errors::{FrameDecoderError, ReadFrameHeaderError};

use crate::core::source::Content;
use crate::core::source::spool::Spool;

/// A zstd frame's magic, little-endian.
const ZSTD_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];
/// How much is read from a decoder at a time.
const CHUNK: usize = 1024 * 1024;

/// A compression recognised by its magic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Compression {
    Gzip,
    Bzip2,
    Xz,
    Zstd,
}

impl Compression {
    /// The compression `head`, a file's first bytes, starts with.
    ///
    /// - gzip (RFC 1952): ID1 ID2, then method 8 (deflate, the only one defined);
    /// - bzip2: `BZh`, the block size digit, then a block's magic (pi) or the empty
    ///   stream's end magic (sqrt(pi));
    /// - xz: the 6-byte stream header magic;
    /// - zstd: the frame magic, or a skippable frame first (as `pzstd` writes).
    pub(crate) fn of(head: &[u8]) -> Option<Self> {
        if head.starts_with(&[0x1F, 0x8B, 0x08]) {
            Some(Self::Gzip)
        } else if head.starts_with(b"BZh")
            && head.get(3).is_some_and(|b| (b'1'..=b'9').contains(b))
            && matches!(
                head.get(4..10),
                Some([0x31, 0x41, 0x59, 0x26, 0x53, 0x59] | [0x17, 0x72, 0x45, 0x38, 0x50, 0x90])
            )
        {
            Some(Self::Bzip2)
        } else if head.starts_with(&[0xFD, b'7', b'z', b'X', b'Z', 0x00]) {
            Some(Self::Xz)
        } else if head.starts_with(&ZSTD_MAGIC) || is_skippable(head) {
            Some(Self::Zstd)
        } else {
            None
        }
    }

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Gzip => "gzip",
            Self::Bzip2 => "bzip2",
            Self::Xz => "xz",
            Self::Zstd => "zstd",
        }
    }

    /// The whole of `input` decoded, in the spool (memory, then a temporary file).
    /// `what` names it in errors ("the compressed tar").
    pub(crate) fn decode(self, input: &[u8], what: &'static str) -> Result<Content<'static>> {
        let mut spool = Spool::new(what);
        let name = self.name();
        match self {
            Self::Gzip => drain(MultiGzDecoder::new(input), &mut spool),
            Self::Bzip2 => drain(MultiBzDecoder::new(input), &mut spool),
            Self::Xz => drain(XzReader::new(input, true), &mut spool),
            Self::Zstd => zstd_frames(input, |bytes| {
                spool.write(bytes)?;
                Ok(true)
            }),
        }
        .with_context(|| format!("cannot decode {what} ({name})"))?;
        spool.finish()
    }

    /// The first `n` decoded bytes of the stream `input` (fewer when it is shorter),
    /// to see what it holds without decoding it all.
    pub(crate) fn head(self, input: impl Read, n: usize) -> Result<Vec<u8>> {
        let limit = u64::try_from(n)?;
        let mut out = Vec::with_capacity(n);
        match self {
            Self::Gzip => MultiGzDecoder::new(input).take(limit).read_to_end(&mut out),
            Self::Bzip2 => MultiBzDecoder::new(input).take(limit).read_to_end(&mut out),
            Self::Xz => XzReader::new(input, true).take(limit).read_to_end(&mut out),
            Self::Zstd => {
                zstd_frames(input, |bytes| {
                    out.extend_from_slice(bytes);
                    Ok(out.len() < n)
                })?;
                out.truncate(n);
                return Ok(out);
            }
        }?;
        Ok(out)
    }
}

/// Whether `head` starts with a zstd skippable frame (magic `0x184D2A50` to `…5F`).
fn is_skippable(head: &[u8]) -> bool {
    matches!(head, [0x50..=0x5F, 0x2A, 0x4D, 0x18, ..])
}

/// Everything `reader` yields, into `spool`; a read error is returned, not taken for
/// the end of the stream.
fn drain(mut reader: impl Read, spool: &mut Spool) -> Result<()> {
    let mut buffer = vec![0u8; CHUNK];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(n) => spool.write(&buffer[..n])?,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
}

/// Every frame of the zstd stream `input`, each content checksum verified, handed to
/// `sink` as it is decoded; skippable frames are passed over. `sink` returns whether
/// to go on (false: enough has been read).
///
/// HOW: the decoder reads one frame from `input` and stops after it; the next frame
/// starts where it stopped. WHY by hand: the decoder reads a single frame and exposes
/// the stored and computed checksums without comparing them.
fn zstd_frames(input: impl Read, mut sink: impl FnMut(&[u8]) -> Result<bool>) -> Result<()> {
    let mut rest = BufReader::new(input);
    let mut buffer = vec![0u8; CHUNK];
    let mut frame = 0usize;
    while !rest.fill_buf()?.is_empty() {
        frame += 1;
        let mut decoder = match StreamingDecoder::new(&mut rest) {
            Ok(decoder) => decoder,
            Err(FrameDecoderError::ReadFrameHeaderError(ReadFrameHeaderError::SkipFrame {
                length,
                ..
            })) => {
                // The 8-byte header has been read; its contents follow.
                let length = u64::from(length);
                let skipped = std::io::copy(&mut (&mut rest).take(length), &mut std::io::sink())?;
                if skipped < length {
                    bail!("frame {frame}: a skippable frame runs past the end of the file");
                }
                continue;
            }
            Err(e) => bail!("frame {frame}: {e}"),
        };
        loop {
            let n = match decoder.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e).with_context(|| format!("frame {frame}")),
            };
            if !sink(&buffer[..n])? {
                return Ok(());
            }
        }
        let frame_decoder = decoder.into_frame_decoder();
        if let (Some(stored), Some(computed)) = (
            frame_decoder.get_checksum_from_data(),
            frame_decoder.get_calculated_checksum(),
        ) && stored != computed
        {
            bail!(
                "frame {frame}: the content checksum does not match (stored {stored:#010x}, computed {computed:#010x})"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Made by the reference tools from `note.tar`, each in two members, streams or
    // frames (zstd after a skippable frame): see `tests/fixtures/README.md`.
    const TAR: &[u8] = include_bytes!("../../../tests/fixtures/compressed/note.tar");
    const FIXTURES: [(Compression, &[u8]); 4] = [
        (
            Compression::Gzip,
            include_bytes!("../../../tests/fixtures/compressed/note.tar.gz"),
        ),
        (
            Compression::Bzip2,
            include_bytes!("../../../tests/fixtures/compressed/note.tar.bz2"),
        ),
        (
            Compression::Xz,
            include_bytes!("../../../tests/fixtures/compressed/note.tar.xz"),
        ),
        (
            Compression::Zstd,
            include_bytes!("../../../tests/fixtures/compressed/note.tar.zst"),
        ),
    ];

    #[test]
    fn each_is_recognised_and_decodes_every_member() {
        for (compression, bytes) in FIXTURES {
            assert_eq!(Compression::of(bytes), Some(compression));
            let content = compression.decode(bytes, "test data").unwrap();
            assert_eq!(&*content, TAR, "{compression:?}");
            let head = compression.head(bytes, 512).unwrap();
            assert_eq!(head, &TAR[..512], "{compression:?}");
        }
        assert_eq!(Compression::of(b"BZh0"), None);
        assert_eq!(Compression::of(b"BZh9 not a block"), None);
        assert_eq!(Compression::of(TAR), None);
    }

    #[test]
    fn a_damaged_or_cut_stream_is_an_error() {
        for (compression, bytes) in FIXTURES {
            // A flipped byte in the second member's compressed body, or the last
            // bytes gone: never a shorter or altered result.
            let mut bad = bytes.to_vec();
            let at = bad.len() - 12;
            bad[at] ^= 0x55;
            assert!(
                compression.decode(&bad, "test data").is_err(),
                "{compression:?}: a damaged stream must fail"
            );
            assert!(
                compression
                    .decode(&bytes[..bytes.len() - 3], "test data")
                    .is_err(),
                "{compression:?}: a cut stream must fail"
            );
        }
    }
}
