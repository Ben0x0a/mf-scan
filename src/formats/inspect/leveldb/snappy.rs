//! Snappy decompression (the raw format LevelDB compresses table blocks with), keeping
//! where each literal run lies in the input, so a match found in a compressed block's
//! bytes maps to its place in the decompressed block.
//!
//! Defines: `decompress` and `Decompressed` (the bytes and the literal map).
//! Used by: `leveldb::table`.
//! Uses: `inspect::leb128`.
//!
//! ── Format (Snappy's `format_description.txt`) ──
//! A varint, the decompressed length, then elements, each starting with a tag byte
//! whose low two bits give its kind:
//! - 00 literal: its length minus one in the upper six bits or, for 60 to 63, in the
//!   next 1 to 4 bytes (little-endian); its bytes follow;
//! - 01 copy: length 4 + bits 2 to 4, offset bits 5 to 7 (high) then the next byte;
//! - 10 copy: length 1 + the upper six bits, offset the next two bytes;
//! - 11 copy: length 1 + the upper six bits, offset the next four bytes.
//!
//! A copy repeats `length` bytes from `offset` back in the output, and may overlap
//! what it writes; an offset of 0 or past the start is invalid.
//!
//! WHY own code, not a crate: forty lines for a fixed, documented format, and the
//! literal map, which is the point here, is not something a decoder gives.
//! WHY the declared length is checked against the input first: no element writes more
//! than 64 bytes for 3 of input (a two-byte-offset copy), so a longer claim is not
//! Snappy, and nothing is allocated for it.

use std::ops::Range;

use crate::formats::inspect::leb128;

/// The most a Snappy element writes per input byte, rounded up (64 for 3).
const MAX_EXPANSION: usize = 22;

/// A decompressed block and where its literal runs came from.
#[derive(Debug)]
pub(super) struct Decompressed {
    pub(super) bytes: Vec<u8>,
    /// Each literal run: its bytes in the input, and where they start in `bytes`; in
    /// input order.
    literals: Vec<(Range<usize>, usize)>,
}

impl Decompressed {
    /// Where input byte `i` is in [`bytes`](Self::bytes), when it belongs to a
    /// literal run (the rest of the input is tags and copies, which hold no text).
    pub(super) fn output_of(&self, i: usize) -> Option<usize> {
        let k = self.literals.partition_point(|(run, _)| run.start <= i);
        let (run, out) = self.literals.get(k.checked_sub(1)?)?;
        run.contains(&i).then(|| out + (i - run.start))
    }
}

/// Decompress `input`, or `None` unless it is valid Snappy whose elements write
/// exactly the declared length.
pub(super) fn decompress(input: &[u8]) -> Option<Decompressed> {
    let (len, mut i) = leb128(input, 0, 5)?;
    let len = usize::try_from(len).ok()?;
    if len > input.len().saturating_mul(MAX_EXPANSION) {
        return None;
    }
    let mut out = Vec::with_capacity(len);
    let mut literals = Vec::new();
    while i < input.len() {
        let tag = input[i];
        i += 1;
        let upper = usize::from(tag >> 2);
        if tag & 3 == 0 {
            let n = match upper {
                0..60 => upper,
                _ => {
                    let extra = upper - 59;
                    let bytes = input.get(i..i + extra)?;
                    i += extra;
                    bytes
                        .iter()
                        .rev()
                        .fold(0usize, |acc, &b| (acc << 8) | usize::from(b))
                }
            } + 1;
            let run = i..i.checked_add(n)?;
            if out.len() + n > len {
                return None;
            }
            out.extend_from_slice(input.get(run.clone())?);
            literals.push((run.clone(), out.len() - n));
            i = run.end;
            continue;
        }
        let (n, offset, size) = match tag & 3 {
            1 => {
                let low = usize::from(*input.get(i)?);
                (4 + (upper & 7), ((upper >> 3) << 8) | low, 1)
            }
            2 => {
                let b: [u8; 2] = input.get(i..i + 2)?.try_into().ok()?;
                (upper + 1, usize::from(u16::from_le_bytes(b)), 2)
            }
            _ => {
                let b: [u8; 4] = input.get(i..i + 4)?.try_into().ok()?;
                (upper + 1, usize::try_from(u32::from_le_bytes(b)).ok()?, 4)
            }
        };
        i += size;
        if offset == 0 || offset > out.len() || out.len() + n > len {
            return None;
        }
        // Byte by byte: a copy may read what it is writing (a run of one byte).
        let start = out.len() - offset;
        for k in 0..n {
            out.push(out[start + k]);
        }
    }
    (out.len() == len).then_some(Decompressed {
        bytes: out,
        literals,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literals_and_the_three_copies_decode() {
        // "abcd" literal; copy 1 (len 4, offset 4) → "abcd"; copy 2 (len 2, offset 8)
        // → "ab"; copy 4 (len 1, offset 1) → "b"; literal "XYZ": 14 bytes.
        let mut s = vec![14];
        s.extend_from_slice(&[3 << 2, b'a', b'b', b'c', b'd']);
        s.extend_from_slice(&[0x01, 4]); // len 4 + 0, offset (0 << 8) | 4
        s.extend_from_slice(&[(1 << 2) | 2, 8, 0]);
        s.extend_from_slice(&[3, 1, 0, 0, 0]); // len 1, offset 1
        s.extend_from_slice(&[2 << 2, b'X', b'Y', b'Z']);
        let d = decompress(&s).unwrap();
        assert_eq!(d.bytes, b"abcdabcdabbXYZ");
        // The literal map: "c" is input 4, output 2; "Y" is in the second literal.
        assert_eq!(d.output_of(4), Some(2));
        let y = s.iter().position(|&b| b == b'Y').unwrap();
        assert_eq!(d.output_of(y), Some(12));
        // A copy's bytes and the tags hold no text.
        assert_eq!(d.output_of(6), None);
        assert_eq!(d.output_of(1), None);
    }

    #[test]
    fn an_overlapping_copy_repeats_a_run() {
        // "a", then copy len 7 offset 1: "aaaaaaaa".
        let s = [8, 0, b'a', (3 << 2) | 1, 1];
        assert_eq!(decompress(&s).unwrap().bytes, b"aaaaaaaa");
    }

    #[test]
    fn a_long_literal_takes_its_length_from_the_next_bytes() {
        let text = vec![b'q'; 300];
        let mut s = vec![0xAC, 0x02]; // 300
        s.extend_from_slice(&[61 << 2, 0x2B, 0x01]); // length - 1 = 299, two bytes
        s.extend_from_slice(&text);
        let d = decompress(&s).unwrap();
        assert_eq!(d.bytes, text);
        assert_eq!(d.output_of(s.len() - 1), Some(299));
    }

    #[test]
    fn invalid_input_is_refused() {
        // Offset 0, an offset past the start, a wrong declared length, a truncated
        // literal, a length no input could write.
        assert!(decompress(&[5, 0, b'a', 1, 0]).is_none());
        assert!(decompress(&[5, 0, b'a', 1, 2]).is_none());
        assert!(decompress(&[2, 0, b'a']).is_none());
        assert!(decompress(&[3, 2 << 2, b'a']).is_none());
        assert!(decompress(&[0xFF, 0xFF, 0x03, 0]).is_none());
        for len in 0..6 {
            let _ = decompress(&[8, 0, b'a', (3 << 2) | 1, 1][..len]);
        }
    }
}
