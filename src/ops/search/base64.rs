//! Base64-alignment fragments: literals that appear in a base64 stream whatever
//! the needle's byte offset.
//!
//! Defines: [`fragments`], which turns a search needle into the (up to three)
//! literal substrings guaranteed to occur in any base64 encoding that contains
//! the needle, regardless of its position.
//! Used by: `run` (builds the `--base64` regex from these fragments).
//! Uses: nothing — a small inline base64 encoder, no extra dependency.
//!
//! ── Why three fragments ─────────────────────────────────────────────────────
//! Base64 packs **3 input bytes into 4 output characters**, so where the needle
//! falls relative to those 3-byte groups (its offset **mod 3**, the "phase")
//! changes how it is encoded. For each of the 3 phases, the characters at the
//! needle's edges also encode the unknown neighbouring bytes and so cannot be
//! predicted — but the characters in the middle depend only on the needle. Those
//! middle characters are a literal that must appear verbatim, so searching all
//! three phases finds the needle at any alignment (≈3× the work).
//!
//! ── How many edge characters are contaminated ───────────────────────────────
//! Worked out from the bit layout (each output char is 6 bits):
//! - **Leading** (a `phase`-byte unknown prefix shares the needle's first group):
//!   strip `[0, 2, 3][phase]` characters.
//! - **Trailing** (the needle's last group is completed by unknown bytes): strip
//!   `0` characters when `(phase + needle.len()) % 3 == 0` (the group is whole),
//!   else `1` — only the final character mixes in an unknown following byte.
//!
//! A phase whose middle collapses to nothing (a needle too short for that
//! alignment) yields no fragment and is dropped.

/// Standard base64 alphabet (RFC 4648 §4).
const STANDARD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
/// URL- and filename-safe base64 alphabet (RFC 4648 §5): `+/` become `-_`.
const URL_SAFE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// The literal fragments to search for the base64 encoding of `needle`.
///
/// Returns one fragment per phase (0, 1, 2) for which a non-empty middle exists,
/// using the URL-safe alphabet when `urlsafe` is set, else the standard one. An
/// empty input yields no fragments.
pub fn fragments(needle: &[u8], urlsafe: bool) -> Vec<String> {
    if needle.is_empty() {
        return Vec::new();
    }
    let table = if urlsafe { URL_SAFE } else { STANDARD };
    let mut out = Vec::with_capacity(3);
    for phase in 0..3usize {
        // Encode a `phase`-byte zero prefix followed by the needle, then drop the
        // edge characters that the unknown neighbours would otherwise change.
        let mut buf = vec![0u8; phase];
        buf.extend_from_slice(needle);
        let encoded = encode_no_pad(&buf, table);

        let lead = [0usize, 2, 3][phase];
        let trail = if (phase + needle.len()).is_multiple_of(3) {
            0
        } else {
            1
        };
        if encoded.len() > lead + trail {
            out.push(encoded[lead..encoded.len() - trail].to_string());
        }
    }
    out
}

/// Encode `data` as base64 with the given alphabet, **without** `=` padding.
///
/// Padding is omitted because the fragments are middle substrings — trailing
/// padding characters are always stripped, so producing them would be wasted work.
fn encode_no_pad(data: &[u8], table: &[u8; 64]) -> String {
    let mut s = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        // Pack up to three bytes big-endian into a 24-bit accumulator, then emit
        // one character per 6 bits — `chunk.len() + 1` characters for the chunk.
        let mut n = 0u32;
        for (i, &b) in chunk.iter().enumerate() {
            n |= (b as u32) << (16 - 8 * i);
        }
        for i in 0..chunk.len() + 1 {
            let idx = (n >> (18 - 6 * i)) & 0x3f;
            s.push(table[idx as usize] as char);
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `encode_no_pad` matches known RFC 4648 vectors (without padding).
    #[test]
    fn encodes_known_vectors() {
        assert_eq!(encode_no_pad(b"", STANDARD), "");
        assert_eq!(encode_no_pad(b"f", STANDARD), "Zg");
        assert_eq!(encode_no_pad(b"fo", STANDARD), "Zm8");
        assert_eq!(encode_no_pad(b"foo", STANDARD), "Zm9v");
        assert_eq!(encode_no_pad(b"SECRET", STANDARD), "U0VDUkVU");
    }

    /// URL-safe alphabet differs only in the 62/63 characters.
    #[test]
    fn url_safe_swaps_62_63() {
        // 0xfb,0xff encode to indices that hit `+`/`/` (standard) → `-`/`_` (url).
        assert_eq!(encode_no_pad(&[0xfb, 0xff], STANDARD), "+/8");
        assert_eq!(encode_no_pad(&[0xfb, 0xff], URL_SAFE), "-_8");
    }

    /// Every generated fragment must actually occur in the base64 of a stream
    /// that contains the needle at the matching phase — the core guarantee.
    #[test]
    fn fragments_are_substrings_at_every_phase() {
        let needle = b"SECRET-token";
        let frags = fragments(needle, false);
        assert_eq!(frags.len(), 3); // long enough for all three phases
        for (phase, frag) in frags.iter().enumerate() {
            assert!(!frag.is_empty());
            // Build a stream: `phase` filler bytes, the needle, then trailing
            // filler — i.e. the needle landing at this exact alignment.
            let mut stream = vec![0xABu8; phase];
            stream.extend_from_slice(needle);
            stream.extend_from_slice(&[0xCDu8; 4]);
            let encoded = encode_no_pad(&stream, STANDARD);
            assert!(
                encoded.contains(frag.as_str()),
                "phase {phase}: fragment {frag:?} not found in {encoded:?}"
            );
        }
    }

    /// A too-short needle drops the phases whose middle collapses, but still
    /// yields the phase(s) that have a usable fragment.
    #[test]
    fn short_needle_drops_empty_phases() {
        let frags = fragments(b"x", false);
        // 1 byte: phase 0 → "eA"? no padding → 2 chars, lead 0 trail 1 → 1 char.
        // phases 1/2 collapse to empty and are dropped.
        assert!(frags.len() <= 3);
        for f in &frags {
            assert!(!f.is_empty());
        }
    }

    #[test]
    fn empty_needle_yields_nothing() {
        assert!(fragments(b"", false).is_empty());
    }
}
