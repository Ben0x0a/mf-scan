//! CESU-8 (Java's "modified UTF-8"): characters beyond U+FFFF written as two 3-byte
//! surrogates instead of one 4-byte sequence, and a matched span decoded.
//!
//! Defines: [`pattern`], [`decode`].
//! Used by: `encodings` (dispatch) → `cmd::run::grep`, `ops::search::classify`.
//! Uses: `encodings::{case_variants, escape_bytes, any_of}`.
//!
//! WHY: Java and Android serialise strings this way (`DataOutputStream.writeUTF`,
//! JNI), so an emoji there is not its UTF-8 bytes. Measured: an emoji so in 16 files
//! of a test Android phone. Below U+10000 CESU-8 is UTF-8, so only a literal with a
//! character beyond it gets a pattern.

use super::{any_of, case_variants, escape_bytes};

/// A byte regex matching any of `literals` in CESU-8; `None` when no literal has a
/// character beyond U+FFFF (its CESU-8 form is its UTF-8 form).
pub fn pattern(literals: &[String], ignore_case: bool) -> Option<String> {
    if !literals
        .iter()
        .any(|l| l.chars().any(|c| u32::from(c) > 0xFFFF))
    {
        return None;
    }
    let alternatives: Vec<String> = literals
        .iter()
        .map(|l| {
            l.chars()
                .map(|c| {
                    let forms = case_variants(c, ignore_case)
                        .into_iter()
                        .map(|v| escape_bytes(&encode(v)))
                        .collect();
                    any_of(forms)
                })
                .collect()
        })
        .collect();
    Some(format!("(?-u)(?:{})", alternatives.join("|")))
}

/// One character in CESU-8: its UTF-8 form, or its surrogates as 3-byte sequences.
fn encode(c: char) -> Vec<u8> {
    let mut units = [0u16; 2];
    c.encode_utf16(&mut units)
        .iter()
        .flat_map(|&u| {
            if u < 0x80 {
                vec![u as u8]
            } else if u < 0x800 {
                vec![0xC0 | (u >> 6) as u8, 0x80 | (u & 0x3F) as u8]
            } else {
                vec![
                    0xE0 | (u >> 12) as u8,
                    0x80 | ((u >> 6) & 0x3F) as u8,
                    0x80 | (u & 0x3F) as u8,
                ]
            }
        })
        .collect()
}

/// A matched span as text: 1- to 3-byte sequences read as UTF-16 units (surrogates
/// included), a 4-byte one as its character; anything else as U+FFFD.
pub fn decode(span: &[u8]) -> String {
    let mut units: Vec<u16> = Vec::new();
    let mut i = 0;
    while i < span.len() {
        let b = span[i];
        let cont = |k: usize| span.get(i + k).map(|&x| u32::from(x & 0x3F));
        let (unit, len) = match b {
            0x00..=0x7F => (Some(u32::from(b)), 1),
            0xC0..=0xDF => (cont(1).map(|c1| (u32::from(b & 0x1F) << 6) | c1), 2),
            0xE0..=0xEF => (
                cont(1)
                    .zip(cont(2))
                    .map(|(c1, c2)| (u32::from(b & 0x0F) << 12) | (c1 << 6) | c2),
                3,
            ),
            0xF0..=0xF7 => {
                let code = cont(1).zip(cont(2)).zip(cont(3)).map(|((c1, c2), c3)| {
                    (u32::from(b & 0x07) << 18) | (c1 << 12) | (c2 << 6) | c3
                });
                if let Some(c) = code.and_then(char::from_u32) {
                    let mut buf = [0u16; 2];
                    units.extend_from_slice(c.encode_utf16(&mut buf));
                } else {
                    units.push(0xFFFD);
                }
                i += 4;
                continue;
            }
            _ => (None, 1),
        };
        units.push(unit.and_then(|u| u16::try_from(u).ok()).unwrap_or(0xFFFD));
        i += len;
    }
    String::from_utf16_lossy(&units)
}

#[cfg(test)]
mod tests {
    use super::*;
    use regex::bytes::Regex;

    #[test]
    fn surrogates_are_found_and_decoded() {
        // 😂 = U+1F602 = D83D DE02 → ED A0 BD ED B8 82.
        assert_eq!(encode('😂'), [0xED, 0xA0, 0xBD, 0xED, 0xB8, 0x82]);
        let re = Regex::new(&pattern(&["ok 😂".into()], false).unwrap()).unwrap();
        let mut hay = b"xx ok ".to_vec();
        hay.extend_from_slice(&encode('😂'));
        let m = re.find(&hay).unwrap();
        assert_eq!(decode(m.as_bytes()), "ok 😂");
        // Plain UTF-8 is not CESU-8 for an emoji.
        assert!(!re.is_match("ok 😂".as_bytes()));
        assert!(pattern(&["café".into()], false).is_none());
    }
}
