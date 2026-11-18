//! UTF-16 search: the byte pattern of a literal's UTF-16 form (little- or
//! big-endian), and the decoding of a matched span back to text.
//!
//! Defines: [`pattern`], [`decode`].
//! Used by: `cmd::run::grep` (builds the patterns for `--encoding utf16*`) and
//! `encodings::decode` (decodes a UTF-16 hit for the report).
//! Uses: `encodings::{case_variants, any_of}`.
//!
//! WHY: binary plists, NSString archives and many Windows-born files store text as
//! UTF-16, so a UTF-8 search misses it (measured on an iPhone: an emoji in 174 files
//! as UTF-8 and in 182 as UTF-16). Each character becomes its UTF-16 code units (a
//! surrogate pair beyond U+FFFF, as for most emoji), written as escaped bytes in a
//! byte regex.

use super::{any_of, case_variants};

/// A byte regex matching any of `literals` in UTF-16, little-endian unless
/// `big_endian`. With `ignore_case`, each character matches its single-character
/// upper- and lowercase forms (the regex engine's own case folding cannot apply to
/// UTF-16 bytes).
pub fn pattern(literals: &[String], ignore_case: bool, big_endian: bool) -> String {
    let alternatives: Vec<String> = literals
        .iter()
        .map(|literal| {
            literal
                .chars()
                .map(|c| char_pattern(c, ignore_case, big_endian))
                .collect::<String>()
        })
        .collect();
    format!("(?-u)(?:{})", alternatives.join("|"))
}

/// One character's UTF-16 bytes, or a group of its case variants.
fn char_pattern(c: char, ignore_case: bool, big_endian: bool) -> String {
    any_of(
        case_variants(c, ignore_case)
            .into_iter()
            .map(|v| bytes(v, big_endian))
            .collect(),
    )
}

/// A character's UTF-16 code units as escaped bytes, e.g. `\x41\x00`.
fn bytes(c: char, big_endian: bool) -> String {
    let mut units = [0u16; 2];
    c.encode_utf16(&mut units)
        .iter()
        .flat_map(|u| {
            if big_endian {
                u.to_be_bytes()
            } else {
                u.to_le_bytes()
            }
        })
        .map(|b| format!("\\x{b:02X}"))
        .collect()
}

/// A matched UTF-16 span as text (invalid units replaced).
pub fn decode(span: &[u8], big_endian: bool) -> String {
    let units: Vec<u16> = span
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&p| {
            if big_endian {
                u16::from_be_bytes(p)
            } else {
                u16::from_le_bytes(p)
            }
        })
        .collect();
    String::from_utf16_lossy(&units)
}

#[cfg(test)]
mod tests {
    use super::*;
    use regex::bytes::Regex;

    fn utf16(text: &str, big_endian: bool) -> Vec<u8> {
        text.encode_utf16()
            .flat_map(|u| {
                if big_endian {
                    u.to_be_bytes()
                } else {
                    u.to_le_bytes()
                }
            })
            .collect()
    }

    #[test]
    fn literals_match_their_utf16_forms_only() {
        for be in [false, true] {
            let re = Regex::new(&pattern(&["prénom".into(), "😂".into()], false, be)).unwrap();
            let mut hay = b"noise ".to_vec();
            hay.extend(utf16("le prénom et 😂", be));
            let found: Vec<String> = re
                .find_iter(&hay)
                .map(|m| decode(m.as_bytes(), be))
                .collect();
            assert_eq!(found, ["prénom", "😂"], "big-endian: {be}");
            // The UTF-8 form and the other byte order are not matched.
            assert!(!re.is_match("prénom".as_bytes()));
            assert!(!re.is_match(&utf16("prénom", !be)));
        }
    }

    #[test]
    fn ignore_case_folds_as_the_plain_search_does() {
        // Final sigma, capital sigma and sigma fold together; so do k, K and the
        // Kelvin sign (U+212A).
        let re = Regex::new(&pattern(&["σοφός".into(), "kilo".into()], true, false)).unwrap();
        assert!(re.is_match(&utf16("ΣΟΦΌΣ", false)));
        assert!(re.is_match(&utf16("\u{212A}ILO", false)));
    }

    #[test]
    fn ignore_case_covers_each_character() {
        let re = Regex::new(&pattern(&["Élan".into()], true, false)).unwrap();
        assert!(re.is_match(&utf16("éLAN", false)));
        assert!(!re.is_match(&utf16("elan", false)));
    }
}
