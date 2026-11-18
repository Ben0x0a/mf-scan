//! Unicode normalisation: a literal's other composed (NFC) or decomposed (NFD) form,
//! e.g. `é` as one character or as `e` + U+0301.
//!
//! Defines: [`patterns`].
//! Used by: `cmd::run::grep` (builds the patterns for `--encoding nfd`).
//! Uses: `unicode_normalization`, `regex::escape`, `crate::core::models::Encoding`.
//!
//! WHY: text typed on a keyboard is usually composed, but iOS file names and some
//! stored text are decomposed, and the bytes differ. Measured: a decomposed `é` in 311
//! files of a test iPhone and 300 of an Android phone (composed: 14,481 and 6,027).

use unicode_normalization::UnicodeNormalization;

use crate::core::models::Encoding;

/// For each normal form that differs from the literals as typed, a UTF-8 regex of
/// those literals in it, tagged [`Encoding::Nfc`] or [`Encoding::Nfd`]. Empty when
/// the literals have no other form (plain ASCII, for one).
pub fn patterns(literals: &[String], ignore_case: bool) -> Vec<(Encoding, String)> {
    let flags = if ignore_case { "(?i)" } else { "" };
    let mut out = Vec::new();
    for (encoding, form) in [
        (Encoding::Nfc, nfc as fn(&str) -> String),
        (Encoding::Nfd, nfd),
    ] {
        let differing: Vec<String> = literals
            .iter()
            .map(|l| form(l))
            .zip(literals)
            .filter(|(f, l)| f != *l)
            .map(|(f, _)| regex::escape(&f))
            .collect();
        if !differing.is_empty() {
            out.push((encoding, format!("{flags}(?:{})", differing.join("|"))));
        }
    }
    out
}

fn nfc(s: &str) -> String {
    s.nfc().collect()
}

fn nfd(s: &str) -> String {
    s.nfd().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use regex::bytes::Regex;

    #[test]
    fn the_other_form_is_searched() {
        let composed = "pr\u{e9}nom";
        let decomposed = "pre\u{301}nom";
        let p = patterns(&[composed.into()], false);
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].0, Encoding::Nfd);
        let re = Regex::new(&p[0].1).unwrap();
        assert!(re.is_match(decomposed.as_bytes()));
        assert!(!re.is_match(composed.as_bytes()));
        // Typed decomposed: the composed form is searched, tagged nfc.
        assert_eq!(patterns(&[decomposed.into()], false)[0].0, Encoding::Nfc);
        assert!(patterns(&["plain".into()], false).is_empty());
    }
}
