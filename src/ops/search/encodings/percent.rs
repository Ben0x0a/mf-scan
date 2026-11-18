//! Percent-encoding (URLs): a literal as it appears in a URL (`caf%C3%A9`,
//! `%F0%9F%98%82`, a space as `%20` or `+`), and a matched span decoded.
//!
//! Defines: [`pattern`], [`decode`].
//! Used by: `encodings` (dispatch) → `cmd::run::grep`, `ops::search::classify`.
//! Uses: `encodings::{case_variants, escape_bytes, any_of, hex_digits}`.
//!
//! WHY: browser history, cookies and app URLs keep non-ASCII text and punctuation
//! percent-encoded. Measured: an emoji so in 6 files of a test Android phone. Each
//! byte matches itself or `%XX` (either case), so partly encoded text is found too;
//! letters and digits, which URLs leave alone, match only themselves.

use super::{any_of, case_variants, escape_bytes, hex_digits};

/// A byte regex matching any of `literals` with any of its bytes percent-encoded;
/// `None` when every literal is only letters and digits (its URL form is itself).
pub fn pattern(literals: &[String], ignore_case: bool) -> Option<String> {
    if literals
        .iter()
        .all(|l| l.bytes().all(|b| b.is_ascii_alphanumeric()))
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
                        .map(|v| {
                            let mut utf8 = [0u8; 4];
                            v.encode_utf8(&mut utf8).bytes().map(byte_forms).collect()
                        })
                        .collect();
                    any_of(forms)
                })
                .collect()
        })
        .collect();
    Some(format!("(?-u)(?:{})", alternatives.join("|")))
}

/// One byte as itself or `%XX`; a space also as `+`.
fn byte_forms(b: u8) -> String {
    let encoded = format!("%{}", hex_digits(u32::from(b), 2));
    match b {
        b if b.is_ascii_alphanumeric() => escape_bytes(&[b]),
        b' ' => any_of(vec![escape_bytes(b" "), encoded, escape_bytes(b"+")]),
        b => any_of(vec![escape_bytes(&[b]), encoded]),
    }
}

/// A matched span with `%XX` decoded. A `+` is kept: in a URL it is a plus sign or a
/// space, and the decoded text shows what is there rather than guess.
pub fn decode(span: &[u8]) -> String {
    let mut out = Vec::with_capacity(span.len());
    let mut i = 0;
    while i < span.len() {
        let hex = span
            .get(i + 1..i + 3)
            .and_then(|h| std::str::from_utf8(h).ok())
            .and_then(|h| u8::from_str_radix(h, 16).ok());
        match (span[i], hex) {
            (b'%', Some(byte)) => {
                out.push(byte);
                i += 3;
            }
            (b, _) => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use regex::bytes::Regex;

    #[test]
    fn encoded_and_mixed_forms_are_found_and_decoded() {
        let re = Regex::new(&pattern(&["café crème".into()], true).unwrap()).unwrap();
        for hay in [
            "q=caf%C3%A9%20cr%C3%A8me&x",
            "q=caf%c3%a9+cr%c3%a8me",
            "q=CAF%C3%89 cr%C3%A8me", // -i: É
        ] {
            let m = re.find(hay.as_bytes()).unwrap_or_else(|| panic!("{hay}"));
            assert!(
                decode(m.as_bytes()).to_lowercase().starts_with("caf"),
                "{hay}"
            );
        }
        assert!(pattern(&["abc123".into()], false).is_none());
    }
}
