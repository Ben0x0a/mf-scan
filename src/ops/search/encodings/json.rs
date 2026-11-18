//! JSON escapes: a literal as JSON writers may escape it (`café`, `😂`
//! for an emoji, `\/`), and a matched span unescaped.
//!
//! Defines: [`pattern`], [`decode`].
//! Used by: `encodings` (dispatch) → `cmd::run::grep`, `ops::search::classify`.
//! Uses: `encodings::{case_variants, escape_bytes, any_of, hex_digits}`, and the JSON
//! inspector's unescaping (`inspect::json_unescape`).
//!
//! WHY: some writers escape every non-ASCII character (Python's default, some
//! Android libraries), and some also `<`, `>`, `&`, `=`, `'` (Gson). Measured: an
//! emoji escaped so in 13 files of a test iPhone and 2 of an Android phone. Each
//! character matches itself or its escape, so text partly escaped is found too.

use super::{any_of, case_variants, escape_bytes, hex_digits};

/// Characters a JSON writer may escape: non-ASCII, controls, the two it must (`"`,
/// `\`), `/`, and the HTML-sensitive ones Gson escapes.
fn escapable(c: char) -> bool {
    !c.is_ascii()
        || c.is_ascii_control()
        || matches!(c, '"' | '\\' | '/' | '<' | '>' | '&' | '=' | '\'')
}

/// A byte regex matching any of `literals` with any of its characters JSON-escaped;
/// `None` when no literal has a character a writer escapes.
pub fn pattern(literals: &[String], ignore_case: bool) -> Option<String> {
    if !literals.iter().any(|l| l.chars().any(escapable)) {
        return None;
    }
    let alternatives: Vec<String> = literals
        .iter()
        .map(|l| l.chars().map(|c| char_forms(c, ignore_case)).collect())
        .collect();
    Some(format!("(?-u)(?:{})", alternatives.join("|")))
}

/// One character as itself or as its escapes, in each of its case forms.
fn char_forms(c: char, ignore_case: bool) -> String {
    let mut forms = Vec::new();
    for v in case_variants(c, ignore_case) {
        let mut utf8 = [0u8; 4];
        forms.push(escape_bytes(v.encode_utf8(&mut utf8).as_bytes()));
        if escapable(v) {
            // `\uXXXX`, one per UTF-16 unit (a surrogate pair for an emoji).
            let mut units = [0u16; 2];
            let escaped: String = v
                .encode_utf16(&mut units)
                .iter()
                .map(|&u| format!("\\x5Cu{}", hex_digits(u32::from(u), 4)))
                .collect();
            forms.push(escaped);
            // The short escapes.
            let short: Option<&[u8]> = match v {
                '"' => Some(b"\\\""),
                '\\' => Some(b"\\\\"),
                '/' => Some(b"\\/"),
                '\n' => Some(b"\\n"),
                '\t' => Some(b"\\t"),
                '\r' => Some(b"\\r"),
                '\u{8}' => Some(b"\\b"),
                '\u{c}' => Some(b"\\f"),
                _ => None,
            };
            if let Some(escape) = short {
                forms.push(escape_bytes(escape));
            }
        }
    }
    any_of(forms)
}

/// A matched span with its escapes resolved (see `inspect::json_unescape`).
pub fn decode(span: &[u8]) -> String {
    crate::formats::inspect::json_unescape(span)
}

#[cfg(test)]
mod tests {
    use super::*;
    use regex::bytes::Regex;

    #[test]
    fn escaped_and_unescaped_forms_are_found_and_decoded() {
        let re = Regex::new(&pattern(&["café 😂".into()], false).unwrap()).unwrap();
        for hay in [
            r#"{"t":"café 😂"}"#,
            r#"{"t":"café 😂"}"#,
            "{\"t\":\"café \\ud83d\\ude02\"}",
        ] {
            let m = re.find(hay.as_bytes()).unwrap_or_else(|| panic!("{hay}"));
            assert_eq!(decode(m.as_bytes()), "café 😂", "{hay}");
        }
    }

    #[test]
    fn short_escapes_are_found() {
        let re = Regex::new(&pattern(&["a\tb\nc".into()], false).unwrap()).unwrap();
        let m = re.find(br#""a\tb\nc""#).unwrap();
        assert_eq!(decode(m.as_bytes()), "a\tb\nc");
    }

    #[test]
    fn plain_ascii_needs_no_json_pattern() {
        assert!(pattern(&["hello".into()], false).is_none());
        assert!(pattern(&["a/b".into()], false).is_some());
        let re = Regex::new(&pattern(&["a/b".into()], false).unwrap()).unwrap();
        assert_eq!(decode(re.find(br#""a\/b""#).unwrap().as_bytes()), "a/b");
    }
}
