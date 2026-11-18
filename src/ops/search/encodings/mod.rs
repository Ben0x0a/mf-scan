//! Encoded forms of a search literal: one module per encoding, each building the byte
//! regex for the literal in that encoding and decoding a matched span back to text.
//!
//! Defines: the per-encoding modules ([`base64`], [`utf16`], [`cesu8`], [`json`],
//! [`percent`], [`normalize`]); [`EncodingSet`] and [`build`] (which encodings to
//! search, and the literal's pattern in each, from `set`); `find` (every match of the query in a file, across
//! its encodings, each once); [`decode`] (a matched span as text, for the report);
//! and the helpers they share: `case_variants`, `escape_bytes`, `any_of`,
//! `hex_digits`.
//! Used by: `cmd::run::grep` (builds the patterns for `--encoding`), and
//! `ops::search::classify` (finds a file's matches).
//! Uses: `crate::core::models::{Encoding, SearchHit}`, `ops::search::{Query,
//! search_bytes_capped}`, `regex_syntax` (case folding).
//!
//! Every builder returns `None` (or nothing) when the literal's form in that encoding
//! is its plain UTF-8 form: such a pattern would find nothing the plain search does
//! not. The patterns are byte regexes (`(?-u)`, bytes escaped as `\xHH`), so `-i` is
//! applied by each builder, character by character, not by the regex engine.

pub mod base64;
pub mod cesu8;
pub mod json;
pub mod normalize;
pub mod percent;
mod set;
pub mod utf16;

pub use set::{Built, EncodingSet, build};

use super::{Query, search_bytes_capped};
use crate::core::models::{Encoding, SearchHit};

/// One match: where it is, the encoding it was found in, and its text when encoded.
pub(crate) struct Found {
    pub(crate) hit: SearchHit,
    pub(crate) encoding: Encoding,
    pub(crate) decoded: Option<String>,
}

/// Every match of `query` in `content`, by offset, each once.
pub(crate) struct Matches {
    pub(crate) found: Vec<Found>,
    /// A pattern stopped at the per-file cap.
    pub(crate) truncated: bool,
    /// Matches per encoding; empty when every match is plain.
    pub(crate) counts: Vec<(Encoding, usize)>,
}

/// Search `content` for the plain pattern and every encoded form of the literal.
///
/// - A base64 match is kept only when the base64 around it decodes to the literal
///   (`base64::holds`): a fragment alone proves nothing.
/// - A span matched by two encodings is kept once, under the first in `Encoding`
///   order; the match length used is the real one, not the capped preview's.
/// - Latin-range UTF-16 among Latin-range UTF-16 reads the same text as little- and
///   big-endian one byte apart: such a pair is one match, tagged [`Encoding::Utf16`].
/// - An encoded match's text is decoded from the file's bytes, not the preview.
pub(crate) fn find(content: &[u8], query: &Query<'_>) -> Matches {
    let mut truncated = false;
    let mut hits: Vec<(SearchHit, Encoding)> = Vec::new();
    for (encoding, re) in std::iter::once((Encoding::Plain, query.plain))
        .chain(query.encoded.iter().map(|(e, re)| (*e, re)))
    {
        let found = search_bytes_capped(content, re);
        truncated |= found.truncated;
        hits.extend(
            found
                .hits
                .into_iter()
                .filter(|h| {
                    encoding != Encoding::Base64
                        || query.decoded.is_some_and(|literal| {
                            let start = h.offset as usize;
                            base64::holds(content, start, start + h.len, literal.as_bytes())
                        })
                })
                .map(|h| (h, encoding)),
        );
    }
    hits.sort_by_key(|(h, e)| (h.offset, h.len, *e));
    hits.dedup_by_key(|(h, _)| (h.offset, h.len));

    let mut found: Vec<Found> = hits
        .into_iter()
        .map(|(hit, encoding)| {
            let span = &content[hit.offset as usize..hit.offset as usize + hit.len];
            let decoded = match encoding {
                Encoding::Base64 => query.decoded.map(str::to_string),
                _ => decode(encoding, span),
            };
            Found {
                hit,
                encoding,
                decoded,
            }
        })
        .collect();
    merge_utf16_pairs(&mut found);

    let mut counts: Vec<(Encoding, usize)> = Vec::new();
    if found.iter().any(|f| f.encoding != Encoding::Plain) {
        for f in &found {
            match counts.iter_mut().find(|(e, _)| *e == f.encoding) {
                Some((_, n)) => *n += 1,
                None => counts.push((f.encoding, 1)),
            }
        }
        counts.sort();
    }
    Matches {
        found,
        truncated,
        counts,
    }
}

/// Merge each UTF-16 little-/big-endian pair reading the same text one byte apart
/// into one match at the first offset, tagged [`Encoding::Utf16`].
fn merge_utf16_pairs(found: &mut Vec<Found>) {
    let is_utf16 = |e: Encoding| matches!(e, Encoding::Utf16Le | Encoding::Utf16Be);
    let mut i = 0;
    while i < found.len() {
        if is_utf16(found[i].encoding) {
            let (offset, len) = (found[i].hit.offset, found[i].hit.len);
            let twin = found[i + 1..]
                .iter()
                .take_while(|f| f.hit.offset <= offset + 1)
                .position(|f| {
                    f.hit.offset == offset + 1
                        && f.hit.len == len
                        && is_utf16(f.encoding)
                        && f.encoding != found[i].encoding
                        && f.decoded == found[i].decoded
                });
            if let Some(p) = twin {
                found.remove(i + 1 + p);
                found[i].encoding = Encoding::Utf16;
            }
        }
        i += 1;
    }
}

/// The text an encoded span holds, for the report. `None` for a plain hit, and for
/// base64, whose decoded value is the literal searched for (set by the caller).
pub fn decode(encoding: Encoding, span: &[u8]) -> Option<String> {
    match encoding {
        Encoding::Utf16Le => Some(utf16::decode(span, false)),
        Encoding::Utf16Be => Some(utf16::decode(span, true)),
        Encoding::Cesu8 => Some(cesu8::decode(span)),
        Encoding::Json => Some(json::decode(span)),
        Encoding::Url => Some(percent::decode(span)),
        Encoding::Nfc | Encoding::Nfd => Some(String::from_utf8_lossy(span).into_owned()),
        // Base64: the literal searched for; UTF-16 of either byte order: the text both
        // readings agreed on, kept by `find` when it merged them.
        Encoding::Plain | Encoding::Base64 | Encoding::Utf16 => None,
    }
}

/// `c`, and with `ignore_case` every character Unicode simple case folding pairs it
/// with (`σ`: `ς`, `Σ`; `k`: `K`, the Kelvin sign), as the plain pattern's `-i` does.
///
/// WHY `regex_syntax`: it is the folding the `regex` engine applies to the plain
/// pattern, so an encoded form matches exactly the case forms the plain search does.
pub(crate) fn case_variants(c: char, ignore_case: bool) -> Vec<char> {
    if !ignore_case {
        return vec![c];
    }
    use regex_syntax::hir::{ClassUnicode, ClassUnicodeRange};
    let mut class = ClassUnicode::new([ClassUnicodeRange::new(c, c)]);
    class.case_fold_simple();
    let mut variants = vec![c];
    for range in class.iter() {
        for other in range.start()..=range.end() {
            if other != c {
                variants.push(other);
            }
        }
    }
    variants
}

/// Bytes as `\xHH` escapes, for a `(?-u)` byte regex.
pub(crate) fn escape_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("\\x{b:02X}")).collect()
}

/// A group matching any of `alternatives` (or the one alternative alone).
pub(crate) fn any_of(mut alternatives: Vec<String>) -> String {
    alternatives.dedup();
    if alternatives.len() == 1 {
        alternatives.pop().unwrap_or_default()
    } else {
        format!("(?:{})", alternatives.join("|"))
    }
}

/// `value` as `width` hex digits, each letter matching either case (`[aA]`).
pub(crate) fn hex_digits(value: u32, width: usize) -> String {
    format!("{value:0width$x}")
        .chars()
        .map(|d| {
            if d.is_ascii_alphabetic() {
                format!("[{d}{}]", d.to_ascii_uppercase())
            } else {
                d.to_string()
            }
        })
        .collect()
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

    fn run(
        literal: &str,
        content: &[u8],
        encodings: &[Encoding],
    ) -> Vec<(u64, Encoding, Option<String>)> {
        let lits = [literal.to_string()];
        let plain = Regex::new(&regex::escape(literal)).unwrap();
        let encoded: Vec<(Encoding, Regex)> = encodings
            .iter()
            .filter_map(|&e| {
                let text = match e {
                    Encoding::Utf16Le => Some(utf16::pattern(&lits, false, false)),
                    Encoding::Utf16Be => Some(utf16::pattern(&lits, false, true)),
                    Encoding::Json => json::pattern(&lits, false),
                    Encoding::Base64 => Some(
                        base64::fragments(literal.as_bytes(), false)
                            .iter()
                            .map(|f| regex::escape(f))
                            .collect::<Vec<_>>()
                            .join("|"),
                    ),
                    _ => None,
                }?;
                Some((e, Regex::new(&text).unwrap()))
            })
            .collect();
        let query = Query {
            plain: &plain,
            encoded: &encoded,
            decoded: Some(literal),
            line_numbers: false,
        };
        find(content, &query)
            .found
            .into_iter()
            .map(|f| (f.hit.offset, f.encoding, f.decoded))
            .collect()
    }

    #[test]
    fn latin_utf16_read_both_ways_is_one_match() {
        // "x hello x" in UTF-16BE: the LE pattern also matches one byte later.
        let content = utf16("x hello x", true);
        let found = run("hello", &content, &[Encoding::Utf16Le, Encoding::Utf16Be]);
        assert_eq!(found, [(4, Encoding::Utf16, Some("hello".into()))]);
        // An emoji's surrogates read one way only: the byte order is kept.
        let emoji = utf16("a 😂 b", true);
        let found = run("😂", &emoji, &[Encoding::Utf16Le, Encoding::Utf16Be]);
        assert_eq!(found, [(4, Encoding::Utf16Be, Some("😂".into()))]);
    }

    #[test]
    fn base64_matches_must_decode_to_the_literal() {
        let real = "token=U3VwZXJTZWNyZXRUb2tlbg== end";
        let found = run("SuperSecretToken", real.as_bytes(), &[Encoding::Base64]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].1, Encoding::Base64);
        // A fragment alone, not part of an encoding of the literal: no match.
        let frag = &base64::fragments(b"SuperSecretToken", false)[1];
        let alone = format!("!!{frag}!!");
        assert!(run("SuperSecretToken", alone.as_bytes(), &[Encoding::Base64]).is_empty());
    }

    #[test]
    fn a_span_matched_twice_is_reported_once_as_plain() {
        // Plain "a/b" is also matched by the JSON pattern (each character as itself).
        let found = run("a/b", br#"{"p":"a/b","q":"a\/b"}"#, &[Encoding::Json]);
        assert_eq!(
            found,
            [
                (6, Encoding::Plain, None),
                (16, Encoding::Json, Some("a/b".into()))
            ]
        );
    }
}
