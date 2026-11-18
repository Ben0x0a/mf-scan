//! Which encodings to search besides plain UTF-8, and the patterns for a literal in
//! each of them.
//!
//! Defines: [`EncodingSet`], [`Built`], [`build`].
//! Used by: `cmd::run::grep` (maps its flags to an `EncodingSet`, prints the notes).
//! Uses: the per-encoding builders in `encodings`, `regex::bytes`, `anyhow`.
//!
//! WHY here and not in the command: which encodings run, in what order, and when
//! base64 is left out are rules of the search, testable without a command line; the
//! command only maps its flags to a set and prints what comes back.

use anyhow::{Context, Result};
use regex::bytes::{Regex, RegexBuilder};

use super::{base64, cesu8, json, normalize, percent, utf16};
use crate::core::models::Encoding;

/// The encodings to search besides plain UTF-8.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct EncodingSet {
    /// The literal's other Unicode normal form (`nfd`; tagged `nfc` or `nfd`).
    pub normal_forms: bool,
    pub utf16le: bool,
    pub utf16be: bool,
    pub cesu8: bool,
    pub json: bool,
    pub url: bool,
    pub base64: bool,
    pub base64url: bool,
    /// Base64 was named, not only implied by "all": a mismatch is then an error or a
    /// warning, where "all" leaves base64 out with a note.
    pub base64_named: bool,
}

impl EncodingSet {
    /// Every encoding ("all"), base64 implied rather than named.
    pub fn all() -> Self {
        Self {
            normal_forms: true,
            utf16le: true,
            utf16be: true,
            cesu8: true,
            json: true,
            url: true,
            base64: true,
            base64url: true,
            base64_named: false,
        }
    }

    /// The encodings in the set, with their names as the run record lists them.
    fn list(&self) -> [(bool, &'static str); 8] {
        [
            (self.normal_forms, "nfd"),
            (self.utf16le, "utf16le"),
            (self.utf16be, "utf16be"),
            (self.cesu8, "cesu8"),
            (self.json, "json"),
            (self.url, "url"),
            (self.base64, "base64"),
            (self.base64url, "base64url"),
        ]
    }

    /// Whether any encoding besides plain is in the set.
    pub fn any(&self) -> bool {
        self.list().iter().any(|(on, _)| *on)
    }

    /// The names of the encodings in the set.
    pub fn names(&self) -> Vec<String> {
        self.list()
            .into_iter()
            .filter(|(on, _)| *on)
            .map(|(_, name)| name.to_string())
            .collect()
    }
}

/// The patterns for a literal in each encoding of a set.
pub struct Built {
    /// In [`Encoding`] order: the precedence when two encodings match the same span.
    pub patterns: Vec<(Encoding, Regex)>,
    /// The literal a base64 match decodes to; `None` without base64.
    pub decoded: Option<String>,
    /// The set actually searched (base64 may have been left out).
    pub searched: EncodingSet,
    /// Notes and warnings for the user, one sentence each.
    pub notes: Vec<String>,
}

/// Build the patterns for `literals` in each encoding of `set`. An encoding whose
/// form of the literals is their plain form gives no pattern. Case is applied in each
/// pattern itself (`ignore_case`): the engine's case folding is for text, not
/// encoded bytes.
///
/// Base64 needs a single literal (a match reports the one value it decodes to) of at
/// least 4 bytes: shorter, chance base64 text decodes to it too. Named, a mismatch is
/// an error (several literals) or a warning (short); implied by "all", base64 is left
/// out with a note and the other encodings still run.
pub fn build(literals: &[String], ignore_case: bool, set: EncodingSet) -> Result<Built> {
    let mut notes = Vec::new();
    let mut searched = set;
    let mut texts: Vec<(Encoding, String)> = Vec::new();
    if set.normal_forms {
        texts.extend(normalize::patterns(literals, ignore_case));
    }
    for (on, encoding, big_endian) in [
        (set.utf16le, Encoding::Utf16Le, false),
        (set.utf16be, Encoding::Utf16Be, true),
    ] {
        if on {
            texts.push((encoding, utf16::pattern(literals, ignore_case, big_endian)));
        }
    }
    for (on, encoding, build) in [
        (
            set.cesu8,
            Encoding::Cesu8,
            cesu8::pattern as fn(&[String], bool) -> Option<String>,
        ),
        (set.json, Encoding::Json, json::pattern),
        (set.url, Encoding::Url, percent::pattern),
    ] {
        if on && let Some(text) = build(literals, ignore_case) {
            texts.push((encoding, text));
        }
    }
    let mut patterns = Vec::with_capacity(texts.len() + 1);
    for (encoding, text) in texts {
        let re = Regex::new(&text)
            .with_context(|| format!("failed to build the {} search pattern", encoding.as_str()))?;
        patterns.push((encoding, re));
    }

    if (set.base64 || set.base64url) && !set.base64_named {
        let left_out = match literals {
            [value] if value.len() < 4 => Some("the term is under 4 bytes"),
            [_] => None,
            _ => Some("it takes a single pattern"),
        };
        if let Some(why) = left_out {
            notes.push(format!(
                "note: base64 left out of the encodings searched: {why}"
            ));
            searched.base64 = false;
            searched.base64url = false;
        }
    }
    let mut decoded = None;
    if searched.base64 || searched.base64url {
        let [value] = literals else {
            anyhow::bail!("base64 takes a single pattern (leave base64 out to search several)");
        };
        if ignore_case {
            notes.push("warning: -i does not apply to base64, which is case-sensitive".into());
        }
        let mut frags = Vec::new();
        for (on, urlsafe) in [(searched.base64, false), (searched.base64url, true)] {
            if on {
                frags.extend(base64::fragments(value.as_bytes(), urlsafe));
            }
        }
        frags.sort();
        frags.dedup();
        if frags.is_empty() {
            anyhow::bail!("pattern is too short to search as base64; give a longer literal");
        }
        if value.len() < 4 {
            notes.push(
                "warning: under 4 bytes, base64 text found by chance can decode to the term too"
                    .into(),
            );
        }
        // Alternation of the (already alphabet-correct) fragments. Base64 is
        // case-sensitive, so this regex never takes the -i flag even if set.
        let alt = frags
            .iter()
            .map(|f| regex::escape(f))
            .collect::<Vec<_>>()
            .join("|");
        let re = RegexBuilder::new(&alt)
            .build()
            .context("failed to build base64 search pattern")?;
        patterns.push((Encoding::Base64, re));
        decoded = Some(value.clone());
    }
    Ok(Built {
        patterns,
        decoded,
        searched,
        notes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_leaves_base64_out_for_short_or_several_terms() {
        let short = build(&["abc".into()], false, EncodingSet::all()).unwrap();
        assert!(!short.searched.base64 && short.decoded.is_none());
        assert_eq!(short.notes.len(), 1);
        let several = build(&["alice".into(), "bob".into()], false, EncodingSet::all()).unwrap();
        assert!(!several.searched.base64);
        assert!(
            several
                .patterns
                .iter()
                .any(|(e, _)| *e == Encoding::Utf16Le)
        );
        // Named, several terms is an error.
        let named = EncodingSet {
            base64: true,
            base64_named: true,
            ..EncodingSet::default()
        };
        assert!(build(&["alice".into(), "bob".into()], false, named).is_err());
    }

    #[test]
    fn patterns_come_in_encoding_order_and_skip_identical_forms() {
        let built = build(&["café 😂".into()], false, EncodingSet::all()).unwrap();
        let order: Vec<Encoding> = built.patterns.iter().map(|(e, _)| *e).collect();
        let mut sorted = order.clone();
        sorted.sort();
        assert_eq!(order, sorted);
        // "hello": no other normal form, no JSON/URL/CESU-8 difference.
        let ascii = build(&["hello".into()], false, EncodingSet::all()).unwrap();
        let kinds: Vec<Encoding> = ascii.patterns.iter().map(|(e, _)| *e).collect();
        assert_eq!(
            kinds,
            [Encoding::Utf16Le, Encoding::Utf16Be, Encoding::Base64]
        );
    }
}
