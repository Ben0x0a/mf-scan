//! Entry filtering: decide which archive entries are worth searching.
//!
//! Defines: `EntryFilter`, which combines include globs (`--path`), exclude
//! globs (`--not-path`), a file-type allowlist (`--type`), and the media skip.
//! It splits into two predicates: `selects(path)` (path-only, applied before
//! reading any bytes) and `accepts_type(TypeInfo)` (applied after detecting the
//! format from the content header).
//! Used by: `engine` (skips entries before/while searching) and `main` (builds
//! it from the CLI flags).
//! Uses: `crate::core::models::TypeInfo` (the detected format/category — a
//! foundation data shape the inspectors fill).
//!
//! Wildcards: `*` matches any run of characters *including* `/`, and `?` matches
//! exactly one character — the intuitive rule for forensic filtering (`*.db`
//! matches a `.db` file at any depth). Matching is case-sensitive.
//!
//! Media skip: phone acquisitions are dominated (often ~80%) by photos and
//! videos, which contain no searchable text, so files whose detected category is
//! `media` are skipped by default for speed; `--include-media` searches them.
//! The skip is just the `--type` machinery applied to the `media` category, so
//! detection lives in one place (the inspectors), not a duplicated extension list.

use crate::core::models::TypeInfo;

/// Outcome of the path-only filter, carrying *why* an entry was kept or dropped.
///
/// A reason-carrying result (rather than a bare `bool`) so the scan statistics
/// can attribute every skip to the rule that caused it — for `--not-path` it
/// even records *which* glob matched, by its index in the exclude list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathDecision {
    /// The path passes the include/exclude globs; read and search it.
    Search,
    /// `--path` was given and this path matched none of the include globs.
    SkipNotIncluded,
    /// The path matched the `--not-path` glob at this index in the exclude list.
    SkipNotPath(usize),
}

/// Outcome of the type/media filter, applied once the content header is known.
///
/// Like [`PathDecision`], it names the rule responsible so the statistics can
/// count media skips and `--type` exclusions separately.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeDecision {
    /// The detected type passes the filter; search the content.
    Search,
    /// The media skip (`--exclude-media`/`--fast`) dropped a `media` file.
    SkipMedia,
    /// The `--type` allowlist did not include this file's format/category.
    SkipType,
}

/// Which entries to search: path include/exclude globs, a `--type` allowlist,
/// and the media skip.
pub struct EntryFilter {
    /// `--path` globs; empty means "every entry" (subject to the rules below).
    include: Vec<String>,
    /// `--not-path` globs; an entry matching any of these is skipped.
    exclude: Vec<String>,
    /// `--type` values (format names or categories); empty means "any type".
    types: Vec<String>,
    /// Skip files whose detected category is `media` (when no `--type` is set).
    skip_media: bool,
}

impl EntryFilter {
    /// Build a filter from the CLI flags.
    pub fn new(include: &[String], exclude: &[String], types: &[String], skip_media: bool) -> Self {
        Self {
            include: include.to_vec(),
            exclude: exclude.to_vec(),
            types: types.to_vec(),
            skip_media,
        }
    }

    /// A filter that selects every entry (used by tests and as a neutral base).
    pub fn all() -> Self {
        Self {
            include: Vec::new(),
            exclude: Vec::new(),
            types: Vec::new(),
            skip_media: false,
        }
    }

    /// The `--not-path` globs, in the order their indices refer to.
    ///
    /// Exposed so the scan statistics can label each [`PathDecision::SkipNotPath`]
    /// index with the glob string that caused the skip.
    pub fn not_path_globs(&self) -> &[String] {
        &self.exclude
    }

    /// Whether a content-based type decision could ever *skip* a file (a `--type`
    /// allowlist or `--exclude-media` is in effect).
    ///
    /// When this is `false`, [`accept_type`](Self::accept_type) always returns
    /// `Search`, so reading a file's header to classify it can only waste a read —
    /// the engine uses this to decide whether header-first classification (over a
    /// remote source) is worth doing at all.
    pub fn may_skip_by_type(&self) -> bool {
        !self.types.is_empty() || self.skip_media
    }

    /// Classify `path` against the path-only filters (include/exclude globs).
    ///
    /// This runs before any content is read; the type/media decision is made
    /// separately by [`accept_type`](Self::accept_type) once the header has been
    /// inspected. Exclude wins over include — a path matching both is skipped,
    /// attributed to the matching `--not-path` glob.
    pub fn select(&self, path: &str) -> PathDecision {
        if !self.include.is_empty() && !self.include.iter().any(|g| matches(g, path)) {
            return PathDecision::SkipNotIncluded;
        }
        if let Some(idx) = self.exclude.iter().position(|g| matches(g, path)) {
            return PathDecision::SkipNotPath(idx);
        }
        PathDecision::Search
    }

    /// Classify an entry by its detected type.
    ///
    /// `info` is the format/category from `inspect::detect_type` (header-first,
    /// then extension), or `None` when no inspector claims the file.
    ///
    /// - With `--type`: keep only files whose format name **or** category is in
    ///   the allowlist (an unrecognised file, `None`, is excluded). The explicit
    ///   allowlist takes over, so the media skip does not also apply.
    /// - Without `--type`: keep everything, except — when `skip_media` is set —
    ///   files whose category is `media`.
    pub fn accept_type(&self, info: Option<TypeInfo>) -> TypeDecision {
        if !self.types.is_empty() {
            let kept = info.is_some_and(|i| {
                self.types
                    .iter()
                    .any(|t| t.as_str() == i.name || t.as_str() == i.category)
            });
            return if kept {
                TypeDecision::Search
            } else {
                TypeDecision::SkipType
            };
        }
        if self.skip_media && info.is_some_and(|i| i.category == "media") {
            return TypeDecision::SkipMedia;
        }
        TypeDecision::Search
    }
}

/// True if `path` matches the `*`/`?` wildcard `pattern`.
fn matches(pattern: &str, path: &str) -> bool {
    wildcard_match(pattern.as_bytes(), path.as_bytes())
}

/// Match `text` against a `*`/`?` wildcard `pattern`.
///
/// HOW: a linear two-pointer scan with backtracking. `star`/`mark` remember the
/// most recent `*` and how far `text` had advanced, so when a later literal
/// fails we let that `*` swallow one more character and retry.
///
/// Exposed `pub(crate)` so the decryption profile matcher (`decrypt::profile`)
/// reuses the *same* wildcard semantics as `--path`/`--not-path`, keeping one
/// glob implementation rather than two that could drift.
pub(crate) fn wildcard_match(pattern: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0usize, 0usize);
    let mut star: Option<usize> = None;
    let mut mark = 0usize;

    while t < text.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == text[t]) {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            mark = t;
            p += 1;
        } else if let Some(star_pos) = star {
            p = star_pos + 1;
            mark += 1;
            t = mark;
        } else {
            return false;
        }
    }

    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn star_crosses_separators() {
        assert!(wildcard_match(b"*.db", b"a/b/c.db"));
        assert!(wildcard_match(b"*Library*", b"x/Library/y"));
        assert!(!wildcard_match(b"*.db", b"c.txt"));
    }

    #[test]
    fn question_matches_one_char() {
        assert!(wildcard_match(b"?at", b"cat"));
        assert!(!wildcard_match(b"?at", b"at"));
    }

    /// `*/x/*` needs a literal `/` before `x`, so a path *starting* with `x/`
    /// is NOT matched — that is what the root-level twin glob (`x/*`) is for.
    /// Locks the semantics `presets/_fast.yml` and docs/presets.md rely on
    /// (review finding L4).
    #[test]
    fn leading_star_slash_does_not_match_a_root_level_path() {
        assert!(wildcard_match(
            b"*/lib/arm64-v8a/*",
            b"data/app/lib/arm64-v8a/x.so"
        ));
        assert!(!wildcard_match(b"*/lib/arm64-v8a/*", b"lib/arm64-v8a/x.so"));
        assert!(wildcard_match(b"lib/arm64-v8a/*", b"lib/arm64-v8a/x.so"));
    }

    fn media() -> Option<TypeInfo> {
        Some(TypeInfo {
            name: "jpeg",
            category: "media",
        })
    }
    fn sqlite() -> Option<TypeInfo> {
        Some(TypeInfo {
            name: "sqlite",
            category: "database",
        })
    }

    #[test]
    fn all_selects_everything() {
        let f = EntryFilter::all();
        assert_eq!(f.select("any/path.txt"), PathDecision::Search);
        assert_eq!(f.select("photo.jpg"), PathDecision::Search); // select() is path-only
        assert_eq!(f.accept_type(media()), TypeDecision::Search); // and `all` keeps media too
    }

    #[test]
    fn include_restricts_to_matching() {
        let f = EntryFilter::new(&["*.db".into()], &[], &[], false);
        assert_eq!(f.select("a/x.db"), PathDecision::Search);
        assert_eq!(f.select("a/x.txt"), PathDecision::SkipNotIncluded);
    }

    #[test]
    fn exclude_rejects_matching() {
        let f = EntryFilter::new(&[], &["*/Caches/*".into()], &[], false);
        assert_eq!(f.select("a/Documents/x.db"), PathDecision::Search);
        assert_eq!(f.select("a/Caches/x.db"), PathDecision::SkipNotPath(0));
    }

    #[test]
    fn exclude_wins_over_include() {
        let f = EntryFilter::new(&["*.db".into()], &["*/Caches/*".into()], &[], false);
        assert_eq!(f.select("a/Caches/x.db"), PathDecision::SkipNotPath(0));
    }

    #[test]
    fn skip_media_drops_media_category() {
        let f = EntryFilter::new(&[], &[], &[], true);
        assert_eq!(f.accept_type(media()), TypeDecision::SkipMedia); // a/v dropped
        assert_eq!(f.accept_type(sqlite()), TypeDecision::Search); // non-media kept
        assert_eq!(f.accept_type(None), TypeDecision::Search); // unrecognised still searched
    }

    #[test]
    fn include_media_keeps_media() {
        let f = EntryFilter::new(&[], &[], &[], false); // skip_media off
        assert_eq!(f.accept_type(media()), TypeDecision::Search);
    }

    #[test]
    fn type_allowlist_matches_name_or_category() {
        let by_name = EntryFilter::new(&[], &[], &["sqlite".into()], true);
        assert_eq!(by_name.accept_type(sqlite()), TypeDecision::Search);
        assert_eq!(by_name.accept_type(media()), TypeDecision::SkipType);
        assert_eq!(by_name.accept_type(None), TypeDecision::SkipType);

        // A category value selects the whole family; it also overrides the media
        // skip, so `--type media` keeps media even though skip_media is set.
        let by_category = EntryFilter::new(&[], &[], &["media".into()], true);
        assert_eq!(by_category.accept_type(media()), TypeDecision::Search);
        assert_eq!(by_category.accept_type(sqlite()), TypeDecision::SkipType);
    }
}
