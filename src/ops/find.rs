//! List a source's files by name, size, date and type, like the `find` command.
//!
//! Defines: [`FindQuery`] (the tests), [`SizeTest`], [`Found`] (one result) and
//! [`find`].
//! Used by: the binary's `find` subcommand (`cmd::run::find`).
//! Uses: `core::filter` (the one wildcard matcher), `core::source`,
//! `formats::inspect` (content-based `--type`), `rayon`.
//!
//! WHY a peer of `ops::search`: search reads every selected file looking for bytes;
//! this asks about names, and reads a file's header only when a format is requested.
//! A listing of a whole acquisition therefore costs what parsing its directory costs.
//!
//! Tests combine as in `find`: different tests must all hold. Unlike `find`, repeating
//! one (`--name '*.db' --name '*.sqlite'`) means either, since there is no `-o`.

use std::collections::BTreeMap;

use anyhow::{Result, bail};
use rayon::prelude::*;
use regex::{Regex, RegexBuilder};

use crate::core::filter::{is_under, matches};
use crate::core::models::Entry;
use crate::core::models::TypeInfo;
use crate::core::source::Source;
use crate::engine::{Typing, type_from_ends};
use crate::formats::inspect::detect_type;

/// One `--size` test. A bare number is bytes; `k`, `M` and `G` are 1024-based.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SizeTest {
    /// `+N`: larger than N.
    Over(u64),
    /// `-N`: smaller than N.
    Under(u64),
    /// `N`: exactly N units, rounding the size up to the unit, as `find` does.
    Equal { units: u64, unit: u64 },
}

impl SizeTest {
    /// Parse `+10M`, `-1k`, `4096`, or `4096c`.
    pub fn parse(text: &str) -> Result<Self> {
        let invalid = || format!("invalid --size '{text}' (expected e.g. +10M, -1k or 4096)");
        let (sign, body) = match text.strip_prefix(['+', '-']) {
            Some(rest) => (text.as_bytes()[0], rest),
            None => (0, text),
        };
        let (digits, unit) = match body.char_indices().last() {
            Some((i, 'c')) => (&body[..i], 1),
            Some((i, 'k' | 'K')) => (&body[..i], 1 << 10),
            Some((i, 'm' | 'M')) => (&body[..i], 1 << 20),
            Some((i, 'g' | 'G')) => (&body[..i], 1 << 30),
            _ => (body, 1),
        };
        let units: u64 = digits.parse().map_err(|_| anyhow::anyhow!(invalid()))?;
        let bytes = units
            .checked_mul(unit)
            .ok_or_else(|| anyhow::anyhow!(invalid()))?;
        Ok(match sign {
            b'+' => SizeTest::Over(bytes),
            b'-' => SizeTest::Under(bytes),
            _ => SizeTest::Equal { units, unit },
        })
    }

    fn holds(&self, size: u64) -> bool {
        match *self {
            SizeTest::Over(limit) => size > limit,
            SizeTest::Under(limit) => size < limit,
            SizeTest::Equal { units, unit } => size.div_ceil(unit) == units,
        }
    }
}

/// What to look for. Empty fields test nothing.
#[derive(Debug, Default)]
pub struct FindQuery {
    /// Wildcards over the file name alone.
    pub names: Vec<String>,
    pub inames: Vec<String>,
    /// Wildcards over the whole path.
    pub paths: Vec<String>,
    pub ipaths: Vec<String>,
    pub not_names: Vec<String>,
    pub not_paths: Vec<String>,
    /// Regexes over the whole path, anchored at both ends as in `find -regex`.
    pub regexes: Vec<Regex>,
    /// `f` (file), `d` (directory), or a format or category such as `sqlite`.
    pub types: Vec<String>,
    pub sizes: Vec<SizeTest>,
    /// Modified after this time (Unix seconds).
    pub newer: Option<u64>,
    /// Modified before this time (Unix seconds).
    pub older: Option<u64>,
    /// Deepest level to list, where a source's top-level names are level 1.
    pub max_depth: Option<usize>,
    /// `--app`: the path prefixes of the apps' containers; a path must be under one.
    /// `None` without `--app`; empty when the apps were found nowhere.
    pub scope: Option<Vec<String>>,
}

impl FindQuery {
    /// Compile a `--regex`, anchored to the whole path as `find` anchors it.
    pub fn compile_regex(pattern: &str, ignore_case: bool) -> Result<Regex> {
        RegexBuilder::new(&format!(r"\A(?:{pattern})\z"))
            .case_insensitive(ignore_case)
            .build()
            .map_err(|e| anyhow::anyhow!("invalid --regex '{pattern}': {e}"))
    }

    /// Whether a format name appears among the types, which needs file contents.
    fn wants_format(&self) -> bool {
        self.types.iter().any(|t| t != "f" && t != "d")
    }

    /// Every test that needs nothing but the listing.
    fn passes_listing_tests(
        &self,
        path: &str,
        is_dir: bool,
        size: u64,
        mtime: Option<u64>,
    ) -> bool {
        let name = path.rsplit('/').next().unwrap_or(path);
        let folded = |text: &str| text.to_lowercase();
        let any_folded =
            |globs: &[String], text: &str| globs.iter().any(|g| matches(&folded(g), &folded(text)));

        // A name test holds if a case-sensitive or case-insensitive pattern matches.
        let name_ok = (self.names.is_empty() && self.inames.is_empty())
            || self.names.iter().any(|g| matches(g, name))
            || any_folded(&self.inames, name);
        let path_ok = (self.paths.is_empty() && self.ipaths.is_empty())
            || self.paths.iter().any(|g| matches(g, path))
            || any_folded(&self.ipaths, path);
        name_ok
            && path_ok
            && self
                .scope
                .as_ref()
                .is_none_or(|scope| scope.iter().any(|prefix| is_under(prefix, path)))
            && !self.not_names.iter().any(|g| matches(g, name))
            && !self.not_paths.iter().any(|g| matches(g, path))
            && (self.regexes.is_empty() || self.regexes.iter().any(|r| r.is_match(path)))
            && self.sizes.iter().all(|s| s.holds(size))
            && self.newer.is_none_or(|t| mtime.is_some_and(|m| m > t))
            && self.older.is_none_or(|t| mtime.is_some_and(|m| m < t))
            && self.max_depth.is_none_or(|d| depth(path) <= d)
            && self.passes_kind_test(is_dir)
    }

    /// The `f`/`d` part of `--type`. With a format requested, only a file can pass.
    fn passes_kind_test(&self, is_dir: bool) -> bool {
        if self.types.is_empty() {
            return true;
        }
        let kind = if is_dir { "d" } else { "f" };
        self.types.iter().any(|t| t == kind) || (!is_dir && self.wants_format())
    }
}

/// One result, borrowing the entry a file came from (directories may have none).
#[derive(Debug)]
pub struct Found<'s> {
    /// The path, without a trailing `/`.
    pub path: String,
    pub is_dir: bool,
    pub size: u64,
    pub mtime: Option<u64>,
    /// The detected format, known only when `--type` asked for one.
    pub format: Option<&'static str>,
    /// The file's entry, for exporting; `None` for a directory.
    pub entry: Option<&'s Entry>,
}

/// What a listing found, and what it could not decide.
#[derive(Debug, Default)]
pub struct FindOutcome<'s> {
    pub found: Vec<Found<'s>>,
    /// Files whose header could not be read to test `--type`.
    pub unreadable: Vec<String>,
    /// How many entries a date test excluded only because they have no timestamp.
    pub undated: usize,
}

/// A path's level below the source root: `a` is 1, `a/b` is 2.
fn depth(path: &str) -> usize {
    path.split('/').filter(|p| !p.is_empty()).count()
}

/// A listing candidate: a file, or a directory recorded or implied by the files.
struct Candidate<'s> {
    path: String,
    is_dir: bool,
    size: u64,
    mtime: Option<u64>,
    entry: Option<&'s Entry>,
}

/// Every file, plus every directory: those the source records, and those only implied
/// by the paths of its files. A folder source and many archives record none, and `find`
/// lists directories whether or not they have a record of their own.
fn candidates<'s>(entries: &'s [Entry]) -> Vec<Candidate<'s>> {
    let mut directories: BTreeMap<String, Option<u64>> = BTreeMap::new();
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        let trimmed = entry.name.trim_end_matches('/');
        if entry.is_dir() {
            directories.insert(trimmed.to_string(), entry.mtime);
        } else {
            out.push(Candidate {
                path: entry.name.clone(),
                is_dir: false,
                size: entry.uncompressed_size,
                mtime: entry.mtime,
                entry: Some(entry),
            });
        }
        let mut parent = trimmed;
        while let Some((up, _)) = parent.rsplit_once('/') {
            if up.is_empty() {
                break;
            }
            directories.entry(up.to_string()).or_insert(None);
            parent = up;
        }
    }
    out.extend(directories.into_iter().map(|(path, mtime)| Candidate {
        path,
        is_dir: true,
        size: 0,
        mtime,
        entry: None,
    }));
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

/// List what in `source` satisfies `query`, in path order.
pub fn find<'s>(source: &'s dyn Source, query: &FindQuery) -> Result<FindOutcome<'s>> {
    if query
        .newer
        .is_some_and(|n| query.older.is_some_and(|o| n >= o))
    {
        bail!("--newer must be earlier than --older, or nothing can match");
    }
    let wants_format = query.wants_format();

    /// One candidate's fate.
    enum Fate<'s> {
        Kept(Found<'s>),
        Unreadable(String),
        Dropped,
    }

    let all = candidates(source.entries());
    let date_test = query.newer.is_some() || query.older.is_some();
    let undated = if date_test {
        all.iter()
            .filter(|c| {
                c.mtime.is_none()
                    && query.passes_listing_tests(
                        &c.path,
                        c.is_dir,
                        c.size,
                        Some(dated_value(query)),
                    )
            })
            .count()
    } else {
        0
    };

    let fates: Vec<Fate<'s>> = all
        .into_par_iter()
        .map(|c| {
            if !query.passes_listing_tests(&c.path, c.is_dir, c.size, c.mtime) {
                return Fate::Dropped;
            }
            let mut format = None;
            if wants_format && !c.is_dir && !query.types.iter().any(|t| t == "f") {
                let entry = c.entry.expect("a file candidate always has its entry");
                let wanted_as = |info: Option<TypeInfo>| {
                    info.filter(|i| query.types.iter().any(|t| t == i.name || t == i.category))
                        .map(|i| i.name)
                };
                let info = match type_from_ends(source, entry, |a, b| wanted_as(a) != wanted_as(b))
                {
                    Ok(Typing::Known(info)) => info,
                    Ok(Typing::Undecided) => match source.content(entry) {
                        Ok(content) => detect_type(&entry.name, &content),
                        Err(_) => return Fate::Unreadable(c.path),
                    },
                    Err(_) => return Fate::Unreadable(c.path),
                };
                let wanted = wanted_as(info).is_some();
                if !wanted {
                    return Fate::Dropped;
                }
                format = info.map(|i| i.name);
            }
            Fate::Kept(Found {
                path: c.path,
                is_dir: c.is_dir,
                size: c.size,
                mtime: c.mtime,
                format,
                entry: c.entry,
            })
        })
        .collect();

    let mut outcome = FindOutcome {
        undated,
        ..FindOutcome::default()
    };
    for fate in fates {
        match fate {
            Fate::Kept(found) => outcome.found.push(found),
            Fate::Unreadable(path) => outcome.unreadable.push(path),
            Fate::Dropped => {}
        }
    }
    Ok(outcome)
}

/// A time satisfying the query's date tests, to ask whether an undated entry would have
/// passed everything else.
fn dated_value(query: &FindQuery) -> u64 {
    match (query.newer, query.older) {
        (Some(newer), _) => newer.saturating_add(1),
        (None, Some(older)) => older.saturating_sub(1),
        (None, None) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::models::Location;
    use crate::core::source::Content;
    use std::path::PathBuf;

    struct Fake(Vec<Entry>);

    impl Source for Fake {
        fn entries(&self) -> &[Entry] {
            &self.0
        }
        fn content(&self, entry: &Entry) -> Result<Content<'_>> {
            if entry.name.ends_with("locked.db") {
                bail!("permission denied");
            }
            let bytes: &[u8] = if entry.name.ends_with(".db") {
                b"SQLite format 3\x00"
            } else {
                b"plain text\n"
            };
            Ok(Content::Borrowed(bytes))
        }
    }

    fn entry(name: &str, size: u64, mtime: Option<u64>) -> Entry {
        Entry {
            name: name.to_string(),
            uncompressed_size: size,
            mtime,
            location: Location::Loose {
                path: PathBuf::from(name),
            },
        }
    }

    fn source() -> Fake {
        Fake(vec![
            entry("Library/SMS/sms.db", 2048, Some(2_000)),
            entry("Library/notes.TXT", 10, Some(1_000)),
            entry("Library/Caches/", 0, Some(1_500)),
            entry("top.txt", 2 * 1024 * 1024, None),
        ])
    }

    fn paths(query: &FindQuery) -> Vec<String> {
        find(&source(), query)
            .unwrap()
            .found
            .into_iter()
            .map(|f| f.path)
            .collect()
    }

    #[test]
    fn no_tests_lists_files_and_directories_including_implied_ones() {
        assert_eq!(
            paths(&FindQuery::default()),
            [
                "Library",
                "Library/Caches",
                "Library/SMS",
                "Library/SMS/sms.db",
                "Library/notes.TXT",
                "top.txt"
            ]
        );
    }

    #[test]
    fn name_tests_the_file_name_and_path_the_whole_path() {
        let query = FindQuery {
            names: vec!["*.db".into()],
            ..FindQuery::default()
        };
        assert_eq!(paths(&query), ["Library/SMS/sms.db"]);

        // As in `find`, `-path` must match the whole path, while `-name` needs only
        // the file name.
        let query = FindQuery {
            names: vec!["sms.db".into()],
            ..FindQuery::default()
        };
        assert_eq!(paths(&query), ["Library/SMS/sms.db"]);
        let query = FindQuery {
            paths: vec!["sms.db".into()],
            ..FindQuery::default()
        };
        assert!(paths(&query).is_empty());
    }

    #[test]
    fn case_insensitive_forms_fold_both_sides() {
        let query = FindQuery {
            inames: vec!["NOTES.txt".into()],
            ..FindQuery::default()
        };
        assert_eq!(paths(&query), ["Library/notes.TXT"]);
        let query = FindQuery {
            names: vec!["notes.txt".into()],
            ..FindQuery::default()
        };
        assert!(paths(&query).is_empty());
    }

    #[test]
    fn repeating_a_test_means_either_and_different_tests_must_all_hold() {
        let query = FindQuery {
            names: vec!["*.db".into(), "top*".into()],
            ..FindQuery::default()
        };
        assert_eq!(paths(&query), ["Library/SMS/sms.db", "top.txt"]);
        let query = FindQuery {
            names: vec!["*.db".into(), "top*".into()],
            sizes: vec![SizeTest::Over(1 << 20)],
            ..FindQuery::default()
        };
        assert_eq!(paths(&query), ["top.txt"]);
    }

    #[test]
    fn negations_and_regex() {
        let query = FindQuery {
            types: vec!["f".into()],
            not_names: vec!["*.db".into()],
            not_paths: vec!["top*".into()],
            ..FindQuery::default()
        };
        assert_eq!(paths(&query), ["Library/notes.TXT"]);

        // Anchored to the whole path, as `find -regex` is.
        let query = FindQuery {
            regexes: vec![FindQuery::compile_regex(r"sms\.db", false).unwrap()],
            ..FindQuery::default()
        };
        assert!(paths(&query).is_empty());
        let query = FindQuery {
            regexes: vec![FindQuery::compile_regex(r".*/sms\.db", false).unwrap()],
            ..FindQuery::default()
        };
        assert_eq!(paths(&query), ["Library/SMS/sms.db"]);
    }

    #[test]
    fn type_covers_kind_and_detected_format() {
        let dirs = FindQuery {
            types: vec!["d".into()],
            ..FindQuery::default()
        };
        assert_eq!(paths(&dirs), ["Library", "Library/Caches", "Library/SMS"]);

        // Detected from content: `.db` here carries the SQLite magic.
        let src = source();
        let result = find(
            &src,
            &FindQuery {
                types: vec!["sqlite".into()],
                ..FindQuery::default()
            },
        )
        .unwrap();
        assert_eq!(result.found.len(), 1);
        assert_eq!(result.found[0].path, "Library/SMS/sms.db");
        assert_eq!(result.found[0].format, Some("sqlite"));
    }

    #[test]
    fn an_unreadable_file_is_reported_not_silently_dropped() {
        let src = Fake(vec![entry("locked.db", 1, None), entry("ok.db", 1, None)]);
        let result = find(
            &src,
            &FindQuery {
                types: vec!["sqlite".into()],
                ..FindQuery::default()
            },
        )
        .unwrap();
        assert_eq!(result.unreadable, ["locked.db"]);
        assert_eq!(result.found.len(), 1);
    }

    #[test]
    fn size_tests_follow_find_except_bare_numbers_are_bytes() {
        assert_eq!(SizeTest::parse("+10M").unwrap(), SizeTest::Over(10 << 20));
        assert_eq!(SizeTest::parse("-1k").unwrap(), SizeTest::Under(1024));
        assert!(SizeTest::parse("4096").unwrap().holds(4096));
        assert!(SizeTest::parse("4096c").unwrap().holds(4096));
        assert!(!SizeTest::parse("4096").unwrap().holds(4097));
        // Exact sizes round up to the unit, as `find` does.
        assert!(SizeTest::parse("2k").unwrap().holds(1025));
        assert!(!SizeTest::parse("2k").unwrap().holds(1024));
        for bad in ["", "+", "ten", "10T"] {
            assert!(SizeTest::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn dates_exclude_undated_entries_and_count_them() {
        let query = FindQuery {
            types: vec!["f".into()],
            newer: Some(1_500),
            ..FindQuery::default()
        };
        let src = source();
        let result = find(&src, &query).unwrap();
        let found: Vec<&str> = result.found.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(found, ["Library/SMS/sms.db"]);
        assert_eq!(result.undated, 1, "top.txt has no timestamp");

        let query = FindQuery {
            older: Some(1_500),
            types: vec!["f".into()],
            ..FindQuery::default()
        };
        assert_eq!(paths(&query), ["Library/notes.TXT"]);

        let impossible = FindQuery {
            newer: Some(2),
            older: Some(1),
            ..FindQuery::default()
        };
        assert!(find(&source(), &impossible).is_err());
    }

    #[test]
    fn max_depth_counts_from_the_source_root() {
        let query = FindQuery {
            max_depth: Some(1),
            ..FindQuery::default()
        };
        assert_eq!(paths(&query), ["Library", "top.txt"]);
    }
}
