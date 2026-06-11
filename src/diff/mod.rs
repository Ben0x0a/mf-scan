//! Diff engine: compare two sources and report which files changed.
//!
//! Defines: [`Change`] (a file's fate), [`FileDiff`] (one file's verdict),
//! [`DiffReport`] (the whole comparison), and [`diff_sources`] (build it). Pairs the
//! two sides' files by their internal path and classifies each as added / removed /
//! modified / unchanged using a [`compare::CompareMode`].
//! Used by: `report::diff` (renders the report) and the binary's `run::diff`.
//! Uses: `crate::filter::EntryFilter` (path selection), `crate::models::Entry`,
//! `crate::source::Source`, and the [`compare`] submodule.
//!
//! "Side A" is the baseline and "side B" the comparison: a file only in B is
//! *added*, a file only in A is *removed*. Intra-file diff (what changed *inside* a
//! modified file) is layered on later via `--inspect`.

pub mod compare;

pub use compare::CompareMode;

use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;

use crate::filter::{EntryFilter, PathDecision};
use crate::inspect;
use crate::models::{ContentDiff, Entry};
use crate::source::Source;

/// What happened to a file between side A (baseline) and side B (comparison).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Change {
    /// Present in B only.
    Added,
    /// Present in A only.
    Removed,
    /// Present in both, but the content (or metadata) differs.
    Modified,
    /// Present in both and the same.
    Unchanged,
}

impl Change {
    /// Lowercase tag for machine-readable output.
    pub fn as_str(self) -> &'static str {
        match self {
            Change::Added => "added",
            Change::Removed => "removed",
            Change::Modified => "modified",
            Change::Unchanged => "unchanged",
        }
    }
}

/// One file's verdict, with the size on each side (`None` where the file is absent)
/// and, for a modified file under `--inspect`, what changed *inside* it.
pub struct FileDiff {
    pub path: String,
    pub change: Change,
    pub size_a: Option<u64>,
    pub size_b: Option<u64>,
    /// Structured intra-file diff, present only for a [`Change::Modified`] file of a
    /// recognised format when `inspect` was requested.
    pub content: Option<ContentDiff>,
}

/// The result of comparing two sources: one [`FileDiff`] per distinct path (across
/// both sides), in path order — unchanged files included, so callers can both
/// summarise and list as they wish.
pub struct DiffReport {
    pub files: Vec<FileDiff>,
}

impl DiffReport {
    /// `(added, removed, modified, unchanged)` counts.
    pub fn counts(&self) -> (usize, usize, usize, usize) {
        let mut c = (0, 0, 0, 0);
        for f in &self.files {
            match f.change {
                Change::Added => c.0 += 1,
                Change::Removed => c.1 += 1,
                Change::Modified => c.2 += 1,
                Change::Unchanged => c.3 += 1,
            }
        }
        c
    }
}

/// Compare two sources, pairing files by internal path and classifying each.
///
/// `filter` restricts which files are compared (path include/exclude globs); it is
/// applied to both sides before pairing. Directory placeholders are ignored. When
/// `inspect` is set, each modified file of a recognised format is parsed on both
/// sides to report what changed *inside* it (see [`crate::inspect::diff`]).
pub fn diff_sources(
    a: &dyn Source,
    b: &dyn Source,
    mode: CompareMode,
    filter: &EntryFilter,
    inspect: bool,
) -> Result<DiffReport> {
    let a_map = comparable(a, filter);
    let b_map = comparable(b, filter);

    // Every path on either side, in sorted order (deterministic report).
    let paths: BTreeSet<&str> = a_map.keys().chain(b_map.keys()).copied().collect();

    let mut files = Vec::with_capacity(paths.len());
    for path in paths {
        let file = match (a_map.get(path), b_map.get(path)) {
            (Some(ea), None) => FileDiff {
                path: path.to_string(),
                change: Change::Removed,
                size_a: Some(ea.uncompressed_size),
                size_b: None,
                content: None,
            },
            (None, Some(eb)) => FileDiff {
                path: path.to_string(),
                change: Change::Added,
                size_a: None,
                size_b: Some(eb.uncompressed_size),
                content: None,
            },
            (Some(ea), Some(eb)) => {
                let (change, content) = if compare::differs(mode, a, ea, b, eb)? {
                    // Read both sides once for the intra-file diff (modified + inspect
                    // only). A format with no structured diff yields `None`.
                    let content = if inspect {
                        inspect::diff(path, &a.content(ea)?, &b.content(eb)?)
                    } else {
                        None
                    };
                    (Change::Modified, content)
                } else {
                    (Change::Unchanged, None)
                };
                FileDiff {
                    path: path.to_string(),
                    change,
                    size_a: Some(ea.uncompressed_size),
                    size_b: Some(eb.uncompressed_size),
                    content,
                }
            }
            // `path` came from the union of both maps, so at least one side has it.
            (None, None) => unreachable!("path {path} is in neither side"),
        };
        files.push(file);
    }
    Ok(DiffReport { files })
}

/// The comparable files of `src`: non-directory entries that pass the path filter,
/// keyed by internal path for pairing.
fn comparable<'s>(src: &'s dyn Source, filter: &EntryFilter) -> BTreeMap<&'s str, &'s Entry> {
    src.entries()
        .iter()
        .filter(|e| !e.is_dir() && matches!(filter.select(&e.name), PathDecision::Search))
        .map(|e| (e.name.as_str(), e))
        .collect()
}
