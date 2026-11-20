//! Where a file lands in a tree export, and which of several nested folders owns a
//! path: the path layout shared by the export planner, the backup rebuild, the
//! search annotation and the app tally.
//!
//! Defines: [`PrefixIndex`] (the one longest-prefix rule), [`output_roots`] and
//! [`tree_dir`] (the output directory for a logical directory), and the helpers that
//! attribute a path to an output root and make each component safe on every host
//! (`attribute`, `relative_under`, `sanitise_label`, `split_dir_base`,
//! `sanitise_segment`, `sanitise_basename`).
//! Used by: `report::export` (planning a tree export), `ops::rebuild` (placing a
//! backup's directory records where its files land), `platform::ios::containers`
//! (the app owning a search hit), `ops::apps` (charging each file to one container),
//! and `core::filter::is_under` (`relative_under`: one segment-boundary rule).
//! Uses: nothing beyond `std`.
//!
//! WHY in `core`: operations (`ops::rebuild`, `ops::apps`), the platform layer and
//! the export writer (`report::export`) need the same answer to "where does this path
//! go", and none of them may depend on the others.

use std::collections::HashMap;

/// The portion of `path` inside container `prefix`: `Some("")` when `path` IS the
/// prefix, `Some(rest)` when `path` is `prefix/rest`, `None` when `path` is not
/// under `prefix`. The segment-boundary rule [`PrefixIndex`] follows.
pub(crate) fn relative_under<'a>(prefix: &str, path: &'a str) -> Option<&'a str> {
    if path == prefix {
        return Some("");
    }
    path.strip_prefix(prefix)
        .and_then(|rest| rest.strip_prefix('/'))
}

/// Path prefixes, each with a value, looked up by the longest prefix holding a path
/// on `/`-segment boundaries (the prefixes `relative_under` accepts).
///
/// WHY one rule: containers nest (an extension's container may sit inside another
/// registered folder), so the most specific owner must claim a path; the search
/// annotation, the export layout, the backup rebuild's directories and `app list`'s
/// tally must agree on which one it is.
/// HOW: the path itself, then each of its folders from the deepest up, is looked up,
/// so a lookup costs the path's depth, not the number of prefixes. A prefix given
/// twice keeps its last value.
#[derive(Debug, Clone)]
pub struct PrefixIndex<T> {
    map: HashMap<String, T>,
}

impl<T> FromIterator<(String, T)> for PrefixIndex<T> {
    fn from_iter<I: IntoIterator<Item = (String, T)>>(iter: I) -> Self {
        Self {
            map: iter.into_iter().collect(),
        }
    }
}

impl<T> PrefixIndex<T> {
    /// The value of the longest prefix holding `path`, and `path` relative to it
    /// (`""` when `path` is the prefix).
    pub fn longest<'p>(&self, path: &'p str) -> Option<(&T, &'p str)> {
        if let Some(value) = self.map.get(path) {
            return Some((value, ""));
        }
        let mut end = path.len();
        while let Some(pos) = path[..end].rfind('/') {
            if let Some(value) = self.map.get(&path[..pos]) {
                return Some((value, &path[pos + 1..]));
            }
            end = pos;
        }
        None
    }

    /// Every `(prefix, value)`, in no particular order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &T)> {
        self.map
            .iter()
            .map(|(prefix, value)| (prefix.as_str(), value))
    }

    /// True when the index holds no prefix.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

/// The output roots of a tree layout: each `(prefix, label)` of `roots` with its
/// label made safe (`sanitise_label`), ready for `attribute` and [`tree_dir`].
pub fn output_roots(roots: &[(String, String)]) -> PrefixIndex<String> {
    roots
        .iter()
        .map(|(prefix, label)| (prefix.clone(), sanitise_label(label)))
        .collect()
}

/// Attribute `path` to the longest root containing it, returning that root's
/// sanitised output label and `path` relative to the root's prefix.
///
/// Shared by [`crate::report::export::plan_tree`] (which then splits the remainder
/// into folder and basename) and [`tree_dir`] (which keeps it whole), so a rebuilt
/// tree's files and its directories cannot be attributed differently.
pub(crate) fn attribute<'r, 'p>(
    path: &'p str,
    roots: &'r PrefixIndex<String>,
) -> Option<(&'r str, &'p str)> {
    roots
        .longest(path)
        .map(|(label, rel)| (label.as_str(), rel))
}

/// The output-relative DIRECTORY path for a logical directory name under `roots`
/// ([`output_roots`]).
///
/// `None` when no root contains it. Used to recreate a backup's directory records,
/// which are not files and so never appear in an [`crate::report::export::ExportPlan`].
pub fn tree_dir(path: &str, roots: &PrefixIndex<String>) -> Option<String> {
    let (label, rel) = attribute(path, roots)?;
    let mut out = label.to_string();
    for seg in rel.split('/').filter(|seg| !seg.is_empty()) {
        out.push('/');
        out.push_str(&sanitise_segment(seg));
    }
    Some(out)
}

/// Make an output label safe to join onto the destination directory.
///
/// Keeps the label's own `/` separators (it names a subtree, not one segment) but
/// drops anything that would let it escape: a leading separator, and any `.` or
/// `..` component. Each remaining component is sanitised like any other path
/// segment.
///
/// WHY this is load-bearing: the destination is built with `dir.join(folder)`, and
/// `Path::join` DISCARDS the base when its argument is absolute — `dir.join("/a")`
/// is `/a`, not `dir/a`. Labels used to be copied verbatim, which was safe only
/// because every caller derived them from bundle identifiers. A label built from
/// iOS filesystem knowledge naturally reads `/private/var/mobile`, and that would
/// have written to the real filesystem root instead of the export directory.
pub(crate) fn sanitise_label(label: &str) -> String {
    label
        .split(['/', '\\'])
        .filter(|seg| !seg.is_empty() && *seg != "." && *seg != "..")
        .map(sanitise_segment)
        .collect::<Vec<_>>()
        .join("/")
}

/// Split a `/`-separated relative path into its directory segments and basename,
/// dropping empty segments. `"Library/Caches/x.db"` → `(["Library","Caches"], "x.db")`.
pub(crate) fn split_dir_base(rel: &str) -> (Vec<&str>, &str) {
    match rel.rfind('/') {
        Some(pos) => (
            rel[..pos].split('/').filter(|s| !s.is_empty()).collect(),
            &rel[pos + 1..],
        ),
        None => (Vec::new(), rel),
    }
}

/// Reduce an internal path to a host-safe basename.
///
/// Strips the directory part, then sanitises the last segment via
/// [`sanitise_segment`].
pub(crate) fn sanitise_basename(path: &str) -> String {
    sanitise_segment(path.rsplit('/').next().unwrap_or(path))
}

/// Make one path component host-safe.
///
/// Replaces characters illegal on Windows/Unix with `_`, trims trailing dots and
/// spaces (which Windows rejects), and falls back to a placeholder for an empty
/// result (e.g. a directory placeholder entry). WHY a per-segment helper:
/// `plan_tree` rebuilds a whole relative tree and must sanitise every segment,
/// not just the basename — both callers share this one rule so the two layouts
/// can never sanitise differently.
pub(crate) fn sanitise_segment(segment: &str) -> String {
    let mut name: String = segment
        .chars()
        .map(|c| {
            if c.is_control() || matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*') {
                '_'
            } else {
                c
            }
        })
        .collect();
    let trimmed = name.trim_end_matches([' ', '.']);
    if trimmed.len() != name.len() {
        name = trimmed.to_string();
    }
    if name.is_empty() {
        name.push_str("unnamed");
    }
    name
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The index finds exactly the longest prefix a scan with [`relative_under`]
    /// would, on segment boundaries, nested prefixes, an empty prefix and paths
    /// starting with `/`.
    #[test]
    fn the_index_agrees_with_a_scan() {
        let prefixes = ["a", "a/b", "a/bc", "", "/p", "/p/q", "x//y"];
        let index: PrefixIndex<&str> = prefixes.iter().map(|p| (p.to_string(), *p)).collect();
        let paths = [
            "a", "a/b", "a/b/c.db", "a/bc/d", "a/bcd/e", "ab/c", "b", "", "/p/q/r", "/p/qr", "/z",
            "x//y/z", "x/y/z",
        ];
        for path in paths {
            let scan = prefixes
                .iter()
                .filter_map(|p| relative_under(p, path).map(|rel| (p.len(), *p, rel)))
                .max_by_key(|(len, _, _)| *len)
                .map(|(_, p, rel)| (p, rel));
            let found = index.longest(path).map(|(p, rel)| (*p, rel));
            assert_eq!(found, scan, "{path:?}");
        }
        assert_eq!(index.longest("a/b/c.db"), Some((&"a/b", "c.db")));
        assert_eq!(index.longest("a/bcd/e"), Some((&"a", "bcd/e")));
    }
}
