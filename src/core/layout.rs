//! Where a file lands in a tree export: the path layout shared by the export planner
//! and the backup rebuild.
//!
//! Defines: [`tree_dir`] (the output directory for a logical directory), and the
//! helpers that attribute a path to an output root and make each component safe on
//! every host (`attribute`, `relative_under`, `sanitise_label`, `split_dir_base`,
//! `sanitise_segment`, `sanitise_basename`).
//! Used by: `report::export` (planning a tree export) and `ops::rebuild` (placing a
//! backup's directory records where its files land).
//! Uses: nothing beyond `std`.
//!
//! WHY in `core`: both an operation (`ops::rebuild`) and the export writer
//! (`report::export`) need the same answer to "where does this path go", and `ops`
//! must not depend on `report`.

/// The portion of `path` inside container `prefix`: `Some("")` when `path` IS the
/// prefix, `Some(rest)` when `path` is `prefix/rest`, `None` when `path` is not
/// under `prefix`. Mirrors the segment-boundary rule in `AppContainerMap`.
pub(crate) fn relative_under<'a>(prefix: &str, path: &'a str) -> Option<&'a str> {
    if path == prefix {
        return Some("");
    }
    path.strip_prefix(prefix)
        .and_then(|rest| rest.strip_prefix('/'))
}

/// Attribute `path` to the longest root containing it, returning that root's
/// sanitised output label and `path` relative to the root's prefix.
///
/// WHY longest-prefix wins: containers nest, so the most specific owner must claim
/// the file. Shared by [`crate::report::export::plan_tree`] (which then splits the remainder into folder
/// and basename) and [`tree_dir`] (which keeps it whole), so a rebuilt tree's
/// files and its directories cannot be attributed differently.
pub(crate) fn attribute<'p>(
    path: &'p str,
    roots: &[(String, String)],
) -> Option<(String, &'p str)> {
    roots
        .iter()
        .filter_map(|(prefix, label)| {
            relative_under(prefix, path).map(|rel| (prefix.len(), label, rel))
        })
        .max_by_key(|(prefix_len, _, _)| *prefix_len)
        .map(|(_, label, rel)| (sanitise_label(label), rel))
}

/// The output-relative DIRECTORY path for a logical directory name under `roots`.
///
/// `None` when no root contains it. Used to recreate a backup's directory records,
/// which are not files and so never appear in an [`crate::report::export::ExportPlan`].
pub fn tree_dir(path: &str, roots: &[(String, String)]) -> Option<String> {
    let (label, rel) = attribute(path, roots)?;
    let mut out = label;
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
/// [`plan_tree`] rebuilds a whole relative tree and must sanitise every segment,
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
