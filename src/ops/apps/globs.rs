//! Resolve an app-identity `--path` glob to the containers it names.
//!
//! Defines: [`AppGlob`] and [`expand`].
//! Used by: the binary's `grep` orchestrator, to widen the path filter before a
//! search.
//! Uses: [`crate::core::filter::matches`] (the same glob rule `--path` itself
//! uses) and [`crate::platform::ios::containers::AppContainerMap`].
//!
//! ── The problem ───────────────────────────────────────────────────────────────
//! On a full-filesystem acquisition an app's data lives under a container named by
//! a GUID:
//!
//! ```text
//! private/var/mobile/Containers/Data/Application/5A92C2C1-…/Documents/notes.db
//! ```
//!
//! The bundle identifier appears nowhere in that path, so the obvious
//! `--path '*com.burbn.instagram*'` matches nothing. The identifier is recorded in
//! each container's metadata plist, which [`AppContainerMap`] already reads.
//!
//! ── Why expansion, and not a smarter filter ───────────────────────────────────
//! The globs are resolved ONCE, before the search, into ordinary path globs. The
//! alternative — teaching the filter to consult an app map per entry — would push
//! iOS knowledge into the parallel hot path and break the rule stated in
//! [`crate::ops::apps`]: the search engine stays app-agnostic. Expansion also
//! costs nothing per entry, which matters on an acquisition with a million of them.

use crate::core::filter::matches;
use crate::platform::ios::containers::AppContainerMap;

/// One user glob resolved to one app container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppGlob {
    /// The pattern the operator wrote.
    pub pattern: String,
    /// The bundle identifier it matched.
    pub bundle_id: String,
    /// The path glob added to cover that app's container.
    pub glob: String,
}

/// Expand each glob in `patterns` that names an app by identity into a glob over
/// that app's container directory.
///
/// A pattern is tried against the bundle identifier alone; anything that matches
/// no identifier contributes nothing, so an ordinary path glob passes through
/// untouched. Results are sorted and deduplicated so the widened filter is
/// deterministic.
pub fn expand(map: &AppContainerMap, patterns: &[String]) -> Vec<AppGlob> {
    let mut out = Vec::new();
    for pattern in patterns {
        for (container_dir, meta) in map.containers() {
            let bundle_id = meta.identifier.as_str();
            if !matches(pattern, bundle_id) {
                continue;
            }
            // Cover the container directory itself and everything beneath it.
            out.push(AppGlob {
                pattern: pattern.clone(),
                bundle_id: bundle_id.to_string(),
                glob: format!("{container_dir}/**"),
            });
        }
    }
    out.sort_by(|a, b| (&a.bundle_id, &a.glob).cmp(&(&b.bundle_id, &b.glob)));
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A bare bundle id resolves to its container, which a path glob alone cannot
    /// reach because the directory is named by a GUID.
    #[test]
    fn a_bundle_id_pattern_resolves_to_its_container() {
        let map = AppContainerMap::from_pairs(&[
            (
                "root/Containers/Data/Application/5A92C2C1",
                "com.burbn.instagram",
            ),
            (
                "root/Containers/Data/Application/7E82ADBC",
                "com.apple.MobileSMS",
            ),
        ]);
        let found = expand(&map, &["com.burbn.instagram".to_string()]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].bundle_id, "com.burbn.instagram");
        assert_eq!(
            found[0].glob,
            "root/Containers/Data/Application/5A92C2C1/**"
        );
    }

    /// A wildcard may legitimately name several apps.
    #[test]
    fn a_wildcard_pattern_can_resolve_to_several_containers() {
        let map = AppContainerMap::from_pairs(&[
            ("root/a", "com.apple.MobileSMS"),
            ("root/b", "com.apple.Maps"),
            ("root/c", "com.burbn.instagram"),
        ]);
        let found = expand(&map, &["com.apple.*".to_string()]);
        let ids: Vec<&str> = found.iter().map(|g| g.bundle_id.as_str()).collect();
        assert_eq!(ids, vec!["com.apple.Maps", "com.apple.MobileSMS"]);
    }

    /// An ordinary path glob names no app and must contribute nothing, so it keeps
    /// its exact original meaning.
    #[test]
    fn a_plain_path_glob_expands_to_nothing() {
        let map = AppContainerMap::from_pairs(&[("root/a", "com.apple.MobileSMS")]);
        assert!(expand(&map, &["*/Library/SMS/*".to_string()]).is_empty());
        assert!(expand(&map, &["*.db".to_string()]).is_empty());
    }

    #[test]
    fn an_empty_map_expands_to_nothing() {
        let map = AppContainerMap::from_pairs(&[]);
        assert!(expand(&map, &["com.apple.*".to_string()]).is_empty());
    }
}
