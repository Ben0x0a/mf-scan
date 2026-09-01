//! iOS app-container GUID → bundle-ID mapping.
//!
//! Defines: `ContainerMeta` (what a container's metadata plist says about it) and
//! `AppContainerMap` — a table of container-directory paths (as they appear in the
//! source) mapped to that metadata, whose identifier is the app bundle ID (e.g.
//! `com.apple.weather`). Built by reading every
//! `.com.apple.mobile_container_manager.metadata.plist` found in the source;
//! unreadable or unparseable metadata files are silently skipped
//! (degrade-don't-die). Resolves a file path to its bundle ID via
//! longest-prefix matching on `/`-segment boundaries, so a file anywhere inside
//! a container directory resolves to that container's app.
//!
//! Used by: `run::grep` (post-search annotation pass) and `ops::apps::ios_ffs`
//! (inverts the mapping into the app catalogue).
//! Uses: `crate::core::source::Source`, `plist` crate (binary/XML plist parsing,
//! already present in the dependency tree).
//!
//! WHY longest-prefix matching: a match deep inside a container sub-directory
//! must still resolve to the correct container. WHY segment-boundary check:
//! `containers/Bundle/Application/AppleX/` must NOT match
//! `containers/Bundle/Application/Apple/` — a naive string-prefix match would
//! do exactly that if the shorter key is a byte-level prefix of the longer path.

use std::collections::HashMap;
use std::io::Cursor;

use crate::core::source::Source;

/// The exact filename that iOS's container manager places in every container
/// directory to record which app owns it.
const CONTAINER_METADATA_NAME: &str = ".com.apple.mobile_container_manager.metadata.plist";

/// The plist key whose string value holds the app bundle ID.
const BUNDLE_ID_KEY: &str = "MCMMetadataIdentifier";

/// The plist key holding the nested info dictionary.
const METADATA_INFO_KEY: &str = "MCMMetadataInfo";

/// Key inside `MCMMetadataInfo` naming the app that owns an extension/widget
/// container — the authoritative parent link, written by `installd`.
const PARENT_BUNDLE_ID_KEY: &str = "com.apple.MobileInstallation.ParentBundleID";

/// What a container's metadata plist records about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerMeta {
    /// `MCMMetadataIdentifier` — the bundle ID, group ID or package the container
    /// belongs to.
    pub identifier: String,
    /// `MCMMetadataInfo → com.apple.MobileInstallation.ParentBundleID` — the app
    /// that owns this extension/widget container, when the plist declares it.
    ///
    /// WHY it matters: an extension's bundle ID usually extends its parent's
    /// (`com.app.Widget` under `com.app`), but not always — `com.apple.siri` and
    /// `com.apple.siri.SiriGeo` are separate installed apps, so a name-prefix rule
    /// wrongly hands the latter's extensions to the former. This field is the
    /// ground truth; the prefix rule is only a fallback where it is absent.
    pub parent_id: Option<String>,
}

/// A map of container-directory path (in-source) → that container's metadata.
///
/// Built once per source by scanning for container-metadata plists; used for
/// O(k * log n) resolution (k = depth of match path, n = number of containers)
/// by walking the match's path components from longest to shortest.
pub struct AppContainerMap {
    /// Keys are container-directory paths exactly as they appear in the source
    /// entries, WITHOUT a trailing `/`. Values are what the metadata plist said.
    map: HashMap<String, ContainerMeta>,
}

impl AppContainerMap {
    /// Build the map by iterating all entries in `source` and parsing every
    /// container-metadata plist found.
    ///
    /// HOW: for each entry whose basename equals `CONTAINER_METADATA_NAME`,
    /// take the parent directory path (the container directory), read the entry,
    /// parse it as a plist, and extract `MCMMetadataIdentifier` (plus the optional
    /// parent-bundle link). Failures are silently skipped — an acquisition may
    /// have partial or corrupt metadata files, and missing one annotation is far
    /// better than aborting the scan.
    pub fn build(source: &dyn Source) -> Self {
        let mut map = HashMap::new();

        for entry in source.entries() {
            // WHY basename check: only the exact metadata file triggers
            // container-directory registration; any deeper path is ignored.
            if !entry.name.ends_with(CONTAINER_METADATA_NAME) {
                continue;
            }

            // Derive the container directory from the metadata file's path.
            // The container dir is the parent: everything before the final `/`.
            let container_dir = match entry.name.rfind('/') {
                Some(pos) => &entry.name[..pos],
                // A metadata plist with no parent separator would sit at the
                // source root — not a valid iOS container layout; skip it.
                None => continue,
            };

            // Read, parse, and extract the metadata. Any failure is skipped.
            let meta = match extract_metadata(source, entry) {
                Some(meta) => meta,
                None => continue,
            };

            map.insert(container_dir.to_string(), meta);
        }

        Self { map }
    }

    /// True when no iOS container metadata was found in the source.
    ///
    /// WHY: callers can skip the annotation pass entirely when the source has no
    /// iOS containers, avoiding a per-record resolve call on non-iOS acquisitions.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Iterate every `(container_dir, metadata)` pair the scan registered.
    ///
    /// WHY this complements [`AppContainerMap::resolve`]: `resolve` answers the
    /// forward question "which app owns this path?" (used by the search-result
    /// annotation), whereas the `app` subcommand needs the *inverse* — "which
    /// container directories belong to this app?" — built by inverting these pairs.
    /// Exposing the raw pairs (rather than a second internal index) keeps this
    /// struct the single source of truth for the container→identifier mapping; the
    /// caller groups them however it needs.
    pub fn containers(&self) -> impl Iterator<Item = (&str, &ContainerMeta)> {
        self.map.iter().map(|(dir, meta)| (dir.as_str(), meta))
    }

    /// Return the bundle ID for the innermost container whose directory path is
    /// a prefix of `path`, comparing on `/`-segment boundaries.
    ///
    /// Returns the bundle ID for the LONGEST matching prefix, so a file inside a
    /// deeply nested container resolves to the correct (innermost) container when
    /// multiple container paths share a common prefix.
    ///
    /// WHY segment-boundary check: appending `/` before the comparison ensures
    /// that `containers/Bundle/Application/Apple/` cannot prefix-match
    /// `containers/Bundle/Application/AppleX/data.db` — every candidate key
    /// must be followed by a `/` in the target path (or be the full path).
    pub fn resolve(&self, path: &str) -> Option<&str> {
        // WHY linear scan with longest-wins: the map is small (one entry per
        // installed app, typically tens to low hundreds), so a linear scan with
        // max tracking is simpler and fast enough compared to a trie.
        let mut best: Option<(&str, &str)> = None; // (container_dir, bundle_id)

        for (container_dir, meta) in &self.map {
            let bundle_id = meta.identifier.as_str();
            // The match path must be a descendant of the container directory.
            // Check: path starts with `<container_dir>/` (file inside), OR
            // path == container_dir (path IS the container dir itself, though
            // that should not happen for a content hit).
            if !is_path_prefix(container_dir, path) {
                continue;
            }
            // Keep the longest prefix (most specific container).
            if best.is_none_or(|(prev, _)| container_dir.len() > prev.len()) {
                best = Some((container_dir, bundle_id));
            }
        }

        best.map(|(_, id)| id)
    }
}

/// True when `prefix` is a `/`-segment-boundary prefix of `path`.
///
/// Accepted cases:
///   - `path == prefix` (exact match, e.g. the container dir itself)
///   - `path` starts with `prefix/` (a file inside the container)
///
/// Rejected: `prefix = "…/Apple"`, `path = "…/AppleX/file"` — the character
/// following the prefix in path must be `/` or nothing.
fn is_path_prefix(prefix: &str, path: &str) -> bool {
    if path == prefix {
        return true;
    }
    // WHY: strip_prefix only returns Some when the exact byte sequence matches;
    // then we require the next byte to be `/` to enforce segment boundaries.
    path.strip_prefix(prefix)
        .map(|rest| rest.starts_with('/'))
        .unwrap_or(false)
}

/// Read the entry's bytes from `source`, parse as a plist, and return what the
/// container metadata records: the required `MCMMetadataIdentifier` and the
/// optional parent-bundle link nested in `MCMMetadataInfo`.
///
/// Returns `None` on any read or parse failure, or when the identifier is absent
/// (a container with no identifier is not attributable) — degrade, don't die.
fn extract_metadata(
    source: &dyn Source,
    entry: &crate::core::models::Entry,
) -> Option<ContainerMeta> {
    // Read the file; a corrupt or unreadable entry is silently skipped.
    let bytes = source.content(entry).ok()?;
    // WHY reuse the `plist` crate: it is already in the dependency tree (used
    // by `inspect::plist`), handles both binary (`bplist00`) and XML plists,
    // and is the one source of truth for plist parsing in this project.
    let value = plist::Value::from_reader(Cursor::new(&*bytes)).ok()?;
    let dict = value.as_dictionary()?;
    let identifier = dict.get(BUNDLE_ID_KEY)?.as_string()?.to_string();
    // The parent link is present only on extension/widget containers, and only
    // when installd recorded it — its absence is normal, not a failure.
    let parent_id = dict
        .get(METADATA_INFO_KEY)
        .and_then(plist::Value::as_dictionary)
        .and_then(|info| info.get(PARENT_BUNDLE_ID_KEY))
        .and_then(plist::Value::as_string)
        .map(str::to_string);
    Some(ContainerMeta {
        identifier,
        parent_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::source::folder::FolderSource;

    /// Build a one-container source whose metadata plist holds `identifier` and,
    /// when given, the nested parent link — then read it back through the real
    /// production path (`AppContainerMap::build`).
    fn meta_of(identifier: &str, parent: Option<&str>) -> ContainerMeta {
        let dir = tempfile::tempdir().unwrap();
        let container = dir.path().join("Containers/Data/PluginKitPlugin/GUID-1");
        std::fs::create_dir_all(&container).unwrap();

        let mut dict = plist::Dictionary::new();
        dict.insert(
            BUNDLE_ID_KEY.to_string(),
            plist::Value::String(identifier.to_string()),
        );
        let mut info = plist::Dictionary::new();
        // A real plist always carries MCMMetadataInfo; only the parent key varies.
        info.insert(
            "com.apple.MobileInstallation.ContentProtectionClass".to_string(),
            plist::Value::Integer(0.into()),
        );
        if let Some(parent) = parent {
            info.insert(
                PARENT_BUNDLE_ID_KEY.to_string(),
                plist::Value::String(parent.to_string()),
            );
        }
        dict.insert(
            METADATA_INFO_KEY.to_string(),
            plist::Value::Dictionary(info),
        );
        plist::Value::Dictionary(dict)
            .to_file_binary(container.join(CONTAINER_METADATA_NAME))
            .unwrap();

        let source = FolderSource::open(dir.path(), 0).unwrap();
        let map = AppContainerMap::build(&source);
        map.containers().next().unwrap().1.clone()
    }

    /// The authoritative parent link is read when installd wrote it.
    #[test]
    fn reads_parent_bundle_id_when_present() {
        let meta = meta_of(
            "com.apple.siri.SiriGeo.SiriGeoIntentExtension",
            Some("com.apple.siri.SiriGeo"),
        );
        assert_eq!(
            meta.identifier,
            "com.apple.siri.SiriGeo.SiriGeoIntentExtension"
        );
        assert_eq!(meta.parent_id.as_deref(), Some("com.apple.siri.SiriGeo"));
    }

    /// Its absence is normal (app-data, group and bundle containers have none)
    /// and must not lose the identifier.
    #[test]
    fn absent_parent_bundle_id_is_none_not_a_failure() {
        let meta = meta_of("com.example.app", None);
        assert_eq!(meta.identifier, "com.example.app");
        assert!(meta.parent_id.is_none());
    }

    /// An entry that is not a readable plist registers nothing, rather than
    /// aborting the whole scan.
    #[test]
    fn unparseable_metadata_is_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let container = dir.path().join("Containers/Data/Application/GUID-2");
        std::fs::create_dir_all(&container).unwrap();
        std::fs::write(container.join(CONTAINER_METADATA_NAME), b"not a plist").unwrap();
        let source = FolderSource::open(dir.path(), 0).unwrap();
        assert!(AppContainerMap::build(&source).is_empty());
    }

    /// `resolve` still answers with the identifier — the annotation path used by
    /// `run::grep` is unchanged by the metadata restructure.
    #[test]
    fn resolve_still_returns_the_identifier() {
        let map = AppContainerMap {
            map: HashMap::from([(
                "a/b".to_string(),
                ContainerMeta {
                    identifier: "com.example.app".to_string(),
                    parent_id: None,
                },
            )]),
        };
        assert_eq!(map.resolve("a/b/Documents/x.db"), Some("com.example.app"));
        assert_eq!(map.resolve("a/bc/x.db"), None);
    }

    #[test]
    fn is_path_prefix_segment_boundary() {
        // Exact match accepted.
        assert!(is_path_prefix("a/b", "a/b"));
        // File inside accepted.
        assert!(is_path_prefix("a/b", "a/b/file.txt"));
        // A longer path that merely starts with the same bytes is rejected.
        assert!(!is_path_prefix("a/b", "a/bc/file.txt"));
        // Prefix that is the entire path minus a non-/ suffix is rejected.
        assert!(!is_path_prefix("Apple", "AppleX/file.txt"));
        // Empty prefix never matches (there is no leading `/`).
        assert!(!is_path_prefix("", "a/b"));
    }
}
