//! The app catalogue: build it from a source, then search/select app data.
//!
//! Defines: [`AppCatalog`] (build, [`AppCatalog::inventory`] for `app grep`,
//! [`AppCatalog::containers_for`] for `app paths`/`app export`), [`detect`] (the
//! platform sniffer), and [`entries_under`] (gather a selection's files for export).
//! Used by: the binary's `app` subcommand (`run::app`).
//! Uses: the data types in [`super::types`], the per-platform resolvers
//! ([`super::ios_ffs`], [`super::ios_backup`], [`super::android`]), and
//! [`crate::core::source::Source`] / [`crate::core::models::Entry`].

use std::collections::{BTreeMap, HashMap};

use crate::core::models::Entry;
use crate::core::source::Source;

use super::types::{AppContainer, AppSummary, ContainerKind, GroupLink, Platform};
use super::{android, ios_backup, ios_ffs};

/// Every app container found in a source, plus the platform it was read as.
pub struct AppCatalog {
    pub platform: Platform,
    pub containers: Vec<AppContainer>,
}

impl AppCatalog {
    /// Detect the platform and resolve every app container, tallying each
    /// container's file count and total size in a single pass over the entries.
    pub fn build(source: &dyn Source) -> Self {
        let platform = detect(source);
        let mut containers = match platform {
            Platform::IosFfs => ios_ffs::resolve(source),
            Platform::IosBackup => ios_backup::resolve(source),
            Platform::Android => android::resolve(source),
            Platform::Unknown => Vec::new(),
        };
        tally(source, &mut containers);
        Self {
            platform,
            containers,
        }
    }

    /// `app grep`: one [`AppSummary`] per installed (primary) app, optionally
    /// filtered by a case-insensitive substring over the id and display name.
    /// Sorted by id for stable output.
    pub fn inventory(&self, source: &dyn Source, pattern: Option<&str>) -> Vec<AppSummary> {
        // Aggregate primary containers by id (an app usually has one, but multi-user
        // Android can have several).
        let mut by_id: BTreeMap<&str, (usize, u64)> = BTreeMap::new();
        for c in &self.containers {
            if !c.kind.is_primary() {
                continue;
            }
            let e = by_id.entry(c.id.as_str()).or_default();
            e.0 += 1;
            e.1 += c.total_size;
        }

        by_id
            .into_iter()
            .map(|(id, (count, size))| AppSummary {
                id: id.to_string(),
                name: self.display_name(source, id),
                container_count: count,
                total_size: size,
            })
            .filter(|s| match pattern {
                None => true,
                Some(p) => {
                    let p = p.to_lowercase();
                    s.id.to_lowercase().contains(&p)
                        || s.name
                            .as_deref()
                            .is_some_and(|n| n.to_lowercase().contains(&p))
                }
            })
            .collect()
    }

    /// `app paths` / `app export`: every container the app `id` or its dependencies
    /// can write — the app's own data (`id`), its extensions/widgets (`id.*`), the
    /// app bundle, and, when `with_groups`, its App Groups (each tagged with how it
    /// was attributed). Returned in a stable, grouped order.
    pub fn containers_for(
        &self,
        source: &dyn Source,
        id: &str,
        with_groups: bool,
    ) -> Vec<AppContainer> {
        let mut out: Vec<AppContainer> = self
            .containers
            .iter()
            .filter(|c| is_app_or_extension(c, id))
            .cloned()
            .collect();

        if with_groups {
            let links = self.resolve_group_links(source, id);
            for c in &self.containers {
                if c.kind == ContainerKind::AppGroup
                    && let Some(&link) = links.get(c.id.as_str())
                {
                    let mut group = c.clone();
                    group.group_link = Some(link);
                    out.push(group);
                }
            }
        }
        out
    }

    /// An app's display name, looked up via its bundle container (iOS only).
    fn display_name(&self, source: &dyn Source, id: &str) -> Option<String> {
        if self.platform != Platform::IosFfs {
            return None;
        }
        let bundle = self.bundle_prefix(id)?;
        ios_ffs::display_name(source, bundle)
    }

    /// The `Bundle/Application` container prefix for an app id, if present.
    fn bundle_prefix(&self, id: &str) -> Option<&str> {
        self.containers
            .iter()
            .find(|c| c.kind == ContainerKind::Bundle && c.id == id)
            .map(|c| c.prefix.as_str())
    }

    /// Resolve which App Groups belong to app `id`, and how each was attributed.
    ///
    /// Authoritative path (iOS FFS): the app binary's code-signature entitlements.
    /// When those can't be read — and always for a backup, which ships no binary —
    /// fall back to the reverse-DNS vendor-token heuristic over the group ids.
    fn resolve_group_links(&self, source: &dyn Source, id: &str) -> HashMap<String, GroupLink> {
        let entitlement_groups = if self.platform == Platform::IosFfs {
            self.bundle_prefix(id)
                .and_then(|bundle| ios_ffs::app_entitlement_groups(source, bundle))
        } else {
            None
        };

        match entitlement_groups {
            Some(groups) => groups
                .into_iter()
                .map(|g| (g, GroupLink::Entitlement))
                .collect(),
            None => self.vendor_heuristic_groups(id),
        }
    }

    /// Fallback group attribution: App Group containers whose `group.*` id shares a
    /// reverse-DNS vendor token with the app id (e.g. `group.com.burbn.*` for
    /// `com.burbn.instagram`). Best-effort — it cannot find a cross-brand shared
    /// group whose id carries no token of the app (the documented limitation).
    fn vendor_heuristic_groups(&self, id: &str) -> HashMap<String, GroupLink> {
        let tokens = vendor_tokens(id);
        self.containers
            .iter()
            .filter(|c| c.kind == ContainerKind::AppGroup && group_matches_tokens(&c.id, &tokens))
            .map(|c| (c.id.clone(), GroupLink::VendorHeuristic))
            .collect()
    }
}

/// Gather every (non-directory) file in `source` that lies under any of `prefixes`
/// — the file set an `app export` copies out. A file under several prefixes is
/// returned once; the planner attributes it to the longest matching prefix.
pub fn entries_under<'s>(source: &'s dyn Source, prefixes: &[String]) -> Vec<&'s Entry> {
    source
        .entries()
        .iter()
        .filter(|e| !e.is_dir() && prefixes.iter().any(|p| is_under(p, &e.name)))
        .collect()
}

/// Detect the acquisition layout from the shape of the entry paths.
///
/// Counts the distinctive signal of each platform across the entries and picks the
/// strongest: iOS containers (`/Containers/…`), iOS-backup domains
/// (`AppDomain-…`), or Android data roots (`/data/data/…`). WHY argmax over a few
/// cheap path checks rather than a definitive probe: it is robust to stray paths,
/// needs no file reads, and the three layouts' path shapes do not overlap.
pub fn detect(source: &dyn Source) -> Platform {
    let (mut ios_ffs, mut backup, mut android) = (0usize, 0usize, 0usize);
    for entry in source.entries() {
        let name = &entry.name;
        if name.contains("/Containers/Data/") || name.contains("/Containers/Bundle/") {
            ios_ffs += 1;
        } else if is_backup_domain(name) {
            backup += 1;
        }
        if name.contains("/data/data/") || name.contains("/data/user/") {
            android += 1;
        }
    }
    let max = ios_ffs.max(backup).max(android);
    if max == 0 {
        Platform::Unknown
    } else if max == ios_ffs {
        Platform::IosFfs
    } else if max == backup {
        Platform::IosBackup
    } else {
        Platform::Android
    }
}

/// Whether an entry name's first segment is an app-scoped iOS-backup domain.
fn is_backup_domain(name: &str) -> bool {
    let domain = name.split('/').next().unwrap_or("");
    domain.starts_with("AppDomain-")
        || domain.starts_with("AppDomainPlugin-")
        || domain.starts_with("AppDomainGroup-")
        || domain.starts_with("SysSharedContainerDomain-")
}

/// Tally each container's file count and total size in one pass: every
/// non-directory entry is charged to the longest container prefix that contains
/// it (an entry deep in a nested container counts toward the innermost one).
fn tally(source: &dyn Source, containers: &mut [AppContainer]) {
    // Owned keys: the index outlives the immutable borrow so the tally below can
    // mutate `containers` (a `&str`-keyed index would borrow it for the whole loop).
    let index: HashMap<String, usize> = containers
        .iter()
        .enumerate()
        .map(|(i, c)| (c.prefix.clone(), i))
        .collect();
    for entry in source.entries() {
        if entry.is_dir() {
            continue;
        }
        if let Some(idx) = longest_container(&entry.name, &index) {
            containers[idx].file_count += 1;
            containers[idx].total_size += entry.uncompressed_size;
        }
    }
}

/// Find the index of the longest container prefix that is an ancestor of `path`,
/// by walking the path's parent directories from longest to shortest.
fn longest_container(path: &str, index: &HashMap<String, usize>) -> Option<usize> {
    let mut cur = path;
    // Start one level up: a file is never itself a container prefix.
    while let Some(pos) = cur.rfind('/') {
        cur = &cur[..pos];
        if let Some(&idx) = index.get(cur) {
            return Some(idx);
        }
    }
    None
}

/// Whether container `c` is the app `id`'s own data, an extension/widget of it, or
/// its bundle — the non-group part of an app's selection.
///
/// Child matching (`id.*`) applies only to extension-style containers: on iOS an
/// extension's bundle id extends the app's (`com.app.Widget`); a sibling Android
/// package (`com.app.helper`) is a *different* app, so Android containers match by
/// exact package only.
fn is_app_or_extension(c: &AppContainer, id: &str) -> bool {
    match c.kind {
        ContainerKind::AppData | ContainerKind::Bundle => c.id == id,
        ContainerKind::Extension => c.id == id || c.id.starts_with(&format!("{id}.")),
        ContainerKind::AndroidData
        | ContainerKind::AndroidUserDe
        | ContainerKind::AndroidExternal
        | ContainerKind::AndroidObb
        | ContainerKind::AndroidMedia => c.id == id,
        ContainerKind::AppGroup => false,
    }
}

/// Whether `path` is `prefix` itself or a descendant of it (segment-boundary safe).
fn is_under(prefix: &str, path: &str) -> bool {
    path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// The distinctive reverse-DNS tokens of a bundle id / package, for the group
/// heuristic — every dotted component except a leading common TLD-ish token and
/// very short fragments. `com.burbn.instagram` → `["burbn", "instagram"]`.
fn vendor_tokens(id: &str) -> Vec<String> {
    const STOPWORDS: &[&str] = &["com", "org", "net", "io", "co", "app", "apps"];
    id.split('.')
        .map(|s| s.to_lowercase())
        .filter(|s| s.len() > 2 && !STOPWORDS.contains(&s.as_str()))
        .collect()
}

/// Whether a `group.*` id shares any vendor token with the app (component match).
fn group_matches_tokens(group_id: &str, tokens: &[String]) -> bool {
    let group_id = group_id.to_lowercase();
    group_id
        .split('.')
        .any(|seg| tokens.iter().any(|t| t == seg))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn container(id: &str, kind: ContainerKind) -> AppContainer {
        AppContainer {
            id: id.to_string(),
            kind,
            prefix: "p".to_string(),
            guid: None,
            file_count: 0,
            total_size: 0,
            group_link: None,
        }
    }

    #[test]
    fn vendor_tokens_drop_tld_and_short_fragments() {
        assert_eq!(
            vendor_tokens("com.burbn.instagram"),
            vec!["burbn", "instagram"]
        );
        assert_eq!(
            vendor_tokens("ph.telegra.Telegraph"),
            vec!["telegra", "telegraph"]
        );
    }

    #[test]
    fn heuristic_matches_vendor_group_but_not_cross_brand() {
        let tokens = vendor_tokens("com.burbn.instagram");
        // Same-vendor groups are caught.
        assert!(group_matches_tokens("group.com.burbn.instagram", &tokens));
        assert!(group_matches_tokens("group.com.burbn.family", &tokens));
        // The cross-brand Meta group carries no burbn/instagram token — missed,
        // exactly the limitation Mach-O entitlements resolve.
        assert!(!group_matches_tokens("group.com.facebook.family", &tokens));
    }

    #[test]
    fn app_and_extension_selection_rules() {
        let app = container("com.x.App", ContainerKind::AppData);
        let ext = container("com.x.App.Widget", ContainerKind::Extension);
        let other = container("com.x.AppHelper", ContainerKind::AppData);
        assert!(is_app_or_extension(&app, "com.x.App"));
        assert!(is_app_or_extension(&ext, "com.x.App")); // child extension included
        assert!(!is_app_or_extension(&other, "com.x.App")); // sibling app excluded
    }

    #[test]
    fn android_child_packages_are_not_extensions() {
        let helper = container("com.x.helper", ContainerKind::AndroidData);
        // A different Android package that merely shares a prefix is NOT pulled in.
        assert!(!is_app_or_extension(&helper, "com.x"));
    }
}
