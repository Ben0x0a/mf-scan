//! iOS backup (iTunes/Finder) app-domain resolution.
//!
//! Defines: [`resolve`] — derive each app/extension/group container from the
//! backup's logical domains, and [`parse_domain`] (the domain → kind + id rule).
//! Used by: `crate::ops::apps` (the platform-agnostic catalog) for the iOS-backup
//! platform.
//! Uses: only the [`crate::core::source::Source`] trait — the heavy lifting (decoding
//! `Manifest.db` into logical `domain/relativePath` entries) is already done by
//! [`crate::platform::ios::backup::source::BackupSource`], so here a container is simply a
//! distinct top-level domain.
//!
//! WHY domains are the unit: an iOS backup has no on-disk directory tree; its
//! authoritative structure is `Manifest.db`, whose `domain` column the backup
//! source already surfaces as each entry's first path segment. App data lives
//! under `AppDomain-<id>`; an extension/widget under `AppDomainPlugin-<id>.<ext>`;
//! a shared group under `AppDomainGroup-<grp>` / `SysSharedContainerDomain-<grp>`.

use std::collections::HashSet;

use super::{AppContainer, ContainerKind};
use crate::core::source::Source;
use crate::platform::ios::domains::{self, BackupDomain};

/// Resolve every app-scoped backup domain into an [`AppContainer`] (file counts
/// are filled by the caller's tally pass). Non-app domains (`HomeDomain`,
/// `CameraRollDomain`, `KeychainDomain`, …) are skipped — they are not attributable
/// to an installed app.
pub fn resolve(source: &dyn Source) -> Vec<AppContainer> {
    let mut seen: HashSet<&str> = HashSet::new();
    let mut out = Vec::new();
    for entry in source.entries() {
        let domain = entry.name.split('/').next().unwrap_or("");
        if domain.is_empty() || !seen.insert(domain) {
            continue;
        }
        if let Some((kind, id)) = parse_domain(domain) {
            out.push(AppContainer {
                id,
                kind,
                // The export layout for a backup is one subfolder per domain, so
                // the domain itself is both the match prefix and the output label.
                prefix: domain.to_string(),
                guid: None,
                // A backup carries no container metadata plists, so no declared
                // parent — extension ownership falls back to the name-prefix rule.
                parent_id: None,
                file_count: 0,
                total_size: 0,
                group_link: None,
            });
        }
    }
    out
}

/// Map a backup domain to its container kind and the app/group identifier it
/// carries, or `None` for a non-app domain.
///
/// The domain grammar itself lives in [`crate::platform::ios::domains`], which is
/// the single place the prefix set and its ordering are defined — this function
/// only decides what each parsed domain means to the app catalogue.
fn parse_domain(domain: &str) -> Option<(ContainerKind, String)> {
    let parsed = domains::parse(domain)?;
    // Only app-scoped domains name an installed app; the rest (HomeDomain,
    // system containers, …) are not attributable to one.
    if !parsed.is_app_scoped() {
        return None;
    }
    let id = parsed.identifier()?.to_string();
    let kind = match parsed {
        BackupDomain::App(_) => ContainerKind::AppData,
        BackupDomain::Plugin(_) => ContainerKind::Extension,
        // A shared App Group and a shared system group are the same kind of
        // thing to the catalogue: storage several apps can reach.
        BackupDomain::AppGroup(_) | BackupDomain::SystemGroup(_) => ContainerKind::AppGroup,
        // Excluded by `is_app_scoped` above; a new app-scoped variant must be
        // given a kind here rather than silently falling through.
        other => unreachable!("non-app-scoped domain passed the guard: {other:?}"),
    };
    Some((kind, id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_app_extension_and_group_domains() {
        assert_eq!(
            parse_domain("AppDomain-com.burbn.instagram"),
            Some((ContainerKind::AppData, "com.burbn.instagram".to_string()))
        );
        assert_eq!(
            parse_domain("AppDomainPlugin-com.burbn.instagram.ShareExtension"),
            Some((
                ContainerKind::Extension,
                "com.burbn.instagram.ShareExtension".to_string()
            ))
        );
        assert_eq!(
            parse_domain("AppDomainGroup-group.com.burbn.instagram"),
            Some((
                ContainerKind::AppGroup,
                "group.com.burbn.instagram".to_string()
            ))
        );
        assert_eq!(
            parse_domain("SysSharedContainerDomain-systemgroup.com.apple.x"),
            Some((
                ContainerKind::AppGroup,
                "systemgroup.com.apple.x".to_string()
            ))
        );
    }

    #[test]
    fn skips_non_app_domains() {
        assert_eq!(parse_domain("HomeDomain"), None);
        assert_eq!(parse_domain("CameraRollDomain"), None);
        assert_eq!(parse_domain("KeychainDomain"), None);
    }
}
