//! iOS backup (iTunes/Finder) app-domain resolution.
//!
//! Defines: [`resolve`] — derive each app/extension/group container from the
//! backup's logical domains, and [`parse_domain`] (the domain → kind + id rule).
//! Used by: `crate::apps` (the platform-agnostic catalog) for the iOS-backup
//! platform.
//! Uses: only the [`crate::source::Source`] trait — the heavy lifting (decoding
//! `Manifest.db` into logical `domain/relativePath` entries) is already done by
//! [`crate::ios::backup::source::BackupSource`], so here a container is simply a
//! distinct top-level domain.
//!
//! WHY domains are the unit: an iOS backup has no on-disk directory tree; its
//! authoritative structure is `Manifest.db`, whose `domain` column the backup
//! source already surfaces as each entry's first path segment. App data lives
//! under `AppDomain-<id>`; an extension/widget under `AppDomainPlugin-<id>.<ext>`;
//! a shared group under `AppDomainGroup-<grp>` / `SysSharedContainerDomain-<grp>`.

use std::collections::HashSet;

use super::{AppContainer, ContainerKind};
use crate::source::Source;

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
/// WHY the `Plugin`/`Group` prefixes are tested before the bare `AppDomain-`:
/// `AppDomainPlugin-` and `AppDomainGroup-` both start with `AppDomain`, so the
/// more specific prefixes must win or an extension would be mis-read as the app.
fn parse_domain(domain: &str) -> Option<(ContainerKind, String)> {
    if let Some(id) = domain.strip_prefix("AppDomainPlugin-") {
        Some((ContainerKind::Extension, id.to_string()))
    } else if let Some(id) = domain.strip_prefix("AppDomainGroup-") {
        Some((ContainerKind::AppGroup, id.to_string()))
    } else if let Some(id) = domain.strip_prefix("SysSharedContainerDomain-") {
        Some((ContainerKind::AppGroup, id.to_string()))
    } else {
        // `AppDomain-` is tested last because the more specific `AppDomainPlugin-`
        // / `AppDomainGroup-` prefixes start with it.
        domain
            .strip_prefix("AppDomain-")
            .map(|id| (ContainerKind::AppData, id.to_string()))
    }
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
