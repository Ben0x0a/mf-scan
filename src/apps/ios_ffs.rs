//! iOS full-file-system (FFS) app-container resolution.
//!
//! Defines: [`resolve`] (every app/extension/group/bundle container, from the
//! container metadata plists), [`app_entitlement_groups`] (an app's authoritative
//! App Groups, read from its executable's code signature), and [`display_name`]
//! (an app's human name from its `Info.plist`).
//! Used by: `crate::apps` (the platform-agnostic catalog) for the iOS-FFS platform.
//! Uses: [`crate::ios::containers::AppContainerMap`] (the existing container→id
//! scan — the single source of truth for the mapping), [`super::entitlements`]
//! (Mach-O code-signature parsing), the `plist` crate (`Info.plist`), and the
//! [`crate::source::Source`] trait.
//!
//! WHY reuse `AppContainerMap`: it already scans every
//! `.com.apple.mobile_container_manager.metadata.plist` in the source — for app
//! data, extension/widget (PluginKitPlugin), shared App Group, and bundle
//! containers alike — so the inverse "which directories belong to apps?" view this
//! module needs is just that scan, classified by container root.

use std::io::Cursor;

use plist::Value;

use super::entitlements;
use super::{AppContainer, ContainerKind};
use crate::ios::containers::AppContainerMap;
use crate::source::Source;

/// Resolve every iOS container in `source` into an [`AppContainer`] (file counts
/// are filled by the caller's tally pass).
pub fn resolve(source: &dyn Source) -> Vec<AppContainer> {
    AppContainerMap::build(source)
        .containers()
        .map(|(dir, id)| {
            let (kind, guid) = classify(dir);
            AppContainer {
                id: id.to_string(),
                kind,
                prefix: dir.to_string(),
                guid,
                file_count: 0,
                total_size: 0,
                group_link: None,
            }
        })
        .collect()
}

/// Classify a container directory by its path root, and extract the short
/// (8-char) container GUID used in the export sub-label.
///
/// WHY the path root decides the kind: iOS files containers under fixed roots —
/// `Data/Application` (the app's own data), `Data/PluginKitPlugin` (an
/// extension/widget), `Shared/AppGroup` (a shared group), `Bundle/Application`
/// (the installed `.app`). Any other `Data/*` container (e.g. an internal daemon)
/// falls through to `AppData` so it is still listed rather than lost.
fn classify(dir: &str) -> (ContainerKind, Option<String>) {
    let kind = if dir.contains("/PluginKitPlugin/") {
        ContainerKind::Extension
    } else if dir.contains("/AppGroup/") {
        ContainerKind::AppGroup
    } else if dir.contains("/Bundle/Application/") {
        ContainerKind::Bundle
    } else {
        ContainerKind::AppData
    };
    // The container directory ends with its GUID; the first 8 chars identify it
    // unambiguously in practice and keep the export folder name short.
    let guid = dir
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .map(|seg| seg.chars().take(8).collect::<String>());
    (kind, guid)
}

/// Read an app's authoritative App Groups from its executable's code-signature
/// entitlements, given the app's `Bundle/Application` container prefix.
///
/// HOW: find the `.app/Info.plist` directly under the bundle container, read
/// `CFBundleExecutable`, open that executable, and hand its bytes to
/// [`entitlements::application_groups`]. Returns `None` on any miss (no bundle,
/// no Info.plist, no executable, or unreadable entitlements) — the caller then
/// falls back to the vendor-token heuristic.
pub fn app_entitlement_groups(source: &dyn Source, bundle_prefix: &str) -> Option<Vec<String>> {
    let info = find_app_info_plist(source, bundle_prefix)?;
    // `app_dir` is the `.app` directory: the Info.plist path minus `/Info.plist`.
    let app_dir = info.name.strip_suffix("/Info.plist")?;
    let exe_name = read_info_string(source, info, "CFBundleExecutable")?;
    let exe_path = format!("{app_dir}/{exe_name}");
    let exe = source.entries().iter().find(|e| e.name == exe_path)?;
    let content = source.content(exe).ok()?;
    entitlements::application_groups(&content)
}

/// An app's display name (`CFBundleDisplayName`, falling back to `CFBundleName`)
/// from the `Info.plist` under its bundle container — best-effort, `None` if absent.
pub fn display_name(source: &dyn Source, bundle_prefix: &str) -> Option<String> {
    let info = find_app_info_plist(source, bundle_prefix)?;
    read_info_string(source, info, "CFBundleDisplayName")
        .or_else(|| read_info_string(source, info, "CFBundleName"))
}

/// Find the `<App>.app/Info.plist` entry directly inside a bundle container.
///
/// WHY the single-`.app` guard: a bundle may contain nested `.app`s (e.g. a
/// companion Watch app) and `.appex` plugins; requiring exactly one `.app/`
/// segment after the prefix selects the top-level app bundle, not a nested one.
fn find_app_info_plist<'s>(
    source: &'s dyn Source,
    bundle_prefix: &str,
) -> Option<&'s crate::models::Entry> {
    let prefix_slash = format!("{bundle_prefix}/");
    source.entries().iter().find(|e| {
        e.name.starts_with(&prefix_slash)
            && e.name.ends_with(".app/Info.plist")
            && e.name[prefix_slash.len()..].matches(".app/").count() == 1
    })
}

/// Read a string value by key from an `Info.plist` entry.
fn read_info_string(source: &dyn Source, info: &crate::models::Entry, key: &str) -> Option<String> {
    let bytes = source.content(info).ok()?;
    let value = Value::from_reader(Cursor::new(&*bytes)).ok()?;
    value
        .as_dictionary()?
        .get(key)?
        .as_string()
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_by_container_root() {
        let base = "/private/var/mobile/Containers";
        assert!(matches!(
            classify(&format!("{base}/Data/Application/5A92C2C1-DEAD")).0,
            ContainerKind::AppData
        ));
        assert!(matches!(
            classify(&format!("{base}/Data/PluginKitPlugin/2C8F4A03-BEEF")).0,
            ContainerKind::Extension
        ));
        assert!(matches!(
            classify(&format!("{base}/Shared/AppGroup/7E82ADBC-CAFE")).0,
            ContainerKind::AppGroup
        ));
        assert!(matches!(
            classify("/private/var/containers/Bundle/Application/4ECFE550-FEED").0,
            ContainerKind::Bundle
        ));
    }

    #[test]
    fn classify_extracts_short_guid() {
        let (_, guid) = classify("/x/Data/Application/5A92C2C1-E1D8-4943");
        assert_eq!(guid.as_deref(), Some("5A92C2C1"));
    }
}
