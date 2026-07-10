//! Android full-file-system app-data location resolution.
//!
//! Defines: [`resolve`] — every per-package data location in the source, across
//! all known Android storage roots, and [`container_for_path`] (the root → package
//! rule).
//! Used by: `crate::ops::apps` (the platform-agnostic catalog) for the Android platform.
//! Uses: only the [`crate::core::source::Source`] trait — on Android a package's data is
//! found purely by its package name appearing as a path segment under a known root,
//! so no metadata file is consulted (unlike iOS).
//!
//! ── Storage roots an app may write to ───────────────────────────────────────
//! - internal app-private: `/data/data/<pkg>`, `/data/user/<n>/<pkg>` (multi-user),
//!   `/data/user_de/<n>/<pkg>` (device-encrypted, available before first unlock);
//! - external app-scoped: `…/Android/data/<pkg>` (cache/files), `…/Android/obb/<pkg>`
//!   (expansion files), `…/Android/media/<pkg>` (media), under each of
//!   `/sdcard`, `/storage/emulated/<n>`, and `/data/media/<n>`.

use std::collections::HashSet;

use super::{AppContainer, ContainerKind};
use crate::core::source::Source;

/// Resolve every distinct per-package data location in `source` (file counts are
/// filled by the caller's tally pass).
pub fn resolve(source: &dyn Source) -> Vec<AppContainer> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut out = Vec::new();
    for entry in source.entries() {
        if let Some((prefix, pkg, kind)) = container_for_path(&entry.name)
            && seen.insert(prefix.clone())
        {
            out.push(AppContainer {
                id: pkg,
                kind,
                prefix,
                guid: None,
                file_count: 0,
                total_size: 0,
                group_link: None,
            });
        }
    }
    out
}

/// If `path` lies under a known Android storage root, return the container prefix
/// (`<root>/<pkg>`, with the original leading-slash preserved), the package name,
/// and the storage kind. `None` when the path is not app-scoped.
///
/// WHY a package must contain a `.`: every root's immediate child is a package
/// directory (reverse-DNS, e.g. `com.whatsapp`); requiring a dot rejects stray
/// non-package entries (a loose file or `lost+found`) sitting at a root.
pub fn container_for_path(path: &str) -> Option<(String, String, ContainerKind)> {
    let had_lead = path.starts_with('/');
    let body = path.trim_start_matches('/');
    let segs: Vec<&str> = body.split('/').collect();

    let (root_len, kind) = match_root(&segs)?;
    let pkg = *segs.get(root_len)?;
    if !pkg.contains('.') {
        return None;
    }
    // Rebuild the prefix from the first `root_len + 1` segments, restoring the
    // leading slash so it matches the entry names this prefix is compared against.
    let prefix_body = segs[..root_len + 1].join("/");
    let prefix = if had_lead {
        format!("/{prefix_body}")
    } else {
        prefix_body
    };
    Some((prefix, pkg.to_string(), kind))
}

/// Match the leading path segments against a known root, returning the number of
/// segments the root occupies (so the next segment is the package) and its kind.
///
/// WHY numeric-user-id segments are accepted positionally: multi-user and external
/// roots embed a user id (`/data/user/<n>`, `/data/media/<n>`) that varies; matching
/// the surrounding fixed segments and skipping the numeric one keeps every profile.
fn match_root(segs: &[&str]) -> Option<(usize, ContainerKind)> {
    let s = |i: usize| segs.get(i).copied();
    let is_num =
        |i: usize| s(i).is_some_and(|x| x.chars().all(|c| c.is_ascii_digit()) && !x.is_empty());
    let external_kind = |dir: &str| match dir {
        "data" => Some(ContainerKind::AndroidExternal),
        "obb" => Some(ContainerKind::AndroidObb),
        "media" => Some(ContainerKind::AndroidMedia),
        _ => None,
    };

    match (s(0), s(1)) {
        // Internal app-private storage.
        (Some("data"), Some("data")) => Some((2, ContainerKind::AndroidData)),
        (Some("data"), Some("user")) if is_num(2) => Some((3, ContainerKind::AndroidData)),
        (Some("data"), Some("user_de")) if is_num(2) => Some((3, ContainerKind::AndroidUserDe)),
        // External app-scoped storage at `/sdcard/Android/<dir>/<pkg>`.
        (Some("sdcard"), Some("Android")) => external_kind(s(2)?).map(|k| (3, k)),
        // External app-scoped storage at `/storage/emulated/<n>/Android/<dir>` and
        // `/data/media/<n>/Android/<dir>` — same shape, different mount root.
        (Some("storage"), Some("emulated")) if is_num(2) && s(3) == Some("Android") => {
            external_kind(s(4)?).map(|k| (5, k))
        }
        (Some("data"), Some("media")) if is_num(2) && s(3) == Some("Android") => {
            external_kind(s(4)?).map(|k| (5, k))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_data_root() {
        let (prefix, pkg, kind) =
            container_for_path("/data/data/com.whatsapp/databases/x.db").unwrap();
        assert_eq!(prefix, "/data/data/com.whatsapp");
        assert_eq!(pkg, "com.whatsapp");
        assert!(matches!(kind, ContainerKind::AndroidData));
    }

    #[test]
    fn multi_user_and_device_encrypted() {
        assert!(matches!(
            container_for_path("/data/user/10/com.x.y/f").unwrap().2,
            ContainerKind::AndroidData
        ));
        assert!(matches!(
            container_for_path("/data/user_de/0/com.x.y/f").unwrap().2,
            ContainerKind::AndroidUserDe
        ));
    }

    #[test]
    fn external_roots() {
        assert!(matches!(
            container_for_path("/sdcard/Android/data/com.x.y/cache/f")
                .unwrap()
                .2,
            ContainerKind::AndroidExternal
        ));
        assert!(matches!(
            container_for_path("/storage/emulated/0/Android/obb/com.x.y/main.obb")
                .unwrap()
                .2,
            ContainerKind::AndroidObb
        ));
        let (prefix, _, kind) =
            container_for_path("/data/media/0/Android/media/com.x.y/clip.mp4").unwrap();
        assert_eq!(prefix, "/data/media/0/Android/media/com.x.y");
        assert!(matches!(kind, ContainerKind::AndroidMedia));
    }

    #[test]
    fn non_package_and_unrelated_paths_are_skipped() {
        // A stray non-package entry at a root.
        assert!(container_for_path("/data/data/lost+found").is_none());
        // Not under any app root.
        assert!(container_for_path("/system/bin/sh").is_none());
        assert!(container_for_path("/data/app/com.x.y-1/base.apk").is_none());
    }

    #[test]
    fn preserves_relative_paths_without_leading_slash() {
        let (prefix, pkg, _) = container_for_path("data/data/com.x.y/f").unwrap();
        assert_eq!(prefix, "data/data/com.x.y");
        assert_eq!(pkg, "com.x.y");
    }
}
