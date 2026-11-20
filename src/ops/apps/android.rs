//! Android full-file-system app-data location resolution.
//!
//! Defines: [`resolve`] — every per-package data location in the source, across
//! all known Android storage roots and their mount aliases —, [`extraction_folders`]
//! (where file systems sit in the source), [`containers_at`] (the root → package
//! rule) and [`Located`].
//! Used by: `crate::ops::apps` (the platform-agnostic catalog) for the Android platform.
//! Uses: [`crate::core::filter::is_under`] and the [`crate::core::source::Source`]
//! trait — on Android a package's data is
//! found purely by its package name appearing as a path segment under a known root,
//! so no metadata file is consulted (unlike iOS).
//!
//! ── Storage roots an app may write to ───────────────────────────────────────
//! - internal app-private: `/data/data/<pkg>`, `/data/user/<n>/<pkg>` (multi-user),
//!   `/data/user_de/<n>/<pkg>` (device-encrypted, available before first unlock);
//! - external app-scoped: `…/Android/data/<pkg>` (cache/files), `…/Android/obb/<pkg>`
//!   (expansion files), `…/Android/media/<pkg>` (media), under each of
//!   `/sdcard`, `/storage/emulated/<n>`, and `/data/media/<n>`; the OBB folder all
//!   users share (`/data/media/obb/<pkg>`); and the same under a removable volume
//!   (`/storage/<volume>`, `/mnt/media_rw/<volume>`).
//!
//! ── Mount aliases ────────────────────────────────────────────────────────────
//! A live file-system capture also walks the views Android mounts over the same
//! storage, each a full copy in the archive: `/data/data` is `/data/user/0`;
//! `/data_mirror/data_ce/<volume>/<n>` and `/data_mirror/data_de/<volume>/<n>`
//! mirror `/data/user/<n>` and `/data/user_de/<n>` (`null` is the internal volume);
//! `/mnt/{user,installer,androidwritable,pass_through}/<u>/emulated/<n>` and
//! `/mnt/runtime/<view>/emulated/<n>` are views of `/data/media/<n>`. Seen on real
//! captures: a Samsung A53 holds `/data/data`, `/data/user/0` and `/data_mirror` for
//! every app, and `/mnt/*` for the external storage; a Redmi 9a the `/mnt/runtime`
//! views. Every alias is a container (a copy may hold what another lacks), labelled
//! by its own root, and [`AndroidRoot::storage`] names the storage it is a view of,
//! so a size is counted once per storage.
//!
//! ── Extraction folders ───────────────────────────────────────────────────────
//! Some tools put the file system under a folder of their own (Cellebrite:
//! `Dump/data/data/…`). [`resolve`] finds that folder once per source, from where
//! the internal data roots sit, and matches the roots below it only: matching a root
//! anywhere in a path would take an app's own copy of another tree (a backup app's
//! `files/data/data/<pkg>`) for that package's data.

use std::collections::{BTreeSet, HashSet};

use super::{AndroidRoot, AppContainer, ContainerKind};
use crate::core::filter::is_under;
use crate::core::source::Source;
use crate::platform::android::paths::is_backup_member;

/// Resolve every distinct per-package data location in `source` (file counts are
/// filled by the caller's tally pass).
///
/// WHY every container a path is in, not only the first: a tree copied inside an
/// app's storage (a backup app's `files/data/data/<pkg>`) is the backup app's data
/// and a copy of `<pkg>`'s; attributed to one only, a search of the other would
/// miss it. The tally charges each file to the innermost one.
///
/// WHY a copy, or a second file system, tags its containers with its folder: two
/// file systems in one source (two phones), or a device's data and a copy of it,
/// would otherwise share a storage, an export folder and a size.
pub fn resolve(source: &dyn Source) -> Vec<AppContainer> {
    let leads = extraction_folders(source.entries().iter().map(|e| e.name.as_str()));
    // A folder inside another found one holds a copy; the others are file systems.
    let is_copy = |lead: &str| {
        leads
            .iter()
            .any(|outer| !outer.is_empty() && is_under(outer, lead) && outer != lead)
    };
    let systems = leads
        .iter()
        .filter(|l| !l.is_empty() && !is_copy(l))
        .count();
    let mut seen: HashSet<String> = HashSet::new();
    let mut found_all: Vec<Located> = Vec::new();
    for entry in source.entries() {
        for found in containers_at(&entry.name, &leads) {
            if seen.insert(found.prefix.clone()) {
                found_all.push(found);
            }
        }
    }
    // A package's own subtree that looks like a root (Android gives each app a
    // `cache/data/user/0/<pkg>` of its own) is already in its container.
    let own: HashSet<(String, String)> = found_all
        .iter()
        .map(|f| (f.package.clone(), f.prefix.clone()))
        .collect();
    found_all.retain(|f| {
        !own.iter().any(|(pkg, prefix)| {
            *pkg == f.package && *prefix != f.prefix && is_under(prefix, &f.prefix)
        })
    });

    found_all
        .into_iter()
        .map(|mut found| {
            if !found.lead.is_empty() && (systems > 1 || is_copy(&found.lead)) {
                found.root.storage = format!("{}:{}", found.lead, found.root.storage);
                found.root.label = format!("{}@{}", found.root.label, found.lead.replace('/', "_"));
            }
            AppContainer {
                id: found.package,
                kind: found.kind,
                prefix: found.prefix,
                guid: None,
                // Android has no per-container parent declaration: a sibling package
                // is a separate app, never an extension of another.
                parent_id: None,
                file_count: 0,
                total_size: 0,
                group_link: None,
                android_root: Some(found.root),
            }
        })
        .collect()
}

/// The folders a file system, or a copy of one, sits under in an extraction:
/// `"Dump"` for `Dump/data/data/…`, a backup's folder for a copied tree, and always
/// `""`, the top, last.
///
/// A folder is wherever `data/data/<pkg>` or `data/user/<n>/<pkg>` appears in a
/// path. WHY every one and not only the outermost: a copy of an app's data (inside a
/// backup app's storage, on the external storage) is still that app's data, and a
/// search limited to the app must reach it; its containers carry the folder in their
/// label, so they never merge with the device's own. WHY the top is always kept: a
/// root there (an external-storage dump beside `Dump/`, or a file system whose
/// internal data was not captured) would otherwise be lost.
pub fn extraction_folders<'a>(names: impl Iterator<Item = &'a str>) -> Vec<String> {
    let mut found: BTreeSet<String> = BTreeSet::new();
    for name in names {
        let segs: Vec<&str> = name.trim_start_matches('/').split('/').collect();
        for k in 0..segs.len().saturating_sub(2) {
            let internal = segs[k] == "data"
                && match segs[k + 1] {
                    "data" => segs[k + 2].contains('.'),
                    "user" => is_number(segs[k + 2]) && segs.get(k + 3).is_some(),
                    _ => false,
                };
            if internal && k > 0 {
                found.insert(segs[..k].join("/"));
            }
        }
    }
    let mut leads: Vec<String> = found.into_iter().collect();
    leads.push(String::new());
    leads
}

/// A container [`containers_at`] found.
#[derive(Debug)]
pub struct Located {
    /// The extraction folder it was found below (`""`: the top).
    pub lead: String,
    /// `<folder>/<root>/<pkg>`, with the path's leading slash kept.
    pub prefix: String,
    pub package: String,
    pub kind: ContainerKind,
    pub root: AndroidRoot,
}

/// Every container `path` lies in, one per extraction folder in `leads` below which a
/// known root holds it. A child that is not package-shaped (`is_package`) is not a
/// container.
pub fn containers_at(path: &str, leads: &[String]) -> Vec<Located> {
    // An `adb backup` member names its package directly: apps/<package>/<token>/...
    if is_backup_member(path) {
        let Some(package) = path.split('/').nth(1) else {
            return Vec::new();
        };
        return vec![Located {
            lead: String::new(),
            prefix: format!("apps/{package}"),
            package: package.to_string(),
            kind: ContainerKind::AndroidData,
            root: AndroidRoot {
                path: "apps".into(),
                storage: "ce/0".into(),
                label: "data_u0".into(),
            },
        }];
    }
    let mut found = Vec::new();
    let had_lead = path.starts_with('/');
    let body = path.trim_start_matches('/');
    let segs: Vec<&str> = body.split('/').collect();
    for lead in leads {
        let skip = if lead.is_empty() {
            0
        } else if body
            .strip_prefix(lead.as_str())
            .is_some_and(|r| r.starts_with('/'))
        {
            lead.split('/').count()
        } else {
            continue;
        };
        let Some((root_len, kind, storage)) = match_root(&segs[skip..]) else {
            continue;
        };
        let end = skip + root_len;
        let Some(&package) = segs.get(end) else {
            continue;
        };
        if !is_package(package) {
            continue;
        }
        // Rebuild the prefix from the segments up to the package, restoring the
        // leading slash so it matches the entry names it is compared against.
        let prefix_body = segs[..=end].join("/");
        let root_path = segs[skip..end].join("/");
        let label = label(kind, &root_path, &storage);
        found.push(Located {
            lead: lead.clone(),
            prefix: if had_lead {
                format!("/{prefix_body}")
            } else {
                prefix_body
            },
            package: package.to_string(),
            kind,
            root: AndroidRoot {
                path: root_path,
                storage,
                label,
            },
        });
    }
    found
}

/// The container's export folder name: its kind and user (`data_u0`, `user_de_u10`,
/// `external_data_u0`), and for a mount alias a short tag naming the view
/// (`data_u0~mirror`, `external_data_u0~pass_through10`).
///
/// WHY short, and not the root's path: the folder is part of every exported file's
/// path, and Windows limits a path to 260 characters by default. WHY the tag: two
/// views of one storage are two copies in the archive; without it they would merge
/// into one folder. The root's full path stays in the export report.
fn label(kind: ContainerKind, root_path: &str, storage: &str) -> String {
    let parts: Vec<&str> = storage.split('/').collect();
    let base = match parts.as_slice() {
        ["ext", "sdcard", _] => kind.as_str().to_string(),
        [_, n] | ["ext", n, _] if is_number(n) => format!("{}_u{n}", kind.as_str()),
        // A removable volume, or the shared OBB folder: named by it.
        ["ext", volume, _] => format!("{}_{volume}", kind.as_str()),
        [_, volume, n] => {
            let short: String = volume.chars().take(8).collect();
            format!("{}_u{n}_{short}", kind.as_str())
        }
        _ => kind.as_str().to_string(),
    };
    let segs: Vec<&str> = root_path.split('/').collect();
    let view = match segs.as_slice() {
        ["data", "data"]
        | ["data", "user_de", _]
        | ["data", "media", ..]
        | ["mnt", "media_rw", ..]
        | ["apps"] => None,
        ["data", "user", n] => (*n == "0").then(|| "user".to_string()),
        ["data_mirror", ..] => Some("mirror".to_string()),
        ["storage", "emulated", ..] => Some("storage".to_string()),
        ["storage", ..] => None,
        ["sdcard", ..] => Some("sdcard".to_string()),
        ["mnt", "runtime", view, ..] => Some(format!("runtime_{view}")),
        ["mnt", view, user, ..] => Some(format!("{view}{user}")),
        _ => Some(segs.join("_")),
    };
    match view {
        Some(view) => format!("{base}~{view}"),
        None => base,
    }
}

/// Whether `name` has the shape of an Android package name: letters, digits and `_`
/// in at least two dot-separated parts, the first starting with a letter.
///
/// WHY: a root's immediate children are package directories; this rejects stray
/// entries at a root (`lost+found`, a `.nomedia` marker file).
fn is_package(name: &str) -> bool {
    name.contains('.')
        && name.split('.').all(|part| {
            !part.is_empty() && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        })
        && name.bytes().next().is_some_and(|b| b.is_ascii_alphabetic())
}

fn is_number(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// Match the leading path segments against a known root (or mount alias), returning
/// the number of segments the root occupies (so the next segment is the package), its
/// kind, and the storage it is a view of (`ce/<n>`, `de/<n>`, `ext/<n>/<dir>`).
///
/// WHY numeric-user-id segments are accepted positionally: multi-user and external
/// roots embed a user id (`/data/user/<n>`, `/data/media/<n>`) that varies; matching
/// the surrounding fixed segments and skipping the numeric one keeps every profile.
fn match_root(segs: &[&str]) -> Option<(usize, ContainerKind, String)> {
    let s = |i: usize| segs.get(i).copied();
    let user = |i: usize| s(i).filter(|x| is_number(x));
    // `Android/<dir>` at `at`, on the external storage of user `n`.
    let external = |at: usize, n: &str| {
        if s(at)? != "Android" {
            return None;
        }
        let dir = s(at + 1)?;
        let kind = match dir {
            "data" => ContainerKind::AndroidExternal,
            "obb" => ContainerKind::AndroidObb,
            "media" => ContainerKind::AndroidMedia,
            _ => return None,
        };
        Some((at + 2, kind, format!("ext/{n}/{dir}")))
    };

    match (s(0)?, s(1)?) {
        // Internal app-private storage; `/data/data` is user 0's.
        ("data", "data") => Some((2, ContainerKind::AndroidData, "ce/0".into())),
        ("data", "user") => {
            let n = user(2)?;
            Some((3, ContainerKind::AndroidData, format!("ce/{n}")))
        }
        ("data", "user_de") => {
            let n = user(2)?;
            Some((3, ContainerKind::AndroidUserDe, format!("de/{n}")))
        }
        // Mirrors of both, per volume (`null`: the internal one).
        ("data_mirror", class @ ("data_ce" | "data_de")) => {
            let (volume, n) = (s(2)?, user(3)?);
            let (kind, short) = if class == "data_ce" {
                (ContainerKind::AndroidData, "ce")
            } else {
                (ContainerKind::AndroidUserDe, "de")
            };
            let storage = if volume == "null" {
                format!("{short}/{n}")
            } else {
                format!("{short}/{volume}/{n}")
            };
            Some((4, kind, storage))
        }
        // The OBB folder all users share since Android 11 (seen, empty, on a Samsung
        // A53 and a Redmi 9a capture).
        ("data", "media") if s(2) == Some("obb") => {
            Some((3, ContainerKind::AndroidObb, "ext/shared/obb".into()))
        }
        // Removable storage (an SD card, a USB drive): `/mnt/media_rw/<volume>`, and
        // `/storage/<volume>` where the volume is not `emulated` or `self`.
        ("mnt", "media_rw") => external(3, s(2)?),
        ("storage", volume) if !matches!(volume, "emulated" | "self") => external(2, volume),
        // External app-scoped storage and its views.
        // `/sdcard` is the current user's view, whichever user that was.
        ("sdcard", "Android") => external(1, "sdcard"),
        ("storage", "emulated") | ("data", "media") => external(3, user(2)?),
        ("mnt", "runtime") if s(3) == Some("emulated") => external(5, user(4)?),
        ("mnt", "user" | "installer" | "androidwritable" | "pass_through")
            if user(2).is_some() && s(3) == Some("emulated") =>
        {
            external(5, user(4)?)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The first container `path` is in, below the extraction folders `leads`.
    fn container_for_path(path: &str, leads: &[String]) -> Option<Located> {
        containers_at(path, leads).into_iter().next()
    }

    /// The container at `path`, roots at the top of the archive.
    fn at_top(path: &str) -> Option<Located> {
        container_for_path(path, &[String::new()])
    }

    fn storage(path: &str, leads: &[String]) -> (String, String) {
        let found = container_for_path(path, leads).unwrap();
        (found.root.path, found.root.storage)
    }

    #[test]
    fn internal_data_root() {
        let found = at_top("/data/data/com.whatsapp/databases/x.db").unwrap();
        assert_eq!(found.prefix, "/data/data/com.whatsapp");
        assert_eq!(found.package, "com.whatsapp");
        assert!(matches!(found.kind, ContainerKind::AndroidData));
        assert_eq!(found.root.storage, "ce/0");
    }

    #[test]
    fn multi_user_and_device_encrypted() {
        let user10 = at_top("/data/user/10/com.x.y/f").unwrap();
        assert!(matches!(user10.kind, ContainerKind::AndroidData));
        assert_eq!(user10.root.storage, "ce/10");
        assert!(matches!(
            at_top("/data/user_de/0/com.x.y/f").unwrap().kind,
            ContainerKind::AndroidUserDe
        ));
    }

    #[test]
    fn external_roots() {
        assert!(matches!(
            at_top("/sdcard/Android/data/com.x.y/cache/f").unwrap().kind,
            ContainerKind::AndroidExternal
        ));
        assert!(matches!(
            at_top("/storage/emulated/0/Android/obb/com.x.y/main.obb")
                .unwrap()
                .kind,
            ContainerKind::AndroidObb
        ));
        let media = at_top("/data/media/0/Android/media/com.x.y/clip.mp4").unwrap();
        assert_eq!(media.prefix, "/data/media/0/Android/media/com.x.y");
        assert!(matches!(media.kind, ContainerKind::AndroidMedia));
    }

    #[test]
    fn mount_aliases_name_the_storage_they_view() {
        let top = [String::new()];
        // Paths as a Samsung A53 and a Redmi 9a capture hold them.
        assert_eq!(
            storage("/data_mirror/data_ce/null/0/com.x.y/f", &top),
            ("data_mirror/data_ce/null/0".into(), "ce/0".into())
        );
        assert_eq!(
            storage("/data_mirror/data_de/null/0/com.x.y/f", &top).1,
            "de/0"
        );
        let views = [
            "/data/media/0/Android/data/com.x.y/f",
            "/storage/emulated/0/Android/data/com.x.y/f",
            "/mnt/user/0/emulated/0/Android/data/com.x.y/f",
            "/mnt/pass_through/10/emulated/0/Android/data/com.x.y/f",
            "/mnt/runtime/write/emulated/0/Android/data/com.x.y/f",
        ];
        for path in views {
            assert_eq!(storage(path, &top).1, "ext/0/data", "{path}");
        }
        // Not a storage root: ART profiles, a mount point without a user.
        assert!(at_top("/data_mirror/cur_profiles/0/com.x.y").is_none());
        assert!(at_top("/mnt/user/emulated/0/Android/data/com.x.y/f").is_none());
    }

    #[test]
    fn export_labels_are_short_and_keep_copies_apart() {
        let label = |path: &str| at_top(path).unwrap().root.label;
        assert_eq!(label("/data/data/com.x.y/f"), "data_u0");
        assert_eq!(label("/data/user/0/com.x.y/f"), "data_u0~user");
        assert_eq!(label("/data/user/10/com.x.y/f"), "data_u10");
        assert_eq!(label("/data/user_de/10/com.x.y/f"), "user_de_u10");
        assert_eq!(
            label("/data_mirror/data_ce/null/0/com.x.y/f"),
            "data_u0~mirror"
        );
        assert_eq!(
            label("/data/media/0/Android/data/com.x.y/f"),
            "external_data_u0"
        );
        assert_eq!(
            label("/mnt/pass_through/10/emulated/0/Android/data/com.x.y/f"),
            "external_data_u0~pass_through10"
        );
        assert_eq!(
            label("/mnt/runtime/write/emulated/0/Android/obb/com.x.y/f"),
            "obb_u0~runtime_write"
        );
        assert_eq!(label("/sdcard/Android/media/com.x.y/f"), "media~sdcard");
        assert_eq!(label("/data/media/obb/com.x.y/main.obb"), "obb_shared");
        assert_eq!(
            label("/storage/1A2B-3C4D/Android/data/com.x.y/f"),
            "external_data_1A2B-3C4D"
        );
        assert_eq!(
            label("/mnt/media_rw/1A2B-3C4D/Android/data/com.x.y/f"),
            "external_data_1A2B-3C4D"
        );
    }

    #[test]
    fn non_package_and_unrelated_paths_are_skipped() {
        // A stray non-package entry at a root.
        assert!(at_top("/data/data/lost+found").is_none());
        assert!(at_top("/data/media/obb/.nomedia").is_none());
        // Not under any app root.
        assert!(at_top("/system/bin/sh").is_none());
        assert!(at_top("/data/app/com.x.y-1/base.apk").is_none());
    }

    #[test]
    fn preserves_relative_paths_without_leading_slash() {
        let found = at_top("data/data/com.x.y/f").unwrap();
        assert_eq!(found.prefix, "data/data/com.x.y");
        assert_eq!(found.package, "com.x.y");
    }

    #[test]
    fn roots_are_matched_below_the_extraction_folder() {
        // Cellebrite puts the file system under `Dump/`.
        let names = [
            "Dump/data/data/com.discord/databases/a.db",
            "Dump/data/user/10/com.discord/f",
            "Dump/data/media/0/Backup/data/data/com.x.y/f",
        ];
        let leads = extraction_folders(names.into_iter());
        assert_eq!(leads, ["Dump", "Dump/data/media/0/Backup", ""]);
        let found = container_for_path(names[0], &leads).unwrap();
        assert_eq!(found.prefix, "Dump/data/data/com.discord");
        assert_eq!(found.root.path, "data/data");
        assert_eq!(storage(names[1], &leads).1, "ce/10");
        // A copy of a tree on the external storage is still the app's data.
        let copy = container_for_path(names[2], &leads).unwrap();
        assert_eq!(copy.package, "com.x.y");
        assert_eq!(copy.lead, "Dump/data/media/0/Backup");
        // Without an internal data root, the top is the file system.
        assert_eq!(
            extraction_folders(["/sdcard/Android/data/com.x.y/f"].into_iter()),
            [""]
        );
        // A root at the top beside the extraction folder is still matched.
        assert!(container_for_path("sdcard/Android/data/com.x.y/f", &leads).is_some());
        // A copy of a tree inside an app's storage is both apps' data.
        let copy = "data/data/com.backup.app/files/data/data/com.x.y/f";
        let leads = extraction_folders([copy].into_iter());
        let packages: Vec<String> = containers_at(copy, &leads)
            .into_iter()
            .map(|c| c.package)
            .collect();
        assert_eq!(packages, ["com.x.y", "com.backup.app"]);
    }
}
