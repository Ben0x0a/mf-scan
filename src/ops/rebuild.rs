//! Rebuild a whole backup, iOS or Android, into a filesystem-like tree.
//!
//! Defines: [`Rebuild`] (the plan: one output root per backup domain or app token, plus
//! what could not be mapped and what had to be invented), [`BackupKind`] and [`plan`].
//! Used by: the binary's `backup rebuild` orchestrator (`cmd::run::backup`).
//! Uses: [`crate::core::source::Source`] (entry names only — never bytes),
//! [`crate::platform::ios::domains`] and [`crate::platform::android::paths`] (the path
//! tables) and [`crate::platform::ios::backup::common::BackupStructure`] (the directory
//! rows).
//!
//! WHY a peer of [`crate::ops::apps`] and not part of it: `apps` answers "which
//! subset of this source belongs to app X" and carries container identity, kinds
//! and group attribution to do it. A rebuild answers "all of it, relabelled" and
//! needs none of that — threading it through `apps` would mean passing a bundle id
//! it ignores, entrenching a wart that already exists there.
//!
//! WHY the dispatch is one match arm: both kinds reduce to the same thing, a list of
//! `(archive prefix, device path)` roots. A full-filesystem acquisition is already a
//! tree and has nothing to rebuild.
//!
//! ── What this module does NOT do ──────────────────────────────────────────────
//! It reads no bytes and writes no files. It produces `(prefix, label)` roots that
//! [`crate::report::export::plan_tree`] turns into an export plan, so the copying,
//! digesting and manifest writing stay in the one export engine every subcommand
//! shares.

use std::collections::BTreeMap;

use crate::core::layout::{output_roots, tree_dir};
use crate::core::models::Entry;
use crate::core::source::Source;
use crate::platform::android::paths;
use crate::platform::ios::backup::common::BackupStructure;
use crate::platform::ios::domains;

/// Output root for domains the grammar does not recognise.
///
/// WHY they get a root rather than being skipped: an unrecognised domain is still
/// evidence, and dropping it would be a silent loss. WHY a visibly non-device
/// name: nothing under it should be mistaken for a real filesystem location.
/// Matches the `unknown_domain_template` the Python `ios-backup-reconstructor`
/// has shipped since its first release, so the two tools put an unrecognised
/// domain in the same place and their outputs can be compared directly.
pub const UNMAPPED_ROOT: &str = "unknown_backup_domains";

/// Which kind of backup is being rebuilt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupKind {
    Ios,
    Android,
}

/// A directory to record in the rebuilt tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebuildDirectory {
    /// Where it goes, relative to the root of the tree.
    pub path: String,
    /// When it last changed on the device (Unix seconds), when recorded.
    pub mtime: Option<u64>,
    /// The logical names of the records that landed here. Usually one, but two domains
    /// can mount at one path.
    pub names: Vec<String>,
}

/// The plan for rebuilding a backup.
pub struct Rebuild {
    /// `(domain, output label)` pairs for [`crate::report::export::plan_tree`],
    /// one per distinct domain in the source.
    pub roots: Vec<(String, String)>,
    /// Domains the grammar did not recognise, placed under [`UNMAPPED_ROOT`].
    /// Reported so an operator learns the map needs extending, rather than
    /// discovering stray folders later.
    pub unmapped: Vec<String>,
    /// Domains whose mapped path contains a component that is NOT in the
    /// evidence — a backup records no container GUIDs, so the identifier is
    /// substituted. Reported because a path that looks like ground truth but was
    /// invented must never pass for one.
    pub synthetic: Vec<String>,
    /// Directory records, mapped through the same roots as the files.
    pub directories: Vec<RebuildDirectory>,
    /// Symlink records, by logical name. Reported, never recreated: the target is
    /// not recorded in a resolvable form, and writing a link into an export is a
    /// way to escape it.
    pub symlinks: Vec<String>,
}

/// Build the rebuild plan for `source`.
///
/// `structure` carries the directory rows, which the source deliberately keeps out
/// of `entries()` (see [`BackupStructure`]).
pub fn plan(source: &dyn Source, structure: &BackupStructure, kind: BackupKind) -> Rebuild {
    let (roots, unmapped, synthetic) = match kind {
        BackupKind::Ios => ios_roots(source, structure),
        BackupKind::Android => {
            let names = source
                .entries()
                .iter()
                .map(|e| e.name.as_str())
                .chain(structure.directories.iter().map(|d| d.name.as_str()));
            (paths::roots(names), Vec::new(), Vec::new())
        }
    };

    // Map the directory records through the SAME roots the files use, so a
    // directory is created exactly where its contents land. Two records can land on one
    // path (a token's root and an empty domain, say); the first with a time wins.
    let index = output_roots(&roots);
    let mut directories: BTreeMap<String, (Option<u64>, Vec<String>)> = BTreeMap::new();
    for directory in &structure.directories {
        if let Some(path) = tree_dir(&directory.name, &index) {
            let (mtime, names) = directories.entry(path).or_default();
            *mtime = mtime.or(directory.mtime);
            names.push(directory.name.clone());
        }
    }
    let directories = directories
        .into_iter()
        .map(|(path, (mtime, names))| RebuildDirectory { path, mtime, names })
        .collect();

    Rebuild {
        roots,
        unmapped,
        synthetic,
        directories,
        symlinks: structure.symlinks.clone(),
    }
}

/// The iOS roots, with the domains that had no mount point and those given an invented
/// path.
fn ios_roots(
    source: &dyn Source,
    structure: &BackupStructure,
) -> (Vec<(String, String)>, Vec<String>, Vec<String>) {
    // BTreeMap, not HashMap: the roots (and therefore the reported lists and the
    // export order) must be deterministic for a forensic tool.
    let mut roots: BTreeMap<String, String> = BTreeMap::new();
    let mut unmapped = Vec::new();
    let mut synthetic = Vec::new();

    for domain in distinct_domains(source.entries(), structure) {
        if roots.contains_key(&domain) {
            continue;
        }
        let label = match domains::parse(&domain) {
            Some(parsed) => {
                let mapped = parsed.filesystem_path();
                if mapped.synthetic {
                    synthetic.push(domain.clone());
                }
                mapped.path
            }
            None => {
                unmapped.push(domain.clone());
                format!("{UNMAPPED_ROOT}/{domain}")
            }
        };
        roots.insert(domain, label);
    }

    unmapped.sort();
    unmapped.dedup();
    synthetic.sort();
    synthetic.dedup();
    (roots.into_iter().collect(), unmapped, synthetic)
}

/// Every distinct first path segment across the file entries and the directory
/// records.
///
/// Directory records are included so a domain that contains ONLY directories still
/// gets a root — otherwise its directories would fall through `tree_dir` and be
/// silently dropped.
fn distinct_domains(entries: &[Entry], structure: &BackupStructure) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let names = entries
        .iter()
        .map(|e| e.name.as_str())
        .chain(structure.directories.iter().map(|d| d.name.as_str()));
    for name in names {
        let domain = name.split('/').next().unwrap_or("");
        if domain.is_empty() {
            continue;
        }
        if seen.insert(domain.to_string()) {
            out.push(domain.to_string());
        }
    }
    out
}

/// The files to rebuild: every entry the source exposes.
///
/// A backup source's `entries()` is files-only by construction, so there is
/// nothing to filter — but the guard is kept so a future source that does emit
/// directory placeholders cannot have them written out as zero-byte files.
pub fn files_to_rebuild(source: &dyn Source) -> Vec<&Entry> {
    source.entries().iter().filter(|e| !e.is_dir()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::models::Location;
    use crate::core::source::Content;
    use crate::platform::ios::backup::common::DirectoryRecord;

    struct FakeSource(Vec<Entry>);

    impl Source for FakeSource {
        fn entries(&self) -> &[Entry] {
            &self.0
        }
        fn content(&self, _entry: &Entry) -> anyhow::Result<Content<'_>> {
            Ok(Content::Owned(Vec::new()))
        }
    }

    fn entry(name: &str) -> Entry {
        Entry {
            name: name.to_string(),
            uncompressed_size: 1,
            mtime: None,
            location: Location::Loose {
                path: std::path::PathBuf::from(name),
            },
        }
    }

    fn source(names: &[&str]) -> FakeSource {
        FakeSource(names.iter().map(|n| entry(n)).collect())
    }

    #[test]
    fn maps_known_domains_to_device_paths() {
        let src = source(&[
            "HomeDomain/Library/SMS/sms.db",
            "CameraRollDomain/Media/DCIM/IMG_0001.JPG",
        ]);
        let rebuilt = plan(&src, &BackupStructure::default(), BackupKind::Ios);
        let map: BTreeMap<_, _> = rebuilt.roots.iter().cloned().collect();
        assert_eq!(map["HomeDomain"], "private/var/mobile");
        // The relativePath already carries "Media/", so the root must not.
        assert_eq!(map["CameraRollDomain"], "private/var/mobile");
        assert!(rebuilt.unmapped.is_empty());
        assert!(rebuilt.synthetic.is_empty());
    }

    #[test]
    fn app_domains_are_reported_as_synthetic() {
        let src = source(&["AppDomain-com.test.app/Documents/notes.txt"]);
        let rebuilt = plan(&src, &BackupStructure::default(), BackupKind::Ios);
        assert_eq!(rebuilt.synthetic, vec!["AppDomain-com.test.app"]);
        let map: BTreeMap<_, _> = rebuilt.roots.iter().cloned().collect();
        assert_eq!(
            map["AppDomain-com.test.app"],
            "private/var/mobile/Containers/Data/Application/com.test.app"
        );
    }

    /// An unrecognised domain must be kept, reported, and parked somewhere that
    /// cannot be mistaken for a device path — never dropped, and never left to
    /// fall into `plan_tree`'s flat-hash fallback.
    #[test]
    fn unknown_domains_are_kept_and_reported() {
        let src = source(&["MysteryDomain/whatever.db"]);
        let rebuilt = plan(&src, &BackupStructure::default(), BackupKind::Ios);
        assert_eq!(rebuilt.unmapped, vec!["MysteryDomain"]);
        let map: BTreeMap<_, _> = rebuilt.roots.iter().cloned().collect();
        assert_eq!(map["MysteryDomain"], "unknown_backup_domains/MysteryDomain");
        // Every entry must be attributable to some root.
        for e in src.entries() {
            assert!(
                rebuilt
                    .roots
                    .iter()
                    .any(|(prefix, _)| e.name.starts_with(prefix)),
                "{} fell under no root",
                e.name
            );
        }
    }

    fn directory(name: &str, mtime: Option<u64>) -> DirectoryRecord {
        DirectoryRecord {
            name: name.to_string(),
            mtime,
        }
    }

    /// A domain's own root directory has a record too, and a timestamp worth keeping.
    /// Two domains can mount at one path, and the first with a time supplies it.
    #[test]
    fn a_domain_root_directory_maps_to_the_domain_path() {
        let src = source(&["HomeDomain/Library/SMS/sms.db"]);
        let structure = BackupStructure {
            directories: vec![
                directory("CameraRollDomain", None),
                directory("HomeDomain", Some(3_000)),
                directory("KeychainDomain", Some(4_000)),
            ],
            ..BackupStructure::default()
        };
        let rebuilt = plan(&src, &structure, BackupKind::Ios);
        assert_eq!(
            rebuilt.directories,
            vec![
                RebuildDirectory {
                    path: "private/var/Keychains".to_string(),
                    mtime: Some(4_000),
                    names: vec!["KeychainDomain".to_string()],
                },
                RebuildDirectory {
                    path: "private/var/mobile".to_string(),
                    mtime: Some(3_000),
                    names: vec!["CameraRollDomain".to_string(), "HomeDomain".to_string()],
                },
            ]
        );
    }

    #[test]
    fn directory_records_map_under_their_domain() {
        let src = source(&["HomeDomain/Library/SMS/sms.db"]);
        let structure = BackupStructure {
            directories: vec![
                directory("HomeDomain/Library", Some(1_000)),
                directory("HomeDomain/Library/Caches", None),
            ],
            ..BackupStructure::default()
        };
        let rebuilt = plan(&src, &structure, BackupKind::Ios);
        assert_eq!(
            rebuilt.directories,
            vec![
                RebuildDirectory {
                    path: "private/var/mobile/Library".to_string(),
                    mtime: Some(1_000),
                    names: vec!["HomeDomain/Library".to_string()],
                },
                RebuildDirectory {
                    path: "private/var/mobile/Library/Caches".to_string(),
                    mtime: None,
                    names: vec!["HomeDomain/Library/Caches".to_string()],
                },
            ]
        );
    }

    /// An Android archive's members and directory records map through its tokens.
    #[test]
    fn android_members_map_through_their_tokens() {
        let src = source(&["apps/com.x/db/m.db", "apps/com.x/_manifest"]);
        let structure = BackupStructure {
            directories: vec![directory("apps/com.x/db", Some(2_000))],
            ..BackupStructure::default()
        };
        let rebuilt = plan(&src, &structure, BackupKind::Android);
        let map: BTreeMap<_, _> = rebuilt.roots.iter().cloned().collect();
        assert_eq!(map["apps/com.x/db"], "data/data/com.x/databases");
        assert_eq!(map["apps/com.x"], "backup_only/apps/com.x");
        assert_eq!(
            rebuilt.directories,
            vec![RebuildDirectory {
                path: "data/data/com.x/databases".to_string(),
                mtime: Some(2_000),
                names: vec!["apps/com.x/db".to_string()],
            }]
        );
    }

    /// A domain present only as directory records still needs a root, or its
    /// directories would be silently lost.
    #[test]
    fn domain_seen_only_in_directory_records_still_gets_a_root() {
        let src = source(&["HomeDomain/Library/SMS/sms.db"]);
        let structure = BackupStructure {
            directories: vec![directory("MediaDomain/Media/Empty", None)],
            ..BackupStructure::default()
        };
        let rebuilt = plan(&src, &structure, BackupKind::Ios);
        let map: BTreeMap<_, _> = rebuilt.roots.iter().cloned().collect();
        assert_eq!(map["MediaDomain"], "private/var/mobile");
        // "Media/" comes from the relativePath, not the root.
        assert_eq!(
            rebuilt.directories[0].path,
            "private/var/mobile/Media/Empty"
        );
    }

    #[test]
    fn roots_are_deterministic() {
        let names = ["ZDomain/a", "HomeDomain/b", "AppDomain-com.x/c"];
        let first = plan(
            &source(&names),
            &BackupStructure::default(),
            BackupKind::Ios,
        )
        .roots;
        let second = plan(
            &source(&names),
            &BackupStructure::default(),
            BackupKind::Ios,
        )
        .roots;
        assert_eq!(first, second);
        let domains: Vec<&str> = first.iter().map(|(d, _)| d.as_str()).collect();
        let mut sorted = domains.clone();
        sorted.sort();
        assert_eq!(domains, sorted, "roots must come out sorted");
    }
}
