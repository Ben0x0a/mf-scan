//! Rebuild a whole iOS backup into a filesystem-like tree.
//!
//! Defines: [`Rebuild`] (the plan: one output root per backup domain, plus what
//! could not be mapped and what had to be invented) and [`plan`].
//! Used by: the binary's `ios-backup rebuild` orchestrator (`cmd::run::ios_backup`).
//! Uses: [`crate::core::source::Source`] (entry names only — never bytes),
//! [`crate::platform::ios::domains`] (the domain → path grammar) and
//! [`crate::platform::ios::backup::common::BackupStructure`] (the directory rows).
//!
//! WHY a peer of [`crate::ops::apps`] and not part of it: `apps` answers "which
//! subset of this source belongs to app X" and carries container identity, kinds
//! and group attribution to do it. A rebuild answers "all of it, relabelled" and
//! needs none of that — threading it through `apps` would mean passing a bundle id
//! it ignores, entrenching a wart that already exists there.
//!
//! WHY no platform dispatch: only an iTunes/Finder backup is flattened into a
//! hash-addressed blob store and therefore needs rebuilding. A full-filesystem or
//! Android acquisition is already a tree. A second acquisition type would add one
//! match arm here, which is cheaper than a permanently one-armed match now.
//!
//! ── What this module does NOT do ──────────────────────────────────────────────
//! It reads no bytes and writes no files. It produces `(prefix, label)` roots that
//! [`crate::report::export::plan_tree`] turns into an export plan, so the copying,
//! digesting and manifest writing stay in the one export engine every subcommand
//! shares.

use std::collections::BTreeMap;

use crate::core::models::Entry;
use crate::core::source::Source;
use crate::platform::ios::backup::common::BackupStructure;
use crate::platform::ios::domains;
use crate::report::export::tree_dir;

/// Output root for domains the grammar does not recognise.
///
/// WHY they get a root rather than being skipped: an unrecognised domain is still
/// evidence, and dropping it would be a silent loss. WHY a visibly non-device
/// name: nothing under it should be mistaken for a real filesystem location.
pub const UNMAPPED_ROOT: &str = "_unmapped_domains";

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
    /// Directory records, as output-relative paths to create.
    pub directories: Vec<String>,
    /// Symlink records, by logical name. Reported, never recreated: the target is
    /// not recorded in a resolvable form, and writing a link into an export is a
    /// way to escape it.
    pub symlinks: Vec<String>,
}

/// Build the rebuild plan for `source`.
///
/// `structure` carries the directory rows, which the source deliberately keeps out
/// of `entries()` (see [`BackupStructure`]).
pub fn plan(source: &dyn Source, structure: &BackupStructure) -> Rebuild {
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

    let roots: Vec<(String, String)> = roots.into_iter().collect();

    // Map the directory records through the SAME roots the files use, so a
    // directory is created exactly where its contents land.
    let mut directories: Vec<String> = structure
        .directories
        .iter()
        .filter_map(|name| tree_dir(name, &roots))
        .collect();
    directories.sort();
    directories.dedup();

    unmapped.sort();
    unmapped.dedup();
    synthetic.sort();
    synthetic.dedup();

    Rebuild {
        roots,
        unmapped,
        synthetic,
        directories,
        symlinks: structure.symlinks.clone(),
    }
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
        .chain(structure.directories.iter().map(String::as_str));
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
        let rebuilt = plan(&src, &BackupStructure::default());
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
        let rebuilt = plan(&src, &BackupStructure::default());
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
        let rebuilt = plan(&src, &BackupStructure::default());
        assert_eq!(rebuilt.unmapped, vec!["MysteryDomain"]);
        let map: BTreeMap<_, _> = rebuilt.roots.iter().cloned().collect();
        assert_eq!(map["MysteryDomain"], "_unmapped_domains/MysteryDomain");
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

    #[test]
    fn directory_records_map_under_their_domain() {
        let src = source(&["HomeDomain/Library/SMS/sms.db"]);
        let structure = BackupStructure {
            directories: vec![
                "HomeDomain/Library".into(),
                "HomeDomain/Library/Caches".into(),
            ],
            symlinks: Vec::new(),
        };
        let rebuilt = plan(&src, &structure);
        assert_eq!(
            rebuilt.directories,
            vec![
                "private/var/mobile/Library".to_string(),
                "private/var/mobile/Library/Caches".to_string(),
            ]
        );
    }

    /// A domain present only as directory records still needs a root, or its
    /// directories would be silently lost.
    #[test]
    fn domain_seen_only_in_directory_records_still_gets_a_root() {
        let src = source(&["HomeDomain/Library/SMS/sms.db"]);
        let structure = BackupStructure {
            directories: vec!["MediaDomain/Media/Empty".into()],
            symlinks: Vec::new(),
        };
        let rebuilt = plan(&src, &structure);
        let map: BTreeMap<_, _> = rebuilt.roots.iter().cloned().collect();
        assert_eq!(map["MediaDomain"], "private/var/mobile");
        // "Media/" comes from the relativePath, not the root.
        assert_eq!(rebuilt.directories, vec!["private/var/mobile/Media/Empty"]);
    }

    #[test]
    fn roots_are_deterministic() {
        let names = ["ZDomain/a", "HomeDomain/b", "AppDomain-com.x/c"];
        let first = plan(&source(&names), &BackupStructure::default()).roots;
        let second = plan(&source(&names), &BackupStructure::default()).roots;
        assert_eq!(first, second);
        let domains: Vec<&str> = first.iter().map(|(d, _)| d.as_str()).collect();
        let mut sorted = domains.clone();
        sorted.sort();
        assert_eq!(domains, sorted, "roots must come out sorted");
    }
}
