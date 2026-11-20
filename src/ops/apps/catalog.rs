//! The app catalogue: build it from a source, then search/select app data.
//!
//! Defines: [`AppCatalog`] (build, [`AppCatalog::inventory`] for `app list`,
//! [`AppCatalog::containers_for`] for `app paths`/`app export`,
//! [`AppCatalog::scope`] and [`AppScope`] for `--app`, [`AppCatalog::matching_ids`]
//! (an id across case and a team-id prefix)), and [`entries_under`] (gather a
//! selection's files for export). Group attribution is in `groups`, platform
//! detection and the tally in `detect`.
//! Used by: the binary's `app` subcommand (`run::app`) and `--app`
//! (`cmd::support::scoping`).
//! Uses: the data types in [`super::types`], the per-platform resolvers
//! ([`super::ios_ffs`], [`super::ios_backup`], [`super::android`]),
//! [`crate::platform::ios::references::McmReferences`] (the App Group source on an
//! iOS FFS), [`crate::core::filter::is_under`], and [`crate::core::source::Source`] /
//! [`crate::core::models::Entry`].

use std::collections::BTreeMap;

use crate::core::filter::is_under;
use crate::core::models::Entry;
use crate::core::source::Source;
use crate::platform::ios::containers::AppContainerMap;
use crate::platform::ios::references::McmReferences;

use super::detect::{detect, tally};
use super::types::{AppContainer, AppSummary, ContainerKind, GroupLink, Platform, SigningRecord};
use super::{android, ios_backup, ios_ffs};

/// What an app id, as an operator typed it, resolved to (see [`AppCatalog::resolve`]).
#[derive(Debug, Clone)]
pub struct AppResolution {
    /// The id as typed.
    pub id: String,
    /// The other ids it matched ([`AppCatalog::matching_ids`]): case, team-id prefix.
    pub aliases: Vec<String>,
    /// Its containers, as `app paths` lists them.
    pub containers: Vec<AppContainer>,
}

impl AppResolution {
    /// Containers were found, all of them App Groups: the app has none of its own
    /// here (not installed, or not captured).
    pub fn only_groups(&self) -> bool {
        !self.containers.is_empty()
            && self
                .containers
                .iter()
                .all(|c| c.kind == ContainerKind::AppGroup)
    }

    /// The App Groups attributed by name only (a guess).
    pub fn guessed_groups(&self) -> impl Iterator<Item = &AppContainer> {
        self.containers
            .iter()
            .filter(|c| c.group_link == Some(GroupLink::VendorHeuristic))
    }
}

/// What `--app` limits a search to (see [`AppCatalog::scope`]).
#[derive(Debug, Default, Clone)]
pub struct AppScope {
    /// The containers' path prefixes, sorted, each once.
    pub prefixes: Vec<String>,
    /// Each id, as it resolved; one with no container is in [`missing`](Self::missing).
    pub apps: Vec<AppResolution>,
    /// The ids with no container in the source.
    pub missing: Vec<String>,
}

/// Every app container found in a source, plus the platform it was read as and
/// the MobileContainerManager signing records that go with it.
pub struct AppCatalog {
    pub platform: Platform,
    /// Every container, sorted by prefix (then id). Not public: `normal` is
    /// computed from it and must stay in step.
    ///
    /// WHY sorted: the iOS container map is a hash map, so its order changed from run
    /// to run, and so did every listing made from it; an output that cannot be
    /// reproduced cannot be compared with an earlier one.
    pub(super) containers: Vec<AppContainer>,
    /// MCM's code-signing/entitlement records, read once per source. Empty for
    /// every platform but iOS FFS, and for an FFS that did not capture the
    /// database — in which case group attribution falls back to the heuristic.
    pub(super) references: McmReferences,
    /// Each container's [`NormalIds`], by its index in `containers`.
    normal: Vec<NormalIds>,
    /// Each normal id → the ids in this source that have it: those of the
    /// containers but App Groups, and of the entitlement records.
    ids_by_normal: BTreeMap<String, Vec<String>>,
}

/// A container's id and its declared parent's, as [`normal_id`]s.
///
/// WHY computed once, when the catalogue is built: every lookup of an app compares
/// them with every container's, and `app list` looks up every app.
pub(super) struct NormalIds {
    id: String,
    parent: Option<String>,
}

impl NormalIds {
    fn of(c: &AppContainer) -> Self {
        Self {
            id: normal_id(&c.id),
            parent: c.parent_id.as_deref().map(normal_id),
        }
    }
}

impl AppCatalog {
    /// Detect the platform and resolve every app container, tallying each
    /// container's file count and total size in a single pass over the entries.
    pub fn build(source: &dyn Source) -> Self {
        Self::build_with(source, None)
    }

    /// [`build`](Self::build), reusing the source's container `map` when the caller
    /// already built one (grep, for its records' owning app), so an iOS file system's
    /// metadata plists are read once.
    pub fn build_with(source: &dyn Source, map: Option<&AppContainerMap>) -> Self {
        let platform = detect(source);
        let mut containers = match platform {
            Platform::IosFfs => match map {
                Some(map) => ios_ffs::resolve(map),
                None => ios_ffs::resolve(&AppContainerMap::build(source)),
            },
            Platform::IosBackup => ios_backup::resolve(source),
            Platform::Android => android::resolve(source),
            Platform::Unknown => Vec::new(),
        };
        tally(source, &mut containers);
        // WHY read the database here and not per app: it is one file holding every
        // app's record, so one read per source serves the whole catalogue.
        let references = match platform {
            Platform::IosFfs => McmReferences::build(source),
            _ => McmReferences::empty(),
        };
        Self::new(platform, containers, references)
    }

    /// A catalogue of `containers`, sorted, their normal ids computed.
    pub(super) fn new(
        platform: Platform,
        mut containers: Vec<AppContainer>,
        references: McmReferences,
    ) -> Self {
        containers.sort_by(|a, b| a.prefix.cmp(&b.prefix).then_with(|| a.id.cmp(&b.id)));
        let normal = containers.iter().map(NormalIds::of).collect();
        let mut ids_by_normal: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let ids = containers
            .iter()
            .filter(|c| c.kind != ContainerKind::AppGroup)
            .map(|c| c.id.as_str())
            .chain(references.ids());
        for id in ids {
            ids_by_normal
                .entry(normal_id(id))
                .or_default()
                .push(id.to_string());
        }
        Self {
            platform,
            containers,
            references,
            normal,
            ids_by_normal,
        }
    }

    /// The containers that are app `id`'s own data, an extension/widget of it, or
    /// its bundle ([`is_app_or_extension`]); `id` stands for every id
    /// [`matching_ids`](Self::matching_ids) gives.
    pub(super) fn own_containers(&self, id: &str) -> impl Iterator<Item = &AppContainer> {
        let wanted = normal_id(id);
        self.containers
            .iter()
            .zip(&self.normal)
            .filter(move |(c, normal)| is_app_or_extension(c, normal, &wanted))
            .map(|(c, _)| c)
    }

    /// True when a `references.sqlite3-wal` sidecar was replayed into the MCM
    /// database image, so the caller can record that in the analyst-facing output.
    pub fn mcm_wal_replayed(&self) -> bool {
        self.references.wal_replayed()
    }

    /// The MobileContainerManager signing record for an app, when the source has one.
    /// `id` stands for every id [`matching_ids`](Self::matching_ids) gives.
    pub fn signing_record(&self, id: &str) -> Option<&SigningRecord> {
        self.matching_ids(id)
            .iter()
            .find_map(|i| self.references.get(i))
    }

    /// `app list`: one [`AppSummary`] per installed (primary) app, optionally
    /// filtered by a case-insensitive substring over the id and display name.
    /// Sorted by id for stable output.
    pub fn inventory(&self, source: &dyn Source, pattern: Option<&str>) -> Vec<AppSummary> {
        // Aggregate primary containers by id (an app usually has one, but multi-user
        // Android can have several). An Android storage captured under several mount
        // aliases (`/data/data` and `/data/user/0`) is one storage: counted once, at
        // its largest copy.
        //
        // WHY every id with a container of its own is listed, and not only those with
        // a data container: an app whose data container was not captured (or an
        // Android package with only external or device-encrypted data) still has data
        // here; left out of the list, it would not be looked at. Only data containers
        // count toward the size.
        //
        // WHY one row per app across case and a team-id prefix ([`normal_id`]): the
        // container manager may record an app's data under `5Q4J53EFRC.com.sbb.ch`
        // and its bundle under `com.sbb.ch`; two rows, one sized and one `-`, would
        // read as two apps, one without data. The row shows the data container's id.
        let mut by_storage: BTreeMap<(String, &str), u64> = BTreeMap::new();
        // Normal id → the id shown, whether it is a data container's, and the size.
        let mut rows: BTreeMap<String, (&str, bool, Option<u64>)> = BTreeMap::new();
        for (c, normal) in self.containers.iter().zip(&self.normal) {
            if matches!(c.kind, ContainerKind::AppGroup | ContainerKind::Extension) {
                continue;
            }
            let key = normal.id.clone();
            let primary = c.kind.is_primary();
            let row = rows
                .entry(key.clone())
                .or_insert((c.id.as_str(), primary, None));
            if primary && !row.1 {
                (row.0, row.1) = (c.id.as_str(), true);
            }
            if !primary {
                continue;
            }
            let storage = c
                .android_root
                .as_ref()
                .map_or(c.prefix.as_str(), |r| r.storage.as_str());
            let size = by_storage.entry((key, storage)).or_default();
            *size = (*size).max(c.total_size);
        }
        for ((key, _), size) in by_storage {
            if let Some(row) = rows.get_mut(&key) {
                *row.2.get_or_insert(0) += size;
            }
        }

        let mut apps: Vec<AppSummary> = rows
            .into_values()
            .map(|(id, _, size)| AppSummary {
                id: id.to_string(),
                name: self.display_name(source, id),
                total_size: size,
                signing: self.signing_record(id).cloned(),
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
            .collect();
        apps.sort_by(|a, b| a.id.cmp(&b.id));
        apps
    }

    /// `app paths` / `app export`: every container the app `id` or its dependencies
    /// can write — the app's own data (`id`), its extensions/widgets (`id.*`), the
    /// app bundle, and, when `with_groups`, its App Groups (each tagged with how it
    /// was attributed). The app's own containers first, then its groups, each by prefix.
    ///
    /// `id` stands for every id [`matching_ids`](Self::matching_ids) gives.
    pub fn containers_for(&self, id: &str, with_groups: bool) -> Vec<AppContainer> {
        let ids = self.matching_ids(id);
        // One pass: every matching id has the same normal form, which the test
        // compares.
        let mut out: Vec<AppContainer> = self.own_containers(id).cloned().collect();

        if with_groups {
            let links = self.resolve_group_links(&ids);
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

    /// `--app` on grep, find and diff: the path prefixes of every container of each
    /// app in `ids` — its data, extensions and widgets, bundle, and App Groups, as
    /// `app paths` lists them — and the ids found nowhere in this source.
    ///
    /// An id with no container of its own (data, extension, bundle) keeps its groups:
    /// an Apple system app may have no data container and still write to its groups.
    /// WHY even the groups matched by name only: a group left out is data silently
    /// not searched; one wrongly in is named as a guess by the caller. An id with
    /// nothing at all is missing.
    pub fn scope(&self, ids: &[String]) -> AppScope {
        let mut scope = AppScope::default();
        for id in ids {
            let resolved = self.resolve(id, true);
            if resolved.containers.is_empty() {
                scope.missing.push(id.clone());
                continue;
            }
            scope
                .prefixes
                .extend(resolved.containers.iter().map(|c| c.prefix.clone()));
            scope.apps.push(resolved);
        }
        scope.prefixes.sort();
        scope.prefixes.dedup();
        scope
    }

    /// What `id`, as an operator typed it, resolves to: the other ids it matched and
    /// its containers ([`containers_for`](Self::containers_for)).
    pub fn resolve(&self, id: &str, with_groups: bool) -> AppResolution {
        AppResolution {
            id: id.to_string(),
            aliases: self
                .matching_ids(id)
                .into_iter()
                .filter(|m| m != id)
                .collect(),
            containers: self.containers_for(id, with_groups),
        }
    }

    /// The ids in this source that `id`, as an operator typed it, stands for: `id`
    /// itself, and the ids of containers and entitlement records equal to it but for
    /// case or an Apple team-id prefix (`5Q4J53EFRC.com.sbb.ch` for `com.sbb.ch`).
    ///
    /// WHY: the container manager records some apps under their team-prefixed id
    /// (seen on a real iPhone), and an id typed in the wrong case is still the
    /// operator asking for that app. Matched exactly, both found only the groups a
    /// name guess attached, which reads as "this app has almost no data".
    pub fn matching_ids(&self, id: &str) -> Vec<String> {
        let mut ids: Vec<String> = self
            .ids_by_normal
            .get(&normal_id(id))
            .into_iter()
            .flatten()
            .cloned()
            .chain(std::iter::once(id.to_string()))
            .collect();
        ids.sort();
        ids.dedup();
        ids
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
        let wanted = normal_id(id);
        self.containers
            .iter()
            .zip(&self.normal)
            .find(|(c, normal)| c.kind == ContainerKind::Bundle && normal.id == wanted)
            .map(|(c, _)| c.prefix.as_str())
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

/// `id` lower-cased, without an Apple team-id prefix (ten upper-case letters or
/// digits, then a dot: `5Q4J53EFRC.com.sbb.ch` → `com.sbb.ch`).
pub(super) fn normal_id(id: &str) -> String {
    let unprefixed = match id.split_once('.') {
        Some((team, rest))
            if team.len() == 10
                && team
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
                && rest.contains('.') =>
        {
            rest
        }
        _ => id,
    };
    unprefixed.to_lowercase()
}

/// Whether container `c` is the app `id`'s own data, an extension/widget of it, or
/// its bundle — the non-group part of an app's selection.
///
/// An extension container is claimed by its DECLARED parent when the container
/// metadata names one, and only otherwise by the `id.*` name-prefix rule. WHY the
/// declared parent must win: bundle ids nest, but installed apps do not nest with
/// them — `com.apple.siri` and `com.apple.siri.SiriGeo` are two separate apps, so
/// the prefix rule alone hands the latter's extensions to the former (measured: 17
/// and 19 such misattributions on two real acquisitions).
///
/// The prefix fallback applies only to extension-style containers: on iOS an
/// extension's bundle id extends the app's (`com.app.Widget`); a sibling Android
/// package (`com.app.helper`) is a *different* app, so Android containers match by
/// exact package only.
///
/// Ids compare as [`normal_id`]s: across case and an Apple team-id prefix, so an
/// app recorded as `5Q4J53EFRC.com.sbb.ch` keeps a widget named `com.sbb.ch.Widget`.
/// `normal` is `c`'s, `id` already normal.
fn is_app_or_extension(c: &AppContainer, normal: &NormalIds, id: &str) -> bool {
    let own = normal.id.as_str();
    match c.kind {
        ContainerKind::AppData | ContainerKind::Bundle => own == id,
        ContainerKind::Extension => match &normal.parent {
            Some(parent) => parent == id,
            None => {
                own == id
                    || own
                        .strip_prefix(id)
                        .is_some_and(|rest| rest.starts_with('.'))
            }
        },
        ContainerKind::AndroidData
        | ContainerKind::AndroidUserDe
        | ContainerKind::AndroidExternal
        | ContainerKind::AndroidObb
        | ContainerKind::AndroidMedia => own == id,
        ContainerKind::AppGroup => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// [`is_app_or_extension`] for an id as typed.
    fn owns(c: &AppContainer, id: &str) -> bool {
        is_app_or_extension(c, &NormalIds::of(c), &normal_id(id))
    }

    fn container(id: &str, kind: ContainerKind) -> AppContainer {
        AppContainer {
            id: id.to_string(),
            kind,
            prefix: "p".to_string(),
            guid: None,
            parent_id: None,
            file_count: 0,
            total_size: 0,
            group_link: None,
            android_root: None,
        }
    }

    /// An extension container whose metadata plist declares its owning app.
    fn extension_of(id: &str, parent: &str) -> AppContainer {
        AppContainer {
            parent_id: Some(parent.to_string()),
            ..container(id, ContainerKind::Extension)
        }
    }

    #[test]
    fn an_id_matches_across_case_and_a_team_prefix() {
        assert_eq!(normal_id("5Q4J53EFRC.com.sbb.ch"), "com.sbb.ch");
        assert_eq!(normal_id("net.whatsapp.WhatsApp"), "net.whatsapp.whatsapp");
        // Not a team id: lower case, or nothing after it but one name.
        assert_eq!(normal_id("abcdefghij.com.x"), "abcdefghij.com.x");
        assert_eq!(normal_id("5Q4J53EFRC.app"), "5q4j53efrc.app");

        let catalog = AppCatalog::new(
            Platform::IosFfs,
            vec![
                container("5Q4J53EFRC.com.sbb.ch", ContainerKind::AppData),
                container("net.whatsapp.WhatsApp", ContainerKind::AppData),
            ],
            McmReferences::empty(),
        );
        assert_eq!(
            catalog.matching_ids("com.sbb.ch"),
            ["5Q4J53EFRC.com.sbb.ch", "com.sbb.ch"]
        );
        assert_eq!(
            catalog.matching_ids("net.whatsapp.whatsapp"),
            ["net.whatsapp.WhatsApp", "net.whatsapp.whatsapp"]
        );
        assert_eq!(catalog.matching_ids("com.absent"), ["com.absent"]);
        assert_eq!(catalog.containers_for("com.sbb.ch", false).len(), 1);
        // A widget named after the plain id belongs to the team-prefixed app.
        let widget = container("com.sbb.ch.Widget", ContainerKind::Extension);
        assert!(owns(&widget, "5Q4J53EFRC.com.sbb.ch"));
        assert!(owns(&widget, "com.sbb.ch"));
    }

    #[test]
    fn app_and_extension_selection_rules() {
        let app = container("com.x.App", ContainerKind::AppData);
        let ext = container("com.x.App.Widget", ContainerKind::Extension);
        let other = container("com.x.AppHelper", ContainerKind::AppData);
        assert!(owns(&app, "com.x.App"));
        assert!(owns(&ext, "com.x.App")); // child extension included
        assert!(!owns(&other, "com.x.App")); // sibling app excluded
    }

    /// The real misattribution the declared parent fixes: `com.apple.siri` and
    /// `com.apple.siri.SiriGeo` are two separate installed apps, so the latter's
    /// extension must NOT be swept into an export of the former.
    #[test]
    fn declared_parent_beats_the_name_prefix_rule() {
        let ext = extension_of(
            "com.apple.siri.SiriGeo.SiriGeoIntentExtension",
            "com.apple.siri.SiriGeo",
        );
        assert!(owns(&ext, "com.apple.siri.SiriGeo"));
        assert!(!owns(&ext, "com.apple.siri"));
    }

    /// Where the metadata declares no parent (147/785 plugin containers on a real
    /// device), the name-prefix rule still applies — the fallback is not dropped.
    #[test]
    fn undeclared_parent_falls_back_to_the_prefix_rule() {
        let ext = container("com.x.App.Widget", ContainerKind::Extension);
        assert!(owns(&ext, "com.x.App"));
        assert!(!owns(&ext, "com.x.Other"));
    }

    #[test]
    fn android_child_packages_are_not_extensions() {
        let helper = container("com.x.helper", ContainerKind::AndroidData);
        // A different Android package that merely shares a prefix is NOT pulled in.
        assert!(!owns(&helper, "com.x"));
    }
}
