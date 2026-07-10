//! The data types of the app catalogue.
//!
//! Defines: [`Platform`] (the recognised acquisition layouts), [`ContainerKind`]
//! (what a container is / which Android root it sits under), [`GroupLink`] (how a
//! group was attributed), [`AppContainer`] (one resolved container with its tally),
//! and [`AppSummary`] (one installed app, for the inventory).
//! Used by: [`crate::ops::apps::catalog`] (builds and queries these) and the per-platform
//! resolvers ([`crate::ops::apps::ios_ffs`], [`crate::ops::apps::ios_backup`],
//! [`crate::ops::apps::android`], which construct [`AppContainer`]s).
//! Uses: `std` plus `serde` (the two output types derive `Serialize` so the
//! `app grep`/`app paths` JSON is the struct itself, not a hand-mirrored field
//! list) — otherwise plain data types, kept in their own module so the resolvers
//! and the catalogue depend on the data shape, not on each other.

use serde::{Serialize, Serializer};

/// Which acquisition layout a source presents, deciding how its app data is found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// An iOS full-file-system extraction (GUID containers + metadata plists).
    IosFfs,
    /// An iOS iTunes/Finder backup (logical `domain/relativePath` entries).
    IosBackup,
    /// An Android full-file-system extraction (package names under data roots).
    Android,
    /// No recognised app-data layout (e.g. a generic archive).
    Unknown,
}

/// The kind of container a path belongs to — both *what* it is (app data, an
/// extension/widget, a shared group, the app bundle) and, on Android, *which*
/// storage root it sits under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerKind {
    /// The app's own data container (iOS `Data/Application`, or a backup `AppDomain-`).
    AppData,
    /// An app extension / widget container (iOS `PluginKitPlugin`, or `AppDomainPlugin-`).
    Extension,
    /// A shared App Group container (iOS `Shared/AppGroup`, or `AppDomainGroup-`).
    AppGroup,
    /// The installed `.app` bundle (iOS `Bundle/Application`). FFS only.
    Bundle,
    /// Android internal app-private storage (`/data/data`, `/data/user/<n>`).
    AndroidData,
    /// Android device-encrypted storage (`/data/user_de/<n>`).
    AndroidUserDe,
    /// Android external app-scoped storage (`…/Android/data`).
    AndroidExternal,
    /// Android OBB expansion-file storage (`…/Android/obb`).
    AndroidObb,
    /// Android external media storage (`…/Android/media`).
    AndroidMedia,
}

impl ContainerKind {
    /// Short label used in the export sub-folder name and in `app paths` output.
    pub fn as_str(self) -> &'static str {
        match self {
            ContainerKind::AppData => "AppData",
            ContainerKind::Extension => "Extension",
            ContainerKind::AppGroup => "AppGroup",
            ContainerKind::Bundle => "Bundle",
            ContainerKind::AndroidData => "data",
            ContainerKind::AndroidUserDe => "user_de",
            ContainerKind::AndroidExternal => "external_data",
            ContainerKind::AndroidObb => "obb",
            ContainerKind::AndroidMedia => "media",
        }
    }

    /// Whether this kind represents a *primary* installed app (vs an extension,
    /// group, bundle, or secondary Android storage) — the unit `app grep`'s
    /// inventory lists one line per.
    pub(crate) fn is_primary(self) -> bool {
        matches!(self, ContainerKind::AppData | ContainerKind::AndroidData)
    }
}

/// How an App Group was attributed to an app — recorded so an analyst can audit
/// which group inclusions are authoritative.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupLink {
    /// Declared in the app binary's code-signature entitlements (authoritative).
    Entitlement,
    /// Matched by the reverse-DNS vendor-token heuristic (best-effort fallback).
    VendorHeuristic,
}

impl GroupLink {
    /// Tag used in output and the export report.
    pub fn as_str(self) -> &'static str {
        match self {
            GroupLink::Entitlement => "Entitlement",
            GroupLink::VendorHeuristic => "VendorHeuristic",
        }
    }
}

/// One resolved container: an app/extension/group/bundle data location, with its
/// file tally and (for a group attributed to an app) how it was attributed.
///
/// The field order and `serde` attributes below define the `app paths --format json`
/// output exactly: `guid` is internal (skipped), and `kind`/`group_link` serialise
/// via their `as_str()` so the enum labels stay the single source of truth.
#[derive(Debug, Clone, Serialize)]
pub struct AppContainer {
    /// The identifier carried by the container: a bundle id (app/extension), a
    /// `group.*` id (App Group), or an Android package name.
    pub id: String,
    #[serde(serialize_with = "serialize_kind")]
    pub kind: ContainerKind,
    /// The path prefix in the source (no trailing `/`).
    pub prefix: String,
    /// Short container GUID for iOS containers; `None` for Android/backup.
    /// Internal-only: not part of the JSON output.
    #[serde(skip)]
    pub guid: Option<String>,
    pub file_count: usize,
    pub total_size: u64,
    /// Set only on a group container included in an app's selection.
    #[serde(serialize_with = "serialize_group_link")]
    pub group_link: Option<GroupLink>,
}

/// Serialise a [`ContainerKind`] as its short label (its [`ContainerKind::as_str`]),
/// so the JSON matches the txt/export label instead of the Rust variant name.
fn serialize_kind<S: Serializer>(kind: &ContainerKind, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(kind.as_str())
}

/// Serialise an optional [`GroupLink`] as its tag string, or `null` when absent.
fn serialize_group_link<S: Serializer>(link: &Option<GroupLink>, s: S) -> Result<S::Ok, S::Error> {
    match link {
        Some(l) => s.serialize_str(l.as_str()),
        None => s.serialize_none(),
    }
}

impl AppContainer {
    /// The export sub-folder name for this container (without the top-level folder):
    /// `"<Kind>_<guid8>"` for iOS, `"<kind>"` for Android, empty for a backup
    /// domain (which uses the domain itself as the whole label).
    fn sublabel(&self) -> String {
        match &self.guid {
            Some(guid) => format!("{}_{}", self.kind.as_str(), guid),
            None => self.kind.as_str().to_string(),
        }
    }

    /// The output label (relative folder) this container's files are written under
    /// during `app export`, given the requested app `id` and the source `platform`.
    ///
    /// Layout rules (see the module doc / the approved design): a backup uses one
    /// subfolder per domain (the domain itself); an App Group uses its own group id
    /// (it is shared, so labelling it by the requesting app would mislead); an
    /// Android container uses `<pkg>/<kind>`; an app's own data / extension / bundle
    /// uses `<requested-id>/<Kind>_<guid8>` so all of one app's own containers nest
    /// under the id the analyst asked for.
    pub fn export_label(&self, requested_id: &str, platform: Platform) -> String {
        if platform == Platform::IosBackup {
            return self.prefix.clone();
        }
        let sub = self.sublabel();
        let top = match self.kind {
            ContainerKind::AppGroup => self.id.as_str(),
            ContainerKind::AndroidData
            | ContainerKind::AndroidUserDe
            | ContainerKind::AndroidExternal
            | ContainerKind::AndroidObb
            | ContainerKind::AndroidMedia => self.id.as_str(),
            _ => requested_id,
        };
        if sub.is_empty() {
            top.to_string()
        } else {
            format!("{top}/{sub}")
        }
    }
}

/// One installed app, for the `app grep` inventory.
///
/// The field order is the `app grep --format json` output (a plain derive matches
/// the previous hand-written object).
#[derive(Debug, Clone, Serialize)]
pub struct AppSummary {
    pub id: String,
    /// Human display name, best-effort (iOS only); `None` when unavailable.
    pub name: Option<String>,
    pub container_count: usize,
    pub total_size: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn container(id: &str, kind: ContainerKind, prefix: &str, guid: Option<&str>) -> AppContainer {
        AppContainer {
            id: id.to_string(),
            kind,
            prefix: prefix.to_string(),
            guid: guid.map(str::to_string),
            file_count: 0,
            total_size: 0,
            group_link: None,
        }
    }

    #[test]
    fn export_label_layouts() {
        let appdata = container(
            "com.x.App",
            ContainerKind::AppData,
            "/p/Data/Application/5A92C2C1-DEAD",
            Some("5A92C2C1"),
        );
        assert_eq!(
            appdata.export_label("com.x.App", Platform::IosFfs),
            "com.x.App/AppData_5A92C2C1"
        );

        // A group is labelled by its OWN id, not the requesting app's.
        let group = container(
            "group.com.x",
            ContainerKind::AppGroup,
            "/p/Shared/AppGroup/7E82ADBC",
            Some("7E82ADBC"),
        );
        assert_eq!(
            group.export_label("com.x.App", Platform::IosFfs),
            "group.com.x/AppGroup_7E82ADBC"
        );

        let android = container(
            "com.whatsapp",
            ContainerKind::AndroidExternal,
            "/sdcard/Android/data/com.whatsapp",
            None,
        );
        assert_eq!(
            android.export_label("com.whatsapp", Platform::Android),
            "com.whatsapp/external_data"
        );

        // A backup uses one subfolder per domain.
        let backup = container(
            "com.x.App",
            ContainerKind::AppData,
            "AppDomain-com.x.App",
            None,
        );
        assert_eq!(
            backup.export_label("com.x.App", Platform::IosBackup),
            "AppDomain-com.x.App"
        );
    }
}
