//! iOS backup domain grammar and its filesystem mount points.
//!
//! Defines: [`BackupDomain`] (the grammar of a `Manifest.db` `domain` value),
//! [`parse`], [`MappedPath`] and the container-root path constants shared with
//! the full-filesystem classifier.
//! Used by: `crate::ops::apps::ios_backup` (domain → container kind),
//! `crate::ops::apps::catalog` (is a domain app-scoped?), `crate::ops::apps::ios_ffs`
//! (the container-root fragments), and the backup rebuild operation (domain →
//! filesystem path).
//! Uses: nothing — this is a leaf of pure artefact knowledge.
//!
//! WHY this lives in `platform/ios` rather than in an operation: a domain's
//! meaning and the directory iOS mounts it at are facts about the artefact, not
//! about any one thing we do with it. Keeping the grammar here gives the
//! container classifier, the app catalogue and the rebuild one definition to
//! agree on; three copies of the same prefix list is how they drift.
//!
//! WHY the paths are relative (no leading `/`): every consumer writes inside a
//! destination directory chosen by the operator. An absolute path handed to
//! `Path::join` silently discards the destination, so the leading separator is
//! omitted at the source rather than stripped later.

/// Path fragments that identify a container's kind inside a full-filesystem
/// acquisition. Shared with [`crate::ops::apps::ios_ffs`] so the paths a rebuild
/// writes and the paths the classifier recognises cannot drift apart.
pub const FRAGMENT_PLUGINKIT: &str = "/PluginKitPlugin/";
pub const FRAGMENT_APPGROUP: &str = "/AppGroup/";
pub const FRAGMENT_BUNDLE_APPLICATION: &str = "/Bundle/Application/";

/// Mount points for app-scoped containers, as iOS lays them out on a device.
const ROOT_DATA_APPLICATION: &str = "private/var/mobile/Containers/Data/Application";
const ROOT_DATA_PLUGINKIT: &str = "private/var/mobile/Containers/Data/PluginKitPlugin";
const ROOT_SHARED_APPGROUP: &str = "private/var/mobile/Containers/Shared/AppGroup";
const ROOT_SHARED_SYSTEMGROUP: &str = "private/var/containers/Shared/SystemGroup";
const ROOT_DATA_SYSTEM: &str = "private/var/containers/Data/System";

/// A domain whose mount point is fixed — it carries no identifier.
///
/// The `Manifest.db` spelling and the device path are kept adjacent on purpose:
/// adding a domain is one row here, and the compiler will not let a variant be
/// added without giving it both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixedDomain {
    CameraRoll,
    Database,
    Health,
    Home,
    HomeKit,
    Install,
    Keyboard,
    Keychain,
    ManagedPreferences,
    Media,
    MobileDevice,
    Root,
    SystemPreferences,
    Wireless,
}

impl FixedDomain {
    /// Every fixed domain, paired with its `Manifest.db` spelling and mount point.
    const TABLE: &'static [(&'static str, FixedDomain, &'static str)] = &[
        (
            "CameraRollDomain",
            FixedDomain::CameraRoll,
            "private/var/mobile/Media",
        ),
        ("DatabaseDomain", FixedDomain::Database, "private/var/db"),
        (
            "HealthDomain",
            FixedDomain::Health,
            "private/var/mobile/Library",
        ),
        ("HomeDomain", FixedDomain::Home, "private/var/mobile"),
        ("HomeKitDomain", FixedDomain::HomeKit, "private/var/mobile"),
        (
            "InstallDomain",
            FixedDomain::Install,
            "private/var/installd",
        ),
        (
            "KeyboardDomain",
            FixedDomain::Keyboard,
            "private/var/mobile",
        ),
        (
            "KeychainDomain",
            FixedDomain::Keychain,
            "private/var/Keychains",
        ),
        (
            "ManagedPreferencesDomain",
            FixedDomain::ManagedPreferences,
            "private/var/Managed Preferences",
        ),
        (
            "MediaDomain",
            FixedDomain::Media,
            "private/var/mobile/Media",
        ),
        (
            "MobileDeviceDomain",
            FixedDomain::MobileDevice,
            "private/var/MobileDevice",
        ),
        ("RootDomain", FixedDomain::Root, "private/var/root"),
        (
            "SystemPreferencesDomain",
            FixedDomain::SystemPreferences,
            "private/var/preferences",
        ),
        (
            "WirelessDomain",
            FixedDomain::Wireless,
            "private/var/wireless",
        ),
    ];

    /// The `Manifest.db` spelling of this domain.
    pub fn as_str(&self) -> &'static str {
        Self::TABLE
            .iter()
            .find(|(_, d, _)| d == self)
            .map(|(name, _, _)| *name)
            .expect("every FixedDomain variant has a TABLE row")
    }

    /// The directory iOS mounts this domain at, relative to the filesystem root.
    pub fn path(&self) -> &'static str {
        Self::TABLE
            .iter()
            .find(|(_, d, _)| d == self)
            .map(|(_, _, path)| *path)
            .expect("every FixedDomain variant has a TABLE row")
    }
}

/// A parsed `Manifest.db` domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackupDomain {
    /// A domain with a fixed mount point, e.g. `HomeDomain`.
    Fixed(FixedDomain),
    /// `AppDomain-<bundle id>` — an app's own data container.
    App(String),
    /// `AppDomainPlugin-<bundle id>` — an extension or widget container.
    Plugin(String),
    /// `AppDomainGroup-<group id>` — a shared App Group container.
    AppGroup(String),
    /// `SysSharedContainerDomain-<group id>` — a shared system-group container.
    SystemGroup(String),
    /// `SysContainerDomain-<id>` — a system data container.
    SystemContainer(String),
}

/// Where a domain lands in a rebuilt tree, and whether getting there required
/// inventing a path component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappedPath {
    /// The mount point, relative to the output root (never absolute).
    pub path: String,
    /// True when a component of `path` is **not** in the evidence.
    ///
    /// A backup records no container GUIDs, so an app container's real
    /// `…/Application/5A92C2C1-…` path cannot be reconstructed; the bundle
    /// identifier is substituted instead. That is useful but it is not ground
    /// truth, and a forensic tool must not present it as though it were, so every
    /// such path is reported.
    pub synthetic: bool,
}

/// Parse a `Manifest.db` domain, or `None` if it is not recognised.
///
/// WHY the prefix order matters: `AppDomainPlugin-` and `AppDomainGroup-` both
/// begin with `AppDomain`, so the more specific prefixes must be tested first or
/// an extension would be mis-read as the app itself.
pub fn parse(domain: &str) -> Option<BackupDomain> {
    if let Some(id) = domain.strip_prefix("AppDomainPlugin-") {
        return Some(BackupDomain::Plugin(id.to_string()));
    }
    if let Some(id) = domain.strip_prefix("AppDomainGroup-") {
        return Some(BackupDomain::AppGroup(id.to_string()));
    }
    if let Some(id) = domain.strip_prefix("SysSharedContainerDomain-") {
        return Some(BackupDomain::SystemGroup(id.to_string()));
    }
    if let Some(id) = domain.strip_prefix("SysContainerDomain-") {
        return Some(BackupDomain::SystemContainer(id.to_string()));
    }
    if let Some(id) = domain.strip_prefix("AppDomain-") {
        return Some(BackupDomain::App(id.to_string()));
    }
    FixedDomain::TABLE
        .iter()
        .find(|(name, _, _)| *name == domain)
        .map(|(_, fixed, _)| BackupDomain::Fixed(*fixed))
}

impl BackupDomain {
    /// The identifier this domain carries, if any.
    pub fn identifier(&self) -> Option<&str> {
        match self {
            BackupDomain::Fixed(_) => None,
            BackupDomain::App(id)
            | BackupDomain::Plugin(id)
            | BackupDomain::AppGroup(id)
            | BackupDomain::SystemGroup(id)
            | BackupDomain::SystemContainer(id) => Some(id),
        }
    }

    /// Whether this domain belongs to an installed app, extension or shared group.
    ///
    /// This is the set the app catalogue treats as attributable to an app.
    /// `SysContainerDomain-` is deliberately excluded: it is a system data
    /// container, not app-scoped, and including it would change which sources
    /// `ops::apps::catalog::detect` recognises as backups.
    pub fn is_app_scoped(&self) -> bool {
        matches!(
            self,
            BackupDomain::App(_)
                | BackupDomain::Plugin(_)
                | BackupDomain::AppGroup(_)
                | BackupDomain::SystemGroup(_)
        )
    }

    /// The directory this domain is mounted at in a rebuilt tree.
    ///
    /// Container domains have no GUID recorded in the backup, so the identifier
    /// is substituted and the result is flagged `synthetic`. A system group is
    /// **not** synthetic: iOS names those directories by the group identifier,
    /// which the backup does record.
    pub fn filesystem_path(&self) -> MappedPath {
        match self {
            BackupDomain::Fixed(fixed) => MappedPath {
                path: fixed.path().to_string(),
                synthetic: false,
            },
            BackupDomain::App(id) => synthetic(ROOT_DATA_APPLICATION, id),
            BackupDomain::Plugin(id) => synthetic(ROOT_DATA_PLUGINKIT, id),
            BackupDomain::AppGroup(id) => synthetic(ROOT_SHARED_APPGROUP, id),
            BackupDomain::SystemContainer(id) => synthetic(ROOT_DATA_SYSTEM, id),
            BackupDomain::SystemGroup(id) => MappedPath {
                path: format!("{ROOT_SHARED_SYSTEMGROUP}/{id}"),
                synthetic: false,
            },
        }
    }
}

/// A container path whose GUID component was replaced by an identifier.
fn synthetic(root: &str, id: &str) -> MappedPath {
    MappedPath {
        path: format!("{root}/{id}"),
        synthetic: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_each_parameterised_prefix() {
        assert_eq!(
            parse("AppDomain-com.burbn.instagram"),
            Some(BackupDomain::App("com.burbn.instagram".into()))
        );
        assert_eq!(
            parse("AppDomainPlugin-com.burbn.instagram.Share"),
            Some(BackupDomain::Plugin("com.burbn.instagram.Share".into()))
        );
        assert_eq!(
            parse("AppDomainGroup-group.com.burbn"),
            Some(BackupDomain::AppGroup("group.com.burbn".into()))
        );
        assert_eq!(
            parse("SysSharedContainerDomain-systemgroup.com.apple.x"),
            Some(BackupDomain::SystemGroup("systemgroup.com.apple.x".into()))
        );
        assert_eq!(
            parse("SysContainerDomain-com.apple.y"),
            Some(BackupDomain::SystemContainer("com.apple.y".into()))
        );
    }

    /// `AppDomainPlugin-`/`AppDomainGroup-` start with `AppDomain`, so a
    /// mis-ordered parser would read an extension as the app.
    #[test]
    fn specific_prefixes_win_over_appdomain() {
        assert_eq!(
            parse("AppDomainPlugin-com.x.ext").unwrap().identifier(),
            Some("com.x.ext")
        );
        assert!(matches!(
            parse("AppDomainPlugin-com.x.ext"),
            Some(BackupDomain::Plugin(_))
        ));
        assert!(matches!(
            parse("AppDomainGroup-group.x"),
            Some(BackupDomain::AppGroup(_))
        ));
    }

    #[test]
    fn parses_fixed_domains_and_rejects_unknown() {
        assert_eq!(
            parse("HomeDomain"),
            Some(BackupDomain::Fixed(FixedDomain::Home))
        );
        assert_eq!(
            parse("KeychainDomain"),
            Some(BackupDomain::Fixed(FixedDomain::Keychain))
        );
        assert_eq!(parse("NotARealDomain"), None);
        assert_eq!(parse(""), None);
    }

    /// The app catalogue's notion of "app-scoped" must stay exactly the four
    /// prefixes it recognised before this grammar existed.
    #[test]
    fn app_scoped_set_is_the_four_app_prefixes() {
        for domain in [
            "AppDomain-com.x",
            "AppDomainPlugin-com.x.ext",
            "AppDomainGroup-group.x",
            "SysSharedContainerDomain-systemgroup.x",
        ] {
            assert!(
                parse(domain).unwrap().is_app_scoped(),
                "{domain} must be app-scoped"
            );
        }
        assert!(
            !parse("SysContainerDomain-com.apple.y")
                .unwrap()
                .is_app_scoped()
        );
        assert!(!parse("HomeDomain").unwrap().is_app_scoped());
    }

    #[test]
    fn fixed_domain_table_is_complete_and_consistent() {
        for (name, fixed, path) in FixedDomain::TABLE {
            assert_eq!(fixed.as_str(), *name);
            assert_eq!(fixed.path(), *path);
            assert!(!path.starts_with('/'), "{name} path must be relative");
        }
    }

    #[test]
    fn container_domains_are_marked_synthetic() {
        let app = parse("AppDomain-com.x").unwrap().filesystem_path();
        assert_eq!(
            app.path,
            "private/var/mobile/Containers/Data/Application/com.x"
        );
        assert!(app.synthetic, "a backup records no container GUID");

        // A system group directory IS named by its identifier on the device, so
        // nothing is invented here.
        let group = parse("SysSharedContainerDomain-systemgroup.x")
            .unwrap()
            .filesystem_path();
        assert_eq!(
            group.path,
            "private/var/containers/Shared/SystemGroup/systemgroup.x"
        );
        assert!(!group.synthetic);

        let home = parse("HomeDomain").unwrap().filesystem_path();
        assert_eq!(home.path, "private/var/mobile");
        assert!(!home.synthetic);
    }

    /// The fragments the FFS classifier matches on must actually occur in the
    /// paths a rebuild produces, or a rebuilt tree would not classify.
    #[test]
    fn rebuild_paths_contain_the_fragments_the_ffs_classifier_matches() {
        let plugin = parse("AppDomainPlugin-com.x.ext")
            .unwrap()
            .filesystem_path()
            .path;
        assert!(plugin.contains(FRAGMENT_PLUGINKIT.trim_end_matches('/')));

        let group = parse("AppDomainGroup-group.x")
            .unwrap()
            .filesystem_path()
            .path;
        assert!(group.contains(FRAGMENT_APPGROUP.trim_end_matches('/')));

        // A rebuild never writes an installed .app bundle: a backup contains no
        // executables, so nothing should land under the Bundle root.
        for domain in ["AppDomain-com.x", "AppDomainPlugin-com.x.e", "HomeDomain"] {
            let mapped = parse(domain).unwrap().filesystem_path().path;
            assert!(!mapped.contains(FRAGMENT_BUNDLE_APPLICATION.trim_matches('/')));
        }
    }

    #[test]
    fn no_mapped_path_is_absolute() {
        for domain in [
            "HomeDomain",
            "AppDomain-com.x",
            "AppDomainPlugin-com.x.e",
            "AppDomainGroup-group.x",
            "SysSharedContainerDomain-systemgroup.x",
            "SysContainerDomain-com.apple.y",
        ] {
            let mapped = parse(domain).unwrap().filesystem_path();
            assert!(
                !mapped.path.starts_with('/') && !mapped.path.starts_with('\\'),
                "{domain} mapped to an absolute path, which Path::join would treat as the root"
            );
        }
    }
}
