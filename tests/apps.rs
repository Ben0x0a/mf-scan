//! Integration tests for the iOS-FFS app catalogue.
//!
//! Defines: tests that build a minimal FFS-like folder under a tempdir — real
//! binary container-metadata plists plus the committed MobileContainerManager
//! `references.sqlite3` fixture — and assert the two attribution rules end to end:
//! App Groups come from MCM's recorded entitlements (falling back to the
//! vendor-token heuristic only when MCM says nothing), and an extension container
//! belongs to the app its metadata declares, not the one its name resembles.
//!
//! Used by: `cargo test`.
//! Uses: `mf_scan::ops::apps` (the catalogue under test),
//! `mf_scan::core::source::folder`, `plist` (to write real binary plists),
//! `tempfile`.

use std::fs;
use std::path::Path;

use mf_scan::core::source::folder::FolderSource;
use mf_scan::ops::apps::{AppCatalog, ContainerKind, GroupLink, Platform};
use tempfile::TempDir;

/// The canonical metadata filename used by iOS's container manager.
const METADATA_FILENAME: &str = ".com.apple.mobile_container_manager.metadata.plist";

/// The committed synthetic MCM database (see `tests/fixtures/README.md`). Its
/// `com.example.full` record declares two App Groups, one of which shares no name
/// token with the app — the case a heuristic provably cannot reach.
const MCM_FIXTURE: &str = "tests/fixtures/mcm_references.sqlite3";

const CROSS_BRAND_GROUP: &str = "group.com.othervendor.crossbrand";
const VENDOR_GROUP: &str = "group.com.example.shared";

/// Write a container's metadata plist: the identifier, and optionally the
/// authoritative parent-app link that only extension containers carry.
fn write_metadata(dir: &Path, identifier: &str, parent: Option<&str>) {
    fs::create_dir_all(dir).unwrap();
    let mut dict = plist::Dictionary::new();
    dict.insert(
        "MCMMetadataIdentifier".into(),
        plist::Value::String(identifier.into()),
    );
    let mut info = plist::Dictionary::new();
    if let Some(parent) = parent {
        info.insert(
            "com.apple.MobileInstallation.ParentBundleID".into(),
            plist::Value::String(parent.into()),
        );
    }
    dict.insert("MCMMetadataInfo".into(), plist::Value::Dictionary(info));
    plist::Value::Dictionary(dict)
        .to_file_binary(dir.join(METADATA_FILENAME))
        .unwrap();
    // A container is only tallied if it holds a file.
    fs::write(dir.join("data.bin"), b"payload").unwrap();
}

/// Build an FFS-shaped tree: one app, one extension whose declared parent is a
/// DIFFERENT app that merely shares its name prefix, and the two App Group
/// containers the fixture's entitlements name.
///
/// The `filesystem1/` root prefix mirrors a real vendor's extraction layout and
/// proves the MCM database is located by path suffix, not absolute path.
fn build_ffs(with_mcm_db: bool) -> TempDir {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("filesystem1/private/var");
    let data = root.join("mobile/Containers/Data");
    let shared = root.join("mobile/Containers/Shared/AppGroup");

    write_metadata(
        &data.join("Application/AAAA1111-0000"),
        "com.example.full",
        None,
    );
    // A separate installed app whose id extends the first app's.
    write_metadata(
        &data.join("Application/BBBB2222-0000"),
        "com.example.full.Sub",
        None,
    );
    // ...and ITS extension. The name-prefix rule alone would hand this to
    // `com.example.full`; the declared parent says otherwise.
    write_metadata(
        &data.join("PluginKitPlugin/CCCC3333-0000"),
        "com.example.full.Sub.Widget",
        Some("com.example.full.Sub"),
    );
    write_metadata(&shared.join("DDDD4444-0000"), VENDOR_GROUP, None);
    write_metadata(&shared.join("EEEE5555-0000"), CROSS_BRAND_GROUP, None);

    if with_mcm_db {
        let mcm = root.join("mobile/Library/MobileContainerManager");
        fs::create_dir_all(&mcm).unwrap();
        fs::copy(MCM_FIXTURE, mcm.join("references.sqlite3")).unwrap();
    }
    tmp
}

/// Group ids attributed to `id`, each with the tag recording how it was attributed.
fn groups_for(tmp: &TempDir, id: &str) -> Vec<(String, &'static str)> {
    let source = FolderSource::open(tmp.path(), 0).unwrap();
    let catalog = AppCatalog::build(&source);
    assert_eq!(
        catalog.platform,
        Platform::IosFfs,
        "layout must be read as FFS"
    );
    let mut out: Vec<(String, &'static str)> = catalog
        .containers_for(id, true)
        .into_iter()
        .filter(|c| c.kind == ContainerKind::AppGroup)
        .map(|c| (c.id, c.group_link.map(GroupLink::as_str).unwrap_or("none")))
        .collect();
    out.sort();
    out
}

/// With the MCM database present, both declared groups are attributed and tagged
/// as coming from it — including the cross-brand group whose name shares no token
/// with the app, which is precisely what the heuristic cannot find.
#[test]
fn app_groups_come_from_container_manager_when_available() {
    let tmp = build_ffs(true);
    assert_eq!(
        groups_for(&tmp, "com.example.full"),
        vec![
            (VENDOR_GROUP.to_string(), "ContainerManager"),
            (CROSS_BRAND_GROUP.to_string(), "ContainerManager"),
        ]
    );
}

/// Without it — the situation on every iOS backup — the vendor-token heuristic
/// still runs and is still labelled as such, but it reaches only the same-vendor
/// group. This locks in BOTH that the fallback survives and what it costs.
#[test]
fn without_the_database_the_vendor_heuristic_still_runs() {
    let tmp = build_ffs(false);
    assert_eq!(
        groups_for(&tmp, "com.example.full"),
        vec![(VENDOR_GROUP.to_string(), "VendorHeuristic")]
    );
}

/// An app whose MCM record declares no App Groups gets none: a recorded empty
/// entitlement list is an answer, so the heuristic must not overrule it.
#[test]
fn recorded_absence_of_groups_is_authoritative() {
    let tmp = build_ffs(true);
    assert!(groups_for(&tmp, "com.example.nogroups").is_empty());
}

/// An extension belongs to the app its metadata declares. `com.example.full` must
/// not collect `com.example.full.Sub.Widget` merely because the name nests.
#[test]
fn extensions_follow_the_declared_parent_not_the_name_prefix() {
    let tmp = build_ffs(true);
    let source = FolderSource::open(tmp.path(), 0).unwrap();
    let catalog = AppCatalog::build(&source);

    let extensions = |id: &str| -> Vec<String> {
        catalog
            .containers_for(id, false)
            .into_iter()
            .filter(|c| c.kind == ContainerKind::Extension)
            .map(|c| c.id)
            .collect()
    };
    assert!(extensions("com.example.full").is_empty());
    assert_eq!(
        extensions("com.example.full.Sub"),
        vec!["com.example.full.Sub.Widget".to_string()]
    );
}

/// A source with no MCM database reports no write-ahead-log replay, and one whose
/// database has no sidecar likewise — the flag must mean what it says.
#[test]
fn wal_replay_is_reported_only_when_it_happens() {
    for with_db in [false, true] {
        let tmp = build_ffs(with_db);
        let source = FolderSource::open(tmp.path(), 0).unwrap();
        assert!(!AppCatalog::build(&source).mcm_wal_replayed());
    }
}
