//! Integration tests for iOS app-container annotation.
//!
//! Defines: tests that build a minimal FFS-like folder under a tempdir (with a
//! dummy root prefix to prove root-prefix robustness), run a search, and assert
//! that `MatchRecord::bundle_id` is set to the correct bundle ID for hits inside
//! a container and `None` for hits outside any container.
//!
//! Also tests: longest-prefix resolution (nested containers), and that an
//! unreadable/unparseable metadata plist degrades without error.
//!
//! Used by: `cargo test`.
//! Uses: `mf_scan::{engine, filter, ios::containers, models, source::folder}`,
//! `plist` (to write real binary plists), `tempfile`.

use std::fs;

use mf_scan::engine::{NoProgress, Query, search_source};
use mf_scan::filter::EntryFilter;
use mf_scan::ios::containers::AppContainerMap;
use mf_scan::source::Source;
use mf_scan::source::folder::FolderSource;
use regex::bytes::Regex;
use tempfile::tempdir;

/// Write a binary plist file containing `{ MCMMetadataIdentifier = bundle_id }`.
///
/// WHY use the `plist` crate here: it is the same crate used by the production
/// code to *read* the plists, so this test exercises the full round-trip without
/// any hand-crafted binary format.
fn write_metadata_plist(path: &std::path::Path, bundle_id: &str) {
    let mut dict = plist::Dictionary::new();
    dict.insert(
        "MCMMetadataIdentifier".to_string(),
        plist::Value::String(bundle_id.to_string()),
    );
    let value = plist::Value::Dictionary(dict);
    // Write as binary plist (bplist00) — the format iOS actually uses.
    value
        .to_file_binary(path)
        .expect("failed to write metadata plist");
}

/// The canonical metadata filename used by iOS's container manager.
const METADATA_FILENAME: &str = ".com.apple.mobile_container_manager.metadata.plist";

// ─── Tests ───────────────────────────────────────────────────────────────────

/// A hit inside an iOS container must carry the bundle ID; a hit outside must not.
///
/// The FFS hierarchy uses a dummy root prefix (`filesystem1/`) to verify that
/// prefix matching is root-agnostic.
#[test]
fn container_hit_gets_bundle_id_outside_does_not() {
    let dir = tempdir().unwrap();

    // Build: filesystem1/private/var/containers/Bundle/Application/<GUID>/
    let guid = "AAAA-0000-0000-0000-000000000001";
    let container = dir
        .path()
        .join("filesystem1/private/var/containers/Bundle/Application")
        .join(guid);
    fs::create_dir_all(&container).unwrap();

    // Metadata plist.
    write_metadata_plist(&container.join(METADATA_FILENAME), "com.example.app");

    // A file inside the container.
    let docs = container.join("Documents");
    fs::create_dir_all(&docs).unwrap();
    fs::write(docs.join("notes.txt"), b"NEEDLE inside container").unwrap();

    // A file outside any container.
    let outside = dir.path().join("filesystem1/private/var/mobile");
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("other.txt"), b"NEEDLE outside container").unwrap();

    let src = FolderSource::open(dir.path(), 0).unwrap();
    let re = Regex::new("NEEDLE").unwrap();
    let findings = search_source(
        &src,
        &Query::plain(&re),
        false,
        false,
        &EntryFilter::all(),
        None,
        &NoProgress,
    )
    .unwrap();

    assert_eq!(findings.records.len(), 2, "expected two hits");

    // Annotate using the map directly (simulates what run::grep does).
    let map = AppContainerMap::build(&src);
    assert!(!map.is_empty(), "container map must not be empty");

    let mut records = findings.records;
    for r in &mut records {
        r.bundle_id = map.resolve(&r.path).map(str::to_string);
    }

    // The hit inside the container must carry the bundle ID.
    let inside = records
        .iter()
        .find(|r| r.path.contains("notes.txt"))
        .expect("notes.txt hit not found");
    assert_eq!(
        inside.bundle_id.as_deref(),
        Some("com.example.app"),
        "inside-container hit must carry bundle_id"
    );

    // The hit outside any container must not carry a bundle ID.
    let out = records
        .iter()
        .find(|r| r.path.contains("other.txt"))
        .expect("other.txt hit not found");
    assert_eq!(
        out.bundle_id, None,
        "outside-container hit must not carry bundle_id"
    );
}

/// Longest-prefix resolution: a match inside a nested container must resolve to
/// the most-specific (innermost) container, not a parent path that also happens
/// to be a container directory.
///
/// Layout:
///   outer-container/ (bundle: com.example.outer)
///     inner-container/ (bundle: com.example.inner)
///       file.txt  ← must resolve to com.example.inner
#[test]
fn longest_prefix_wins_for_nested_containers() {
    let dir = tempdir().unwrap();

    // Outer container.
    let outer = dir
        .path()
        .join("fs/var/containers/Bundle/Application/OUTER-GUID");
    fs::create_dir_all(&outer).unwrap();
    write_metadata_plist(&outer.join(METADATA_FILENAME), "com.example.outer");

    // Inner container nested inside the outer container's directory tree.
    // (Unusual on real iOS, but the longest-prefix rule must handle it correctly.)
    let inner = outer.join("NestedContainers/INNER-GUID");
    fs::create_dir_all(&inner).unwrap();
    write_metadata_plist(&inner.join(METADATA_FILENAME), "com.example.inner");

    // Target file inside the inner container.
    fs::write(inner.join("data.txt"), b"NEEDLE").unwrap();

    let src = FolderSource::open(dir.path(), 0).unwrap();
    let map = AppContainerMap::build(&src);

    // Identify the path as the source sees it.
    let entry = src
        .entries()
        .iter()
        .find(|e| e.name.ends_with("data.txt"))
        .expect("data.txt entry not found");

    let resolved = map.resolve(&entry.name);
    assert_eq!(
        resolved,
        Some("com.example.inner"),
        "innermost container must win"
    );
}

/// A metadata plist with invalid/unparseable content is silently skipped; the
/// source still scans without error, and other valid containers still resolve.
#[test]
fn invalid_metadata_plist_degrades_without_error() {
    let dir = tempdir().unwrap();

    // Valid container.
    let good_guid = "BBBB-0000-0000-0000-000000000001";
    let good = dir
        .path()
        .join("fs/var/containers/Bundle/Application")
        .join(good_guid);
    fs::create_dir_all(&good).unwrap();
    write_metadata_plist(&good.join(METADATA_FILENAME), "com.example.good");
    fs::write(good.join("file.txt"), b"NEEDLE good").unwrap();

    // Container with a corrupt metadata plist.
    let bad_guid = "CCCC-0000-0000-0000-000000000002";
    let bad = dir
        .path()
        .join("fs/var/containers/Bundle/Application")
        .join(bad_guid);
    fs::create_dir_all(&bad).unwrap();
    // Write garbage bytes — not a valid plist.
    fs::write(bad.join(METADATA_FILENAME), b"\xFF\xFE garbage data").unwrap();
    fs::write(bad.join("file.txt"), b"NEEDLE bad").unwrap();

    // Build must not panic; the bad container is simply absent from the map.
    let src = FolderSource::open(dir.path(), 0).unwrap();
    let map = AppContainerMap::build(&src);

    // The good container still resolves.
    let good_entry = src
        .entries()
        .iter()
        .find(|e| e.name.contains(good_guid) && e.name.ends_with("file.txt"))
        .expect("good file.txt entry not found");
    assert_eq!(
        map.resolve(&good_entry.name),
        Some("com.example.good"),
        "valid container must still resolve after skipping the bad one"
    );

    // The bad container simply has no bundle ID — no panic, no error.
    let bad_entry = src
        .entries()
        .iter()
        .find(|e| e.name.contains(bad_guid) && e.name.ends_with("file.txt"))
        .expect("bad file.txt entry not found");
    assert_eq!(
        map.resolve(&bad_entry.name),
        None,
        "container with unparseable metadata must resolve to None"
    );
}

/// Verify that the segment-boundary check prevents a container directory named
/// `Apple` from matching a file under `AppleX/`.
#[test]
fn segment_boundary_prevents_false_prefix_match() {
    let dir = tempdir().unwrap();

    // Container named `Apple`.
    let apple = dir
        .path()
        .join("fs/var/containers/Bundle/Application/Apple");
    fs::create_dir_all(&apple).unwrap();
    write_metadata_plist(&apple.join(METADATA_FILENAME), "com.example.apple");

    // A different container whose name merely starts with `Apple`.
    let applex = dir
        .path()
        .join("fs/var/containers/Bundle/Application/AppleX");
    fs::create_dir_all(&applex).unwrap();
    fs::write(applex.join("data.txt"), b"unrelated").unwrap();

    let src = FolderSource::open(dir.path(), 0).unwrap();
    let map = AppContainerMap::build(&src);

    // The file under AppleX/ must NOT resolve to com.example.apple.
    let entry = src
        .entries()
        .iter()
        .find(|e| e.name.contains("AppleX") && e.name.ends_with("data.txt"))
        .expect("AppleX/data.txt entry not found");

    assert_eq!(
        map.resolve(&entry.name),
        None,
        "AppleX/data.txt must not match the Apple container"
    );
}
