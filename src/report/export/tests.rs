//! Tests for the export plan, writer, records and manifest.

use std::collections::HashSet;
use std::path::Path;

use super::plan::decrypted_name_numbered;
use super::write::{PathCheck, check_export_path, safe_join};
use crate::core::layout::tree_dir;
#[test]
fn decrypted_names_keep_a_usable_extension() {
    assert_eq!(decrypted_name("signal.sqlite"), "signal.decrypted.sqlite");
    assert_eq!(
        decrypted_name("NetworkDiagnostic"),
        "NetworkDiagnostic.decrypted"
    );
    assert_eq!(
        decrypted_name("msgstore.db.crypt14"),
        "msgstore.decrypted.db"
    );
    assert_eq!(decrypted_name("wa.db.crypt12"), "wa.decrypted.db");
    assert_eq!(decrypted_name(".crypt14"), ".crypt14.decrypted");
    assert_eq!(decrypted_name_numbered("x.db", 2), "x.decrypted-2.db");
}

use super::*;
use crate::core::models::{Entry, Location};
use crate::ops::search::MatchedFile;
use std::path::PathBuf;

/// A loose-file [`MatchedFile`] at `name` of `size` bytes, for the planner tests.
fn loose(name: &str, size: u64) -> MatchedFile {
    MatchedFile {
        entry: Entry {
            name: name.to_string(),
            uncompressed_size: size,
            mtime: None,
            location: Location::Loose { path: name.into() },
        },
        offsets: Vec::new(),
    }
}

/// An absolute label must not escape the destination. `Path::join` discards
/// its base for an absolute argument, so a label of `/private/var/mobile`
/// would previously have written to the real filesystem root.
#[test]
fn plan_tree_label_cannot_escape_the_destination() {
    let files = vec![MatchedFile {
        entry: Entry {
            name: "HomeDomain/Library/SMS/sms.db".into(),
            uncompressed_size: 4,
            mtime: None,
            location: Location::Loose {
                path: std::path::PathBuf::from("x"),
            },
        },
        offsets: Vec::new(),
    }];

    for label in [
        "/private/var/mobile",
        "//private/var/mobile",
        "../../private/var/mobile",
        "private/../../../var/mobile",
        r"\\private\\var\\mobile",
    ] {
        let roots = vec![("HomeDomain".to_string(), label.to_string())];
        let plan = plan_tree(&files, &roots);
        let folder = &plan.items[0].folder;
        assert!(
            !folder.starts_with('/') && !folder.starts_with('\\'),
            "label {label:?} produced an absolute folder {folder:?}"
        );
        assert!(
            !folder.split('/').any(|seg| seg == ".."),
            "label {label:?} kept a parent-directory escape: {folder:?}"
        );
        // The joined destination must stay inside the export directory.
        let dest = std::path::Path::new("/tmp/export").join(folder);
        assert!(
            dest.starts_with("/tmp/export"),
            "label {label:?} escaped to {dest:?}"
        );
    }
}

/// Regression: two files whose paths differ ONLY in case must both survive.
///
/// A real iPhone backup holds `com.apple.Preferences.plist` and
/// `com.apple.preferences.plist` as distinct files with distinct `fileID`s. On
/// a case-insensitive file system the second overwrote the first, so a rebuild
/// reported 815 files exported while writing 813 to disk — silent evidence
/// loss, with a report that said otherwise.
#[test]
fn plan_tree_does_not_let_case_colliding_files_overwrite_each_other() {
    let names = [
        "HomeDomain/Library/Preferences/com.apple.Preferences.plist",
        "HomeDomain/Library/Preferences/com.apple.preferences.plist",
        "HomeDomain/Library/Preferences/com.apple.SpringBoard.plist",
        "HomeDomain/Library/Preferences/com.apple.springboard.plist",
    ];
    let files: Vec<MatchedFile> = names
        .iter()
        .map(|n| MatchedFile {
            entry: Entry {
                name: (*n).to_string(),
                uncompressed_size: 1,
                mtime: None,
                location: Location::Loose {
                    path: std::path::PathBuf::from(n),
                },
            },
            offsets: Vec::new(),
        })
        .collect();
    let roots = vec![("HomeDomain".to_string(), "private/var/mobile".to_string())];
    let plan = plan_tree(&files, &roots);

    assert_eq!(plan.items.len(), 4, "every file must still be planned");
    let destinations: HashSet<String> = plan
        .items
        .iter()
        .map(|i| i.output_path().to_ascii_lowercase())
        .collect();
    assert_eq!(
        destinations.len(),
        4,
        "each file needs a destination no other file claims, case-insensitively: {:?}",
        plan.items
            .iter()
            .map(|i| i.output_path())
            .collect::<Vec<_>>()
    );
    assert_eq!(plan.renamed.len(), 2, "the two collisions must be reported");
    // The first claimant keeps the plain name; the suffix matches the Python tool.
    assert!(
        plan.renamed.iter().all(|r| r.used.ends_with("~1")),
        "{:?}",
        plan.renamed
    );
}

/// The flat layout must hold the same invariant.
#[test]
fn plan_does_not_let_two_files_share_a_destination() {
    let files: Vec<MatchedFile> = ["a/X.db", "a/x.db"]
        .iter()
        .map(|n| MatchedFile {
            entry: Entry {
                name: (*n).to_string(),
                uncompressed_size: 1,
                mtime: None,
                location: Location::Loose {
                    path: std::path::PathBuf::from(n),
                },
            },
            offsets: Vec::new(),
        })
        .collect();
    let plan = plan(&files);
    let destinations: HashSet<String> = plan
        .items
        .iter()
        .map(|i| i.output_path().to_ascii_lowercase())
        .collect();
    assert_eq!(destinations.len(), 2);
}

/// Without a collision nothing is renamed, so ordinary exports are unchanged.
#[test]
fn distinct_paths_are_never_renamed() {
    let files: Vec<MatchedFile> = ["HomeDomain/a.db", "HomeDomain/b.db"]
        .iter()
        .map(|n| MatchedFile {
            entry: Entry {
                name: (*n).to_string(),
                uncompressed_size: 1,
                mtime: None,
                location: Location::Loose {
                    path: std::path::PathBuf::from(n),
                },
            },
            offsets: Vec::new(),
        })
        .collect();
    let roots = vec![("HomeDomain".to_string(), "private/var/mobile".to_string())];
    let plan = plan_tree(&files, &roots);
    assert!(plan.renamed.is_empty());
    assert_eq!(plan.items[0].name, "a.db");
    assert_eq!(plan.items[1].name, "b.db");
}

/// A file and the directory containing it must land in the same place, or a
/// rebuilt tree would create the directory somewhere other than its contents.
#[test]
fn tree_dir_agrees_with_plan_tree() {
    let roots = vec![("HomeDomain".to_string(), "private/var/mobile".to_string())];
    let files = vec![MatchedFile {
        entry: Entry {
            name: "HomeDomain/Library/SMS/sms.db".into(),
            uncompressed_size: 1,
            mtime: None,
            location: Location::Loose {
                path: std::path::PathBuf::from("x"),
            },
        },
        offsets: Vec::new(),
    }];
    let plan = plan_tree(&files, &roots);
    assert_eq!(plan.items[0].folder, "private/var/mobile/Library/SMS");
    assert_eq!(
        tree_dir("HomeDomain/Library/SMS", &roots).as_deref(),
        Some("private/var/mobile/Library/SMS"),
        "the directory record must map to exactly the folder its files land in"
    );
    assert_eq!(tree_dir("OtherDomain/x", &roots), None);
}

/// A well-formed relative label must survive untouched, so hardening the
/// label did not change the existing `app export` layout.
#[test]
fn plan_tree_leaves_a_relative_label_intact() {
    let files = vec![MatchedFile {
        entry: Entry {
            name: "AppDomain-com.x/Documents/a.txt".into(),
            uncompressed_size: 1,
            mtime: None,
            location: Location::Loose {
                path: std::path::PathBuf::from("x"),
            },
        },
        offsets: Vec::new(),
    }];
    let roots = vec![(
        "AppDomain-com.x".to_string(),
        "com.x/AppData_5A92C2C1".to_string(),
    )];
    let plan = plan_tree(&files, &roots);
    assert_eq!(plan.items[0].folder, "com.x/AppData_5A92C2C1/Documents");
    assert_eq!(plan.items[0].name, "a.txt");
}

/// `plan_tree` preserves the directory tree under a per-container label, and
/// routes each file to the LONGEST matching root prefix.
#[test]
fn plan_tree_preserves_tree_under_longest_root() {
    let files = [
        loose("/c/Data/App/GUID/Library/Preferences/x.plist", 10),
        loose("/c/Data/App/GUID/Extra/GUID2/y.db", 20),
    ];
    let roots = [
        (
            "/c/Data/App/GUID".to_string(),
            "id/AppData_GUID".to_string(),
        ),
        // A deeper, more specific root that must win for the second file.
        (
            "/c/Data/App/GUID/Extra/GUID2".to_string(),
            "id/Extension_GUID2".to_string(),
        ),
    ];
    let plan = plan_tree(&files, &roots);

    assert_eq!(plan.total_size, 30);
    assert_eq!(plan.items[0].folder, "id/AppData_GUID/Library/Preferences");
    assert_eq!(plan.items[0].name, "x.plist");
    // The second file is under both roots; the longest (the extension) wins.
    assert_eq!(plan.items[1].folder, "id/Extension_GUID2");
    assert_eq!(plan.items[1].name, "y.db");
}

/// The path-length guard: a safe path passes, `0` disables it, a >255-char
/// component is unwritable everywhere (`Skip`), and a long relative path is a
/// portability warning on non-Windows (the host these tests run on).
#[test]
fn path_length_guard_classifies_paths() {
    let dir = Path::new("/out");
    assert!(matches!(
        check_export_path(dir, "app/file.db", 260),
        PathCheck::Ok
    ));
    // Disabled guard never flags anything.
    assert!(matches!(
        check_export_path(dir, &"a".repeat(300), 0),
        PathCheck::Ok
    ));
    // A single component over 255 cannot exist on any filesystem.
    let long_component = format!("{}/f", "b".repeat(300));
    assert!(matches!(
        check_export_path(dir, &long_component, 100_000),
        PathCheck::Skip(_)
    ));
}

/// On a non-Windows host, an over-limit RELATIVE path is exported but flagged
/// as not Windows-portable (rather than skipped).
#[cfg(not(target_os = "windows"))]
#[test]
fn long_relative_path_is_a_portability_warning_off_windows() {
    let dir = Path::new("/out");
    // 300 single-char segments: no component exceeds 255, but the whole path does.
    let rel = vec!["a"; 300].join("/");
    assert!(matches!(
        check_export_path(dir, &rel, 260),
        PathCheck::NotPortable(_)
    ));
}

/// `safe_join` must not let a backslash-encoded traversal escape the destination.
///
/// A tampered manifest entry like `a\..\..\evil.exe` contains no `/`, so a
/// `/`-only split would pass it to the OS as one segment; on Windows the OS
/// resolves the `..` components and escapes the destination directory.  Splitting
/// on `\` too decomposes the payload so every `..` is dropped.
#[test]
fn safe_join_blocks_backslash_traversal() {
    let dir = PathBuf::from("/export/out");

    // Forward-slash traversal (already blocked before this fix).
    let result = safe_join(&dir, "../../etc/passwd");
    assert!(
        result.starts_with(&dir),
        "forward-slash traversal escaped: {result:?}"
    );

    // Backslash traversal — the fix under test.
    let result = safe_join(&dir, r"a\..\..\evil.exe");
    assert!(
        result.starts_with(&dir),
        "backslash traversal escaped: {result:?}"
    );

    // Mixed separators.
    let result = safe_join(&dir, r"a\..\../secret");
    assert!(
        result.starts_with(&dir),
        "mixed traversal escaped: {result:?}"
    );

    // A legitimate path must still resolve correctly under the dir.
    let result = safe_join(&dir, "folder/file.db");
    assert_eq!(result, dir.join("folder").join("file.db"));
}
