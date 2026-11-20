//! Tests for the export plan, writer, records and manifest.

use std::collections::HashSet;

use super::plan::decrypted_name_numbered;

/// The first decrypted copy's name.
fn decrypted_name(name: &str) -> String {
    decrypted_name_numbered(name, 1)
}
use super::write::{extraction_warning, member_name};
use crate::core::layout::{output_roots, tree_dir};
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
        encodings: Vec::new(),
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
        encodings: Vec::new(),
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
            encodings: Vec::new(),
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
            encodings: Vec::new(),
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
            encodings: Vec::new(),
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
        encodings: Vec::new(),
    }];
    let plan = plan_tree(&files, &roots);
    assert_eq!(plan.items[0].folder, "private/var/mobile/Library/SMS");
    let index = output_roots(&roots);
    assert_eq!(
        tree_dir("HomeDomain/Library/SMS", &index).as_deref(),
        Some("private/var/mobile/Library/SMS"),
        "the directory record must map to exactly the folder its files land in"
    );
    assert_eq!(tree_dir("OtherDomain/x", &index), None);
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
        encodings: Vec::new(),
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

/// A member name is checked against what an extraction can hold: a name over 255
/// characters anywhere, and a path over 260 on Windows. The file is written anyway.
#[test]
fn extraction_limits_are_flagged_not_enforced() {
    assert!(extraction_warning("app/file.db").is_none());
    let long_component = format!("{}/f", "b".repeat(300));
    assert!(extraction_warning(&long_component).unwrap().contains("255"));
    // 300 single-char segments: no name exceeds 255, but the whole path does.
    let long_path = vec!["a"; 300].join("/");
    assert!(extraction_warning(&long_path).unwrap().contains("Windows"));
}

/// A member name never escapes the folder it is extracted to, whatever a tampered
/// manifest says: `..`, empty and `.` parts are dropped, and `\` splits as `/` does,
/// as an extractor on Windows would resolve it.
#[test]
fn member_names_cannot_escape_the_extraction_folder() {
    assert_eq!(member_name("../../etc/passwd"), "etc/passwd");
    assert_eq!(member_name(r"a\..\..\evil.exe"), "a/evil.exe");
    assert_eq!(member_name(r"a\..\../secret"), "a/secret");
    assert_eq!(member_name("/folder//./file.db"), "folder/file.db");
}

#[test]
fn names_differing_only_in_accent_encoding_clash() {
    // One file named with a composed é (U+00E9), one with e + U+0301: distinct on a
    // phone's file system, one name on macOS. The second must be renamed, not merged.
    let composed = "Media/caf\u{e9}.jpg";
    let decomposed = "Media/cafe\u{301}.jpg";
    assert_ne!(composed, decomposed);
    assert_eq!(
        super::plan::fold_case(composed),
        super::plan::fold_case(decomposed)
    );
    assert_eq!(
        super::plan::fold_case("Media/CAF\u{c9}.jpg"),
        super::plan::fold_case(decomposed),
        "case and accent form fold together"
    );
}
