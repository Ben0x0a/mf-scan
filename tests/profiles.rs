//! Integration test: the profiles shipped in `profiles/` parse and validate.
//!
//! Defines: a guard that loads the repository's real `profiles/` directory
//! through [`ProfileRegistry::from_dir`], so a typo or platform mismatch in a
//! shipped profile fails the build rather than only surfacing at runtime.
//! Used by: `cargo test`. Uses: the `mf_scan` library and `CARGO_MANIFEST_DIR`
//! (the crate root at compile time) to locate the directory.

use std::path::Path;

use mf_scan::decrypt::ProfileRegistry;

#[test]
fn shipped_profiles_parse_and_validate() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("profiles");
    let registry = ProfileRegistry::from_dir(&dir)
        .expect("the shipped profiles/ directory must parse and validate");

    // The directory is real and at least one profile loaded (the Signal starter).
    assert!(
        !registry.profiles().is_empty(),
        "expected at least one shipped profile"
    );
    let signal = registry
        .by_name("signal-ios")
        .expect("the signal-ios profile should ship and load");
    assert_eq!(signal.app, "Signal");
}

/// Every data directory the binary resolves at run time must be staged into the
/// release archive.
///
/// `cmd::support::dir_beside_binary` looks for these next to the executable, and a
/// missing one degrades silently — `profiles/` was absent from every archive up to
/// v0.4.0, so no released binary could decrypt anything. This reads the release
/// workflow and fails if a directory the code resolves is not copied.
#[test]
fn release_archive_stages_every_runtime_data_dir() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workflow = std::fs::read_to_string(root.join(".github/workflows/release.yml"))
        .expect("the release workflow must exist");
    let staging: String = workflow
        .lines()
        .filter(|l| l.trim_start().starts_with("cp "))
        .collect::<Vec<_>>()
        .join("\n");

    for dir in ["presets", "profiles"] {
        assert!(
            root.join(dir).is_dir(),
            "{dir}/ is resolved at run time but is not in the repo"
        );
        assert!(
            staging.contains(dir),
            "{dir}/ is resolved beside the binary at run time but the release \
             workflow never copies it into the archive"
        );
    }
}
