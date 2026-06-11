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
