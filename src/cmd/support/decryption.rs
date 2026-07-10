//! Decryption setup for the `grep`/`diff` subcommands: build the context, report it.
//!
//! Defines: [`build_decryption_context`] (load the profile registry + keyfile
//! dumps into a [`DecryptionContext`]) and [`report_decryptions`] (the stderr
//! audit-trail summary). Takes the shared [`crate::cmd::cli::DecryptArgs`] group, so
//! both `grep` and `diff` reuse it unchanged.
//! Used by: `run::grep` (and `run::diff`). Uses: `mf_scan::decrypt` (the library
//! decryption types) and `crate::cmd::cli`.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use mf_scan::decrypt::{
    DecryptionContext, DecryptionOutcome, DecryptionRecord, ProfileRegistry, SecretStore,
    load_dump, load_if_dump,
};

use crate::cmd::cli::DecryptArgs;

/// Build the decryption context from `--keyfile` dumps, an auto-detected keyfile
/// next to the archive, and the profile registry.
///
/// Decryption is on by default: keys come from any `--keyfile` dump *and* from a
/// keychain/keystore dump found in the same directory as each archive (the common
/// forensic layout: `case.zip` beside `keychain.plist`). Returns `None` (decryption
/// off) when `--no-decrypt` is set, when no profiles are available, or when no
/// secrets were found. Messages are loud when the operator named a keyfile explicitly
/// and quiet for the automatic path (where finding nothing is the normal case).
pub(crate) fn build_decryption_context(
    decrypt: &DecryptArgs,
    archive_paths: &[&Path],
) -> Result<Option<DecryptionContext>> {
    if decrypt.no_decrypt {
        return Ok(None);
    }
    let explicit = !decrypt.keyfile.is_empty();

    let registry = match find_profiles_dir() {
        Ok(dir) => ProfileRegistry::from_dir(&dir).with_context(|| {
            format!("failed to load decryption profiles from {}", dir.display())
        })?,
        Err(e) => {
            if explicit {
                eprintln!("decrypt: {e}; no decryption profiles available");
            }
            return Ok(None);
        }
    };
    if registry.profiles().is_empty() {
        if explicit {
            eprintln!("decrypt: no decryption profiles found; nothing to decrypt");
        }
        return Ok(None);
    }

    let mut secrets = SecretStore::default();

    // 1. Keyfile dumps named explicitly on the command line. A parse failure here
    //    is reported — the operator pointed at this specific file.
    for path in &decrypt.keyfile {
        let bytes = std::fs::read(path)
            .with_context(|| format!("cannot read keyfile dump {}", path.display()))?;
        let store = load_dump(&bytes)
            .with_context(|| format!("cannot parse keychain dump {}", path.display()))?;
        eprintln!(
            "decrypt: loaded {} secret(s) from {}",
            store.len(),
            path.display()
        );
        secrets.merge(store);
    }

    // 2. A keychain dump sitting next to each archive on disk.
    for dir in unique_parents(archive_paths) {
        autodetect_in_dir(dir, &mut secrets);
    }

    if secrets.is_empty() {
        if explicit {
            eprintln!("decrypt: keyfile dump(s) contained no secrets; nothing to decrypt");
        }
        return Ok(None);
    }

    let platform = decrypt.platform.map(|p| p.to_platform());
    Ok(Some(DecryptionContext::new(registry, secrets, platform)))
}

/// The unique parent directories of the given archive paths (each scanned once).
fn unique_parents<'a>(archive_paths: &[&'a Path]) -> Vec<&'a Path> {
    let mut dirs: Vec<&Path> = archive_paths
        .iter()
        .map(|p| match p.parent() {
            // A bare filename has an empty parent; that means the current directory.
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        })
        .collect();
    dirs.sort();
    dirs.dedup();
    dirs
}

/// Merge into `secrets` any keychain dump found in `dir`.
///
/// Scans for regular files whose name contains "keychain" (case-insensitive) and
/// that a provider recognises as a dump. A non-match is silent — most files are not
/// keychains; only a successful load is announced. Errors reading the directory or
/// a file are ignored: auto-detection is best-effort and never fails the search.
fn autodetect_in_dir(dir: &Path, secrets: &mut SecretStore) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let is_candidate = path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.to_ascii_lowercase().contains("keychain"));
        if !is_candidate {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        if let Some(store) = load_if_dump(&bytes) {
            eprintln!(
                "decrypt: auto-detected keychain {} ({} secret(s))",
                path.display(),
                store.len()
            );
            secrets.merge(store);
        }
    }
}

/// Resolve the `profiles/` directory sitting next to the running binary.
fn find_profiles_dir() -> Result<PathBuf> {
    crate::cmd::support::dir_beside_binary("profiles")
}

/// Print the decryption audit trail to stderr (so it never mixes with results).
///
/// A headline line, then one line per matched database: whether it was decrypted
/// (with the key's provenance) or why it failed. The same records, with the
/// ciphertext/plaintext hashes, are written to the scan report.
pub(crate) fn report_decryptions(decryptions: &[DecryptionRecord]) {
    if decryptions.is_empty() {
        return;
    }
    let decrypted = decryptions.iter().filter(|d| !d.is_failure()).count();
    let verified = decryptions.iter().filter(|d| d.is_verified()).count();
    let failed = decryptions.len() - decrypted;
    eprintln!("── decryption ───────────────────────────────────");
    eprintln!("decrypted: {decrypted} database(s) ({verified} key-verified), failed: {failed}");
    for d in decryptions {
        match &d.outcome {
            DecryptionOutcome::Decrypted {
                verified,
                secret_source,
                secret_service,
                secret_account,
                ..
            } => {
                let mark = if *verified { "verified" } else { "UNVERIFIED" };
                let svc = secret_service.as_deref().unwrap_or("?");
                let acct = secret_account.as_deref().unwrap_or("?");
                eprintln!(
                    "  {} [{}]  {mark}  (key svc={svc} acct={acct}, src={secret_source})",
                    d.path, d.app
                );
            }
            DecryptionOutcome::Failed { reason } => {
                eprintln!("  {} [{}]  FAILED: {reason}", d.path, d.app);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    const KEYCHAIN_XML: &[u8] = br#"<?xml version="1.0"?>
        <plist version="1.0"><array>
          <dict><key>svc</key><string>S</string><key>v_Data</key><data>AAA=</data></dict>
        </array></plist>"#;

    #[test]
    fn autodetect_finds_keychain_named_dump_only() {
        let dir = tempdir().unwrap();
        // A keychain dump beside the archive — found.
        fs::write(dir.path().join("decrypted_keychain.plist"), KEYCHAIN_XML).unwrap();
        // A non-keychain file — ignored (wrong name).
        fs::write(dir.path().join("notes.txt"), KEYCHAIN_XML).unwrap();
        // A keychain-named file that is not a dump — ignored (content not a dump).
        fs::write(dir.path().join("keychain.log"), b"just a log line").unwrap();

        let mut secrets = SecretStore::default();
        autodetect_in_dir(dir.path(), &mut secrets);
        assert_eq!(secrets.len(), 1);
    }

    #[test]
    fn unique_parents_dedupes_directories() {
        let a = Path::new("/case/one.zip");
        let b = Path::new("/case/two.zip");
        let c = Path::new("/other/three.zip");
        let parents = unique_parents(&[a, b, c]);
        assert_eq!(parents, vec![Path::new("/case"), Path::new("/other")]);
    }

    #[test]
    fn bare_filename_parent_is_current_dir() {
        let parents = unique_parents(&[Path::new("case.zip")]);
        assert_eq!(parents, vec![Path::new(".")]);
    }
}
