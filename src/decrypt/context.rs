//! Decryption context: match an entry to a profile, find its key, decrypt.
//!
//! Defines: [`DecryptionContext`] (the registry + secret store + optional platform
//! scope that the search engine consults per entry), [`TryOutcome`] (the result of
//! attempting one entry), and the provenance types [`DecryptionRecord`] /
//! [`DecryptionOutcome`] recorded for the audit trail.
//! Used by: `engine` (the per-entry content transform) and, in a later milestone,
//! `run` (which builds the context from a keychain dump + the profile registry).
//! Uses: `decrypt::profile` (matching), `decrypt::keyfile` (key lookup),
//! `decrypt::cipher` (decryption), `sha2` (provenance hashes).
//!
//! ── How one entry is handled ─────────────────────────────────────────────────
//! [`DecryptionContext::try_decrypt`] returns:
//!   • `None` — the path matched no profile; it is not an encrypted target, so the
//!     engine searches it unchanged.
//!   • `Some(Decrypted)` — a profile matched and a candidate key produced a
//!     (HMAC-verified, where the cipher supports it) plaintext; the engine replaces
//!     the entry's bytes with that plaintext before searching/inspecting.
//!   • `Some(Failed)` — a profile matched but no candidate key worked; the engine
//!     records the failure and does **not** search the ciphertext (it has no
//!     meaningful content).
//!
//! The "try each candidate" loop is what gives forensic robustness: a profile's
//! match criteria may select several keychain items, so each is tried until one
//! decrypts and verifies.

use serde::Serialize;

use crate::decrypt::cipher;
use crate::decrypt::keyfile::SecretStore;
use crate::decrypt::profile::{Platform, Profile, ProfileRegistry};
use crate::util::sha256_hex;

/// Everything the engine needs to decrypt entries: the profile registry, the
/// secrets, and an optional platform scope.
pub struct DecryptionContext {
    registry: ProfileRegistry,
    secrets: SecretStore,
    /// When set, only profiles of this platform are considered.
    platform: Option<Platform>,
}

/// A successful decryption of one entry, with the provenance of the key used.
pub struct Decryption {
    /// The decrypted plaintext bytes.
    pub plaintext: Vec<u8>,
    /// Whether the cipher cryptographically verified the key (e.g. SQLCipher HMAC).
    pub verified: bool,
    /// The profile that matched.
    pub profile: String,
    /// The app the profile targets.
    pub app: String,
    /// Which keychain loader produced the secret used.
    pub secret_source: String,
    /// The secret's service attribute, for provenance.
    pub secret_service: Option<String>,
    /// The secret's account attribute, for provenance.
    pub secret_account: Option<String>,
}

/// The outcome of attempting to decrypt one entry whose path matched a profile.
pub enum TryOutcome {
    /// A candidate key decrypted the entry.
    Decrypted(Decryption),
    /// A profile matched but no candidate key worked.
    Failed {
        profile: String,
        app: String,
        reason: String,
    },
}

impl DecryptionContext {
    /// Build a context from the profile registry, the loaded secrets, and an
    /// optional platform scope.
    pub fn new(
        registry: ProfileRegistry,
        secrets: SecretStore,
        platform: Option<Platform>,
    ) -> Self {
        Self {
            registry,
            secrets,
            platform,
        }
    }

    /// Whether the context can decrypt anything (it has at least one secret).
    ///
    /// With no secrets there is no key to try, so the engine can skip the
    /// per-entry matching entirely.
    pub fn has_secrets(&self) -> bool {
        !self.secrets.is_empty()
    }

    /// The first profile whose database binding matches `path` (within the
    /// platform scope, if one is set).
    fn profile_for(&self, path: &str) -> Option<&Profile> {
        self.registry
            .profiles()
            .iter()
            .find(|p| self.platform.is_none_or(|plat| p.platform == plat) && p.db.matches(path))
    }

    /// Attempt to decrypt `ciphertext` for the entry at `path`.
    ///
    /// `None` means no profile matched (not an encrypted target). Otherwise a
    /// profile matched and the result is [`TryOutcome::Decrypted`] or
    /// [`TryOutcome::Failed`]. Each matching secret is tried in turn; the first to
    /// decrypt wins — for an HMAC cipher that is the key that authenticates.
    pub fn try_decrypt(&self, path: &str, ciphertext: &[u8]) -> Option<TryOutcome> {
        let profile = self.profile_for(path)?;

        let candidates = self.secrets.candidates(&profile.key.keychain);
        if candidates.is_empty() {
            return Some(TryOutcome::Failed {
                profile: profile.name.clone(),
                app: profile.app.clone(),
                reason: "no keychain secret matched the profile's criteria".to_string(),
            });
        }

        let mut last_reason = String::from("no candidate key matched");
        for secret in candidates {
            let key_material = match secret.key_material(profile.key.encoding) {
                Ok(km) => km,
                Err(e) => {
                    last_reason = e.to_string();
                    continue;
                }
            };
            match cipher::decrypt(ciphertext, &key_material, &profile.cipher) {
                Ok(db) => {
                    return Some(TryOutcome::Decrypted(Decryption {
                        plaintext: db.plaintext,
                        verified: db.verified,
                        profile: profile.name.clone(),
                        app: profile.app.clone(),
                        secret_source: secret.source.clone(),
                        secret_service: secret.service.clone(),
                        secret_account: secret.account.clone(),
                    }));
                }
                Err(e) => last_reason = e.to_string(),
            }
        }
        Some(TryOutcome::Failed {
            profile: profile.name.clone(),
            app: profile.app.clone(),
            reason: format!("no candidate key decrypted the database ({last_reason})"),
        })
    }
}

/// One entry's decryption result, recorded for the audit trail.
///
/// `Serialize` so it can be embedded in the scan report (a later milestone); the
/// hashes attest exactly which ciphertext became which plaintext.
#[derive(Debug, Clone, Serialize)]
pub struct DecryptionRecord {
    /// The entry's internal path.
    pub path: String,
    /// The profile that matched.
    pub profile: String,
    /// The app the profile targets.
    pub app: String,
    /// What happened.
    #[serde(flatten)]
    pub outcome: DecryptionOutcome,
}

/// The decryption result for one entry.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum DecryptionOutcome {
    /// The entry was decrypted; the hashes attest the ciphertext→plaintext mapping.
    Decrypted {
        /// Whether the cipher cryptographically verified the key.
        verified: bool,
        /// Which keychain loader produced the key.
        secret_source: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        secret_service: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        secret_account: Option<String>,
        /// SHA-256 of the encrypted bytes read from the archive.
        cipher_sha256: String,
        /// SHA-256 of the decrypted plaintext.
        plain_sha256: String,
    },
    /// A profile matched but decryption failed.
    Failed { reason: String },
}

impl DecryptionRecord {
    /// Build a record for a successful decryption, hashing both byte streams.
    pub fn decrypted(path: String, decryption: &Decryption, ciphertext: &[u8]) -> Self {
        Self {
            path,
            profile: decryption.profile.clone(),
            app: decryption.app.clone(),
            outcome: DecryptionOutcome::Decrypted {
                verified: decryption.verified,
                secret_source: decryption.secret_source.clone(),
                secret_service: decryption.secret_service.clone(),
                secret_account: decryption.secret_account.clone(),
                cipher_sha256: sha256_hex(ciphertext),
                plain_sha256: sha256_hex(&decryption.plaintext),
            },
        }
    }

    /// Build a record for a failed decryption.
    pub fn failed(path: String, profile: String, app: String, reason: String) -> Self {
        Self {
            path,
            profile,
            app,
            outcome: DecryptionOutcome::Failed { reason },
        }
    }

    /// Whether this record is a successful, key-verified decryption.
    pub fn is_verified(&self) -> bool {
        matches!(
            self.outcome,
            DecryptionOutcome::Decrypted { verified: true, .. }
        )
    }

    /// Whether this record is a failure.
    pub fn is_failure(&self) -> bool {
        matches!(self.outcome, DecryptionOutcome::Failed { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decrypt::cipher::sqlcipher::encrypt_db;
    use crate::decrypt::keyfile::Secret;
    use crate::decrypt::profile::{
        CipherSpec, DbBinding, HashAlgorithm, KeyEncoding, KeySpec, KeychainMatch, Profile,
        SqlCipherParams,
    };
    use crate::search::search_bytes;
    use regex::bytes::Regex;

    const PAGE_SIZE: usize = 1024;

    /// A Signal-like SQLCipher v4 profile keyed on service "Signal".
    fn signal_profile() -> Profile {
        Profile {
            name: "signal-test".into(),
            app: "Signal".into(),
            platform: Platform::Ios,
            description: None,
            db: DbBinding::Glob("*/grdb/signal.sqlite".into()),
            key: KeySpec {
                encoding: KeyEncoding::Raw,
                keychain: KeychainMatch {
                    service: Some("Signal".into()),
                    ..Default::default()
                },
            },
            cipher: CipherSpec::Sqlcipher(SqlCipherParams {
                page_size: PAGE_SIZE,
                kdf_iter: 256_000,
                hmac: HashAlgorithm::Sha512,
                kdf: HashAlgorithm::Sha512,
                use_hmac: true,
                plaintext_header_size: 0,
            }),
        }
    }

    fn secret(service: &str, key: &[u8]) -> Secret {
        Secret {
            account: Some("acct".into()),
            service: Some(service.into()),
            access_group: None,
            label: None,
            protection_class: None,
            data: key.to_vec(),
            source: "test".into(),
        }
    }

    /// Build a one-page encrypted SQLCipher DB containing a needle.
    fn encrypted_db(key: &[u8; 32]) -> Vec<u8> {
        let mut page = vec![0u8; PAGE_SIZE];
        page[..16].copy_from_slice(b"SQLite format 3\x00");
        page[100..115].copy_from_slice(b"FINDME-secret!!");
        let profile = signal_profile();
        let CipherSpec::Sqlcipher(params) = &profile.cipher else {
            unreachable!("the test profile uses sqlcipher");
        };
        encrypt_db(&[page], key, &[0x55u8; 16], params)
    }

    #[test]
    fn no_profile_match_returns_none() {
        let ctx = DecryptionContext::new(
            ProfileRegistry::new(vec![signal_profile()]),
            SecretStore::new(vec![secret("Signal", &[0x42u8; 32])]),
            None,
        );
        // Path does not match the profile's db glob.
        assert!(ctx.try_decrypt("some/other/file.txt", b"data").is_none());
    }

    #[test]
    fn matching_entry_is_decrypted_and_searchable() {
        let key = [0x42u8; 32];
        let ctx = DecryptionContext::new(
            ProfileRegistry::new(vec![signal_profile()]),
            SecretStore::new(vec![secret("Signal", &key)]),
            None,
        );
        let blob = encrypted_db(&key);
        let outcome = ctx
            .try_decrypt("App/grdb/signal.sqlite", &blob)
            .expect("profile should match");
        let TryOutcome::Decrypted(d) = outcome else {
            panic!("expected a successful decryption");
        };
        assert!(d.verified);
        // The needle inside the encrypted DB is found once decrypted.
        let re = Regex::new("FINDME-secret!!").unwrap();
        assert_eq!(search_bytes(&d.plaintext, &re).len(), 1);
        // ...and not in the ciphertext.
        assert_eq!(search_bytes(&blob, &re).len(), 0);
    }

    #[test]
    fn wrong_key_reports_failure_not_panic() {
        let ctx = DecryptionContext::new(
            ProfileRegistry::new(vec![signal_profile()]),
            // The stored secret is the wrong key.
            SecretStore::new(vec![secret("Signal", &[0x11u8; 32])]),
            None,
        );
        let blob = encrypted_db(&[0x42u8; 32]);
        match ctx.try_decrypt("App/grdb/signal.sqlite", &blob) {
            Some(TryOutcome::Failed { reason, .. }) => assert!(!reason.is_empty()),
            other => panic!("expected Failed, got something else: {}", other.is_some()),
        }
    }

    #[test]
    fn tries_multiple_candidates_until_one_verifies() {
        let key = [0x42u8; 32];
        let ctx = DecryptionContext::new(
            ProfileRegistry::new(vec![signal_profile()]),
            // Two secrets match service "Signal"; only the second is correct.
            SecretStore::new(vec![
                secret("Signal", &[0x11u8; 32]),
                secret("Signal", &key),
            ]),
            None,
        );
        let blob = encrypted_db(&key);
        let outcome = ctx.try_decrypt("App/grdb/signal.sqlite", &blob).unwrap();
        assert!(matches!(outcome, TryOutcome::Decrypted(d) if d.verified));
    }

    #[test]
    fn platform_scope_excludes_other_platforms() {
        let key = [0x42u8; 32];
        let ctx = DecryptionContext::new(
            ProfileRegistry::new(vec![signal_profile()]), // platform = ios
            SecretStore::new(vec![secret("Signal", &key)]),
            Some(Platform::Android), // scope to android only
        );
        // The ios profile is out of scope, so the path matches nothing.
        assert!(
            ctx.try_decrypt("App/grdb/signal.sqlite", &encrypted_db(&key))
                .is_none()
        );
    }
}
