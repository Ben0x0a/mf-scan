//! Secret store: normalised keychain/keystore items and key lookup.
//!
//! Defines: [`Secret`] (one normalised dump item), [`SecretStore`] (a queryable
//! collection with [`SecretStore::candidates`] matching), and the
//! [`KeyfileProvider`] trait + [`load_dump`] entry point that auto-detects a
//! dump's format.
//! Used by: `decrypt::mod` (re-exports) and the engine shim (M4), which looks up a
//! profile's key in the store; per-source loaders (iLEAPP, Cellebrite, …) are
//! added in a later milestone and registered in `PROVIDERS`.
//! Uses: `crate::decrypt::profile::{KeychainMatch, KeyEncoding, KeyMaterial}` and
//! `anyhow`.
//!
//! Why a normalised `Secret`: every dump format (commercial or open-source)
//! ultimately exposes the same iOS keychain attributes (`acct`, `svc`, `agrp`,
//! `pdmn`, `v_Data`). Mapping each format onto one shape in its loader keeps the
//! rest of the pipeline format- and platform-agnostic — adding a source is adding
//! one [`KeyfileProvider`], nothing else.

mod keychain_plist;

use anyhow::{Result, bail};

use crate::decrypt::profile::{KeyEncoding, KeyMaterial, KeychainMatch};

/// One normalised secret-store item — the common subset every dump format exposes.
///
/// Field names mirror the iOS keychain attributes. Android Keystore entries are
/// mapped onto the same shape by their loader, so callers never branch on platform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Secret {
    /// Account attribute (`acct`).
    pub account: Option<String>,
    /// Service attribute (`svc`).
    pub service: Option<String>,
    /// Access group (`agrp`).
    pub access_group: Option<String>,
    /// Human-readable label.
    pub label: Option<String>,
    /// Protection class (`pdmn`), e.g. `ak`/`ck`/`dk`. Provenance only.
    pub protection_class: Option<String>,
    /// The raw key material (`v_Data`), decoded per a profile's [`KeyEncoding`].
    pub data: Vec<u8>,
    /// Identifier of the loader that produced this item, recorded for provenance.
    pub source: String,
}

impl Secret {
    /// Decode this secret's data into key material per `encoding`.
    pub fn key_material(&self, encoding: KeyEncoding) -> Result<KeyMaterial> {
        encoding.decode(&self.data)
    }
}

/// A collection of secrets, queryable by [`KeychainMatch`] criteria.
#[derive(Debug, Default)]
pub struct SecretStore {
    items: Vec<Secret>,
}

impl SecretStore {
    /// Wrap a list of secrets.
    pub fn new(items: Vec<Secret>) -> Self {
        Self { items }
    }

    /// Number of secrets held.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether the store holds no secrets.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// All secrets held.
    pub fn items(&self) -> &[Secret] {
        &self.items
    }

    /// Merge another store's items in — e.g. several dump files for one device.
    pub fn merge(&mut self, other: SecretStore) {
        self.items.extend(other.items);
    }

    /// Every secret matching `m`: each *set* criterion equals the secret's field.
    ///
    /// Returns all matches (not just the first) so the caller can try each as a
    /// candidate key and keep the one whose decryption verifies — loose criteria
    /// may legitimately match several items across access groups.
    pub fn candidates(&self, m: &KeychainMatch) -> Vec<&Secret> {
        self.items.iter().filter(|s| secret_matches(s, m)).collect()
    }
}

/// True when every field set in `m` equals the secret's corresponding field.
fn secret_matches(s: &Secret, m: &KeychainMatch) -> bool {
    field_matches(&m.account, &s.account)
        && field_matches(&m.service, &s.service)
        && field_matches(&m.access_group, &s.access_group)
        && field_matches(&m.label, &s.label)
}

/// A single criterion: `None` is a wildcard; `Some` must equal the secret's value
/// (which must itself be present). Exact, case-sensitive comparison.
fn field_matches(want: &Option<String>, have: &Option<String>) -> bool {
    match want {
        None => true,
        Some(w) => have.as_deref() == Some(w.as_str()),
    }
}

/// A loader that turns one keychain/keystore dump format into normalised secrets.
///
/// Adding a source is adding one implementor and listing it in `PROVIDERS`;
/// detection is by content so a dump need not be named correctly (mirrors the
/// inspectors' header-first rule).
pub trait KeyfileProvider: Sync {
    /// Short identifier, recorded on each produced [`Secret`] as its `source`.
    fn name(&self) -> &'static str;
    /// Recognise this dump format from its content.
    fn detect(&self, content: &[u8]) -> bool;
    /// Parse the dump into secrets.
    fn load(&self, content: &[u8]) -> Result<Vec<Secret>>;
}

/// Every keychain provider, tried in detection order. Add a source by adding its
/// loader here.
static PROVIDERS: &[&dyn KeyfileProvider] = &[&keychain_plist::KeychainPlist];

/// The first provider whose `detect` recognises `content`, if any.
fn provider_for(content: &[u8]) -> Option<&'static dyn KeyfileProvider> {
    PROVIDERS.iter().copied().find(|p| p.detect(content))
}

/// Load a keychain/keystore dump by auto-detecting its format.
///
/// Returns the secrets from the first provider whose `detect` matches. An
/// unrecognised dump is an error: we will not guess a format for key material.
/// Use this for a dump the operator named explicitly (`--keyfile`), where a
/// parse failure should be reported rather than silently ignored.
pub fn load_dump(content: &[u8]) -> Result<SecretStore> {
    match provider_for(content) {
        Some(provider) => Ok(SecretStore::new(provider.load(content)?)),
        None => {
            bail!("unrecognised keychain/keystore dump format (no provider matched its content)")
        }
    }
}

/// Load `content` as a keychain dump only if a provider recognises it.
///
/// `None` when no provider claims it (or it failed to parse) — the quiet variant
/// for auto-detection, where most files scanned are *not* keychain dumps and a
/// non-match is the normal case, not an error.
pub fn load_if_dump(content: &[u8]) -> Option<SecretStore> {
    let provider = provider_for(content)?;
    provider.load(content).ok().map(SecretStore::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(account: &str, service: &str, agrp: Option<&str>) -> Secret {
        Secret {
            account: Some(account.into()),
            service: Some(service.into()),
            access_group: agrp.map(Into::into),
            label: None,
            protection_class: None,
            data: account.as_bytes().to_vec(),
            source: "test".into(),
        }
    }

    fn store() -> SecretStore {
        SecretStore::new(vec![
            secret("acct-a", "Signal", Some("group.org.signal")),
            secret("acct-b", "Signal", Some("group.other")),
            secret("acct-c", "WhatsApp", None),
        ])
    }

    #[test]
    fn set_fields_must_all_match() {
        let m = KeychainMatch {
            service: Some("Signal".into()),
            ..Default::default()
        };
        // Both Signal items match; the WhatsApp one does not.
        assert_eq!(store().candidates(&m).len(), 2);
    }

    #[test]
    fn unset_fields_are_wildcards() {
        // An empty match selects everything.
        assert_eq!(store().candidates(&KeychainMatch::default()).len(), 3);
    }

    #[test]
    fn narrowing_by_access_group() {
        let m = KeychainMatch {
            service: Some("Signal".into()),
            access_group: Some("group.org.signal".into()),
            ..Default::default()
        };
        let store = store();
        let hits = store.candidates(&m);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].account.as_deref(), Some("acct-a"));
    }

    #[test]
    fn no_match_returns_empty() {
        let m = KeychainMatch {
            service: Some("Telegram".into()),
            ..Default::default()
        };
        assert!(store().candidates(&m).is_empty());
    }

    #[test]
    fn key_material_decodes_via_secret() {
        let s = Secret {
            data: b"00ff".to_vec(),
            ..secret("a", "svc", None)
        };
        assert_eq!(
            s.key_material(KeyEncoding::Hex).unwrap(),
            KeyMaterial::Raw(vec![0x00, 0xff])
        );
    }

    #[test]
    fn load_dump_rejects_unknown_format() {
        // No provider recognises arbitrary bytes, so the format is unrecognised.
        assert!(load_dump(b"whatever").is_err());
    }

    #[test]
    fn load_if_dump_returns_none_for_non_dump_some_for_dump() {
        // Quiet variant: a non-dump is None, not an error.
        assert!(load_if_dump(b"not a keychain at all").is_none());
        let dump = br#"<?xml version="1.0"?>
            <plist version="1.0"><array>
              <dict><key>svc</key><string>S</string><key>v_Data</key><data>AAA=</data></dict>
            </array></plist>"#;
        assert_eq!(load_if_dump(dump).map(|s| s.len()), Some(1));
    }

    #[test]
    fn load_dump_auto_detects_keychain_plist_and_finds_a_key() {
        // End-to-end: a keychain XML plist is recognised by a provider, loaded into
        // a store, and queried by a profile-style match — exercising the registry
        // wiring, not just one loader in isolation.
        let dump = br#"<?xml version="1.0"?>
            <plist version="1.0"><array>
                <dict>
                    <key>svc</key><string>TSKeyChainService</string>
                    <key>acct</key><string>OWSDatabaseCipherKeySpec</string>
                    <key>v_Data</key><data>3q2+7w==</data>
                </dict>
            </array></plist>"#;
        let store = load_dump(dump).unwrap();
        assert_eq!(store.len(), 1);

        let m = KeychainMatch {
            service: Some("TSKeyChainService".into()),
            ..Default::default()
        };
        let hits = store.candidates(&m);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].data, vec![0xde, 0xad, 0xbe, 0xef]);
    }
}
