//! Android-Keystore JSON provider: an acquisition tool's keystore dump → secrets.
//!
//! Defines: [`AndroidKeystoreJson`], a [`KeyfileProvider`](super::KeyfileProvider) for
//! the JSON report a full-filesystem acquisition writes next to an Android extraction
//! (`<serial>_android_keystore`, often shipped inside a zip).
//! Used by: `decrypt::keyfile` (registered in its `PROVIDERS` list).
//! Uses: `serde_json` and `super::Secret`.
//!
//! ── Format (from a real Samsung Galaxy A53 dump, December 2025) ──────────────
//! A JSON object keyed by package name. Each value is a list of items:
//!   • `result_type`: what the tool unwrapped, e.g. `Data Blob` (a value an app
//!     encrypted with a Keystore key, such as a database password) or
//!     `EncryptedSharedPreference Data Blob` (a Tink keyset); `Key Not Found` when the
//!     tool could not reach the app's key;
//!   • `description`: what the blob is (a preference name, a file path, a label);
//!   • `key_name`: the Keystore alias that wrapped it;
//!   • `encrypted_data` / `decrypted_data`: hex. Only `decrypted_data` is key material.
//!
//! Mapping onto [`Secret`] (whose fields mirror the iOS keychain): the package becomes
//! the access group, so a profile selects an app's secrets the same way on both
//! platforms; the Keystore alias becomes the account, the description the label, and
//! the result type the service. Items with no decrypted data are dropped.

use anyhow::{Context, Result};
use serde_json::Value;

use super::{KeyfileProvider, Secret};

/// The provider's identifier, also recorded on each [`Secret`] as its `source`.
const SOURCE_NAME: &str = "android-keystore-json";
/// The fields every item carries; their presence is what recognises the format.
const RESULT_TYPE: &str = "result_type";
const DECRYPTED_DATA: &str = "decrypted_data";
const DESCRIPTION: &str = "description";
const KEY_NAME: &str = "key_name";

/// How far into a candidate file to look for the item markers when detecting.
const DETECT_WINDOW: usize = 4096;

/// Reads the JSON Android-Keystore dump.
pub struct AndroidKeystoreJson;

impl KeyfileProvider for AndroidKeystoreJson {
    fn name(&self) -> &'static str {
        SOURCE_NAME
    }

    /// A JSON object (`{` after optional whitespace) whose first items carry both
    /// `result_type` and `decrypted_data`. WHY a window: the markers appear in the
    /// first item, so the whole dump need not be parsed to reject an unrelated file.
    fn detect(&self, content: &[u8]) -> bool {
        let head = &content[..content.len().min(DETECT_WINDOW)];
        let starts_object = head
            .iter()
            .find(|b| !b.is_ascii_whitespace())
            .is_some_and(|&b| b == b'{');
        starts_object
            && crate::formats::inspect::contains(head, RESULT_TYPE.as_bytes())
            && crate::formats::inspect::contains(head, DECRYPTED_DATA.as_bytes())
    }

    fn load(&self, content: &[u8]) -> Result<Vec<Secret>> {
        let root: Value =
            serde_json::from_slice(content).context("failed to parse the Android keystore JSON")?;
        let packages = root
            .as_object()
            .context("the Android keystore JSON is not an object keyed by package")?;
        let mut secrets = Vec::new();
        for (package, items) in packages {
            for item in items.as_array().into_iter().flatten() {
                if let Some(secret) = secret_from_item(package, item) {
                    secrets.push(secret);
                }
            }
        }
        Ok(secrets)
    }
}

/// One item as a [`Secret`], if it carries decrypted key material.
fn secret_from_item(package: &str, item: &Value) -> Option<Secret> {
    let text = |key: &str| {
        item.get(key)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    let data = decode_hex(&text(DECRYPTED_DATA)?)?;
    if data.is_empty() {
        return None;
    }
    Some(Secret {
        account: text(KEY_NAME),
        service: text(RESULT_TYPE),
        access_group: Some(package.to_string()),
        label: text(DESCRIPTION),
        protection_class: None,
        data,
        source: SOURCE_NAME.to_string(),
    })
}

/// Decode a hex string; `None` if it is not valid hex.
fn decode_hex(hex: &str) -> Option<Vec<u8>> {
    let hex = hex.trim();
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(hex.get(i..i + 2)?, 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const DUMP: &[u8] = br#"{
      "com.samsung.android.dqagent": [
        {
          "result_type": "Data Blob",
          "description": "pwenc",
          "key_name": "com.samsung.android.dqagent_SA_SDK",
          "encrypted_data": "aabb",
          "decrypted_data": "deadbeef"
        }
      ],
      "org.thoughtcrime.securesms": [
        {
          "result_type": "Key Not Found",
          "description": "Unable to find key for application",
          "key_name": "",
          "encrypted_data": "",
          "decrypted_data": ""
        }
      ]
    }"#;

    #[test]
    fn detects_the_dump_and_rejects_other_json() {
        assert!(AndroidKeystoreJson.detect(DUMP));
        assert!(!AndroidKeystoreJson.detect(br#"{"a": 1}"#));
        assert!(!AndroidKeystoreJson.detect(b"[1, 2]"));
    }

    #[test]
    fn maps_items_and_drops_missing_keys() {
        let secrets = AndroidKeystoreJson.load(DUMP).unwrap();
        assert_eq!(secrets.len(), 1, "the Key Not Found item carries no key");
        let s = &secrets[0];
        assert_eq!(
            s.access_group.as_deref(),
            Some("com.samsung.android.dqagent")
        );
        assert_eq!(
            s.account.as_deref(),
            Some("com.samsung.android.dqagent_SA_SDK")
        );
        assert_eq!(s.label.as_deref(), Some("pwenc"));
        assert_eq!(s.service.as_deref(), Some("Data Blob"));
        assert_eq!(s.data, vec![0xde, 0xad, 0xbe, 0xef]);
    }
}
