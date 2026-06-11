//! Keychain-plist provider: a property-list keychain dump (XML *or* binary) →
//! normalised secrets.
//!
//! Defines: [`KeychainPlist`], a [`KeyfileProvider`](super::KeyfileProvider)
//! that reads a keychain dump in either plist encoding and maps each item to a
//! [`Secret`].
//! Used by: `decrypt::keyfile` (registered in its `PROVIDERS` list).
//! Uses: the `plist` crate (pure-Rust, both encodings) and `super::Secret`.
//!
//! Format accepted: a property list holding keychain items as dictionaries that
//! use the standard iOS keychain (SecItem) attribute short-names — `acct`
//! (account), `svc` (service), `agrp` (access group), `labl` (label), `pdmn`
//! (protection class), and `v_Data` (the value/key bytes). This is the
//! representation that open-source and several commercial tools export (iLEAPP,
//! GrayKey, and any dump produced via `SecItemCopyMatching`). Items may be a root
//! array or grouped under class keys (`genp`/`inet`/`keys`/`cert`): the loader
//! collects *every* dictionary carrying a `v_Data`, wherever it sits.
//!
//! Why the `plist` crate (vs. hand-rolling): keychain dumps from forensic tools
//! are frequently *binary* plists, and decoding the binary object table correctly
//! over untrusted evidence is exactly where a battle-tested pure-Rust parser is
//! the responsible choice. The XML-offset inspector in `crate::inspect::plist`
//! stays hand-rolled because it resolves byte offsets to key paths — something the
//! value-oriented `plist` crate does not expose; the two serve different needs.
//!
//! Not (yet) covered: a Cellebrite/GrayKey export whose schema differs from the
//! standard SecItem attributes (e.g. different field names, or a non-plist report
//! format). That needs a real sample to implement correctly rather than guess; a
//! new [`KeyfileProvider`](super::KeyfileProvider) can be added for it.

use std::io::Cursor;

use anyhow::{Context, Result};
use plist::{Dictionary, Value};

use super::{KeyfileProvider, Secret};

/// iOS keychain attribute short-names we read off each item dictionary.
const ACCOUNT_KEY: &str = "acct";
const SERVICE_KEY: &str = "svc";
const ACCESS_GROUP_KEY: &str = "agrp";
const LABEL_KEY: &str = "labl";
const PROTECTION_CLASS_KEY: &str = "pdmn";
const VALUE_DATA_KEY: &str = "v_Data";

/// The provider's identifier, also recorded on each [`Secret`] as its `source`.
const SOURCE_NAME: &str = "keychain-plist";

/// Reads an XML or binary property-list keychain dump.
pub struct KeychainPlist;

impl KeyfileProvider for KeychainPlist {
    fn name(&self) -> &'static str {
        SOURCE_NAME
    }

    /// Recognise a keychain dump in either plist encoding.
    ///
    /// HOW: it is a binary plist (`bplist00`) or an XML plist (declaration +
    /// `<plist`), and it mentions the `v_Data` value attribute — the marker of
    /// keychain content. WHY require `v_Data`: it distinguishes a keychain dump
    /// from an arbitrary plist without parsing the whole file, and stops the
    /// provider claiming (then emptily "loading") an unrelated plist.
    fn detect(&self, content: &[u8]) -> bool {
        let mentions_value_data = crate::inspect::contains(content, VALUE_DATA_KEY.as_bytes());
        if content.starts_with(b"bplist00") {
            return mentions_value_data;
        }
        if crate::inspect::looks_like_xml(content) {
            let head = &content[..content.len().min(512)];
            return crate::inspect::contains(head, b"<plist") && mentions_value_data;
        }
        false
    }

    fn load(&self, content: &[u8]) -> Result<Vec<Secret>> {
        // `from_reader` auto-detects XML vs binary; Cursor gives the Read + Seek it
        // needs over the in-memory bytes.
        let root = Value::from_reader(Cursor::new(content))
            .context("failed to parse keychain plist (XML or binary)")?;
        let mut secrets = Vec::new();
        collect_items(&root, &mut secrets);
        Ok(secrets)
    }
}

/// Walk the plist value, turning every `v_Data`-bearing dict into a [`Secret`].
///
/// A dict that carries key material is one item and is not descended into; other
/// dicts and arrays are traversed so items grouped under class keys are found.
fn collect_items(value: &Value, out: &mut Vec<Secret>) {
    match value {
        Value::Dictionary(dict) => {
            if let Some(secret) = item_from_dict(dict) {
                out.push(secret);
            } else {
                for (_, child) in dict.iter() {
                    collect_items(child, out);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_items(item, out);
            }
        }
        _ => {}
    }
}

/// Build a [`Secret`] from a dictionary, if it carries `v_Data`.
fn item_from_dict(dict: &Dictionary) -> Option<Secret> {
    let data = dict.get(VALUE_DATA_KEY)?.as_data()?.to_vec();
    Some(Secret {
        account: string_attr(dict, ACCOUNT_KEY),
        service: string_attr(dict, SERVICE_KEY),
        access_group: string_attr(dict, ACCESS_GROUP_KEY),
        label: string_attr(dict, LABEL_KEY),
        protection_class: string_attr(dict, PROTECTION_CLASS_KEY),
        data,
        source: SOURCE_NAME.to_string(),
    })
}

/// Read dict key `key` as an owned string, when present and string-typed.
fn string_attr(dict: &Dictionary, key: &str) -> Option<String> {
    dict.get(key)?.as_string().map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decrypt::profile::{KeyEncoding, KeyMaterial};

    // Two genp items in a root array. v_Data values:
    //   3q2+7w==  -> 0xDEADBEEF      (Signal item)
    //   AAECAw==  -> 0x00 01 02 03   (WhatsApp item)
    const XML_DUMP: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <array>
            <dict>
                <key>class</key><string>genp</string>
                <key>svc</key><string>TSKeyChainService</string>
                <key>acct</key><string>OWSDatabaseCipherKeySpec</string>
                <key>agrp</key><string>group.org.whispersystems.signal</string>
                <key>pdmn</key><string>ak</string>
                <key>v_Data</key><data>3q2+7w==</data>
            </dict>
            <dict>
                <key>class</key><string>genp</string>
                <key>svc</key><string>WhatsApp</string>
                <key>acct</key><string>wa-key</string>
                <key>v_Data</key><data>AAECAw==</data>
            </dict>
        </array>
        </plist>"#;

    /// Encode the same two-item dump as a *binary* plist using the crate's writer,
    /// so the loader is exercised over the binary object table, not just XML.
    fn binary_dump() -> Vec<u8> {
        fn item(svc: &str, acct: &str, data: Vec<u8>) -> Value {
            let mut d = Dictionary::new();
            d.insert("svc".into(), Value::String(svc.into()));
            d.insert("acct".into(), Value::String(acct.into()));
            d.insert("v_Data".into(), Value::Data(data));
            Value::Dictionary(d)
        }
        let root = Value::Array(vec![
            item(
                "TSKeyChainService",
                "OWSDatabaseCipherKeySpec",
                vec![0xde, 0xad, 0xbe, 0xef],
            ),
            item("WhatsApp", "wa-key", vec![0, 1, 2, 3]),
        ]);
        let mut buf = Vec::new();
        root.to_writer_binary(&mut buf).unwrap();
        buf
    }

    #[test]
    fn detects_both_encodings() {
        assert!(KeychainPlist.detect(XML_DUMP));
        let bin = binary_dump();
        assert!(bin.starts_with(b"bplist00"));
        assert!(KeychainPlist.detect(&bin));

        // A plist without v_Data is not a keychain dump.
        assert!(!KeychainPlist.detect(br#"<?xml version="1.0"?><plist><dict/></plist>"#));
        // Random binary that is not a plist is rejected.
        assert!(!KeychainPlist.detect(b"\x00\x01not a plist"));
    }

    #[test]
    fn loads_xml_items_with_attributes_and_decoded_data() {
        let secrets = KeychainPlist.load(XML_DUMP).unwrap();
        assert_eq!(secrets.len(), 2);

        let signal = &secrets[0];
        assert_eq!(signal.service.as_deref(), Some("TSKeyChainService"));
        assert_eq!(signal.account.as_deref(), Some("OWSDatabaseCipherKeySpec"));
        assert_eq!(
            signal.access_group.as_deref(),
            Some("group.org.whispersystems.signal")
        );
        assert_eq!(signal.protection_class.as_deref(), Some("ak"));
        assert_eq!(signal.data, vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(signal.source, "keychain-plist");

        // The raw item bytes decode straight through as a Raw key.
        assert_eq!(
            signal.key_material(KeyEncoding::Raw).unwrap(),
            KeyMaterial::Raw(vec![0xde, 0xad, 0xbe, 0xef])
        );

        assert_eq!(secrets[1].service.as_deref(), Some("WhatsApp"));
        assert_eq!(secrets[1].data, vec![0, 1, 2, 3]);
    }

    #[test]
    fn loads_binary_items_identically_to_xml() {
        let secrets = KeychainPlist.load(&binary_dump()).unwrap();
        assert_eq!(secrets.len(), 2);
        assert_eq!(
            secrets[0].account.as_deref(),
            Some("OWSDatabaseCipherKeySpec")
        );
        assert_eq!(secrets[0].data, vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(secrets[1].service.as_deref(), Some("WhatsApp"));
        assert_eq!(secrets[1].data, vec![0, 1, 2, 3]);
    }

    #[test]
    fn finds_items_grouped_under_class_keys() {
        // A root dict grouping items by class, rather than a flat array.
        let grouped = br#"<plist><dict>
            <key>genp</key>
            <array>
                <dict><key>svc</key><string>A</string><key>v_Data</key><data>AAA=</data></dict>
            </array>
            <key>keys</key>
            <array>
                <dict><key>svc</key><string>B</string><key>v_Data</key><data>AQA=</data></dict>
            </array>
        </dict></plist>"#;
        let secrets = KeychainPlist.load(grouped).unwrap();
        assert_eq!(secrets.len(), 2);
        assert_eq!(secrets[0].service.as_deref(), Some("A"));
        assert_eq!(secrets[1].service.as_deref(), Some("B"));
    }
}
