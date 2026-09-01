//! iOS MobileContainerManager code-signing references (`references.sqlite3`).
//!
//! Defines: [`SigningRecord`] (one app's code-signing facts as the container
//! manager recorded them — entitlements, App Groups, keychain groups, signing
//! team/identity) and [`McmReferences`], the bundle-id-keyed table of them read
//! from `/private/var/mobile/Library/MobileContainerManager/references.sqlite3`.
//! Used by: `crate::ops::apps::catalog` (attributes shared App Group containers to
//! the owning app) and `crate::ops::apps::ios_ffs`.
//! Uses: [`crate::formats::sqlite`] (the in-house reader — no SQLite library), the
//! `plist` crate (the entitlement blobs are binary plists), and the
//! [`crate::core::source::Source`] trait.
//!
//! ── What this artefact is, and why it is the authoritative group source ─────
//! `installd` records, per installed code-signing identity, the entitlements iOS
//! actually provisioned the app's containers from. The path to an app's groups is:
//!
//! ```text
//! code_signing_info(id, code_signing_id_text)      ← the bundle id, as MCM knows it
//!   └─ code_signing_data(cs_info_id → id, data)    ← a binary plist blob
//!        └─ com.apple.MobileContainerManager.Entitlements
//!             └─ com.apple.security.application-groups
//! ```
//!
//! WHY this beats reading the app binary's code signature: it is present for
//! essentially every installed app (measured 214/214 and 223/225 app-data
//! containers on two real acquisitions), whereas the executable is only in an
//! extraction some of the time — and where both existed the two never disagreed.
//! It does NOT replace the container-metadata scan in [`super::containers`]: this
//! file holds no container GUIDs at all, and is not a strict superset of the
//! installed apps, so the metadata plists remain the source of truth for the
//! container → app mapping.
//!
//! WHY the join needs row ids: `code_signing_info.id` is an `INTEGER PRIMARY KEY`,
//! i.e. an alias of the cell's row id, so it is not stored in the record and
//! decodes to `Null`. See [`crate::formats::sqlite`]'s `read_table_with_rowid`.
//!
//! WRITE-AHEAD LOG: a `references.sqlite3-wal` sidecar is replayed onto the
//! database image before reading ([`crate::formats::sqlite`]'s `checkpoint`), and
//! this is not optional. Measured on a real iPhone FFS acquisition: the main file
//! alone held 1077 records, the WAL added 12 and superseded 8 — including
//! replacing an "Unsigned Placeholder" stub for an installed messaging app with
//! its real record and its App Group. Reading the main file alone would have
//! reported that app as having no shared containers.
//! [`McmReferences::wal_replayed`] records whether a replay happened, so the fact
//! appears in the analyst-facing output rather than being invisible.
//!
//! Degrade-don't-die throughout: a missing, truncated or corrupt database yields
//! an empty table, and an unparseable blob skips that one app — never an error,
//! because an acquisition is routinely partial.

use std::collections::HashMap;
use std::io::Cursor;

use serde::Serialize;

use crate::core::source::Source;
use crate::formats::sqlite::{Value, checkpoint, read_table, read_table_with_rowid};

/// Path suffix of the container manager's code-signing reference database.
///
/// Matched as a suffix rather than an absolute path because an acquisition's root
/// varies (one vendor prefixes every path with `filesystem1/`, another does not).
const REFERENCES_PATH_SUFFIX: &str = "Library/MobileContainerManager/references.sqlite3";

/// Table holding one row per registered code-signing identity.
const INFO_TABLE: &str = "code_signing_info";
/// The bundle id (occasionally team-id-prefixed, e.g. `5Q4J53EFRC.com.sbb.ch`),
/// matching the `MCMMetadataIdentifier` in a container's metadata plist.
const CODE_SIGNING_ID_COLNAME: &str = "code_signing_id_text";

/// Table holding the serialised signing/entitlement blob for each identity.
const DATA_TABLE: &str = "code_signing_data";
/// Foreign key into `code_signing_info.id` (i.e. into that table's row ids).
const CS_INFO_ID_COLNAME: &str = "cs_info_id";
/// The binary-plist payload column.
const DATA_COLNAME: &str = "data";

/// Top-level blob key holding the app's entitlements dictionary.
const ENTITLEMENTS_KEY: &str = "com.apple.MobileContainerManager.Entitlements";
/// Entitlement key listing the App Groups the app may write to.
const APPLICATION_GROUPS_KEY: &str = "com.apple.security.application-groups";
/// Entitlement key listing the app's keychain access groups.
const KEYCHAIN_GROUPS_KEY: &str = "keychain-access-groups";

/// One app's code-signing record, as MobileContainerManager recorded it.
///
/// Every field is best-effort: a blob that omits a key yields `None`/empty rather
/// than failing the record, because the key set varies by iOS version and by how
/// the app was signed (App Store, enterprise, development).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct SigningRecord {
    /// `CodeInfoIdentifier` — the plain bundle id, which differs from the table
    /// key when the latter carries a team-id prefix.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bundle_id: Option<String>,
    /// `TeamIdentifier` — the developer team the app was signed under.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub team_identifier: Option<String>,
    /// `SignerIdentity` — e.g. `Apple iPhone OS Application Signing`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_identity: Option<String>,
    /// `SignerOrganization` (the plist key is US-spelt; the field is not).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_organisation: Option<String>,
    /// Whether MobileContainerManager recorded an entitlements dictionary for this
    /// app at all.
    ///
    /// WHY it is worth a field: it separates "declared no App Groups" from "we do
    /// not know". When the dictionary is present, its silence on
    /// `application-groups` IS the answer — the app has none — and a name
    /// heuristic must not overrule it. When it is absent, nothing is known and the
    /// caller may fall back.
    pub entitlements_recorded: bool,
    /// `com.apple.security.application-groups` — the authoritative App Groups.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub application_groups: Vec<String>,
    /// `keychain-access-groups` — the keychain groups the app may read.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub keychain_access_groups: Vec<String>,
}

/// Every code-signing record in a source's `references.sqlite3`, keyed by the
/// identifier the container metadata plists use.
pub struct McmReferences {
    records: HashMap<String, SigningRecord>,
    wal_replayed: bool,
}

impl McmReferences {
    /// An empty table — the state for a source with no such database (an iOS
    /// backup, an Android extraction, a generic archive).
    pub fn empty() -> Self {
        Self {
            records: HashMap::new(),
            wal_replayed: false,
        }
    }

    /// Locate and read the database in `source`.
    ///
    /// HOW: find the entry whose path ends with [`REFERENCES_PATH_SUFFIX`], read
    /// its bytes, replay any `-wal` sidecar onto them, then join
    /// `code_signing_info`'s row ids to `code_signing_data.cs_info_id` and decode
    /// each blob into a [`SigningRecord`]. Any failure at any step degrades — a
    /// WAL that will not replay leaves the main image in use, and an unreadable
    /// database leaves an empty table.
    pub fn build(source: &dyn Source) -> Self {
        let Some(entry) = source
            .entries()
            .iter()
            .find(|e| !e.is_dir() && e.name.ends_with(REFERENCES_PATH_SUFFIX))
        else {
            return Self::empty();
        };
        let Ok(main) = source.content(entry) else {
            return Self::empty();
        };

        // Fold in the sidecar: rows written since the last checkpoint live only
        // there, and on a live acquisition that routinely includes current ones.
        let wal_name = format!("{}-wal", entry.name);
        let replayed = source
            .entries()
            .iter()
            .find(|e| e.name == wal_name)
            .and_then(|wal_entry| source.content(wal_entry).ok())
            .and_then(|wal| checkpoint(&main, &wal));

        match replayed {
            Some(image) => Self {
                records: parse_records(&image),
                wal_replayed: true,
            },
            None => Self {
                records: parse_records(&main),
                wal_replayed: false,
            },
        }
    }

    /// True when a `references.sqlite3-wal` sidecar was found and replayed into
    /// the image these records were read from.
    pub fn wal_replayed(&self) -> bool {
        self.wal_replayed
    }

    /// The record for a code-signing identifier, as it appears in a container's
    /// `MCMMetadataIdentifier`.
    pub fn get(&self, code_signing_id: &str) -> Option<&SigningRecord> {
        self.records.get(code_signing_id)
    }
}

/// Decode both tables and join them into the identifier → record map.
fn parse_records(bytes: &[u8]) -> HashMap<String, SigningRecord> {
    // The identity table: its `id` column is an aliased row id, so the join key
    // comes from the cell row id, not from a column.
    let Some(info_rows) = read_table_with_rowid(bytes, INFO_TABLE, &[CODE_SIGNING_ID_COLNAME])
    else {
        return HashMap::new();
    };
    let Some(data_rows) = read_table(bytes, DATA_TABLE, &[CS_INFO_ID_COLNAME, DATA_COLNAME]) else {
        return HashMap::new();
    };

    // Index the blobs by the identity row id they belong to. `cs_info_id` is
    // UNIQUE, so one blob per identity.
    let blobs: HashMap<i64, &[u8]> = data_rows
        .iter()
        .filter_map(|row| match (row.first(), row.get(1)) {
            (Some(Value::Int(cs_info_id)), Some(Value::Blob(data))) => {
                Some((*cs_info_id, data.as_slice()))
            }
            _ => None,
        })
        .collect();

    info_rows
        .iter()
        .filter_map(|(rowid, row)| {
            let Some(Value::Text(id)) = row.first() else {
                return None;
            };
            let blob = blobs.get(&(*rowid as i64))?;
            // An unreadable blob loses this one app, not the whole table.
            let record = parse_signing_blob(blob)?;
            Some((id.clone(), record))
        })
        .collect()
}

/// Decode one `code_signing_data.data` binary plist into a [`SigningRecord`].
fn parse_signing_blob(blob: &[u8]) -> Option<SigningRecord> {
    let value = plist::Value::from_reader(Cursor::new(blob)).ok()?;
    let dict = value.as_dictionary()?;
    // The entitlements sub-dictionary is optional: a record with only the signing
    // identity is still worth keeping (it carries the team id).
    let entitlements = dict
        .get(ENTITLEMENTS_KEY)
        .and_then(plist::Value::as_dictionary);

    Some(SigningRecord {
        entitlements_recorded: entitlements.is_some(),
        bundle_id: dict_string(dict, "CodeInfoIdentifier"),
        team_identifier: dict_string(dict, "TeamIdentifier"),
        signer_identity: dict_string(dict, "SignerIdentity"),
        signer_organisation: dict_string(dict, "SignerOrganization"),
        application_groups: entitlements
            .map(|e| dict_string_array(e, APPLICATION_GROUPS_KEY))
            .unwrap_or_default(),
        keychain_access_groups: entitlements
            .map(|e| dict_string_array(e, KEYCHAIN_GROUPS_KEY))
            .unwrap_or_default(),
    })
}

/// Read a string value by key, or `None` when absent or not a string.
fn dict_string(dict: &plist::Dictionary, key: &str) -> Option<String> {
    dict.get(key)?.as_string().map(str::to_string)
}

/// Read an array-of-strings value by key, skipping non-string elements.
fn dict_string_array(dict: &plist::Dictionary, key: &str) -> Vec<String> {
    dict.get(key)
        .and_then(plist::Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_string().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The committed fixture mirrors the real schema with THREE identities whose
    /// row ids (7, 11, 23) are non-contiguous and whose blob rows are stored in a
    /// different order — so a reader that joined by row position, or by the data
    /// table's own row id, would fail these assertions rather than pass by luck.
    /// It is synthetic: no bytes from any device.
    fn fixture() -> HashMap<String, SigningRecord> {
        let bytes = std::fs::read("tests/fixtures/mcm_references.sqlite3").unwrap();
        parse_records(&bytes)
    }

    #[test]
    fn joins_blobs_to_the_right_identity_by_rowid() {
        let records = fixture();
        // The corrupt blob's app is dropped; the two decodable ones survive.
        assert_eq!(records.len(), 2);

        let full = records.get("com.example.full").expect("full record");
        assert_eq!(
            full.application_groups,
            vec![
                "group.com.example.shared",
                "group.com.othervendor.crossbrand"
            ]
        );
        assert_eq!(full.team_identifier.as_deref(), Some("TEAMID1234"));
        assert_eq!(full.signer_organisation.as_deref(), Some("Example Ltd"));
        assert_eq!(full.bundle_id.as_deref(), Some("com.example.full"));
        assert_eq!(
            full.keychain_access_groups,
            vec!["TEAMID1234.com.example.full"]
        );
    }

    #[test]
    fn record_without_groups_is_kept_for_its_signing_facts() {
        let records = fixture();
        let rec = records.get("com.example.nogroups").expect("record");
        assert!(rec.application_groups.is_empty());
        // The entitlements WERE recorded — so "no groups" is an answer, not a gap.
        assert!(rec.entitlements_recorded);
        assert_eq!(rec.team_identifier.as_deref(), Some("TEAMID5678"));
    }

    /// A blob that is not a property list must lose only its own app.
    #[test]
    fn corrupt_blob_is_skipped_not_fatal() {
        assert!(!fixture().contains_key("com.example.corrupt"));
    }

    /// A buffer that is not a database at all yields nothing, without panicking.
    #[test]
    fn non_database_yields_no_records() {
        assert!(parse_records(b"not a database at all").is_empty());
    }

    /// The empty table — what every non-iOS-FFS source gets — answers "nothing
    /// known" rather than panicking or claiming an absence of groups.
    #[test]
    fn empty_table_knows_nothing() {
        let refs = McmReferences::empty();
        assert!(!refs.wal_replayed());
        assert!(refs.get("com.example.full").is_none());
    }
}
