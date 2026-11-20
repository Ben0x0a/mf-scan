//! Where each member of an `adb backup` lived on the device.
//!
//! Defines: [`roots`], the `(archive prefix, device path)` pairs that
//! `report::export::plan_tree` rebuilds an `.ab` with, and [`is_backup_member`].
//! Used by: `ops::rebuild` (the Android arm) and `ops::apps` (recognising an `.ab`).
//! Uses: nothing; this is a fixed table.
//!
//! An `.ab` has no file table like iOS's `Manifest.db`: the tar member names are the
//! index, `apps/<package>/<token>/<path>` and `shared/<volume>/<path>`. Each token
//! names one app directory, defined by AOSP's `FullBackup.java` (the `*_TREE_TOKEN`
//! constants) and `FullBackup.BackupScheme.tokenToDirectoryPath`. Paths are for user 0,
//! the user `adb backup` runs as by default. `data/data/<package>` is that user's
//! credential-encrypted data directory, the form acquisitions commonly present.
//!
//! Anything with no device location (each app's `_manifest` and `_meta`, key/value
//! records, unknown tokens, anything outside `apps/` and `shared/`) goes under
//! [`NO_DEVICE_PATH_ROOT`], so nothing in the archive is dropped and nothing is given
//! a device path it did not have.
//!
//! WHY a compiled table, not a data file: as with the iOS domains (ADR 0004), these
//! are fixed platform constants, and a typo should fail at build time, not silently
//! on an operator's machine. The values match the Python reconstructor's
//! `config/android_maps/aosp_full_backup.yaml`, so the two tools' outputs compare.

use std::collections::BTreeMap;

use crate::core::models::Entry;

/// Root for members with no location on the device.
pub const NO_DEVICE_PATH_ROOT: &str = "backup_only";

/// `(token, device path)`, with `{package}` standing for the package name.
const APP_TOKENS: &[(&str, &str)] = &[
    ("r", "data/data/{package}"),
    ("f", "data/data/{package}/files"),
    ("db", "data/data/{package}/databases"),
    ("sp", "data/data/{package}/shared_prefs"),
    ("c", "data/data/{package}/cache"),
    ("nb", "data/data/{package}/no_backup"),
    ("d_r", "data/user_de/0/{package}"),
    ("d_f", "data/user_de/0/{package}/files"),
    ("d_db", "data/user_de/0/{package}/databases"),
    ("d_sp", "data/user_de/0/{package}/shared_prefs"),
    ("d_c", "data/user_de/0/{package}/cache"),
    ("d_nb", "data/user_de/0/{package}/no_backup"),
    ("ef", "storage/emulated/0/Android/data/{package}/files"),
    ("obb", "storage/emulated/0/Android/obb/{package}"),
    // On the device an APK sits under a randomised directory the backup does not
    // record, so this path is an approximation.
    ("a", "data/app/{package}"),
    // Key/value records are not files on the device.
    ("k", "backup_only/apps/{package}/k"),
];

/// Volume 0 of `shared/<volume>` is the primary shared storage.
const PRIMARY_SHARED_VOLUME: &str = "0";
const PRIMARY_SHARED_PATH: &str = "storage/emulated/0";

/// The device path of one app token, if the token is known.
fn token_path(token: &str, package: &str) -> Option<String> {
    APP_TOKENS
        .iter()
        .find(|(known, _)| *known == token)
        .map(|(_, path)| path.replace("{package}", package))
}

/// The `(archive prefix, device path)` roots covering every entry, deterministically
/// ordered. `plan_tree` attributes each member to its longest matching prefix.
pub fn roots<'e>(names: impl Iterator<Item = &'e str>) -> Vec<(String, String)> {
    let mut roots: BTreeMap<String, String> = BTreeMap::new();
    for name in names {
        let parts: Vec<&str> = name
            .split('/')
            .filter(|p| !p.is_empty() && *p != ".")
            .collect();
        let Some(first) = parts.first() else { continue };
        // Every top-level name gets a root, so nothing falls through unattributed.
        roots
            .entry((*first).to_string())
            .or_insert_with(|| format!("{NO_DEVICE_PATH_ROOT}/{first}"));
        match parts.as_slice() {
            ["apps", package, rest @ ..] => {
                roots
                    .entry(format!("apps/{package}"))
                    .or_insert_with(|| format!("{NO_DEVICE_PATH_ROOT}/apps/{package}"));
                // A file directly under the package (`_manifest`, `_meta`) is backup
                // metadata, not a token directory, unless it is a known token's own
                // directory record.
                if let [token, inner @ ..] = rest {
                    let path = token_path(token, package);
                    if !inner.is_empty() || path.is_some() {
                        roots
                            .entry(format!("apps/{package}/{token}"))
                            .or_insert_with(|| {
                                path.unwrap_or_else(|| {
                                    format!("{NO_DEVICE_PATH_ROOT}/apps/{package}/{token}")
                                })
                            });
                    }
                }
            }
            ["shared", volume, ..] => {
                roots.entry(format!("shared/{volume}")).or_insert_with(|| {
                    if *volume == PRIMARY_SHARED_VOLUME {
                        PRIMARY_SHARED_PATH.to_string()
                    } else {
                        format!("{NO_DEVICE_PATH_ROOT}/shared/{volume}")
                    }
                });
            }
            _ => {}
        }
    }
    roots.into_iter().collect()
}

/// Whether `name` has the shape of an `.ab` app member: `apps/<package>/...`, where the
/// next segment is a known token or the per-app `_manifest`.
///
/// Deliberately narrow: an unrelated acquisition can easily have a top-level `apps/`.
pub fn is_backup_member(name: &str) -> bool {
    let mut parts = name.split('/');
    if parts.next() != Some("apps") {
        return false;
    }
    let (Some(package), Some(next)) = (parts.next(), parts.next()) else {
        return false;
    };
    package.contains('.') && (next == "_manifest" || token_path(next, package).is_some())
}

/// The names of `entries`, for [`roots`].
pub fn entry_names(entries: &[Entry]) -> impl Iterator<Item = &str> {
    entries.iter().map(|e| e.name.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::layout::{output_roots, tree_dir};

    fn device_path(name: &str, names: &[&str]) -> String {
        let roots = output_roots(&roots(names.iter().copied()));
        tree_dir(name, &roots).unwrap_or_else(|| panic!("{name} has no root"))
    }

    /// Mirrors `test_path_mapping` in the Python reconstructor's test suite.
    #[test]
    fn maps_members_as_the_python_reconstructor_does() {
        let cases = [
            ("apps/com.x/f/a.txt", "data/data/com.x/files/a.txt"),
            ("apps/com.x/db/m.db", "data/data/com.x/databases/m.db"),
            ("apps/com.x/sp/p.xml", "data/data/com.x/shared_prefs/p.xml"),
            ("apps/com.x/r/lib/a.so", "data/data/com.x/lib/a.so"),
            ("apps/com.x/d_f/a", "data/user_de/0/com.x/files/a"),
            (
                "apps/com.x/ef/a",
                "storage/emulated/0/Android/data/com.x/files/a",
            ),
            ("apps/com.x/obb/a", "storage/emulated/0/Android/obb/com.x/a"),
            ("apps/com.x/a/base.apk", "data/app/com.x/base.apk"),
            ("apps/com.x/k/record", "backup_only/apps/com.x/k/record"),
            ("apps/com.x/_manifest", "backup_only/apps/com.x/_manifest"),
            ("apps/com.x/zz/a", "backup_only/apps/com.x/zz/a"),
            ("shared/0/DCIM/a.jpg", "storage/emulated/0/DCIM/a.jpg"),
            ("shared/1/a.jpg", "backup_only/shared/1/a.jpg"),
            ("other/a.bin", "backup_only/other/a.bin"),
        ];
        let names: Vec<&str> = cases.iter().map(|(name, _)| *name).collect();
        for (name, expected) in cases {
            assert_eq!(device_path(name, &names), expected, "{name}");
        }
    }

    #[test]
    fn recognises_only_the_shape_of_a_backup_member() {
        assert!(is_backup_member("apps/com.x/db/m.db"));
        assert!(is_backup_member("apps/com.x/_manifest"));
        assert!(
            !is_backup_member("apps/settings/db/m.db"),
            "no dot in the package"
        );
        assert!(!is_backup_member("apps/com.x/notes.txt"));
        assert!(!is_backup_member("data/data/com.x/db"));
    }
}
