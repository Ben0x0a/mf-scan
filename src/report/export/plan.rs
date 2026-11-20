//! Plan an export: where each file goes, without writing anything.
//!
//! Defines: [`ExportItem`] / [`ExportPlan`] / [`Renamed`], [`plan`] (one folder per
//! file) and [`plan_tree`] (the device tree), the clash rule (`disambiguate`,
//! `fold_case`), and the name of a decrypted copy ([`decrypted_name_numbered`]).
//! Used by: `report::export::write` and `manifest`, and the binary's export paths.
//! Uses: `core::layout` (tree layout), `ops::search::MatchedFile`.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;

use crate::core::layout::{
    attribute, output_roots, sanitise_basename, sanitise_segment, split_dir_base,
};
use crate::core::models::Encoding;
use crate::ops::search::MatchedFile;

/// Number of hex characters (4 bits each) of the path hash in a folder name.
const HASH_HEX_LEN: usize = 10;

/// One file to export, with its assigned output location.
pub struct ExportItem {
    pub internal_path: String,
    pub file_start: u64,
    pub folder: String, // <basename>_<hash>[ _0x<offset> on collision ]
    pub name: String,   // sanitised basename (the file inside the folder)
    pub size: u64,
    pub compressed: bool,
    pub offsets: Vec<u64>,
    /// Matches per encoding, when other encodings than plain were found (see
    /// `MatchedFile::encodings`); empty otherwise.
    pub encodings: Vec<(Encoding, usize)>,
}

impl ExportItem {
    /// Relative output path: `<folder>/<basename>`, or just the name at the root.
    pub(crate) fn output_path(&self) -> String {
        if self.folder.is_empty() {
            return self.name.clone();
        }
        format!("{}/{}", self.folder, self.name)
    }
}

/// A complete export plan plus the total size of all matched files.
pub struct ExportPlan {
    pub items: Vec<ExportItem>,
    pub total_size: u64,
    /// Files whose destination had to be renamed because another file already
    /// claimed that path. Empty in the normal case, and reported when not: a tool
    /// must not quietly hand back a name other than the one it was asked for.
    pub renamed: Vec<Renamed>,
}

/// One file whose output path collided with another's and was disambiguated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Renamed {
    /// The path inside the source.
    pub internal_path: String,
    /// The destination it would have taken.
    pub wanted: String,
    /// The destination it was given instead.
    pub used: String,
}

/// The file name of the `n`th decrypted copy: `.decrypted` before the extension, so
/// the copy keeps the extension tools open it by (`signal.sqlite` →
/// `signal.decrypted.sqlite`), numbered after the first (`x.decrypted-2.db` for `n` =
/// 2). A name with no extension, or only a leading dot, gets the suffix at the end.
///
/// An encryption suffix such as `.crypt14` is dropped first, so WhatsApp's
/// `msgstore.db.crypt14` becomes `msgstore.decrypted.db`, a name tools open as SQLite.
pub(crate) fn decrypted_name_numbered(name: &str, n: usize) -> String {
    let tag = if n > 1 {
        format!(".decrypted-{n}")
    } else {
        ".decrypted".to_string()
    };
    let name = strip_encryption_suffix(name);
    match name.rfind('.') {
        Some(dot) if dot > 0 => format!("{}{tag}{}", &name[..dot], &name[dot..]),
        _ => format!("{name}{tag}"),
    }
}

/// `name` without a trailing `.cryptNN` (WhatsApp's encrypted-backup suffix).
fn strip_encryption_suffix(name: &str) -> &str {
    match name.rsplit_once(".crypt") {
        Some((stem, digits))
            if !stem.is_empty()
                && !digits.is_empty()
                && digits.bytes().all(|b| b.is_ascii_digit()) =>
        {
            stem
        }
        _ => name,
    }
}

/// Build an export plan from the matched files (one item per file, in order).
///
/// HOW: assign each file `<basename>_<path-hash>` as its folder, then resolve
/// the (rare) folder collision by appending the unique hex offset.
pub fn plan(files: &[MatchedFile]) -> ExportPlan {
    let mut total_size = 0u64;
    let mut items: Vec<ExportItem> = files
        .iter()
        .map(|file| {
            total_size += file.entry.uncompressed_size;
            let name = sanitise_basename(&file.entry.name);
            let folder = format!("{name}_{}", path_hash(&file.entry.name));
            ExportItem {
                internal_path: file.entry.name.clone(),
                file_start: file.entry.archive_data_start().unwrap_or(0),
                folder,
                name,
                size: file.entry.uncompressed_size,
                compressed: file.entry.is_compressed(),
                offsets: file.offsets.clone(),
                encodings: file.encodings.clone(),
            }
        })
        .collect();

    // Disambiguate any folder name shared by more than one file. Comparison is
    // case-insensitive because Windows/macOS file systems are.
    let mut counts: HashMap<String, usize> = HashMap::new();
    for item in &items {
        *counts.entry(item.folder.to_ascii_lowercase()).or_default() += 1;
    }
    for item in &mut items {
        if counts[&item.folder.to_ascii_lowercase()] > 1 {
            item.folder = format!("{}_0x{:x}", item.folder, item.file_start);
        }
    }

    let renamed = disambiguate(&mut items);
    ExportPlan {
        items,
        total_size,
        renamed,
    }
}

/// A path as a case- and normalisation-insensitive file system compares it.
///
/// Two folds, because a phone's file system (ext4, f2fs) compares names byte for
/// byte while the export may land on macOS or Windows:
///   • Unicode case: `Été.jpg` and `été.jpg` are one name on APFS and NTFS;
///   • accent encoding: `é` stored as one code point (U+00E9, NFC) or as `e` plus a
///     combining accent (U+0301, NFD) is one name on macOS.
/// HOW: decompose, lowercase, recompose, so both spellings of an accented letter
/// reach the same canonical string whatever case or form they started in.
pub(crate) fn fold_case(path: &str) -> String {
    path.nfd()
        .collect::<String>()
        .to_lowercase()
        .nfc()
        .collect()
}

/// Give every item a destination no other item claims, comparing case-INSENSITIVELY.
///
/// WHY case-insensitively even on a case-sensitive host: macOS and Windows file
/// systems are case-insensitive by default, so `com.apple.Preferences.plist` and
/// `com.apple.preferences.plist` — two DISTINCT files with distinct `fileID`s, both
/// present in a real iPhone backup — silently overwrite each other there. Folding
/// only on hosts that need it would make the output depend on where the tool ran,
/// which is exactly what a forensic export must not do: the same evidence must
/// produce the same tree everywhere.
///
/// The suffix format (`name~1`, `name~2`) matches the Python
/// `ios-backup-reconstructor`, so the two tools agree on the resulting paths.
///
/// Items are walked in order and the FIRST claimant keeps the unsuffixed name.
/// Callers build `items` from entries sorted by name, so the assignment is
/// reproducible.
fn disambiguate(items: &mut [ExportItem]) -> Vec<Renamed> {
    let mut claimed: HashSet<String> = HashSet::with_capacity(items.len());
    let mut renamed = Vec::new();
    for item in items.iter_mut() {
        let wanted = item.output_path();
        if claimed.insert(fold_case(&wanted)) {
            continue;
        }
        let base = item.name.clone();
        let mut suffix = 1usize;
        loop {
            item.name = format!("{base}~{suffix}");
            let candidate = item.output_path();
            if claimed.insert(fold_case(&candidate)) {
                renamed.push(Renamed {
                    internal_path: item.internal_path.clone(),
                    wanted,
                    used: candidate,
                });
                break;
            }
            suffix += 1;
        }
    }
    renamed
}

/// Build an export plan that PRESERVES each file's directory tree under a
/// per-container label — the layout the `app export` path wants (one output
/// subfolder per app container, real names retained).
///
/// `roots` is a list of `(prefix, label)` pairs: `prefix` is a resolved source
/// path prefix (an app's data container, an extension/widget container, an App
/// Group, or a backup domain) and `label` is the output subfolder it maps to
/// (e.g. `"com.app/AppData_5A92C2C1"`). Each file is attributed to the LONGEST
/// matching prefix, that prefix is stripped, and the remaining relative path is
/// rebuilt under `label` with every segment host-sanitised so the on-device tree
/// is mirrored safely under the destination.
///
/// WHY longest-prefix wins: containers can nest (an extension container may sit
/// inside another registered directory), so the most specific owner must claim the
/// file — the one rule of [`crate::core::layout::PrefixIndex`].
/// WHY per-segment sanitisation (not only the member-name cleaning at write time):
/// the tree is reconstructed here, so each component must be made safe to extract on
/// any host as it is built; every member name, a re-ingested manifest's included,
/// still passes through `write::member_name`, which drops any `..`.
pub fn plan_tree(files: &[MatchedFile], roots: &[(String, String)]) -> ExportPlan {
    let roots = output_roots(roots);
    let mut total_size = 0u64;
    let mut items: Vec<ExportItem> = files
        .iter()
        .map(|file| {
            total_size += file.entry.uncompressed_size;
            let path = file.entry.name.as_str();
            let (folder, name) = match attribute(path, &roots) {
                // The file IS the root: the label's last segment is its name.
                Some((label, "")) => match label.rsplit_once('/') {
                    Some((folder, name)) => (folder.to_string(), name.to_string()),
                    None => (String::new(), label.to_string()),
                },
                Some((label, rel)) => {
                    let (dirs, base) = split_dir_base(rel);
                    let mut folder = label.to_string();
                    for seg in dirs {
                        folder.push('/');
                        folder.push_str(&sanitise_segment(seg));
                    }
                    (folder, sanitise_segment(base))
                }
                // Defensive: a file under no root keeps the flat hashed layout
                // rather than being lost (should not happen — callers pass only
                // files gathered from these prefixes).
                None => {
                    let name = sanitise_basename(path);
                    (format!("{name}_{}", path_hash(path)), name)
                }
            };

            ExportItem {
                internal_path: file.entry.name.clone(),
                file_start: file.entry.archive_data_start().unwrap_or(0),
                folder,
                name,
                size: file.entry.uncompressed_size,
                compressed: file.entry.is_compressed(),
                offsets: file.offsets.clone(),
                encodings: file.encodings.clone(),
            }
        })
        .collect();

    let renamed = disambiguate(&mut items);
    ExportPlan {
        items,
        total_size,
        renamed,
    }
}

/// Stable short hash of an internal path: low `HASH_HEX_LEN` hex digits of
/// FNV-1a-64.
///
/// WHY FNV-1a and not `std::hash::DefaultHasher`: the standard hasher's output
/// is explicitly *not* stable across Rust versions/platforms, which would break
/// the promise that the same file path always yields the same folder name. A
/// fixed algorithm keeps the name identical forever.
fn path_hash(path: &str) -> String {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = FNV_OFFSET;
    for &byte in path.as_bytes() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    let bits = HASH_HEX_LEN * 4;
    let mask = if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    };
    format!("{:0width$x}", hash & mask, width = HASH_HEX_LEN)
}
