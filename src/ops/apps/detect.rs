//! Which acquisition layout a source presents, and each container's file tally.
//!
//! Defines: [`detect`] (the platform sniffer) and `tally` (each container's file
//! count and size, in one pass).
//! Used by: `catalog` (`AppCatalog::build`), and re-exported as `ops::apps::detect`.
//! Uses: the data types in `types`, [`crate::platform::ios::domains`] (backup
//! domains), [`crate::platform::android::paths::is_backup_member`] (`.ab` members).
//!
//! WHY its own module: reading the source's shape is done once, before and apart
//! from the questions the catalogue answers about apps.

use std::collections::HashMap;

use super::types::{AppContainer, Platform};
use crate::core::source::Source;
use crate::platform::android::paths::is_backup_member;
use crate::platform::ios::domains;

/// Detect the acquisition layout from the shape of the entry paths.
///
/// Counts the distinctive signal of each platform across the entries and picks the
/// strongest: iOS containers (`/Containers/…`), iOS-backup domains
/// (`AppDomain-…`), or Android data roots (`/data/data/…`). WHY argmax over a few
/// cheap path checks rather than a definitive probe: it is robust to stray paths,
/// needs no file reads, and the three layouts' path shapes do not overlap.
pub fn detect(source: &dyn Source) -> Platform {
    let (mut ios_ffs, mut backup, mut android) = (0usize, 0usize, 0usize);
    for entry in source.entries() {
        let name = &entry.name;
        if name.contains("/Containers/Data/") || name.contains("/Containers/Bundle/") {
            ios_ffs += 1;
        } else if is_backup_domain(name) {
            backup += 1;
        }
        // A leading slash is optional: a rebuilt archive's paths are relative.
        if name.contains("/data/data/")
            || name.contains("/data/user/")
            || name.starts_with("data/data/")
            || name.starts_with("data/user/")
            || is_backup_member(name)
        {
            android += 1;
        }
    }
    let max = ios_ffs.max(backup).max(android);
    if max == 0 {
        Platform::Unknown
    } else if max == ios_ffs {
        Platform::IosFfs
    } else if max == backup {
        Platform::IosBackup
    } else {
        Platform::Android
    }
}

/// Whether an entry name's first segment is an app-scoped iOS-backup domain.
///
/// Delegates to [`crate::platform::ios::domains`] so the prefix set is defined
/// once. NOTE this counts only APP-SCOPED domains, so a backup holding no
/// third-party app data scores zero here and [`detect`] reports
/// `Platform::Unknown` for it. That is the long-standing behaviour and is left
/// deliberately unchanged: `detect` drives every `app` subcommand, and widening
/// it is a behavioural change that belongs in its own commit.
fn is_backup_domain(name: &str) -> bool {
    let domain = name.split('/').next().unwrap_or("");
    domains::parse(domain).is_some_and(|d| d.is_app_scoped())
}

/// Tally each container's file count and total size in one pass: every
/// non-directory entry is charged to the longest container prefix that contains
/// it (an entry deep in a nested container counts toward the innermost one).
pub(super) fn tally(source: &dyn Source, containers: &mut [AppContainer]) {
    // Owned keys: the index outlives the immutable borrow so the tally below can
    // mutate `containers` (a `&str`-keyed index would borrow it for the whole loop).
    let index: HashMap<String, usize> = containers
        .iter()
        .enumerate()
        .map(|(i, c)| (c.prefix.clone(), i))
        .collect();
    for entry in source.entries() {
        if entry.is_dir() {
            continue;
        }
        if let Some(idx) = longest_container(&entry.name, &index) {
            containers[idx].file_count += 1;
            containers[idx].total_size += entry.uncompressed_size;
        }
    }
}

/// Find the index of the longest container prefix that is an ancestor of `path`,
/// by walking the path's parent directories from longest to shortest.
fn longest_container(path: &str, index: &HashMap<String, usize>) -> Option<usize> {
    let mut cur = path;
    // Start one level up: a file is never itself a container prefix.
    while let Some(pos) = cur.rfind('/') {
        cur = &cur[..pos];
        if let Some(&idx) = index.get(cur) {
            return Some(idx);
        }
    }
    None
}
