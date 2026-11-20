//! App Group attribution: which shared App Group containers belong to an app, and
//! how each was attributed.
//!
//! Defines: `AppCatalog::resolve_group_links` (the app's groups: entitlements, else
//! the name heuristic), [`AppCatalog::unclaimed_groups`], and the vendor-token
//! heuristic (`vendor_tokens`, `group_matches_tokens`).
//! Used by: `catalog` (`containers_for`), and the binary's `app list`
//! (`unclaimed_groups`).
//! Uses: `catalog` (the `AppCatalog` it extends, `is_app_or_extension`), the data
//! types in `types`, and the MobileContainerManager records it holds
//! ([`crate::platform::ios::references`]).
//!
//! WHY its own module: attribution is a question of its own (entitlements, the
//! heuristic and its measured precision), apart from building the catalogue and
//! answering what an app's containers are.

use std::collections::{HashMap, HashSet};

use super::catalog::{AppCatalog, is_app_or_extension};
use super::types::{AppContainer, ContainerKind, GroupLink};

impl AppCatalog {
    /// The App Group containers no readable entitlement record names, when the
    /// source has the records (an iOS file system): no app's `app paths` or `--app`
    /// reaches them but by the name heuristic, if at all.
    pub fn unclaimed_groups(&self) -> Vec<&AppContainer> {
        let claimed: HashSet<&str> = self
            .references
            .records()
            .flat_map(|(_, r)| r.application_groups.iter().map(String::as_str))
            .collect();
        if claimed.is_empty() {
            return Vec::new();
        }
        self.containers
            .iter()
            .filter(|c| c.kind == ContainerKind::AppGroup && !claimed.contains(c.id.as_str()))
            .collect()
    }

    /// Resolve which App Groups belong to app `id`, and how each was attributed.
    ///
    /// Authoritative path: the entitlements of the app and of each of its
    /// extensions as MobileContainerManager recorded them (`references.sqlite3`).
    /// An extension can be entitled to a group the app is not (2 of 93 apps on a
    /// real iPhone), and it writes there on the app's behalf. When the source
    /// records no entitlements for the app itself — always the case for an iOS
    /// backup, which ships no MCM database — the reverse-DNS vendor-token heuristic
    /// stands in for the app's own, still joined by any extension's recorded ones.
    ///
    /// WHY a recorded-but-empty entitlement list ends the search rather than
    /// falling through: it says the app was provisioned with no App Groups, which
    /// is an answer. Running the heuristic anyway would re-add exactly the
    /// false positives this source exists to remove — measured at 518 spurious
    /// group inclusions across 7 apps on one real device.
    ///
    /// `ids` are one app's ids ([`matching_ids`](Self::matching_ids)): when any has
    /// its entitlements recorded, the heuristic does not run for the others.
    pub(super) fn resolve_group_links(&self, ids: &[String]) -> HashMap<String, GroupLink> {
        let recorded = ids.iter().any(|id| {
            self.references
                .get(id)
                .is_some_and(|record| record.entitlements_recorded)
        });
        let mut links = HashMap::new();
        if !recorded {
            for id in ids {
                links.extend(self.vendor_heuristic_groups(id));
            }
        }
        // The app, its extensions as MCM links them, and its extension containers
        // (an extension MCM does not list may still have a record of its own).
        let mut identities: Vec<&str> = ids.iter().map(String::as_str).collect();
        for id in ids {
            identities.extend(self.references.children(id).iter().map(String::as_str));
        }
        // Every id in `ids` has the same normal form, which the test compares: one
        // pass over the containers serves them all.
        if let Some(id) = ids.first() {
            identities.extend(
                self.containers
                    .iter()
                    .filter(|c| c.kind == ContainerKind::Extension && is_app_or_extension(c, id))
                    .map(|c| c.id.as_str()),
            );
        }
        for identity in identities {
            if let Some(record) = self.references.get(identity)
                && record.entitlements_recorded
            {
                for group in &record.application_groups {
                    links.insert(group.clone(), GroupLink::ContainerManager);
                }
            }
        }
        links
    }

    /// Fallback group attribution: App Group containers whose `group.*` id shares a
    /// reverse-DNS vendor token with the app id (e.g. `group.com.burbn.*` for
    /// `com.burbn.instagram`). Best-effort — it cannot find a cross-brand shared
    /// group whose id carries no token of the app (the documented limitation).
    fn vendor_heuristic_groups(&self, id: &str) -> HashMap<String, GroupLink> {
        let tokens = vendor_tokens(id);
        self.containers
            .iter()
            .filter(|c| c.kind == ContainerKind::AppGroup && group_matches_tokens(&c.id, &tokens))
            .map(|c| (c.id.clone(), GroupLink::VendorHeuristic))
            .collect()
    }
}

/// The distinctive reverse-DNS tokens of a bundle id / package, for the group
/// heuristic — every dotted component except a leading common TLD-ish token and
/// very short fragments. `com.burbn.instagram` → `["burbn", "instagram"]`.
///
/// WHY `apple` is NOT a stopword, though it over-matches: every `com.apple.*` app
/// shares it with every `group.com.apple.*` group (measured against MCM's
/// entitlements for one iPhone: 83 right, 8,919 wrong inclusions, 0.9% precision).
/// As a stopword it also loses about three quarters of the right ones (80.8%
/// precision but ~21 right), and a group left out is data silently not searched,
/// where a group wrongly in is named as a guess in the output.
fn vendor_tokens(id: &str) -> Vec<String> {
    const STOPWORDS: &[&str] = &["com", "org", "net", "io", "co", "app", "apps"];
    id.split('.')
        .map(|s| s.to_lowercase())
        .filter(|s| s.len() > 2 && !STOPWORDS.contains(&s.as_str()))
        .collect()
}

/// Whether a `group.*` id shares any vendor token with the app (component match).
fn group_matches_tokens(group_id: &str, tokens: &[String]) -> bool {
    let group_id = group_id.to_lowercase();
    group_id
        .split('.')
        .any(|seg| tokens.iter().any(|t| t == seg))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vendor_tokens_drop_tld_and_short_fragments() {
        assert_eq!(
            vendor_tokens("com.burbn.instagram"),
            vec!["burbn", "instagram"]
        );
        assert_eq!(
            vendor_tokens("ph.telegra.Telegraph"),
            vec!["telegra", "telegraph"]
        );
    }

    #[test]
    fn heuristic_matches_vendor_group_but_not_cross_brand() {
        let tokens = vendor_tokens("com.burbn.instagram");
        // Same-vendor groups are caught.
        assert!(group_matches_tokens("group.com.burbn.instagram", &tokens));
        assert!(group_matches_tokens("group.com.burbn.family", &tokens));
        // The cross-brand Meta group carries no burbn/instagram token — missed,
        // exactly the limitation Mach-O entitlements resolve.
        assert!(!group_matches_tokens("group.com.facebook.family", &tokens));
    }
}
