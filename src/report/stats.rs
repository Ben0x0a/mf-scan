//! Scan coverage statistics: what was searched, what was skipped, and why.
//!
//! Defines: `ScanStats` (the per-run coverage tally) and its small components
//! `SkipTally` and `GlobTally`, plus `merge` for aggregating across archives.
//! Used by: `engine` (fills the counts during the search pass), `run` (prints the
//! stderr summary and aggregates across sources), `output` (embeds it in the JSON
//! report).
//! Uses: `std::collections::BTreeMap` (a stable, sorted type breakdown),
//! `std::time::Duration`, and `serde` so the stats serialise into the report.
//!
//! WHY this exists: `--fast` and presets can exclude whole subtrees of an
//! acquisition. For a forensic tool, "what did you *not* look at" is a real
//! question, so every skip is attributed to the rule that caused it and the
//! coverage (files and bytes scanned vs skipped) is recorded.

use std::collections::BTreeMap;
use std::time::Duration;

use serde::{Serialize, Serializer};

/// Serialise a `Duration` as fractional seconds (e.g. `1.23`) for the report,
/// rather than serde's default `{ secs, nanos }` object.
fn elapsed_as_secs<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_f64(d.as_secs_f64())
}

/// A count of skipped files and the bytes they would have contributed.
///
/// `bytes` is the uncompressed (logical) size — the amount of content the skip
/// kept us from searching, which is the figure that matters for coverage.
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct SkipTally {
    pub count: usize,
    pub bytes: u64,
}

impl SkipTally {
    /// Record one more skipped file of `bytes` logical size.
    fn add(&mut self, bytes: u64) {
        self.count += 1;
        self.bytes += bytes;
    }

    /// Fold another tally into this one (for cross-archive aggregation).
    fn merge(&mut self, other: SkipTally) {
        self.count += other.count;
        self.bytes += other.bytes;
    }
}

/// Files skipped by one specific `--not-path` glob.
#[derive(Debug, Clone, Default, Serialize)]
pub struct GlobTally {
    /// The `--not-path` glob string responsible for these skips.
    pub glob: String,
    pub count: usize,
    pub bytes: u64,
}

/// Coverage statistics for one search run (or several archives, after merging).
///
/// `elapsed` is filled by the caller (`run`) around the search; the engine fills
/// everything else. It serialises as fractional seconds (see `elapsed_as_secs`).
#[derive(Debug, Clone, Default, Serialize)]
pub struct ScanStats {
    /// Every entry in the archive(s), directories included.
    pub total_entries: usize,
    /// Directory entries (names ending in `/`) — not files, never searched.
    pub directories: usize,
    /// Files whose content (or path, in `--match-path`) was actually searched.
    pub files_scanned: usize,
    /// Files dropped by any filter (sum of the skip tallies below).
    pub files_skipped: usize,
    /// Σ uncompressed size of all file (non-directory) entries.
    pub bytes_total: u64,
    /// Σ uncompressed size of the files actually searched.
    pub bytes_scanned: u64,
    /// On-disk size of the archive(s) (the memory-mapped length).
    pub archive_bytes: u64,
    /// Files skipped because `--path` was set and none of its globs matched.
    pub skipped_not_included: SkipTally,
    /// Files skipped by the media skip (`--exclude-media`/`--fast`).
    pub skipped_media: SkipTally,
    /// Files skipped by the `--type` allowlist.
    pub skipped_type: SkipTally,
    /// Files skipped per `--not-path` glob (one entry per glob that hit).
    pub skipped_not_path: Vec<GlobTally>,
    /// Files whose content could not be read (permission denied, corrupt entry).
    /// Not searched, but the scan continued — "what did you not look at" must
    /// stay exact for a forensic run.
    pub unreadable: SkipTally,
    /// Profile-matched files no candidate key could decrypt: their ciphertext
    /// was not searched, so they are excluded from the scanned figures.
    pub decrypt_failed: SkipTally,
    /// Count of scanned files per detected type name (sorted, stable order).
    pub scanned_by_type: BTreeMap<String, usize>,
    /// Files that contained at least one match.
    pub files_with_matches: usize,
    /// Total matches across all scanned files.
    pub total_matches: usize,
    /// Wall-clock time of the search, filled by the caller.
    #[serde(serialize_with = "elapsed_as_secs")]
    pub elapsed: Duration,
}

impl ScanStats {
    /// Record a scanned file of `bytes` logical size and (when known) its type.
    pub fn add_scanned(&mut self, bytes: u64, type_name: Option<&str>) {
        self.files_scanned += 1;
        self.bytes_scanned += bytes;
        if let Some(name) = type_name {
            *self.scanned_by_type.entry(name.to_string()).or_default() += 1;
        }
    }

    /// Record a file skipped because `--path` was set and none of its globs matched.
    pub fn add_not_included(&mut self, bytes: u64) {
        self.skipped_not_included.add(bytes);
        self.files_skipped += 1;
    }

    /// Record a file skipped by the media skip.
    pub fn add_media(&mut self, bytes: u64) {
        self.skipped_media.add(bytes);
        self.files_skipped += 1;
    }

    /// Record a file skipped by the `--type` allowlist.
    pub fn add_type(&mut self, bytes: u64) {
        self.skipped_type.add(bytes);
        self.files_skipped += 1;
    }

    /// Record a file whose content could not be read (the scan continued).
    pub fn add_unreadable(&mut self, bytes: u64) {
        self.unreadable.add(bytes);
    }

    /// Record a profile-matched file no candidate key could decrypt.
    pub fn add_decrypt_failed(&mut self, bytes: u64) {
        self.decrypt_failed.add(bytes);
    }

    /// Attribute a `--not-path` skip to `glob` (the glob at the decision's index).
    ///
    /// HOW: tallies are keyed by the glob string and created lazily on first hit,
    /// so only globs that actually skipped a file appear in the report.
    pub fn add_not_path(&mut self, glob: &str, bytes: u64) {
        if let Some(slot) = self.skipped_not_path.iter_mut().find(|t| t.glob == glob) {
            slot.count += 1;
            slot.bytes += bytes;
        } else {
            self.skipped_not_path.push(GlobTally {
                glob: glob.to_string(),
                count: 1,
                bytes,
            });
        }
        self.files_skipped += 1;
    }

    /// Fold another run's stats into this one, summing every counter and merging
    /// the per-glob and per-type breakdowns by key.
    ///
    /// Used to aggregate a multi-archive run into a single coverage figure.
    pub fn merge(&mut self, other: ScanStats) {
        self.total_entries += other.total_entries;
        self.directories += other.directories;
        self.files_scanned += other.files_scanned;
        self.files_skipped += other.files_skipped;
        self.bytes_total += other.bytes_total;
        self.bytes_scanned += other.bytes_scanned;
        self.archive_bytes += other.archive_bytes;
        self.skipped_not_included.merge(other.skipped_not_included);
        self.skipped_media.merge(other.skipped_media);
        self.skipped_type.merge(other.skipped_type);
        self.unreadable.merge(other.unreadable);
        self.decrypt_failed.merge(other.decrypt_failed);
        self.files_with_matches += other.files_with_matches;
        self.total_matches += other.total_matches;
        self.elapsed += other.elapsed;
        for tally in other.skipped_not_path {
            if let Some(slot) = self
                .skipped_not_path
                .iter_mut()
                .find(|t| t.glob == tally.glob)
            {
                slot.count += tally.count;
                slot.bytes += tally.bytes;
            } else {
                self.skipped_not_path.push(tally);
            }
        }
        for (name, count) in other.scanned_by_type {
            *self.scanned_by_type.entry(name).or_default() += count;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_scanned_tracks_type_breakdown() {
        let mut s = ScanStats::default();
        s.add_scanned(100, Some("sqlite"));
        s.add_scanned(50, Some("sqlite"));
        s.add_scanned(10, None);
        assert_eq!(s.files_scanned, 3);
        assert_eq!(s.bytes_scanned, 160);
        assert_eq!(s.scanned_by_type["sqlite"], 2);
        assert_eq!(s.scanned_by_type.len(), 1); // None contributes no type row
    }

    #[test]
    fn not_path_groups_by_glob() {
        let mut s = ScanStats::default();
        s.add_not_path("*/Caches/*", 10);
        s.add_not_path("*/Caches/*", 20);
        s.add_not_path("*.log", 5);
        assert_eq!(s.files_skipped, 3);
        assert_eq!(s.skipped_not_path.len(), 2);
        let caches = &s.skipped_not_path[0];
        assert_eq!(caches.count, 2);
        assert_eq!(caches.bytes, 30);
    }

    #[test]
    fn merge_sums_counters_and_keys() {
        let mut a = ScanStats::default();
        a.add_scanned(100, Some("sqlite"));
        a.add_not_path("*.log", 7);
        let mut b = ScanStats::default();
        b.add_scanned(40, Some("plist"));
        b.add_scanned(60, Some("sqlite"));
        b.add_not_path("*.log", 3);
        a.merge(b);
        assert_eq!(a.files_scanned, 3);
        assert_eq!(a.scanned_by_type["sqlite"], 2);
        assert_eq!(a.scanned_by_type["plist"], 1);
        assert_eq!(a.skipped_not_path.len(), 1);
        assert_eq!(a.skipped_not_path[0].count, 2);
        assert_eq!(a.skipped_not_path[0].bytes, 10);
    }
}
