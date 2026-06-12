//! Per-entry classification: decide an entry's fate and search its content.
//!
//! Defines: [`classify_entry`] (the body of the engine's parallel map) plus the
//! [`Class`] / [`EntryResult`] carriers it returns, and `match_entry_path` (the
//! `--match-path` mode). This is the per-entry half of the search engine; the
//! drivers and public types live in [`super`] (`engine/mod.rs`).
//! Used by: `super` (the parallel map + the stats fold).
//! Uses: `crate::{filter, search, inspect, models, decrypt}` and `super` (for the
//! engine's public types `Query` / `Progress` / `MatchedFile`).

use anyhow::Result;
use regex::bytes::Regex;

use crate::decrypt::{DecryptionContext, DecryptionRecord, TryOutcome};
use crate::filter::{EntryFilter, PathDecision, TypeDecision};
use crate::inspect;
use crate::models::{Encoding, Entry, MatchRecord, SearchHit};
use crate::search;
use crate::source::Source;

use super::{MatchedFile, Progress, Query};

/// How one entry was classified during the search pass — the per-entry input to
/// the [`ScanStats`] fold. Kept private: it exists only to carry a skip reason
/// (and the bytes/type it represents) out of the parallel map and into the
/// sequential tally, so the statistics can attribute every skip to its rule.
pub(super) enum Class {
    /// A directory entry (name ending in `/`); not a file, never searched.
    Directory,
    /// `--path` was set and none of its globs matched this path.
    SkippedNotIncluded { bytes: u64 },
    /// The `--not-path` glob at this index matched this path.
    SkippedNotPath { glob_idx: usize, bytes: u64 },
    /// The media skip dropped this file.
    SkippedMedia { bytes: u64 },
    /// The `--type` allowlist excluded this file.
    SkippedType { bytes: u64 },
    /// The file's content could not be read (permission denied, corrupt entry).
    /// Counted, not fatal: forensic acquisitions are routinely partial, so one
    /// unreadable file must never abort the scan of the rest ("degrade, don't
    /// die" — the same rule the inspectors follow).
    Unreadable { bytes: u64 },
    /// A decryption profile matched but no candidate key decrypted the entry —
    /// its ciphertext was **not** searched, so it must not count as scanned or
    /// the coverage figures would overstate what was actually looked at.
    DecryptFailed { bytes: u64 },
    /// The file was searched.
    Scanned {
        bytes: u64,
        type_name: Option<&'static str>,
        matches: usize,
        /// The per-file hit cap stopped collection: the file has MORE matches
        /// than `matches` reports (surfaced in the statistics).
        truncated: bool,
    },
}

/// One entry's contribution to the run: its output records and matched file (if
/// any), how it was classified for the statistics, and any decryption that was
/// attempted on it.
pub(super) struct EntryResult {
    pub(super) records: Vec<MatchRecord>,
    pub(super) file: Option<MatchedFile>,
    pub(super) class: Class,
    /// Set when a decryption profile matched this entry (decrypted or failed).
    pub(super) decryption: Option<DecryptionRecord>,
}

/// Classify and (when selected) search a single entry — the body of the parallel
/// map in [`super::search_source`].
///
/// Returns the entry's output records, its matched-file record, and a [`Class`]
/// describing how it was handled for the statistics. The order of checks mirrors
/// the filter pipeline: directory → path globs → (read content) → type/media.
#[allow(clippy::too_many_arguments)]
pub(super) fn classify_entry(
    source: &dyn Source,
    entry: &Entry,
    query: &Query,
    deep: bool,
    match_path: bool,
    filter: &EntryFilter,
    decrypt: Option<&DecryptionContext>,
    progress: &dyn Progress,
) -> Result<EntryResult> {
    // Directory entries are not files; never read or count them as searchable.
    if entry.is_dir() {
        return Ok(EntryResult {
            records: Vec::new(),
            file: None,
            class: Class::Directory,
            decryption: None,
        });
    }

    let bytes = entry.uncompressed_size;

    // Path-only filter, applied before any byte is read.
    match filter.select(&entry.name) {
        PathDecision::SkipNotIncluded => {
            return Ok(EntryResult {
                records: Vec::new(),
                file: None,
                class: Class::SkippedNotIncluded { bytes },
                decryption: None,
            });
        }
        PathDecision::SkipNotPath(glob_idx) => {
            return Ok(EntryResult {
                records: Vec::new(),
                file: None,
                class: Class::SkippedNotPath { glob_idx, bytes },
                decryption: None,
            });
        }
        PathDecision::Search => {}
    }

    // --match-path: the path itself is the haystack; no content is read and the
    // type/media filter does not apply (documented on `match_entry_path`).
    if match_path {
        let (records, file) = match_entry_path(entry, query.plain);
        let matches = records.len();
        progress.inc();
        return Ok(EntryResult {
            records,
            file,
            class: Class::Scanned {
                bytes,
                type_name: None,
                matches,
                truncated: false,
            },
            decryption: None,
        });
    }

    // A read failure (permission-denied loose file, corrupt compressed entry) is
    // classified and counted instead of propagated — propagating would cancel the
    // whole parallel map and kill the scan of every other file.
    let mut content = match source.content(entry) {
        Ok(content) => content,
        Err(_) => {
            progress.inc();
            return Ok(EntryResult {
                records: Vec::new(),
                file: None,
                class: Class::Unreadable { bytes },
                decryption: None,
            });
        }
    };

    // Decryption transform: if a profile matches this entry, decrypt it and search
    // the plaintext from here on (type detection, search, inspection all see the
    // decrypted bytes — so a decrypted SQLite is inspected as SQLite for free). A
    // profile match that cannot be decrypted is recorded and its ciphertext is not
    // searched (it holds no meaningful content). Entries no profile matches are
    // left untouched and stay on the zero-copy path.
    let mut decryption: Option<DecryptionRecord> = None;
    if let Some(ctx) = decrypt {
        match ctx.try_decrypt(&entry.name, &content) {
            None => {}
            Some(TryOutcome::Decrypted(decrypted)) => {
                decryption = Some(DecryptionRecord::decrypted(
                    entry.name.clone(),
                    &decrypted,
                    &content,
                ));
                content = crate::source::Content::Owned(decrypted.plaintext);
            }
            Some(TryOutcome::Failed {
                profile,
                app,
                reason,
            }) => {
                progress.inc();
                return Ok(EntryResult {
                    records: Vec::new(),
                    file: None,
                    class: Class::DecryptFailed { bytes },
                    decryption: Some(DecryptionRecord::failed(
                        entry.name.clone(),
                        profile,
                        app,
                        reason,
                    )),
                });
            }
        }
    }

    // Type/media filter: classify by content header (then extension). Done here,
    // not in the path pre-filter, because the header is only available once the
    // content is read.
    let type_info = inspect::detect_type(&entry.name, &content);
    match filter.accept_type(type_info) {
        TypeDecision::SkipMedia => {
            progress.inc();
            return Ok(EntryResult {
                records: Vec::new(),
                file: None,
                class: Class::SkippedMedia { bytes },
                decryption: decryption.take(),
            });
        }
        TypeDecision::SkipType => {
            progress.inc();
            return Ok(EntryResult {
                records: Vec::new(),
                file: None,
                class: Class::SkippedType { bytes },
                decryption: decryption.take(),
            });
        }
        TypeDecision::Search => {}
    }
    let type_name = type_info.map(|i| i.name);

    // Search the plain pattern, then (when `--base64`) the base64 fragments. Each
    // hit is tagged with its encoding; base64 hits also carry the decoded value.
    // Combining into one list keeps a single record/offset stream per file.
    let plain_hits = search::search_bytes_capped(&content, query.plain);
    let mut truncated = plain_hits.truncated;
    let mut hits: Vec<(SearchHit, Encoding)> = plain_hits
        .hits
        .into_iter()
        .map(|h| (h, Encoding::Plain))
        .collect();
    if let Some(b64) = query.base64 {
        let b64_hits = search::search_bytes_capped(&content, b64);
        truncated |= b64_hits.truncated;
        hits.extend(b64_hits.hits.into_iter().map(|h| (h, Encoding::Base64)));
    }
    // Sort by in-file offset so records and export offsets stay in position order
    // regardless of which pattern produced each hit.
    hits.sort_by_key(|(h, _)| h.offset);

    // `decryption` is set only when this entry was decrypted (a failed match
    // returns earlier), so its presence marks the content as decrypted plaintext.
    let was_decrypted = decryption.is_some();

    let matches = hits.len();
    let (records, file) = if hits.is_empty() {
        (Vec::new(), None)
    } else {
        let offsets: Vec<u64> = hits.iter().map(|(hit, _)| hit.offset).collect();
        // One batch inspection call per entry: format detection and any per-file
        // inspector state (e.g. SQLite's schema map) are derived once for all of
        // this entry's matches instead of once per match.
        let mut inspections = if deep {
            let offs: Vec<usize> = offsets.iter().map(|&o| o as usize).collect();
            inspect::inspect_many(&entry.name, &content, &offs).into_iter()
        } else {
            Vec::new().into_iter()
        };
        let records = hits
            .into_iter()
            .map(|(hit, encoding)| {
                let mut record = MatchRecord::new(entry, hit);
                record.encoding = encoding;
                if encoding == Encoding::Base64 {
                    record.decoded = query.decoded.map(str::to_string);
                }
                if was_decrypted {
                    // The offsets are within the decrypted plaintext; the archive
                    // byte is the entry's data start (None for a loose file), not an
                    // exact match position.
                    record.decrypted = true;
                    record.archive_offset = entry.archive_data_start();
                }
                if deep {
                    // Positional: inspect_many returns one result per offset, in
                    // the same (sorted) order as `hits`.
                    record.inspection = inspections.next().flatten();
                }
                record
            })
            .collect();
        let file = MatchedFile {
            entry: entry.clone(),
            offsets,
        };
        (records, Some(file))
    };

    progress.inc();
    Ok(EntryResult {
        records,
        file,
        class: Class::Scanned {
            bytes,
            type_name,
            matches,
            truncated,
        },
        decryption,
    })
}

/// Match `re` against an entry's internal **path** (the `--match-path` mode).
///
/// Produces one record per matching file, with the path itself as the displayed
/// line and the regex span recorded for highlighting. No file content is read,
/// so the in-file offsets are not meaningful: `file_offset` is 0 and the
/// archive offsets point at the file's data start. A single offset is recorded
/// on the matched file so `--count` reports one hit per file.
fn match_entry_path(entry: &Entry, re: &Regex) -> (Vec<MatchRecord>, Option<MatchedFile>) {
    // Directory entries (name ending in `/`) are not files; never list them.
    if entry.is_dir() {
        return (Vec::new(), None);
    }
    let name = entry.name.as_bytes();
    let Some(m) = re.find(name) else {
        return (Vec::new(), None);
    };
    let record = MatchRecord {
        archive: None,
        archive_path: None,
        path: entry.name.clone(),
        file_start: entry.archive_data_start().unwrap_or(0),
        file_offset: 0,
        archive_offset: entry.archive_data_start(),
        compressed: entry.is_compressed(),
        decrypted: false,
        line: name.to_vec(),
        match_in_line: m.start()..m.end(),
        inspection: None,
        encoding: Encoding::Plain,
        decoded: None,
    };
    let file = MatchedFile {
        entry: entry.clone(),
        offsets: vec![0],
    };
    (vec![record], Some(file))
}
