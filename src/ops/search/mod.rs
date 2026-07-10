//! The search operation: scan a `Source` for a pattern → `Findings`.
//!
//! Defines: the `grep` operation surface — `Findings`, `MatchedFile`, and the two
//! entry points [`search_source`] (any [`Source`](crate::core::source::Source)) and
//! the [`search_with_query`] convenience over raw archive bytes — which search
//! entries in parallel and return both the per-match records (for output) and the
//! de-duplicated matched files (for the export step). Also re-exports the byte-search
//! primitives ([`search_bytes`], [`search_entry`], …) and the [`base64`] fragments.
//! Used by: the binary's `cmd::run::grep` (and `cmd::support`), `report::export`, and
//! the integration tests.
//! Uses: `crate::engine` (the shared [`Progress`] contract and the [`is_selected`]
//! rule), `crate::core` (source + models), `crate::formats::inspect` (deep search),
//! `crate::decrypt` (the per-entry decryption transform), `rayon`, `regex::bytes`.
//!
//! Why this lives in the library rather than `main`: it lets the end-to-end search
//! be unit-tested directly, and keeps `main` to CLI parsing and I/O. Thread-pool
//! sizing is the caller's concern (set before calling); here we just use rayon's
//! current global pool. Both outputs come from a single search pass, so printing and
//! exporting never re-scan the archive.

mod classify;

pub mod base64;
mod scan;

pub use scan::{MAX_HITS_PER_FILE, SearchHits, search_bytes, search_bytes_capped};

use anyhow::Result;
use rayon::prelude::*;
use regex::bytes::Regex;

use crate::core::filter::EntryFilter;
use crate::core::models::{Entry, MatchRecord, SearchHit};
use crate::core::source::Source;
use crate::core::source::zip::{self, ZipSource};
use crate::decrypt::{DecryptionContext, DecryptionRecord};
use crate::engine::{Progress, is_selected};
use crate::report::stats::ScanStats;

use classify::{Class, classify_entry};

/// Search one ZIP entry for every (non-overlapping) match of `re`.
///
/// A convenience for callers (and tests) that hold the raw archive bytes; the
/// engine reads through a [`crate::core::source::Source`] instead.
pub fn search_entry(archive: &[u8], entry: &Entry, re: &Regex) -> Result<Vec<SearchHit>> {
    let content = zip::content(archive, entry)?;
    Ok(search_bytes(&content, re))
}

/// A file that contained at least one match, with the offsets of those matches.
///
/// Carries the full `Entry` so the export step can re-read (and decompress) the
/// file's content without re-parsing the archive.
pub struct MatchedFile {
    pub entry: Entry,
    pub offsets: Vec<u64>,
}

/// The result of searching an archive.
pub struct Findings {
    /// One record per match, in entry-then-match order (for output).
    pub records: Vec<MatchRecord>,
    /// One entry per matched file, de-duplicated (for the export step).
    pub files: Vec<MatchedFile>,
    /// Coverage statistics for the run: what was searched, what was skipped, why.
    pub stats: ScanStats,
    /// Audit trail of every entry a decryption profile matched: which were
    /// decrypted (with key provenance + hashes) and which failed. Empty when no
    /// decryption context was supplied.
    pub decryptions: Vec<DecryptionRecord>,
}

/// What to search for: the verbatim pattern, plus optionally its base64 encoding.
///
/// `plain` is matched against the raw bytes as before. When `base64` is set
/// (`--base64`), it is a second regex — an alternation of the base64 *alignment
/// fragments* (see [`base64`]) — and any hit it produces is tagged
/// [`Encoding::Base64`](crate::core::models::Encoding::Base64) with `decoded` (the
/// literal the user searched for) so the
/// report shows what the encoded run contains. Borrows the regexes so the caller
/// keeps ownership; building both once and reusing them across entries.
pub struct Query<'a> {
    pub plain: &'a Regex,
    pub base64: Option<&'a Regex>,
    /// The decoded value carried onto base64 hits; `None` when `base64` is unset.
    pub decoded: Option<&'a str>,
}

impl<'a> Query<'a> {
    /// A plain-only query — the default when `--base64` is not in play.
    pub fn plain(re: &'a Regex) -> Self {
        Self {
            plain: re,
            base64: None,
            decoded: None,
        }
    }
}

/// Search a ZIP `archive` for `query` — a thin wrapper that opens a [`ZipSource`]
/// over the memory-mapped bytes and delegates to [`search_source`]. Kept so callers
/// (and tests) holding raw archive bytes need not build the source themselves.
pub fn search_with_query(
    archive: &[u8],
    query: &Query,
    deep: bool,
    match_path: bool,
    filter: &EntryFilter,
    decrypt: Option<&DecryptionContext>,
    progress: &dyn Progress,
) -> Result<Findings> {
    let source = ZipSource::open(archive)?;
    search_source(&source, query, deep, match_path, filter, decrypt, progress)
}

/// Search every file in `source` for `query`, reporting progress via `progress`.
///
/// HOW: the entries to search are selected first (so the total is known up
/// front), then searched in parallel; rayon's `collect` into a `Vec` preserves
/// input order, so both outputs stay deterministic (entry order, then match
/// order within each entry). Each entry's content is obtained once (through the
/// source) and reused for searching, inspection, and the matched-file list.
///
/// When `match_path` is set, the pattern is matched against each entry's internal
/// **path** instead of its content (no bytes are read); each matching file is
/// reported once. The type/media filter, inspection, and base64 search are all
/// skipped in this mode (a path is not base64).
pub fn search_source(
    source: &dyn Source,
    query: &Query,
    deep: bool,
    match_path: bool,
    filter: &EntryFilter,
    decrypt: Option<&DecryptionContext>,
    progress: &dyn Progress,
) -> Result<Findings> {
    // With no secrets there is nothing to decrypt; drop the context so the hot
    // path skips per-entry profile matching entirely.
    let decrypt = decrypt.filter(|ctx| ctx.has_secrets());
    let entries = source.entries();

    // Progress reflects the files we actually read: entries that pass the
    // path-only filter and are not directories (the shared `is_selected` rule).
    // Path/type skips finish instantly and are not counted towards the bar. The
    // path check is cheap, so running it here (for the total) and again in the
    // loop is not worth de-duplicating.
    let to_read = entries.iter().filter(|e| is_selected(e, filter)).count();
    progress.set_total(to_read);

    let per_entry = entries
        .par_iter()
        .map(|entry| {
            classify_entry(
                source, entry, query, deep, match_path, filter, decrypt, progress,
            )
        })
        .collect::<Result<Vec<_>>>()?;

    // Fold the per-entry results: records and matched files stay in entry order
    // (rayon's collect preserves it); everything else accumulates into the stats.
    let mut records = Vec::new();
    let mut files = Vec::new();
    let mut decryptions = Vec::new();
    let mut stats = ScanStats {
        total_entries: entries.len(),
        archive_bytes: source.byte_size(),
        ..ScanStats::default()
    };
    let not_path_globs = filter.not_path_globs();
    for result in per_entry {
        records.extend(result.records);
        if let Some(file) = result.file {
            files.push(file);
        }
        if let Some(decryption) = result.decryption {
            decryptions.push(decryption);
        }
        match result.class {
            Class::Directory => stats.directories += 1,
            Class::SkippedNotIncluded { bytes } => {
                stats.bytes_total += bytes;
                stats.add_not_included(bytes);
            }
            Class::SkippedNotPath { glob_idx, bytes } => {
                stats.bytes_total += bytes;
                stats.add_not_path(&not_path_globs[glob_idx], bytes);
            }
            Class::SkippedMedia { bytes } => {
                stats.bytes_total += bytes;
                stats.add_media(bytes);
            }
            Class::SkippedType { bytes } => {
                stats.bytes_total += bytes;
                stats.add_type(bytes);
            }
            Class::Unreadable { bytes } => {
                stats.bytes_total += bytes;
                stats.add_unreadable(bytes);
            }
            Class::DecryptFailed { bytes } => {
                stats.bytes_total += bytes;
                stats.add_decrypt_failed(bytes);
            }
            Class::Scanned {
                bytes,
                type_name,
                matches,
                truncated,
            } => {
                stats.bytes_total += bytes;
                stats.add_scanned(bytes, type_name);
                stats.total_matches += matches;
                if matches > 0 {
                    stats.files_with_matches += 1;
                }
                if truncated {
                    stats.files_truncated += 1;
                }
            }
        }
    }

    Ok(Findings {
        records,
        files,
        stats,
        decryptions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decrypt::cipher::sqlcipher::encrypt_db;
    use crate::decrypt::keyfile::{Secret, SecretStore};
    use crate::decrypt::profile::{
        CipherSpec, DbBinding, HashAlgorithm, KeyEncoding, KeySpec, KeychainMatch, Platform,
        Profile, ProfileRegistry, SqlCipherParams,
    };
    use crate::engine::NoProgress;
    use crate::testutil::stored_zip;

    fn sqlcipher_v4(page_size: usize) -> SqlCipherParams {
        SqlCipherParams {
            page_size,
            kdf_iter: 256_000,
            hmac: HashAlgorithm::Sha512,
            kdf: HashAlgorithm::Sha512,
            use_hmac: true,
            plaintext_header_size: 0,
        }
    }

    #[test]
    fn decrypts_matching_entry_and_finds_needle_through_the_engine() {
        let page_size = 1024;
        let key = [0x42u8; 32];

        // An encrypted Signal-like DB with a needle in its (plaintext) page 1.
        let mut page = vec![0u8; page_size];
        page[..16].copy_from_slice(b"SQLite format 3\x00");
        page[100..114].copy_from_slice(b"ENGINE-needle!");
        let params = sqlcipher_v4(page_size);
        let blob = encrypt_db(&[page], &key, &[0x55u8; 16], &params);

        // Plus a plaintext decoy entry that should be searched normally.
        let zip = stored_zip(&[
            ("App/grdb/signal.sqlite", &blob),
            ("notes.txt", b"ENGINE-needle! in the clear"),
        ]);

        let profile = Profile {
            name: "signal".into(),
            app: "Signal".into(),
            platform: Platform::Ios,
            description: None,
            db: DbBinding::Glob("*/grdb/signal.sqlite".into()),
            key: KeySpec {
                encoding: KeyEncoding::Raw,
                keychain: KeychainMatch {
                    service: Some("Signal".into()),
                    ..Default::default()
                },
            },
            cipher: CipherSpec::Sqlcipher(params),
        };
        let secrets = SecretStore::new(vec![Secret {
            account: Some("a".into()),
            service: Some("Signal".into()),
            access_group: None,
            label: None,
            protection_class: None,
            data: key.to_vec(),
            source: "test".into(),
        }]);
        let ctx = DecryptionContext::new(ProfileRegistry::new(vec![profile]), secrets, None);

        let re = Regex::new("ENGINE-needle!").unwrap();
        let findings = search_with_query(
            &zip,
            &Query::plain(&re),
            false,
            false,
            &EntryFilter::all(),
            Some(&ctx),
            &NoProgress,
        )
        .unwrap();

        // Found in BOTH the decrypted DB and the plaintext decoy.
        assert_eq!(findings.records.len(), 2);
        let db_record = findings
            .records
            .iter()
            .find(|r| r.path == "App/grdb/signal.sqlite")
            .expect("a match in the decrypted DB");
        // The decrypted-DB match is flagged decrypted, with the archive offset
        // pointing at the entry's data start (the match offset is in plaintext).
        assert!(db_record.decrypted);
        assert_eq!(db_record.archive_offset, Some(db_record.file_start));
        // The plaintext decoy is not flagged.
        let decoy = findings
            .records
            .iter()
            .find(|r| r.path == "notes.txt")
            .expect("a match in the decoy");
        assert!(!decoy.decrypted);

        // Exactly one decryption, verified, attributed to the encrypted entry.
        assert_eq!(findings.decryptions.len(), 1);
        let record = &findings.decryptions[0];
        assert!(record.is_verified());
        assert_eq!(record.path, "App/grdb/signal.sqlite");
        assert_eq!(record.app, "Signal");
    }

    #[test]
    fn profile_match_with_wrong_key_records_failure_and_does_not_match_ciphertext() {
        let page_size = 1024;
        let params = sqlcipher_v4(page_size);
        let mut page = vec![0u8; page_size];
        page[..16].copy_from_slice(b"SQLite format 3\x00");
        page[100..110].copy_from_slice(b"SECRET-abc");
        let blob = encrypt_db(&[page], &[0x42u8; 32], &[0x55u8; 16], &params);
        let zip = stored_zip(&[("App/grdb/signal.sqlite", &blob)]);

        let profile = Profile {
            name: "signal".into(),
            app: "Signal".into(),
            platform: Platform::Ios,
            description: None,
            db: DbBinding::Glob("*/grdb/signal.sqlite".into()),
            key: KeySpec {
                encoding: KeyEncoding::Raw,
                keychain: KeychainMatch {
                    service: Some("Signal".into()),
                    ..Default::default()
                },
            },
            cipher: CipherSpec::Sqlcipher(params),
        };
        // The stored key is wrong.
        let secrets = SecretStore::new(vec![Secret {
            account: None,
            service: Some("Signal".into()),
            access_group: None,
            label: None,
            protection_class: None,
            data: vec![0x00u8; 32],
            source: "test".into(),
        }]);
        let ctx = DecryptionContext::new(ProfileRegistry::new(vec![profile]), secrets, None);

        let re = Regex::new("SECRET-abc").unwrap();
        let findings = search_with_query(
            &zip,
            &Query::plain(&re),
            false,
            false,
            &EntryFilter::all(),
            Some(&ctx),
            &NoProgress,
        )
        .unwrap();

        // No match (ciphertext is not searched), and the failure is recorded.
        assert_eq!(findings.records.len(), 0);
        assert_eq!(findings.decryptions.len(), 1);
        assert!(findings.decryptions[0].is_failure());
    }
}
