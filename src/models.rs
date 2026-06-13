//! Shared data containers for mf-scan.
//!
//! Defines: `Method` (the supported compression methods), `Entry` (a located
//! file inside the archive), `SearchHit` (one regex match within an entry's
//! data) and `MatchRecord` (an archive-level match enriched with every offset,
//! ready for output).
//! Used by: `zip` (produces `Entry`), `engine` (consumes `Entry`, produces
//! `SearchHit`), `report::output` (renders `MatchRecord`), and
//! `ios::containers` (sets `bundle_id` on annotated records).
//! Uses: only `std::ops::Range` and `serde` — these are plain data types,
//! kept in their own module so the parser and the search engine can each depend
//! on the data shape without depending on each other.

use std::ops::Range;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Run-level metadata: the tool, the query, and every filter in effect.
///
/// Recorded so machine-readable output and the export manifest/report are
/// self-describing — a result file states exactly which archives, pattern, and
/// filters produced it. Embedded in JSON output, the manifest, and the export
/// report; never shown in txt/csv (which stay line-oriented).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunInfo {
    /// Tool name (`mf-scan`).
    pub tool: String,
    /// Tool version (`CARGO_PKG_VERSION`).
    pub version: String,
    /// The pattern as given on the command line.
    pub pattern: String,
    /// Pattern was treated as a literal string (`-l`), not a regex.
    pub literal: bool,
    /// Case-insensitive matching (`-i`).
    pub ignore_case: bool,
    /// Pattern was matched against file paths, not content (`--match-path`).
    pub match_path: bool,
    /// Deep inspection was on (`--inspect`).
    pub inspect: bool,
    /// Source archives, as full filesystem paths.
    pub archives: Vec<String>,
    /// `--path` include globs.
    pub path_globs: Vec<String>,
    /// `--not-path` exclude globs.
    pub not_path_globs: Vec<String>,
    /// `--type` format/category allowlist.
    pub types: Vec<String>,
    /// Media files were excluded (`--exclude-media` or `--fast`).
    pub exclude_media: bool,
    /// Also searched for the pattern's base64 encoding (`--base64`).
    pub base64: bool,
    /// Used the URL-safe base64 alphabet (`--base64-urlsafe`).
    pub base64_urlsafe: bool,
    /// Keychain/keystore dump files supplied for decryption (`--keyfile`).
    pub keyfiles: Vec<String>,
    /// Platform scope for decryption profiles (`--platform`), if set.
    pub platform: Option<String>,
}

/// How a match's bytes were encoded in the file.
///
/// `Plain` is the pattern found verbatim; `Base64` is the pattern found inside a
/// base64-encoded run (see [`crate::search::base64`]). The distinction is carried
/// through to the report so an analyst can tell an encoded hit from a literal one
/// and see the decoded value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Encoding {
    Plain,
    Base64,
}

impl Encoding {
    /// Lowercase tag used in txt/csv output (`"plain"`, `"base64"`).
    pub fn as_str(self) -> &'static str {
        match self {
            Encoding::Plain => "plain",
            Encoding::Base64 => "base64",
        }
    }
}

/// Compression method of a searchable entry.
///
/// Only the two methods that appear in mobile-forensic archives are modelled;
/// any other method is dropped by the parser rather than represented here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Stored,
    Deflate,
}

/// Where a located file's bytes physically live — the one thing that differs
/// between a file inside an archive and a loose file on disk.
///
/// A ZIP entry is addressed by a byte range inside the archive (plus its
/// compression method); a loose file is addressed by its path on disk. The search
/// engine reads bytes through a [`crate::source::Source`], so it never matches on
/// this directly — but the offset model (`MatchRecord`) and the export step do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Location {
    /// Inside a ZIP archive. `data_offset`/`data_len` describe the entry's bytes as
    /// they sit in the archive (the literal content for STORED, the compressed
    /// stream for DEFLATE).
    Zip {
        method: Method,
        data_offset: u64,
        data_len: u64,
    },
    /// A loose file on disk, read from its own `path`. It has no archive offsets.
    Loose { path: PathBuf },
    /// Inside a nested archive that a folder scan opened in memory (see
    /// `--archive-depth`). `archive` indexes the producing
    /// [`crate::source::folder::FolderSource`]'s arena of opened archive buffers, and
    /// the offsets are into that buffer — so only that source can read the entry back,
    /// and it carries no absolute archive offset to the report.
    Nested {
        archive: usize,
        method: Method,
        data_offset: u64,
        data_len: u64,
    },
}

/// One searchable file, from a ZIP archive or a folder.
///
/// `name` is the file's logical path (inside the archive, or relative to the
/// scanned folder); `uncompressed_size` is its logical size. `location` carries the
/// source-specific addressing — see [`Location`]. `mtime` is the last-modified time
/// (Unix epoch seconds, best-effort) used by `diff`'s metadata comparison: from the
/// ZIP central-directory DOS timestamp, or the filesystem for a loose file; `None`
/// when the source does not record one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub uncompressed_size: u64,
    pub mtime: Option<u64>,
    pub location: Location,
}

impl Entry {
    /// True for a directory placeholder entry (a name ending in `/`).
    pub fn is_dir(&self) -> bool {
        self.name.ends_with('/')
    }

    /// The archive byte where this file's data begins, or `None` when the file has
    /// no enclosing top-level archive (a loose file, or a file inside a nested
    /// archive opened in memory).
    pub fn archive_data_start(&self) -> Option<u64> {
        match &self.location {
            Location::Zip { data_offset, .. } => Some(*data_offset),
            Location::Loose { .. } | Location::Nested { .. } => None,
        }
    }

    /// True when the file is stored compressed (a DEFLATE entry, top-level or nested).
    pub fn is_compressed(&self) -> bool {
        matches!(
            &self.location,
            Location::Zip {
                method: Method::Deflate,
                ..
            } | Location::Nested {
                method: Method::Deflate,
                ..
            }
        )
    }
}

/// Format-specific context for a match, produced by an inspector (`--inspect`).
///
/// `summary` is a human one-liner (used in txt/csv); `detail` is a structured
/// object (used as the nested `context` in JSON). Keeping both lets each output
/// format show inspection at its natural fidelity.
#[derive(Debug, Clone, PartialEq)]
pub struct Inspection {
    /// Detected format, e.g. "txt", "json", "xml", "sqlite".
    pub format: String,
    /// Human-readable one-liner, e.g. `line 12, col 4` or `$.users[3].token`.
    pub summary: String,
    /// Structured detail for machine-readable output.
    pub detail: serde_json::Value,
}

/// What changed *inside* a modified file, produced by an inspector for `diff
/// --inspect`. Mirrors [`Inspection`]'s shape (a one-line `summary` plus structured
/// `detail`) so each output format shows the intra-file diff at its natural fidelity
/// — e.g. SQLite table row-count deltas, plist/JSON changed key paths, text line
/// counts.
#[derive(Debug, Clone, PartialEq)]
pub struct ContentDiff {
    /// Format that produced the diff, e.g. "sqlite", "json", "plist", "txt".
    pub format: String,
    /// Human-readable one-liner, e.g. `messages 100→103 rows; +1 table`.
    pub summary: String,
    /// Structured detail for machine-readable output.
    pub detail: serde_json::Value,
}

/// A single regex match within an entry.
///
/// The line is kept as raw bytes (not a decoded `String`) so the caller can
/// splice in colour escapes at exact byte positions before lossily decoding —
/// decoding first would shift byte offsets and break match highlighting on
/// non-UTF-8 forensic data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchHit {
    /// Byte offset of the match start within the entry's (uncompressed) data.
    pub offset: u64,
    /// Raw bytes of the line containing the match (trailing `\r`/`\n` removed).
    pub line: Vec<u8>,
    /// Byte range of the match within `line`, for highlighting.
    pub match_in_line: Range<usize>,
}

/// An archive-level match, enriched with every offset the caller might want.
///
/// This is the unit handed to `report::output`. The offsets answer "where":
/// - `file_start`: where the matching file's data begins in the archive (0 for a
///   loose file, which is its own data starting at byte 0),
/// - `file_offset`: the match position *within the file's logical content*,
/// - `archive_offset`: the match's absolute byte position in the archive, or `None`
///   for a loose file (no enclosing archive) and for DEFLATE/decrypted content.
///
/// For STORED entries `file_start + file_offset == archive_offset`. For DEFLATE
/// entries the match lives in the decompressed stream, which has no single archive
/// byte, so `archive_offset` is the compressed blob's start and `compressed` is
/// `true` to flag that it is approximate. For a loose file there is no archive, so
/// `archive_offset` is `None`.
///
/// `Eq` is intentionally not derived: `Inspection::detail` is a
/// `serde_json::Value`, which is only `PartialEq` (it may hold floats).
#[derive(Debug, Clone, PartialEq)]
pub struct MatchRecord {
    /// Source archive display label, set only when more than one archive is
    /// searched in a run (so single-archive txt/csv output is unchanged).
    pub archive: Option<String>,
    /// Full filesystem path of the source archive, set for every record. Used by
    /// JSON output so each result names its origin; txt/csv use `archive`.
    pub archive_path: Option<String>,
    /// File name and path inside the archive.
    pub path: String,
    pub file_start: u64,
    pub file_offset: u64,
    /// Absolute byte position of the match in the archive, or `None` when there is
    /// no single archive byte (a loose file, a DEFLATE entry, or decrypted content).
    pub archive_offset: Option<u64>,
    /// True when the entry was DEFLATE — see `archive_offset` note above.
    pub compressed: bool,
    /// True when the entry was decrypted before searching: the offsets are then
    /// positions within the *decrypted* plaintext, not the archive, so
    /// `archive_offset` is set to the entry's data start (like the DEFLATE case)
    /// and this flags that the match was found in decrypted content.
    pub decrypted: bool,
    /// Raw bytes of the line containing the match (trailing `\r`/`\n` removed).
    pub line: Vec<u8>,
    /// Byte range of the match within `line`, for highlighting.
    pub match_in_line: Range<usize>,
    /// Format-specific context, present only when `--inspect` matched a format.
    pub inspection: Option<Inspection>,
    /// How the matched bytes were encoded (plain or base64). `Plain` for an
    /// ordinary match; `Base64` when found via `--base64`.
    pub encoding: Encoding,
    /// The decoded value, set only for base64 matches — it is the literal the
    /// user searched for, shown so the report says what the encoded run contains.
    pub decoded: Option<String>,
    /// iOS app bundle ID (e.g. `com.apple.weather`) for matches inside a
    /// container directory — resolved from the container's
    /// `.com.apple.mobile_container_manager.metadata.plist`. Populated by
    /// `ios::containers::AppContainerMap` in the post-search annotation pass;
    /// `None` when the source has no iOS container metadata or the match is
    /// outside any known container.
    /// Serialised by `report::output::JsonView` (not directly on this struct).
    pub bundle_id: Option<String>,
}

impl MatchRecord {
    /// Assemble an archive-level record from an entry and one of its hits.
    ///
    /// Centralised here (rather than in `main`) so the STORED-vs-DEFLATE offset
    /// rule has a single, unit-tested home.
    pub fn new(entry: &Entry, hit: SearchHit) -> Self {
        // Derive the offset model from where the file lives. STORED: exact archive
        // byte (`data_offset + hit.offset`). DEFLATE: no exact byte exists, so point
        // at the compressed blob's start and let `compressed` flag the caveat. Loose:
        // no archive at all, so `file_start` is 0 and `archive_offset` is `None`.
        let (file_start, archive_offset, compressed) = match &entry.location {
            Location::Zip {
                method,
                data_offset,
                ..
            } => {
                let compressed = *method == Method::Deflate;
                let archive_offset = if compressed {
                    *data_offset
                } else {
                    *data_offset + hit.offset
                };
                (*data_offset, Some(archive_offset), compressed)
            }
            Location::Loose { .. } => (0, None, false),
            // Inside a nested archive: no single top-level archive byte, so the
            // offsets are within the extracted file (like a loose file), but the
            // entry can still be DEFLATE-compressed.
            Location::Nested { method, .. } => (0, None, *method == Method::Deflate),
        };
        Self {
            archive: None,
            archive_path: None,
            path: entry.name.clone(),
            file_start,
            file_offset: hit.offset,
            archive_offset,
            compressed,
            decrypted: false,
            line: hit.line,
            match_in_line: hit.match_in_line,
            inspection: None,
            encoding: Encoding::Plain,
            decoded: None,
            bundle_id: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hit() -> SearchHit {
        SearchHit {
            offset: 17,
            line: b"x".to_vec(),
            match_in_line: 0..1,
        }
    }

    fn zip_entry(method: Method, data_offset: u64, data_len: u64) -> Entry {
        Entry {
            name: "a".into(),
            uncompressed_size: 50,
            mtime: None,
            location: Location::Zip {
                method,
                data_offset,
                data_len,
            },
        }
    }

    #[test]
    fn stored_archive_offset_is_exact() {
        let entry = zip_entry(Method::Stored, 100, 50);
        let rec = MatchRecord::new(&entry, hit());
        assert_eq!(rec.archive_offset, Some(117));
        assert_eq!(rec.file_start, 100);
        assert!(!rec.compressed);
    }

    #[test]
    fn deflate_archive_offset_falls_back_to_file_start() {
        let entry = zip_entry(Method::Deflate, 100, 20);
        let rec = MatchRecord::new(&entry, hit());
        assert_eq!(rec.archive_offset, Some(100)); // blob start, not 117
        assert_eq!(rec.file_offset, 17); // still the decompressed position
        assert!(rec.compressed);
    }

    #[test]
    fn loose_file_has_no_archive_offset() {
        let entry = Entry {
            name: "a".into(),
            uncompressed_size: 50,
            mtime: None,
            location: Location::Loose {
                path: "/tmp/a".into(),
            },
        };
        let rec = MatchRecord::new(&entry, hit());
        assert_eq!(rec.archive_offset, None); // no enclosing archive
        assert_eq!(rec.file_start, 0); // the file is its own data from byte 0
        assert_eq!(rec.file_offset, 17);
        assert!(!rec.compressed);
    }
}
