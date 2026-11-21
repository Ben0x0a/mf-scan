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

/// The detected format name and category of a file (header-first, then
/// extension), used by the `--type` filter and the media skip.
///
/// WHY it lives here: it is a plain data shape consumed by `core::filter`, so it
/// belongs in the foundation layer. The `formats::inspect` layer *fills* it (via
/// `detect_type`) from the actual inspectors; `core` only consumes it. Keeping it
/// in `core` avoids an upward dependency from the foundation into `formats`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TypeInfo {
    pub name: &'static str,
    pub category: &'static str,
}

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
    /// The pattern as given on the command line (several `-e` patterns are joined
    /// with ` | `, and listed individually in `patterns`).
    pub pattern: String,
    /// Each pattern, when `-e` gave more than one. Omitted otherwise.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub patterns: Vec<String>,
    /// Pattern was treated as a literal string (`-F`), not a regex.
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
    /// Every encoding searched besides plain UTF-8 (`--encoding`,
    /// `--all-encodings`): `nfd`, `utf16le`, `utf16be`, `cesu8`, `json`, `url`, `base64`,
    /// `base64url`.
    /// Absent from manifests written before it existed.
    #[serde(default)]
    pub encodings: Vec<String>,
    /// Keychain/keystore dump files supplied for decryption (`--keyfile`).
    pub keyfiles: Vec<String>,
    /// Platform scope for decryption profiles (`--platform`), if set.
    pub platform: Option<String>,
    /// The application identifier(s) the run was limited to: an `app export`'s, or
    /// a search's or diff's `--app` (comma-separated). `None` for a run not limited
    /// to apps.
    ///
    /// WHY `#[serde(default)]` on this and the two fields below: they were added
    /// after the manifest/report format was already in use, so an older manifest
    /// (written without them) must still deserialise — `default` supplies the empty
    /// value rather than failing the parse.
    #[serde(default)]
    pub app: Option<String>,
    /// The source path prefixes the app's data was resolved to (one per container:
    /// the app's own data, its extension/widget containers, and any App Groups); for
    /// a search, those of the source an export came from.
    #[serde(default)]
    pub app_containers: Vec<String>,
    /// How each included App Group was attributed, as `"<group-id> -> <link>"`
    /// where `<link>` is `Entitlement` (authoritative, from the app binary's
    /// code-signature) or `VendorHeuristic` (reverse-DNS vendor-token fallback) —
    /// recorded so an analyst can audit which group inclusions are authoritative.
    #[serde(default)]
    pub app_group_links: Vec<String>,
    /// Loose files `-r` found while walking for archives and did NOT search. Omitted
    /// from JSON when zero, so a run with no such scope loss is unchanged.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub loose_files_skipped: usize,
}

/// `skip_serializing_if` predicate: omit a zero count from JSON output.
fn is_zero(n: &usize) -> bool {
    *n == 0
}

impl Default for RunInfo {
    /// The tool/version fields (constant for a build) plus empty defaults for
    /// everything else, so each call site states only the fields it actually sets
    /// via struct-update syntax (`..Default::default()`).
    fn default() -> Self {
        RunInfo {
            tool: "mf-scan".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            pattern: String::new(),
            patterns: Vec::new(),
            literal: false,
            ignore_case: false,
            match_path: false,
            inspect: false,
            archives: Vec::new(),
            path_globs: Vec::new(),
            not_path_globs: Vec::new(),
            types: Vec::new(),
            exclude_media: false,
            encodings: Vec::new(),
            keyfiles: Vec::new(),
            platform: None,
            app: None,
            app_containers: Vec::new(),
            app_group_links: Vec::new(),
            loose_files_skipped: 0,
        }
    }
}

/// How a match's bytes were encoded in the file.
///
/// `Plain` is the pattern found verbatim (as typed: UTF-8); every other variant is the
/// same literal in another encoding (see [`crate::ops::search::encodings`]): its other
/// Unicode normal form (`Nfc`, `Nfd`), UTF-16, CESU-8, JSON escapes, percent-encoding
/// (`Url`), or inside a base64 run. The distinction is carried through to the report
/// so an analyst can tell an encoded hit from a literal one and see the decoded value.
///
/// The order of the variants is the order of precedence when two encodings match the
/// same bytes: the match is reported once, under the first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Encoding {
    Plain,
    Nfc,
    Nfd,
    Utf16Le,
    Utf16Be,
    /// UTF-16 whose byte order the text cannot tell: the same characters read one
    /// byte apart as little- and big-endian (Latin-range text among Latin-range
    /// text), reported once.
    Utf16,
    Cesu8,
    Json,
    Url,
    Base64,
}

impl Encoding {
    /// Lowercase tag used in txt/csv/json output.
    pub fn as_str(self) -> &'static str {
        match self {
            Encoding::Plain => "plain",
            Encoding::Nfc => "nfc",
            Encoding::Nfd => "nfd",
            Encoding::Utf16Le => "utf16le",
            Encoding::Utf16Be => "utf16be",
            Encoding::Utf16 => "utf16",
            Encoding::Cesu8 => "cesu8",
            Encoding::Json => "json",
            Encoding::Url => "url",
            Encoding::Base64 => "base64",
        }
    }
}

/// Compression method of a ZIP entry.
///
/// Stored and Deflate are the two methods mobile-forensic archives use, and the two
/// read. Any other is kept as [`Method::Other`], so the entry is listed and reported
/// as not searched rather than left out of the archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Stored,
    Deflate,
    /// A method this tool does not decode, by its ZIP number (12 bzip2, 14 LZMA, …).
    Other(u16),
}

/// How a ZIP entry's data is encrypted (APPNOTE 6.1, and WinZip's AE-1/AE-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encryption {
    None,
    /// Traditional PKWARE encryption. `check` is the byte the 12-byte encryption
    /// header must decrypt to last; `crc32` is the CRC of the plain data, verified
    /// after decoding, since one check byte lets a wrong password through 1 time in
    /// 256.
    ZipCrypto {
        check: u8,
        crc32: u32,
    },
    /// WinZip AES (method 99). `strength` 1, 2 or 3 is AES-128, -192 or -256; the
    /// data carries a password check value and an HMAC-SHA1 over the ciphertext.
    Aes {
        strength: u8,
    },
    /// An encryption this tool does not read (PKWARE strong encryption, or an AES
    /// entry without a valid AES extra field).
    Unsupported,
}

/// Where a located file's bytes physically live — the one thing that differs
/// between a file inside an archive and a loose file on disk.
///
/// A ZIP entry is addressed by a byte range inside the archive (plus its
/// compression method); a loose file is addressed by its path on disk. The search
/// engine reads bytes through a [`crate::core::source::Source`], so it never matches on
/// this directly — but the offset model (`MatchRecord`) and the export step do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Location {
    /// Inside a ZIP archive. `data_offset`/`data_len` describe the entry's bytes as
    /// they sit in the archive (the literal content for STORED, the compressed
    /// stream for DEFLATE).
    Zip {
        method: Method,
        encryption: Encryption,
        data_offset: u64,
        data_len: u64,
    },
    /// Inside a ZIP archive read by *positioned reads* rather than a memory map
    /// (a remote SMB/NFS source — see [`crate::core::source::ranged`]). Carries the
    /// Local File Header offset (`header_offset`), not the resolved data offset:
    /// the data start is resolved lazily, per file, when the entry is read, so
    /// listing never touches every header. Because the absolute data offset is
    /// not known at listing time, a match here reports no absolute archive offset
    /// (like a loose/nested entry) — the in-file offset is still exact.
    RangedZip {
        method: Method,
        encryption: Encryption,
        header_offset: u64,
        data_len: u64,
    },
    /// A loose file on disk, read from its own `path`. It has no archive offsets.
    Loose { path: PathBuf },
    /// Inside a nested archive that a folder scan opened in memory (see
    /// `--archive-depth`). `archive` indexes the producing
    /// [`crate::core::source::folder::FolderSource`]'s arena of opened archive buffers, and
    /// the offsets are into that buffer — so only that source can read the entry back,
    /// and it carries no absolute archive offset to the report.
    Nested {
        archive: usize,
        method: Method,
        encryption: Encryption,
        data_offset: u64,
        data_len: u64,
    },
    /// Inside a `tar` archive. A tar stores each file uncompressed and contiguous,
    /// so `data_offset`/`data_len` are the byte range in the backing buffer (the
    /// memory-mapped `.tar` file, or the decompressed stream of a `.tar.gz`). For a
    /// plain `.tar` the offset is a true file offset (a real carve coordinate); for
    /// a `.tar.gz` it indexes the decompressed stream, so the source reports no
    /// absolute archive offset there — see
    /// `TarSource::archive_data_start`.
    Tar { data_offset: u64, data_len: u64 },
    /// Inside a 7z archive. 7z compresses files together in blocks, so the source
    /// decodes every block once, whole, and `data_offset`/`data_len` are the byte
    /// range in that decoded stream; no byte of the `.7z` file corresponds to them,
    /// so the source reports no absolute archive offset.
    SevenZ { data_offset: u64, data_len: u64 },
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
            // A tar entry's absolute offset (physical only for a plain `.tar`) is
            // resolved by `TarSource::archive_data_start`, which knows whether its
            // backing is a mapped file or a decompressed stream; the default here is
            // conservative.
            Location::RangedZip { .. }
            | Location::Loose { .. }
            | Location::Nested { .. }
            | Location::Tar { .. }
            | Location::SevenZ { .. } => None,
        }
    }

    /// True when a ZIP entry's data is encrypted (in whichever ZIP location).
    pub fn is_encrypted(&self) -> bool {
        match &self.location {
            Location::Zip { encryption, .. }
            | Location::RangedZip { encryption, .. }
            | Location::Nested { encryption, .. } => *encryption != Encryption::None,
            Location::Loose { .. } | Location::Tar { .. } | Location::SevenZ { .. } => false,
        }
    }

    /// True when the file is stored compressed (a DEFLATE entry, top-level,
    /// ranged, or nested).
    pub fn is_compressed(&self) -> bool {
        matches!(
            &self.location,
            Location::Zip {
                method: Method::Deflate,
                ..
            } | Location::RangedZip {
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
    /// The match's length in bytes. Not `match_in_line.len()`: the preview is capped
    /// and drops a trailing carriage return.
    pub len: usize,
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
    /// The match's 1-based line number within the file, set only with `-n`.
    pub line_number: Option<u64>,
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
    /// ordinary match; another variant when found via `--encoding`.
    pub encoding: Encoding,
    /// The decoded value, set only for encoded (non-plain) matches: the matched bytes'
    /// text, or for base64 the literal searched for (the run around the match was
    /// checked to decode to it), so the report says what the encoded bytes contain.
    pub decoded: Option<String>,
    /// iOS app bundle ID (e.g. `com.apple.weather`) for matches inside a
    /// container directory — resolved from the container's
    /// `.com.apple.mobile_container_manager.metadata.plist`. Populated by
    /// `ios::containers::AppContainerMap` in the post-search annotation pass;
    /// `None` when the source has no iOS container metadata or the match is
    /// outside any known container.
    /// Serialised by `report::output::JsonView` (not directly on this struct).
    pub bundle_id: Option<String>,
    /// True when the pattern matched the file's PATH, not its content
    /// (`--match-path`, or the path half of `--and-paths`): `line` then holds the
    /// path and there is no in-file offset.
    pub path_match: bool,
}

impl MatchRecord {
    /// Assemble an archive-level record from an entry, one of its hits, and the
    /// entry's resolved data start (`archive_data_start`) — the absolute archive
    /// byte where its data begins, or `None` when the source cannot place it (a
    /// loose/nested file, or a ranged header that failed to resolve).
    ///
    /// Centralised here (rather than in `main`) so the STORED-vs-DEFLATE offset
    /// rule has a single, unit-tested home. Taking the data start as a parameter
    /// (rather than reading it off `Location`) lets the *positioned-read* source
    /// report the same exact offsets as the memory-mapped one: both resolve the
    /// data start through [`crate::core::source::Source::archive_data_start`] and feed it
    /// here, so the offset model no longer depends on which I/O path read the file.
    pub fn new(entry: &Entry, hit: SearchHit, archive_data_start: Option<u64>) -> Self {
        // Derive the offset model from the compression method and the resolved data
        // start. STORED with a known start: exact archive byte (`start + offset`).
        // DEFLATE: no exact byte exists, so point at the compressed blob's start and
        // let `compressed` flag the caveat. No resolved start (loose/nested, or an
        // unresolvable ranged header): no archive byte, `file_start` 0.
        let compressed = entry.is_compressed();
        // An encrypted entry's match is in the decrypted bytes: like DEFLATE, no
        // archive byte holds it, so the offset is the data's start.
        let decrypted = entry.is_encrypted();
        let (file_start, archive_offset) = match (&entry.location, archive_data_start) {
            // A top-level ZIP entry (mmap or ranged) or a plain `.tar` entry with its
            // data start resolved — the offset is the exact archive byte.
            (
                Location::Zip { .. } | Location::RangedZip { .. } | Location::Tar { .. },
                Some(start),
            ) => {
                let offset = if compressed || decrypted {
                    start
                } else {
                    start + hit.offset
                };
                (start, Some(offset))
            }
            // Loose, nested, or a ranged entry whose header could not be read: the
            // match is still exact *within the file*, but there is no archive byte.
            _ => (0, None),
        };
        Self {
            archive: None,
            archive_path: None,
            path: entry.name.clone(),
            file_start,
            file_offset: hit.offset,
            line_number: None,
            archive_offset,
            compressed,
            decrypted,
            line: hit.line,
            match_in_line: hit.match_in_line,
            inspection: None,
            encoding: Encoding::Plain,
            decoded: None,
            bundle_id: None,
            path_match: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hit() -> SearchHit {
        SearchHit {
            offset: 17,
            len: 1,
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
                encryption: Encryption::None,
                data_offset,
                data_len,
            },
        }
    }

    #[test]
    fn stored_archive_offset_is_exact() {
        let entry = zip_entry(Method::Stored, 100, 50);
        let rec = MatchRecord::new(&entry, hit(), entry.archive_data_start());
        assert_eq!(rec.archive_offset, Some(117));
        assert_eq!(rec.file_start, 100);
        assert!(!rec.compressed);
    }

    #[test]
    fn deflate_archive_offset_falls_back_to_file_start() {
        let entry = zip_entry(Method::Deflate, 100, 20);
        let rec = MatchRecord::new(&entry, hit(), entry.archive_data_start());
        assert_eq!(rec.archive_offset, Some(100)); // blob start, not 117
        assert_eq!(rec.file_offset, 17); // still the decompressed position
        assert!(rec.compressed);
    }

    /// A ranged (positioned-read) STORED entry reports the SAME exact archive
    /// offset as the mmap path, once the source resolves its data start and feeds
    /// it in — the unification that lets `ranged` be the default without losing the
    /// carve coordinate. (`None` would be reported only if the header is unresolvable.)
    #[test]
    fn ranged_stored_archive_offset_is_exact_when_resolved() {
        let entry = Entry {
            name: "a".into(),
            uncompressed_size: 50,
            mtime: None,
            location: Location::RangedZip {
                method: Method::Stored,
                encryption: Encryption::None,
                header_offset: 40,
                data_len: 50,
            },
        };
        // The source resolved the data start to byte 100 (header + name/extra).
        let rec = MatchRecord::new(&entry, hit(), Some(100));
        assert_eq!(rec.archive_offset, Some(117));
        assert_eq!(rec.file_start, 100);
        assert!(!rec.compressed);

        // Unresolvable header ⇒ no archive byte, but the in-file offset is intact.
        let rec_none = MatchRecord::new(&entry, hit(), None);
        assert_eq!(rec_none.archive_offset, None);
        assert_eq!(rec_none.file_offset, 17);
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
        let rec = MatchRecord::new(&entry, hit(), entry.archive_data_start());
        assert_eq!(rec.archive_offset, None); // no enclosing archive
        assert_eq!(rec.file_start, 0); // the file is its own data from byte 0
        assert_eq!(rec.file_offset, 17);
        assert!(!rec.compressed);
    }
}
