//! In-file deep search: the inspector API, format detection, and dispatch.
//!
//! Defines: the [`Inspector`] trait (the standard interface every format
//! implements), the `classify_inspector!` macro, the inspector registry, and the
//! dispatch entry points [`inspect`] / [`inspect_many`], [`diff`], [`sidecars_for`];
//! re-exports the detection API of `detect` ([`detect_type`], [`is_known_type`],
//! [`type_names`], …, which drive `--type` and the media skip).
//! Used by: `ops::search::classify` (`--inspect`, `--type`), `ops::find`, `ops::diff`,
//! `engine::type_from_ends`, `report::export::write` (sidecar export), `cmd`.
//! Uses: `crate::core::models::{Inspection, ContentDiff}`, the per-format submodules,
//! `detect` (which inspector a file belongs to) and `nested` (data inside a value).
//!
//! ── The inspector API ───────────────────────────────────────────────────────
//! An *inspector* turns a raw byte `offset` into a meaningful location inside a
//! recognised format. Every inspector is a zero-sized type implementing
//! [`Inspector`], lives in its own submodule, and is listed once in the
//! `INSPECTORS` registry. The core logic (detection order, dispatch, the public
//! entry points) is identical across formats and lives here; an inspector only
//! supplies its extensions, a header check, the resolver, and (optionally) its
//! sidecar files.
//!
//! Shared helpers (`line_at`, `looks_like_xml`, `contains`) are kept here and
//! documented so several inspectors can reuse them without duplicating code.
//!
//! Adding one: copy `docs/inspector-template.rs` into a new submodule, implement
//! [`Inspector`], and add it to the `INSPECTORS` registry. See
//! `docs/inspectors.md`.
//!
//! Currently implemented (resolve an offset): TXT, JSON, XML, SQLite (and its
//! `-wal`), CSV, plist (XML + binary), protobuf (by structure), SEGB (v1, v2) and
//! Realm (format 10+), ABX (Android Binary XML), typedstream (iMessage
//! `attributedBody`), MMKV (by structure), LevelDB logs and manifests, and unified-log
//! `uuidtext`.
//! Plus classification-only inspectors that detect but do not resolve: the media
//! formats (`media/`, one file per family: image, video, audio) and the identify-only formats
//! (`identify/`, one file per category: LevelDB, Realm, archives, executables, …).

use crate::core::models::{ContentDiff, Inspection};

// WHY defined here, above the `mod` lines: a `macro_rules!` is in scope for the
// modules declared after it, so the per-format files use it with no import.
/// Generate a classification-only inspector: a zero-sized type that names a file's
/// format (`$name`, category `$cat`) from the `$detect` header predicate (and the
/// `$ext` list), but does not resolve offsets (`inspect` is always `None`). Used by
/// the media formats and the identify-only formats.
macro_rules! classify_inspector {
    ($ty:ident, $name:literal, $cat:literal, [$($ext:literal),*], $detect:expr) => {
        pub struct $ty;
        impl $crate::formats::inspect::Inspector for $ty {
            fn name(&self) -> &'static str { $name }
            fn category(&self) -> &'static str { $cat }
            fn extensions(&self) -> &'static [&'static str] { &[$($ext),*] }
            fn detect(&self, content: &[u8]) -> bool { ($detect)(content) }
            fn inspect(
                &self,
                _content: &[u8],
                _offset: usize,
            ) -> Option<$crate::core::models::Inspection> {
                None
            }
        }
    };
}

// Structured / database / text inspectors (resolve offsets).
mod abx;
mod csv;
// Format detection (header, end, name, structure) and the `--type` answers.
mod detect;
pub use detect::{
    HEAD_LEN, TAIL_LEN, TypeInfo, detect_type, end_types, is_known_type, type_from_end,
    type_from_start, type_names,
};
use detect::{detect, detect_by_extension, detect_by_tail};
pub(crate) use detect::{detect_by_header, detect_structure};
mod json;
pub(crate) use json::unescape as json_unescape;
mod leveldb;
mod mmkv;
// What an embedded byte run holds (shared by the SQLite and SEGB inspectors).
mod nested;
pub(crate) use nested::describe_nested_many;
// NSKeyedArchiver graph-walk resolver — sibling of `plist`, uses `plist::Bplist`
// via the `pub(super)` helpers exposed below.
mod nskeyed;
mod plist;
mod protobuf;
mod realm;
mod segb;
mod sqlite;
pub(crate) use sqlite::inspect_wal;
mod txt;
mod typedstream;
mod uuidtext;
mod xml;

// Shared helper: structured diff of two JSON value trees (used by json + plist).
mod value_diff;

// Media inspectors — the `media` category, one file per family (image, video,
// audio) under `inspect/media/` (classify only). Its `mod.rs` is the category
// aggregator (the family submodules + the shared magic), re-exporting each struct.
mod media;

// Identify-only formats (LevelDB, Realm, archives, executables, …) — recognised
// by a signature at the start of the file, not inspected further. One file per
// category under `inspect/identify/`.
mod identify;

/// The interface every format inspector implements — the inspector API.
///
/// Implementors are zero-sized marker types (e.g. `struct Sqlite;`). The dispatch
/// here calls these methods; an inspector never has to touch detection ordering
/// or output plumbing.
pub trait Inspector: Sync {
    /// Short format tag, e.g. `"sqlite"`, `"jpeg"`. Used as the `--type` value
    /// for this exact format and as the `format` shown in inspection output.
    fn name(&self) -> &'static str;

    /// Coarse group this format belongs to, e.g. `"media"`, `"database"`,
    /// `"structured"`, `"text"`. Used as a `--type` value to select a whole
    /// family at once (the media skip is just `--type`-style exclusion of the
    /// `"media"` category).
    fn category(&self) -> &'static str;

    /// File-name extensions (lowercase, no dot) used for fallback detection when
    /// the content has no recognisable header.
    ///
    /// WHY kept small: a file name is weak evidence in an acquisition. List only
    /// the format's standard extensions, and none when it has no common one
    /// (protobuf) — an extension there would only add false claims.
    fn extensions(&self) -> &'static [&'static str];

    /// Recognise the format from the content's header/magic. Preferred over the
    /// extension, because forensic file names are often wrong or absent. Return
    /// `false` for formats with no signature (JSON, CSV, TXT).
    fn detect(&self, content: &[u8]) -> bool;

    /// Recognise the format from the **last** [`TAIL_LEN`] bytes of the file (fewer
    /// for a shorter file), for a format whose only signature is at its end (a
    /// LevelDB table's footer). Checked only when no header matched. Default: none.
    fn detect_tail(&self, _tail: &[u8]) -> bool {
        false
    }

    /// Whether this format has an end-of-file signature ([`Self::detect_tail`]), so
    /// a caller can tell, before reading a file's end, whether that read could
    /// change anything. Must be `true` for every inspector that overrides
    /// `detect_tail`.
    fn has_tail_signature(&self) -> bool {
        false
    }

    /// Whether `--type` can select this format. `false` for a format that is only
    /// ever recognised by structure after a match (protobuf), never when files are
    /// classified, so offering it as a `--type` would silently select nothing.
    fn selectable_by_type(&self) -> bool {
        true
    }

    /// Resolve a match at `offset` to a meaningful location. Return `None` when
    /// the offset can't be placed; the caller then emits a plain record.
    fn inspect(&self, content: &[u8], offset: usize) -> Option<Inspection>;

    /// Resolve several match offsets within ONE file in a single call,
    /// returning one (positional) result per offset.
    ///
    /// The default just loops over [`Inspector::inspect`]. Override when
    /// resolution re-derives expensive per-file state for every offset —
    /// SQLite re-walks the schema and every table's b-tree per call, which is
    /// O(matches × tables × pages) on a match-heavy database; building that
    /// state once per file makes it O(tables × pages + matches).
    fn inspect_many(&self, content: &[u8], offsets: &[usize]) -> Vec<Option<Inspection>> {
        offsets.iter().map(|&o| self.inspect(content, o)).collect()
    }

    /// Describe what changed *inside* a modified file of this format, comparing the
    /// `old` (side A) and `new` (side B) bytes, for `diff --inspect`. Return `None`
    /// when this format has no structured diff or the bytes cannot be parsed; the
    /// caller then reports the file as modified with no intra-file detail. Default:
    /// no structured diff.
    fn diff(&self, _old: &[u8], _new: &[u8]) -> Option<ContentDiff> {
        None
    }

    /// Sidecar file suffixes exported alongside a matched file of this format
    /// (e.g. SQLite's `-wal`). Default: none. Declaring them here is all it takes
    /// for `export` to fetch them — see [`sidecars_for`].
    fn sidecars(&self) -> &'static [&'static str] {
        &[]
    }
}

/// Every inspector, in **detection-priority order**: `detect` (header) checks run
/// top-to-bottom, so list more specific formats first — e.g. plist before
/// generic XML, since both begin with `<?xml`.
static INSPECTORS: &[&dyn Inspector] = &[
    // Structured / database — recognised by header magic.
    &sqlite::Sqlite,
    &plist::Plist,
    &xml::Xml,
    &segb::Segb,
    &typedstream::Typedstream,
    &uuidtext::Uuidtext,
    // Identify-only — before media, because several media checks are weak (MP3's
    // 11-bit frame sync matches any file starting `FF Ex`) and would otherwise take
    // files these stronger signatures name. Within: magic at offset 0 first, then
    // those further in (Realm and LMDB at 16, tar at 257), then LevelDB's checksum.
    &identify::SqliteWal,
    &identify::SqliteShm,
    &identify::SqliteJournal,
    &abx::Abx,
    &identify::BinaryCookies,
    &identify::Bom,
    &identify::Zip,
    &identify::Gzip,
    &identify::Bzip2,
    &identify::Xz,
    &identify::Zstd,
    &identify::SevenZip,
    &identify::Lz4,
    &identify::Lzfse,
    &identify::Aea,
    &identify::Elf,
    &identify::MachO,
    &identify::Dex,
    &identify::Hermes,
    &identify::Pdf,
    &identify::Ole,
    &identify::Vcard,
    &identify::Icalendar,
    &identify::Pem,
    &identify::ChromiumCache,
    &identify::Tracev3,
    &identify::Dsc,
    &realm::Realm,
    &identify::Lmdb,
    &identify::Tar,
    &leveldb::Leveldb,
    // Media — recognised by header magic; classification only (no offset
    // resolution). List the more specific container before the generic one:
    // WebM before Matroska, Opus before Ogg (both share a magic).
    &media::Jpeg,
    &media::Png,
    &media::Gif,
    &media::Bmp,
    &media::Tiff,
    &media::Heif,
    &media::Webp,
    &media::Ico,
    &media::Ktx,
    &media::AppleKtx,
    &media::Dng,
    &media::Cr2,
    &media::Nef,
    &media::Mp4,
    &media::Mov,
    &media::M4v,
    &media::Avi,
    &media::Webm,
    &media::Mkv,
    &media::ThreeGp,
    &media::Mpeg,
    &media::Wmv,
    &media::Flv,
    &media::Mp3,
    &media::M4a,
    &media::Aac,
    &media::Wav,
    &media::Flac,
    &media::Opus,
    &media::Ogg,
    &media::Wma,
    &media::Amr,
    &media::Caf,
    &media::Aiff,
    // No signature — matched by extension only; keep last so a real header
    // always wins over a misleading file name.
    &json::Json,
    &mmkv::Mmkv,
    &protobuf::Protobuf,
    &csv::Csv,
    &txt::Txt,
];

/// Produce inspection context for a match at `offset` in `content`.
///
/// Returns `None` when the format is unsupported or undetected — the caller then
/// emits the plain match record.
pub fn inspect(name: &str, content: &[u8], offset: usize) -> Option<Inspection> {
    inspect_many(name, content, &[offset]).pop().flatten()
}

/// Produce inspection context for several match offsets in one file, one
/// (positional) result per offset. The batch twin of [`inspect`]: detection
/// runs once, and inspectors with per-file state derive it once for all
/// offsets (see [`Inspector::inspect_many`]).
///
/// A file no inspector claims by header or extension gets one more chance: when its
/// whole content is JSON or a protobuf message, that inspector resolves the matches,
/// and each result is marked `"detection": "structure"` and "(by structure)" (inferred,
/// not read from a signature or a name). Only matched files reach this, so the parse costs nothing
/// for the rest, and `--type` never classifies a file this way.
pub fn inspect_many(name: &str, content: &[u8], offsets: &[usize]) -> Vec<Option<Inspection>> {
    // A header is proof of the format: report it even where the inspector cannot
    // place the match (an identify-only format, a media file), as `[format]`.
    if let Some(insp) = detect_by_header(content).or_else(|| detect_by_tail(content)) {
        return insp
            .inspect_many(content, offsets)
            .into_iter()
            .map(|found| found.or_else(|| Some(identified(insp))))
            .collect();
    }
    if let Some(insp) = detect_by_extension(name) {
        return insp.inspect_many(content, offsets);
    }
    match detect_structure(content) {
        Some(insp) => insp
            .inspect_many(content, offsets)
            .into_iter()
            .map(|found| found.map(mark_inferred))
            .collect(),
        None => offsets.iter().map(|_| None).collect(),
    }
}

/// The result for a match in a file whose format is known from its header but whose
/// position the inspector does not resolve: the format alone, with no summary.
fn identified(insp: &dyn Inspector) -> Inspection {
    Inspection {
        format: insp.name().to_string(),
        summary: String::new(),
        detail: serde_json::json!({}),
    }
}

/// Mark an inspection as resting on a structural guess: `"detection": "structure"` in
/// its detail and "(by structure)" in its summary. The `format` stays the plain name,
/// so a consumer filtering on it still finds these results.
fn mark_inferred(mut found: Inspection) -> Inspection {
    if let Some(detail) = found.detail.as_object_mut() {
        detail.insert("detection".into(), serde_json::json!("structure"));
    }
    found.summary.push_str("  (by structure)");
    found
}

/// Describe what changed inside a modified file, comparing `old` (side A) and `new`
/// (side B) bytes. The format is detected from `new` (the file's name is the same on
/// both sides). Returns `None` when the format is unsupported/undetected or has no
/// structured diff — the caller then reports the file as modified without detail.
pub fn diff(name: &str, old: &[u8], new: &[u8]) -> Option<ContentDiff> {
    detect(name, new)?.diff(old, new)
}

/// Sidecar suffixes to export alongside a matched file (empty if unrecognised).
///
/// Lets `export` fetch each format's associated files without hard-coding them:
/// the list comes from the matching inspector's [`Inspector::sidecars`].
pub fn sidecars_for(name: &str, content: &[u8]) -> &'static [&'static str] {
    detect(name, content).map_or(&[], |insp| insp.sidecars())
}

// ── Shared helpers (reused by several inspectors) ───────────────────────────

/// The longest text shown in a one-line summary, in characters.
pub(crate) const SHOWN_CHARS: usize = 120;

/// `text` for a one-line summary: control characters (a newline in a message) as
/// spaces, at most [`SHOWN_CHARS`] characters, then `…` when cut. The detail (JSON)
/// keeps the exact text; this is for the summary only.
pub(crate) fn one_line(text: &str) -> String {
    let mut shown: String = text
        .chars()
        .take(SHOWN_CHARS)
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if text.chars().nth(SHOWN_CHARS).is_some() {
        shown.push('…');
    }
    shown
}

/// [`one_line`] in double quotes.
pub(crate) fn quoted(text: &str) -> String {
    format!("\"{}\"", one_line(text))
}

/// Bytes as [`quoted`] text (invalid UTF-8 replaced).
pub(crate) fn quoted_bytes(bytes: &[u8]) -> String {
    quoted(&String::from_utf8_lossy(bytes))
}

/// A LEB128 varint at `i` in `b`, at most `max` bytes long (5 for a 32-bit value, 10
/// for 64-bit): its value and the position after it.
pub(crate) fn leb128(b: &[u8], mut i: usize, max: usize) -> Option<(u64, usize)> {
    let mut value = 0u64;
    for k in 0..max.min(10) {
        let byte = *b.get(i)?;
        i += 1;
        value |= u64::from(byte & 0x7F) << (7 * k);
        if byte & 0x80 == 0 {
            return Some((value, i));
        }
    }
    None
}

/// 1-based line number of `offset` within `content` (newline count + 1).
///
/// Used by the text-based inspectors (JSON, XML, plist-XML) so their summaries
/// can cite a line, like the TXT inspector.
pub(crate) fn line_at(content: &[u8], offset: usize) -> usize {
    let end = offset.min(content.len());
    1 + content[..end].iter().filter(|&&b| b == b'\n').count()
}

/// True if `content` looks like XML: an `<?xml` declaration, after an optional
/// UTF-8 BOM. Shared by the XML and plist inspectors' `detect`.
pub(crate) fn looks_like_xml(content: &[u8]) -> bool {
    let body = content.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(content);
    body.starts_with(b"<?xml")
}

/// True if `haystack` contains `needle`.
pub(crate) fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// True if `content` is a RIFF container whose 4-byte form type (bytes 8..12)
/// equals `form` — e.g. `WAVE`, `AVI `, `WEBP`. Shared by those media inspectors.
pub(crate) fn riff_form(content: &[u8], form: &[u8; 4]) -> bool {
    content.len() >= 12 && &content[0..4] == b"RIFF" && &content[8..12] == form
}

/// True if `content` is an ISO Base Media file (`ftyp` box at byte 4) whose major
/// brand (bytes 8..12) is one of `brands` — e.g. `mp42`, `qt  `, `M4A `. Shared by
/// the MP4/MOV/HEIF/M4A family of media inspectors.
pub(crate) fn ftyp_brand(content: &[u8], brands: &[&[u8; 4]]) -> bool {
    content.len() >= 12 && &content[4..8] == b"ftyp" && brands.iter().any(|b| &content[8..12] == *b)
}

#[cfg(test)]
mod tests {
    use super::INSPECTORS;

    /// Position of the inspector named `name` in the registry.
    fn index_of(name: &str) -> usize {
        INSPECTORS
            .iter()
            .position(|i| i.name() == name)
            .unwrap_or_else(|| panic!("{name} missing from INSPECTORS"))
    }

    /// Detection correctness depends on registry ORDER for formats that share a
    /// magic: the more specific one must come first or it is never detected.
    /// The comments in the registry say so; this test makes a reorder fail loud
    /// instead of silently misclassifying (review finding C7).
    #[test]
    fn registry_lists_specific_formats_before_their_generic_twins() {
        assert!(index_of("plist") < index_of("xml"), "plist IS xml + magic");
        assert!(index_of("webm") < index_of("mkv"), "WebM shares EBML magic");
        assert!(index_of("opus") < index_of("ogg"), "Opus shares OggS magic");
    }
}
