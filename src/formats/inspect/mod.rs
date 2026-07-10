//! In-file deep search: the inspector API, format detection, and dispatch.
//!
//! Defines: the [`Inspector`] trait (the standard interface every format
//! implements), the inspector registry, and the public entry points
//! [`inspect`], [`sidecars_for`], and the file-type helpers [`detect_type`] /
//! [`is_known_type`] / [`type_names`] (which drive `--type` and the media skip).
//! Used by: `engine.rs` (`--inspect`) and `export.rs` (sidecar export).
//! Uses: `crate::core::models::Inspection` and the per-format submodules.
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
//! Currently implemented (resolve an offset): TXT, JSON, XML, SQLite, CSV, plist
//! (XML + binary). Plus classification-only media inspectors (one per format,
//! category `media`) used by `--type` and the media skip — they detect but do
//! not resolve.

use crate::core::models::{ContentDiff, Inspection};

// Structured / database / text inspectors (resolve offsets).
mod csv;
mod json;
// NSKeyedArchiver graph-walk resolver — sibling of `plist`, uses `plist::Bplist`
// via the `pub(super)` helpers exposed below.
mod nskeyed;
mod plist;
mod sqlite;
mod txt;
mod xml;

// Shared helper: structured diff of two JSON value trees (used by json + plist).
mod value_diff;

// Media inspectors — the `media` category, one file per format under
// `inspect/media/` (classify only). Its `mod.rs` is the category aggregator
// (per-format submodules + the shared macro/magic), re-exporting each struct.
mod media;

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
    fn extensions(&self) -> &'static [&'static str];

    /// Recognise the format from the content's header/magic. Preferred over the
    /// extension, because forensic file names are often wrong or absent. Return
    /// `false` for formats with no signature (JSON, CSV, TXT).
    fn detect(&self, content: &[u8]) -> bool;

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
    &csv::Csv,
    &txt::Txt,
];

/// Produce inspection context for a match at `offset` in `content`.
///
/// Returns `None` when the format is unsupported or undetected — the caller then
/// emits the plain match record.
pub fn inspect(name: &str, content: &[u8], offset: usize) -> Option<Inspection> {
    detect(name, content)?.inspect(content, offset)
}

/// Produce inspection context for several match offsets in one file, one
/// (positional) result per offset. The batch twin of [`inspect`]: detection
/// runs once, and inspectors with per-file state derive it once for all
/// offsets (see [`Inspector::inspect_many`]).
pub fn inspect_many(name: &str, content: &[u8], offsets: &[usize]) -> Vec<Option<Inspection>> {
    match detect(name, content) {
        Some(insp) => insp.inspect_many(content, offsets),
        None => offsets.iter().map(|_| None).collect(),
    }
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

/// Pick the inspector for a file: the first whose header matches, else the first
/// claiming the file-name extension.
fn detect(name: &str, content: &[u8]) -> Option<&'static dyn Inspector> {
    if let Some(insp) = detect_by_header(content) {
        return Some(insp);
    }
    let base = name.rsplit('/').next().unwrap_or(name);
    let ext = base.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase())?;
    INSPECTORS
        .iter()
        .copied()
        .find(|i| i.extensions().contains(&ext.as_str()))
}

/// Pick the inspector by **content header only** (no extension fallback).
///
/// Used to classify a nameless byte run — e.g. a SQLite BLOB cell — where there
/// is no file name to fall back on, only the bytes' signature.
pub(crate) fn detect_by_header(content: &[u8]) -> Option<&'static dyn Inspector> {
    INSPECTORS.iter().copied().find(|i| i.detect(content))
}

// `TypeInfo` is defined in `core::models` (the foundation layer that `core::filter`
// consumes); re-exported here because this layer fills it and callers reach it via
// `crate::formats::inspect::TypeInfo`.
pub use crate::core::models::TypeInfo;

/// Classify a file by format and category (header-first, then extension).
///
/// `None` when no inspector claims the file — such a file has no known type, so
/// `--type` excludes it while the default (untyped) search still scans it.
pub fn detect_type(name: &str, content: &[u8]) -> Option<TypeInfo> {
    detect(name, content).map(|i| TypeInfo {
        name: i.name(),
        category: i.category(),
    })
}

/// Whether `s` names a known format or category — for validating `--type`.
pub fn is_known_type(s: &str) -> bool {
    INSPECTORS
        .iter()
        .any(|i| i.name() == s || i.category() == s)
}

/// Every `--type` value the tool accepts (format names + categories), sorted and
/// de-duplicated — for help text and error messages.
pub fn type_names() -> Vec<&'static str> {
    let mut names: Vec<&'static str> = INSPECTORS
        .iter()
        .flat_map(|i| [i.name(), i.category()])
        .collect();
    names.sort_unstable();
    names.dedup();
    names
}

// ── Shared helpers (reused by several inspectors) ───────────────────────────

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
