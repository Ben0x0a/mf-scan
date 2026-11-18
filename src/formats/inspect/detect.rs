//! Format detection: which inspector a file (or a nameless byte run) belongs to, and
//! the file-type answers built on it for `--type` and the media skip.
//!
//! Defines: the detection order — header ([`detect_by_header`]), end of file
//! ([`detect_by_tail`]), extension ([`detect_by_extension`]), and by whole structure
//! ([`detect_structure`], JSON then protobuf) — with the [`HEAD_LEN`] / [`TAIL_LEN`]
//! read sizes, and the type helpers [`detect_type`], [`type_from_start`],
//! [`type_from_end`], [`end_types`], [`is_known_type`], [`type_names`].
//! Used by: `inspect::mod` (dispatch, re-exporting the public items), `inspect::nested`
//! (BLOB and SEGB data), `engine::type_from_ends`, `ops::find`, `ops::search`, `cmd`.
//! Uses: the `INSPECTORS` registry and [`Inspector`] trait in `inspect::mod`, the JSON
//! and protobuf inspectors (structure), `crate::core::models::TypeInfo`.
//!
//! WHY apart from dispatch: deciding what a file *is* runs on every file (classifying
//! for `--type`), while resolving a match runs only on matched files; the two have
//! different costs and callers, and detection has rules of its own (start before end
//! before name, at most `HEAD_LEN` bytes) that are easier to keep in one place.

use super::{INSPECTORS, Inspector};

/// Pick the inspector for a file: the first whose header matches, else the first
/// claiming the file-name extension.
pub(super) fn detect(name: &str, content: &[u8]) -> Option<&'static dyn Inspector> {
    detect_by_header(content)
        .or_else(|| detect_by_tail(content))
        .or_else(|| detect_by_extension(name))
}

/// The first inspector claiming `name`'s extension (the fallback for formats with no
/// signature).
pub(super) fn detect_by_extension(name: &str) -> Option<&'static dyn Inspector> {
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

/// How many bytes from the start of a file type detection reads (`--type`, the
/// media skip): an [`Inspector::detect`] must decide from at most these, so a file
/// is classified the same whether its source hands over the whole file or only
/// this much.
pub const HEAD_LEN: usize = 4 * 1024;

/// How many bytes from the end of a file [`Inspector::detect_tail`] sees.
pub const TAIL_LEN: usize = 8;

/// Pick the inspector by the file's **end**: `end` is the file's last bytes (any
/// length; only the last [`TAIL_LEN`] are used).
pub(super) fn detect_by_tail(end: &[u8]) -> Option<&'static dyn Inspector> {
    let tail = &end[end.len().saturating_sub(TAIL_LEN)..];
    INSPECTORS.iter().copied().find(|i| i.detect_tail(tail))
}

// `TypeInfo` is defined in `core::models` (the foundation layer that `core::filter`
// consumes); re-exported here because this layer fills it and callers reach it via
// `crate::formats::inspect::TypeInfo`.
pub use crate::core::models::TypeInfo;

/// Classify a file by format and category (header, then end, then extension).
///
/// `None` when no inspector claims the file — such a file has no known type, so
/// `--type` excludes it while the default (untyped) search still scans it.
pub fn detect_type(name: &str, content: &[u8]) -> Option<TypeInfo> {
    match type_from_start(name, content) {
        Ok(found) => Some(found),
        Err(by_name) => type_from_end(content).or(by_name),
    }
}

/// [`detect_type`]'s first step, for a source that reads only part of each file:
/// `Ok` when the file's start (`head`) names its format, which is final; else `Err`
/// with what the file name says, which only an end-of-file signature
/// ([`type_from_end`], one of [`end_types`]) can still override.
pub fn type_from_start(name: &str, head: &[u8]) -> Result<TypeInfo, Option<TypeInfo>> {
    match detect_by_header(head) {
        Some(insp) => Ok(type_info(insp)),
        None => Err(detect_by_extension(name).map(type_info)),
    }
}

/// The type named by the file's end (`end`: its last bytes, any length).
pub fn type_from_end(end: &[u8]) -> Option<TypeInfo> {
    detect_by_tail(end).map(type_info)
}

/// Every type an end-of-file signature can name: what reading a file's end could
/// turn it into.
pub fn end_types() -> impl Iterator<Item = TypeInfo> {
    INSPECTORS
        .iter()
        .filter(|i| i.has_tail_signature())
        .map(|i| type_info(*i))
}

fn type_info(insp: &dyn Inspector) -> TypeInfo {
    TypeInfo {
        name: insp.name(),
        category: insp.category(),
    }
}

/// Whether `s` names a known format or category — for validating `--type`.
pub fn is_known_type(s: &str) -> bool {
    INSPECTORS
        .iter()
        .filter(|i| i.selectable_by_type())
        .any(|i| i.name() == s || i.category() == s)
}

/// Every `--type` value the tool accepts (format names + categories), sorted and
/// de-duplicated — for help text and error messages.
pub fn type_names() -> Vec<&'static str> {
    let mut names: Vec<&'static str> = INSPECTORS
        .iter()
        .filter(|i| i.selectable_by_type())
        .flat_map(|i| [i.name(), i.category()])
        .collect();
    names.sort_unstable();
    names.dedup();
    names
}

/// Recognise content with no signature by its whole structure: JSON (starts with `{`
/// or `[` and parses completely), then an MMKV store (entries framing its data
/// exactly), then a protobuf message (parses completely, by `protoc --decode_raw`'s
/// rule). Used for a matched file nothing else claims and
/// for a SQLite BLOB with no signature.
pub(crate) fn detect_structure(content: &[u8]) -> Option<&'static dyn Inspector> {
    let first = content.iter().find(|b| !b.is_ascii_whitespace());
    if matches!(first, Some(b'{' | b'['))
        && serde_json::from_slice::<serde::de::IgnoredAny>(content).is_ok()
    {
        return Some(&super::json::Json);
    }
    // MMKV before protobuf: its rule (entries framing the data exactly, UTF-8 keys)
    // is the stricter of the two.
    if super::mmkv::parses(content) {
        return Some(&super::mmkv::Mmkv);
    }
    if super::protobuf::parses(content) {
        return Some(&super::protobuf::Protobuf);
    }
    None
}
