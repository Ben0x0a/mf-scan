//! Nested data: what an embedded byte run holds (a SQLite BLOB, a SEGB entry's data)
//! and where a match falls inside it, through the same inspector registry.
//!
//! Defines: [`describe_nested_many`] and the [`NestedNote`] it returns per match.
//! Used by: the SQLite and SEGB inspectors.
//! Uses: `inspect::detect` (by header, then by structure), `crate::core::models::Inspection`.

use super::detect::{detect_by_header, detect_structure};
use crate::core::models::Inspection;

/// What [`describe_nested_many`] found for one match in an embedded byte run: text
/// for the summary and fields for the detail, added with [`NestedNote::apply`].
pub(crate) struct NestedNote {
    summary: String,
    detail: serde_json::Map<String, serde_json::Value>,
}

impl NestedNote {
    /// Append the note to a match's result.
    pub(crate) fn apply(self, target: &mut Inspection) {
        target.summary.push_str(&self.summary);
        if let Some(obj) = target.detail.as_object_mut() {
            obj.extend(self.detail);
        }
    }
}

/// Describe what an embedded byte run holds (a SQLite BLOB, a SEGB entry's data) and
/// where each of `offsets` (relative to it) falls inside, one note per offset:
/// `  {label}: {format}` (plus " (by structure)" when no signature named it) and the
/// nested summary, with `{label}_format`, `{label}_detection` and `{label}_context`
/// for the detail. `None`s when the bytes are neither signed nor structured.
///
/// The one rule for nested data: signature first, then JSON or protobuf by structure,
/// which is a hint only, never a certainty. All of a value's matches go through one
/// detection and one `inspect_many`, so a large value is parsed once, not per match.
pub(crate) fn describe_nested_many(
    data: &[u8],
    label: &str,
    offsets: &[usize],
) -> Vec<Option<NestedNote>> {
    let Some((insp, by_signature)) = detect_by_header(data)
        .map(|i| (i, true))
        .or_else(|| detect_structure(data).map(|i| (i, false)))
    else {
        return offsets.iter().map(|_| None).collect();
    };
    let how = if by_signature { "" } else { " (by structure)" };
    insp.inspect_many(data, offsets)
        .into_iter()
        .map(|nested| {
            let format = nested
                .as_ref()
                .map_or_else(|| insp.name().to_string(), |n| n.format.clone());
            let mut summary = format!("  {label}: {format}{how}");
            let mut detail = serde_json::Map::new();
            detail.insert(format!("{label}_format"), serde_json::json!(format));
            if !by_signature {
                detail.insert(format!("{label}_detection"), serde_json::json!("structure"));
            }
            if let Some(n) = nested {
                summary.push_str(&format!("  {}", n.summary));
                detail.insert(format!("{label}_context"), n.detail);
            }
            Some(NestedNote { summary, detail })
        })
        .collect()
}
