//! Identify-only document formats.
//!
//! Defines: [`Pdf`], [`Ole`].
//! Used by: `identify` (re-export) → `inspect::mod` registry.
//! Uses: `identify::has_at`, the `classify_inspector!` macro.

use super::has_at;

classify_inspector!(Pdf, "pdf", "document", [], |c: &[u8]| has_at(
    c, 0, b"%PDF-"
));

// OLE2 compound file (legacy Office `.doc`, `.xls`, `.ppt`, `.msg`).
classify_inspector!(Ole, "ole", "document", [], |c: &[u8]| has_at(
    c,
    0,
    &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]
));
