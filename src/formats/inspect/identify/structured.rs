//! Identify-only structured formats: Apple binary files. (Android Binary XML, once
//! here, has its own inspector: `inspect::abx`.)
//!
//! Defines: [`BinaryCookies`], [`Bom`].
//! Used by: `identify` (re-export) → `inspect::mod` registry.
//! Uses: `identify::has_at`, the `classify_inspector!` macro.

use super::has_at;

// Apple `.binarycookies`: "cook", the page count (big-endian), one size per page,
// then the first page, which starts with the page header 0x00000100.
classify_inspector!(
    BinaryCookies,
    "binarycookies",
    "structured",
    [],
    |c: &[u8]| {
        // Within the first 4 KiB, as detection must decide from those (a store with
        // over 1,022 pages has its first page later, and is not named).
        let c = &c[..c.len().min(crate::formats::inspect::HEAD_LEN)];
        let Some(&[b0, b1, b2, b3]) = c.get(4..8) else {
            return false;
        };
        let pages = u32::from_be_bytes([b0, b1, b2, b3]) as usize;
        let first_page = pages.checked_mul(4).and_then(|n| n.checked_add(8));
        has_at(c, 0, b"cook")
            && pages > 0
            && first_page.is_some_and(|at| has_at(c, at, &[0x00, 0x00, 0x01, 0x00]))
    }
);

// Apple BOM store (`Assets.car` asset catalogues, `.bom` receipts).
classify_inspector!(Bom, "bom", "structured", [], |c: &[u8]| has_at(
    c,
    0,
    b"BOMStore"
));
