//! Identify-only Apple unified log formats: the `.tracev3` log files and the
//! shared-cache strings (`uuidtext/dsc/`). (`uuidtext` files have their own
//! inspector: `inspect::uuidtext`.)
//!
//! Defines: [`Tracev3`], [`Dsc`].
//! Used by: `identify` (re-export) → `inspect::mod` registry.
//! Uses: `identify::has_at`, the `classify_inspector!` macro.
//!
//! WHY identified only: a `.tracev3` keeps its entries in LZ4-compressed chunk sets,
//! so a plain search sees compressed bytes, and rendering an entry also needs its
//! format string from `uuidtext` or the shared cache.

use super::has_at;

// `.tracev3`: the first chunk is the header chunk, tag 0x1000 then sub-tag 0x11
// (u32, little-endian). Seen on all 318 `.tracev3` files of an iPhone.
classify_inspector!(Tracev3, "tracev3", "log", [], |c: &[u8]| has_at(
    c,
    0,
    &[0x00, 0x10, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00]
));

// Shared-cache strings (`/private/var/db/uuidtext/dsc/<uuid>`): "hcsd".
classify_inspector!(Dsc, "dsc", "log", [], |c: &[u8]| has_at(c, 0, b"hcsd"));
