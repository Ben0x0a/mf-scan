//! TIFF image inspector (media): classify by `II*\0`/`MM\0*` magic / extension.
//! Registered in `inspect::mod`; uses the shared `media::media_inspector!` macro.

use super::media_inspector;

media_inspector!(Tiff, "tiff", "media", ["tif", "tiff"], |c: &[u8]| c
    .starts_with(&[0x49, 0x49, 0x2A, 0x00])
    || c.starts_with(&[0x4D, 0x4D, 0x00, 0x2A]));
