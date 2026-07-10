//! BMP image inspector (media): classify by the `BM` magic / extension.
//! Registered in `inspect::mod`; uses the shared `media::media_inspector!` macro.

use super::media_inspector;

media_inspector!(Bmp, "bmp", "media", ["bmp"], |c: &[u8]| c
    .starts_with(b"BM"));
