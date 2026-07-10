//! WebP image inspector (media): classify by RIFF `WEBP` form / extension.
//! Registered in `inspect::mod`; uses the shared `media::media_inspector!` macro.

use super::media_inspector;

media_inspector!(Webp, "webp", "media", ["webp"], |c: &[u8]| {
    crate::formats::inspect::riff_form(c, b"WEBP")
});
