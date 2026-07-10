//! AVI video inspector (media): classify by RIFF `AVI ` form / extension.
//! Registered in `inspect::mod`; uses the shared `media::media_inspector!` macro.

use super::media_inspector;

media_inspector!(Avi, "avi", "media", ["avi"], |c: &[u8]| {
    crate::formats::inspect::riff_form(c, b"AVI ")
});
