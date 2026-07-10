//! QuickTime MOV video inspector (media): classify by `ftyp qt  ` / extension.
//! Registered in `inspect::mod`; uses the shared `media::media_inspector!` macro.

use super::media_inspector;

media_inspector!(Mov, "mov", "media", ["mov"], |c: &[u8]| {
    crate::formats::inspect::ftyp_brand(c, &[b"qt  "])
});
