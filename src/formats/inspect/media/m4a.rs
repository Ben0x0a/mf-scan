//! M4A audio inspector (media): classify by `ftyp M4A`/`M4B` brand / extension.
//! Registered in `inspect::mod`; uses the shared `media::media_inspector!` macro.

use super::media_inspector;

media_inspector!(M4a, "m4a", "media", ["m4a"], |c: &[u8]| {
    crate::formats::inspect::ftyp_brand(c, &[b"M4A ", b"M4B "])
});
