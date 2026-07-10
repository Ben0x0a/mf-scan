//! M4V video inspector (media): classify by `ftyp M4V*` brand / extension.
//! Registered in `inspect::mod`; uses the shared `media::media_inspector!` macro.

use super::media_inspector;

media_inspector!(M4v, "m4v", "media", ["m4v"], |c: &[u8]| {
    crate::formats::inspect::ftyp_brand(c, &[b"M4V ", b"M4VH", b"M4VP"])
});
