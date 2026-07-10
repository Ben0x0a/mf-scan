//! 3GP/3G2 video inspector (media): classify by ISO-BMFF `ftyp 3g*` / extension.
//! Registered in `inspect::mod`; uses the shared `media::media_inspector!` macro.

use super::media_inspector;

media_inspector!(ThreeGp, "3gp", "media", ["3gp", "3g2"], |c: &[u8]| {
    crate::formats::inspect::ftyp_brand(c, &[b"3gp4", b"3gp5", b"3gg6", b"3gp1", b"3g2a", b"3g2b"])
});
