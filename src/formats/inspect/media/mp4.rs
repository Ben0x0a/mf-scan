//! MP4 video inspector (media): classify by ISO-BMFF `ftyp` brand / extension.
//! Registered in `inspect::mod`; uses the shared `media::media_inspector!` macro.

use super::media_inspector;

media_inspector!(Mp4, "mp4", "media", ["mp4"], |c: &[u8]| {
    crate::formats::inspect::ftyp_brand(
        c,
        &[
            b"isom", b"iso2", b"mp41", b"mp42", b"avc1", b"dash", b"mmp4",
        ],
    )
});
