//! HEIF/HEIC image inspector (media): classify by ISO-BMFF `ftyp` brand / extension.
//! Registered in `inspect::mod`; uses the shared `media::media_inspector!` macro.

use super::media_inspector;

media_inspector!(Heif, "heif", "media", ["heic", "heif"], |c: &[u8]| {
    crate::formats::inspect::ftyp_brand(
        c,
        &[
            b"heic", b"heix", b"hevc", b"hevx", b"mif1", b"msf1", b"heif",
        ],
    )
});
