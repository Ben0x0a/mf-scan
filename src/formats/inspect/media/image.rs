//! Image formats (media category): classification only, by header magic (and the
//! extension list each declares). One `classify_inspector!` call per format.
//!
//! Defines: [`Ktx`], [`AppleKtx`], [`Jpeg`], [`Png`], [`Gif`], [`Bmp`], [`Tiff`], [`Heif`], [`Webp`], [`Ico`], [`Dng`], [`Cr2`], [`Nef`].
//! Used by: `media` (re-export) → `inspect::mod` registry.
//! Uses: the `classify_inspector!` macro, `inspect::{riff_form, ftyp_brand, contains}`
//! and `media::{ASF_GUID, EBML}` where a format needs them.
//!
//! The order below is the registry's: a more specific container before the generic one
//! that shares its magic (WebM before Matroska, Opus before Ogg).

// JPEG image inspector (media): classify by `FF D8 FF` magic / extension.
classify_inspector!(Jpeg, "jpeg", "media", ["jpg", "jpeg"], |c: &[u8]| c
    .starts_with(&[0xFF, 0xD8, 0xFF]));

// PNG image inspector (media): classify by the 8-byte PNG magic / extension.
classify_inspector!(Png, "png", "media", ["png"], |c: &[u8]| c
    .starts_with(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]));

// GIF image inspector (media): classify by `GIF87a`/`GIF89a` magic / extension.
classify_inspector!(Gif, "gif", "media", ["gif"], |c: &[u8]| c
    .starts_with(b"GIF87a")
    || c.starts_with(b"GIF89a"));

// BMP image inspector (media): `BM`, the reserved words zero, and a DIB header size
// the format defines (see `bmp_header`).
classify_inspector!(Bmp, "bmp", "media", ["bmp"], bmp_header);

/// `BM`, reserved bytes 6-9 zero, and a DIB header size at 14 of a defined version
/// (12 core, 40 info, 52/56 v2/v3, 64 OS/2 v2, 108 v4, 124 v5). WHY more than `BM`:
/// two letters start plenty of text ("BMW") and binary data.
fn bmp_header(c: &[u8]) -> bool {
    c.starts_with(b"BM")
        && c.get(6..10) == Some(&[0, 0, 0, 0])
        && c.get(14..18)
            .and_then(|b| b.try_into().ok())
            .map(u32::from_le_bytes)
            .is_some_and(|dib| matches!(dib, 12 | 40 | 52 | 56 | 64 | 108 | 124))
}

// TIFF image inspector (media): classify by `II*\0`/`MM\0*` magic / extension.
classify_inspector!(Tiff, "tiff", "media", ["tif", "tiff"], |c: &[u8]| c
    .starts_with(&[0x49, 0x49, 0x2A, 0x00])
    || c.starts_with(&[0x4D, 0x4D, 0x00, 0x2A]));

// HEIF/HEIC image inspector (media): classify by ISO-BMFF `ftyp` brand / extension.
classify_inspector!(Heif, "heif", "media", ["heic", "heif"], |c: &[u8]| {
    crate::formats::inspect::ftyp_brand(
        c,
        &[
            b"heic", b"heix", b"hevc", b"hevx", b"mif1", b"msf1", b"heif",
        ],
    )
});

// WebP image inspector (media): classify by RIFF `WEBP` form / extension.
classify_inspector!(Webp, "webp", "media", ["webp"], |c: &[u8]| {
    crate::formats::inspect::riff_form(c, b"WEBP")
});

// ICO image inspector (media): the icon directory header and a valid first entry
// (see `ico_header`).
classify_inspector!(Ico, "ico", "media", ["ico"], ico_header);

/// Reserved 0 and type 1 (`00 00 01 00`), at least one image, and a first directory
/// entry that fits the format: reserved byte 0, 0 or 1 colour planes, a defined bit
/// depth, a non-zero size, and image data after the directory. WHY more than 4 bytes:
/// `00 00 01 00` is also the big-endian integer 256, common in binary data.
fn ico_header(c: &[u8]) -> bool {
    let u16_at = |at: usize| c.get(at..at + 2).map(|b| u16::from_le_bytes([b[0], b[1]]));
    let u32_at = |at: usize| {
        c.get(at..at + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
    let (Some(count), Some(planes), Some(bits), Some(size), Some(offset)) =
        (u16_at(4), u16_at(10), u16_at(12), u32_at(14), u32_at(18))
    else {
        return false;
    };
    c.starts_with(&[0x00, 0x00, 0x01, 0x00])
        && count > 0
        && c[9] == 0
        && planes <= 1
        && matches!(bits, 0 | 1 | 4 | 8 | 16 | 24 | 32)
        && size > 0
        && u64::from(offset) >= 6 + 16 * u64::from(count)
}

// DNG raw-image inspector (media): TIFF-based, so it classifies by extension only — a
// readable header is detected as `tiff`.
classify_inspector!(Dng, "dng", "media", ["dng"], |_c: &[u8]| false);

// Canon CR2 raw-image inspector (media): TIFF-based, so it classifies by extension
// only.
classify_inspector!(Cr2, "cr2", "media", ["cr2"], |_c: &[u8]| false);

// Nikon NEF raw-image inspector (media): TIFF-based, so it classifies by extension
// only.
classify_inspector!(Nef, "nef", "media", ["nef"], |_c: &[u8]| false);

// KTX texture (Khronos), versions 1 and 2: the 12-byte identifier «KTX 11» / «KTX 20».
// iOS keeps app snapshots and textures in them. No extension (Apple's own container
// below also uses `.ktx`).
classify_inspector!(Ktx, "ktx", "media", [], |c: &[u8]| c
    .starts_with(b"\xABKTX 11\xBB\r\n\x1A\n")
    || c.starts_with(b"\xABKTX 20\xBB\r\n\x1A\n"));

// Apple's texture container (not KTX, though named `.ktx`): "AAPL\r\n\x1A\n", then
// chunks (`HEAD`, `LZFS`, `astc`) holding an LZFSE-compressed ASTC image. iOS app
// snapshots (`SplashBoard/Snapshots`). Identified only: the image is compressed.
classify_inspector!(AppleKtx, "apple-ktx", "media", [], |c: &[u8]| c
    .starts_with(b"AAPL\r\n\x1A\n"));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bmp_and_ico_need_their_header_fields() {
        let mut bmp = b"BM".to_vec();
        bmp.extend_from_slice(&[0x36, 0, 0, 0, 0, 0, 0, 0, 0x36, 0, 0, 0, 40, 0, 0, 0]);
        assert!(bmp_header(&bmp));
        assert!(!bmp_header(b"BMW 3 series, 2019, 90,000 km"));

        // One 16x16 32-bit icon, its data after the 22-byte directory.
        let ico = [
            0, 0, 1, 0, 1, 0, 16, 16, 0, 0, 1, 0, 32, 0, 0x68, 4, 0, 0, 22, 0, 0, 0,
        ];
        assert!(ico_header(&ico));
        // The big-endian integer 256 followed by other data.
        assert!(!ico_header(&[
            0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ]));
    }
}
