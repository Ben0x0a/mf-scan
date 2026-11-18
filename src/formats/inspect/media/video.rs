//! Video formats (media category): classification only, by header magic (and the
//! extension list each declares). One `classify_inspector!` call per format.
//!
//! Defines: [`Mp4`], [`Mov`], [`M4v`], [`Avi`], [`Webm`], [`Mkv`], [`ThreeGp`], [`Mpeg`], [`Wmv`], [`Flv`].
//! Used by: `media` (re-export) → `inspect::mod` registry.
//! Uses: the `classify_inspector!` macro, `inspect::{riff_form, ftyp_brand, contains}`
//! and `media::{ASF_GUID, EBML}` where a format needs them.
//!
//! The order below is the registry's: a more specific container before the generic one
//! that shares its magic (WebM before Matroska, Opus before Ogg).

// MP4 video inspector (media): classify by ISO-BMFF `ftyp` brand / extension.
classify_inspector!(Mp4, "mp4", "media", ["mp4"], |c: &[u8]| {
    crate::formats::inspect::ftyp_brand(
        c,
        &[
            b"isom", b"iso2", b"mp41", b"mp42", b"avc1", b"dash", b"mmp4",
        ],
    )
});

// QuickTime MOV video inspector (media): classify by `ftyp qt  ` / extension.
classify_inspector!(Mov, "mov", "media", ["mov"], |c: &[u8]| {
    crate::formats::inspect::ftyp_brand(c, &[b"qt  "])
});

// M4V video inspector (media): classify by `ftyp M4V*` brand / extension.
classify_inspector!(M4v, "m4v", "media", ["m4v"], |c: &[u8]| {
    crate::formats::inspect::ftyp_brand(c, &[b"M4V ", b"M4VH", b"M4VP"])
});

// AVI video inspector (media): classify by RIFF `AVI ` form / extension.
classify_inspector!(Avi, "avi", "media", ["avi"], |c: &[u8]| {
    crate::formats::inspect::riff_form(c, b"AVI ")
});

// WebM video inspector (media): EBML magic plus a `webm` doctype in the head (so it
// is matched before generic Matroska).
classify_inspector!(Webm, "webm", "media", ["webm"], |c: &[u8]| c
    .starts_with(&super::EBML)
    && crate::formats::inspect::contains(&c[..c.len().min(64)], b"webm"));

// Matroska MKV video inspector (media): classify by EBML magic / extension (listed
// after WebM, which shares the magic).
classify_inspector!(Mkv, "mkv", "media", ["mkv"], |c: &[u8]| c
    .starts_with(&super::EBML));

// 3GP/3G2 video inspector (media): classify by ISO-BMFF `ftyp 3g*` / extension.
classify_inspector!(ThreeGp, "3gp", "media", ["3gp", "3g2"], |c: &[u8]| {
    crate::formats::inspect::ftyp_brand(c, &[b"3gp4", b"3gp5", b"3gg6", b"3gp1", b"3g2a", b"3g2b"])
});

// MPEG program/system-stream video inspector (media): classify by the `00 00 01
// BA`/`00 00 01 B3` start codes / extension.
classify_inspector!(Mpeg, "mpeg", "media", ["mpg", "mpeg"], |c: &[u8]| c
    .starts_with(&[0x00, 0x00, 0x01, 0xBA])
    || c.starts_with(&[0x00, 0x00, 0x01, 0xB3]));

// WMV video inspector (media): classify by the ASF container GUID / extension.
classify_inspector!(Wmv, "wmv", "media", ["wmv"], |c: &[u8]| c
    .starts_with(&super::ASF_GUID));

// FLV video inspector (media): classify by the `FLV` magic / extension.
classify_inspector!(Flv, "flv", "media", ["flv"], |c: &[u8]| c
    .starts_with(b"FLV"));
