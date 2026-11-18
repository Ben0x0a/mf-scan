//! The `media` inspector category: image, video and audio formats, one file per family.
//!
//! Defines: the `image`, `video` and `audio` submodules (one `classify_inspector!`
//! call per format in each), plus the magic constants used by more than one format
//! (`ASF_GUID` for WMV/WMA, `EBML` for MKV/WebM). The format structs are re-exported
//! here so `inspect::mod`'s registry lists them as `media::Jpeg`, …
//! Used by: `inspect::mod` (registers the re-exported structs in `INSPECTORS`).
//! Uses: the `classify_inspector!` macro, `crate::formats::inspect::{riff_form,
//! ftyp_brand, contains}`.
//!
//! A media inspector only *classifies* a file (header magic + extension); it
//! never resolves an offset, so the generated `inspect` returns `None`. They
//! exist so `--type` and the media skip recognise media by signature through the
//! one shared inspector registry — no duplicated extension/magic lists. This is
//! the category aggregator, not itself a file-type inspector.
//!
//! WHY one file per family: each format is a single macro call, so a file per
//! format scattered 32 near-empty files; grouped by family, the layout matches the
//! identify-only formats (`identify/`, one file per category).

mod audio;
mod image;
mod video;

pub(crate) use audio::{Aac, Aiff, Amr, Caf, Flac, M4a, Mp3, Ogg, Opus, Wav, Wma};
pub(crate) use image::{AppleKtx, Bmp, Cr2, Dng, Gif, Heif, Ico, Jpeg, Ktx, Nef, Png, Tiff, Webp};
pub(crate) use video::{Avi, Flv, M4v, Mkv, Mov, Mp4, Mpeg, ThreeGp, Webm, Wmv};

/// ASF/WMV/WMA container header GUID (first 16 bytes of every ASF file).
pub(crate) const ASF_GUID: [u8; 16] = [
    0x30, 0x26, 0xB2, 0x75, 0x8E, 0x66, 0xCF, 0x11, 0xA6, 0xD9, 0x00, 0xAA, 0x00, 0x62, 0xCE, 0x6C,
];

/// EBML magic shared by Matroska (`.mkv`) and WebM.
pub(crate) const EBML: [u8; 4] = [0x1A, 0x45, 0xDF, 0xA3];
