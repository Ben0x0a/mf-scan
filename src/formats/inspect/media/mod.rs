//! The `media` inspector category: one submodule per media file type.
//!
//! Defines: the per-format media inspectors (`jpeg`, `png`, …, `mp3`), each in
//! its own file, plus the shared scaffolding they build on — the
//! `media_inspector!` macro and the magic constants used by more than one format
//! (`ASF_GUID` for WMV/WMA, `EBML` for MKV/WebM). The format structs are
//! re-exported here so `inspect::mod`'s registry lists them as `media::Jpeg`, …
//! Used by: `inspect::mod` (registers the re-exported structs in `INSPECTORS`).
//! Uses: `crate::formats::inspect::{Inspector, riff_form, ftyp_brand, contains}`,
//! `crate::core::models::Inspection`.
//!
//! A media inspector only *classifies* a file (header magic + extension); it
//! never resolves an offset, so the generated `inspect` returns `None`. They
//! exist so `--type` and the media skip recognise media by signature through the
//! one shared inspector registry — no duplicated extension/magic lists. This is
//! the category aggregator, not itself a file-type inspector.

mod aac;
mod aiff;
mod amr;
mod avi;
mod bmp;
mod caf;
mod cr2;
mod dng;
mod flac;
mod flv;
mod gif;
mod heif;
mod ico;
mod jpeg;
mod m4a;
mod m4v;
mod mkv;
mod mov;
mod mp3;
mod mp4;
mod mpeg;
mod nef;
mod ogg;
mod opus;
mod png;
mod threegp;
mod tiff;
mod wav;
mod webm;
mod webp;
mod wma;
mod wmv;

pub(crate) use aac::Aac;
pub(crate) use aiff::Aiff;
pub(crate) use amr::Amr;
pub(crate) use avi::Avi;
pub(crate) use bmp::Bmp;
pub(crate) use caf::Caf;
pub(crate) use cr2::Cr2;
pub(crate) use dng::Dng;
pub(crate) use flac::Flac;
pub(crate) use flv::Flv;
pub(crate) use gif::Gif;
pub(crate) use heif::Heif;
pub(crate) use ico::Ico;
pub(crate) use jpeg::Jpeg;
pub(crate) use m4a::M4a;
pub(crate) use m4v::M4v;
pub(crate) use mkv::Mkv;
pub(crate) use mov::Mov;
pub(crate) use mp3::Mp3;
pub(crate) use mp4::Mp4;
pub(crate) use mpeg::Mpeg;
pub(crate) use nef::Nef;
pub(crate) use ogg::Ogg;
pub(crate) use opus::Opus;
pub(crate) use png::Png;
pub(crate) use threegp::ThreeGp;
pub(crate) use tiff::Tiff;
pub(crate) use wav::Wav;
pub(crate) use webm::Webm;
pub(crate) use webp::Webp;
pub(crate) use wma::Wma;
pub(crate) use wmv::Wmv;

/// ASF/WMV/WMA container header GUID (first 16 bytes of every ASF file).
pub(crate) const ASF_GUID: [u8; 16] = [
    0x30, 0x26, 0xB2, 0x75, 0x8E, 0x66, 0xCF, 0x11, 0xA6, 0xD9, 0x00, 0xAA, 0x00, 0x62, 0xCE, 0x6C,
];

/// EBML magic shared by Matroska (`.mkv`) and WebM.
pub(crate) const EBML: [u8; 4] = [0x1A, 0x45, 0xDF, 0xA3];

/// Generate a media inspector: a zero-sized type that classifies a file by
/// `$name`/`$cat`, the `$ext` list, and the `$detect` header predicate, but does
/// not resolve offsets (`inspect` is always `None`).
macro_rules! media_inspector {
    ($ty:ident, $name:literal, $cat:literal, [$($ext:literal),*], $detect:expr) => {
        pub struct $ty;
        impl $crate::formats::inspect::Inspector for $ty {
            fn name(&self) -> &'static str { $name }
            fn category(&self) -> &'static str { $cat }
            fn extensions(&self) -> &'static [&'static str] { &[$($ext),*] }
            fn detect(&self, content: &[u8]) -> bool { ($detect)(content) }
            fn inspect(
                &self,
                _content: &[u8],
                _offset: usize,
            ) -> Option<$crate::core::models::Inspection> {
                None
            }
        }
    };
}
pub(crate) use media_inspector;
