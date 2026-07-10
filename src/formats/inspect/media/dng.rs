//! DNG raw-image inspector (media): TIFF-based, so it classifies by extension
//! only — a readable header is detected as `tiff`. Registered in `inspect::mod`;
//! uses the shared `media::media_inspector!` macro.

use super::media_inspector;

media_inspector!(Dng, "dng", "media", ["dng"], |_c: &[u8]| false);
