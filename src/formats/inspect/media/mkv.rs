//! Matroska MKV video inspector (media): classify by EBML magic / extension
//! (listed after WebM, which shares the magic). Registered in `inspect::mod`;
//! uses the shared `media::media_inspector!` macro.

use super::media_inspector;

media_inspector!(Mkv, "mkv", "media", ["mkv"], |c: &[u8]| c
    .starts_with(&super::EBML));
