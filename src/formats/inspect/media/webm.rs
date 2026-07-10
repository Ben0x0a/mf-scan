//! WebM video inspector (media): EBML magic plus a `webm` doctype in the head
//! (so it is matched before generic Matroska). Registered in `inspect::mod`;
//! uses the shared `media::media_inspector!` macro.

use super::media_inspector;

media_inspector!(Webm, "webm", "media", ["webm"], |c: &[u8]| c
    .starts_with(&super::EBML)
    && crate::formats::inspect::contains(&c[..c.len().min(64)], b"webm"));
