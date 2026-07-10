//! Opus audio inspector (media): Ogg container carrying an `OpusHead` (matched
//! before generic Ogg). Registered in `inspect::mod`; uses `media::media_inspector!`.

use super::media_inspector;

media_inspector!(Opus, "opus", "media", ["opus"], |c: &[u8]| c
    .starts_with(b"OggS")
    && crate::formats::inspect::contains(&c[..c.len().min(128)], b"OpusHead"));
