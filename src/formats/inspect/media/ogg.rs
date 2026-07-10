//! Ogg audio inspector (media): classify by the `OggS` magic / extension
//! (listed after Opus, which shares the magic). Registered in `inspect::mod`;
//! uses the shared `media::media_inspector!` macro.

use super::media_inspector;

media_inspector!(Ogg, "ogg", "media", ["ogg", "oga"], |c: &[u8]| c
    .starts_with(b"OggS"));
