//! AAC audio inspector (media): raw ADTS streams have no stable file signature
//! that won't collide with MP3, so it classifies by extension only. Registered
//! in `inspect::mod`; uses the shared `media::media_inspector!` macro.

use super::media_inspector;

media_inspector!(Aac, "aac", "media", ["aac"], |_c: &[u8]| false);
