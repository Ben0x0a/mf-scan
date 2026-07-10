//! MP3 audio inspector (media): classify by an `ID3` tag or an MPEG frame sync
//! / extension. Registered in `inspect::mod`; uses `media::media_inspector!`.

use super::media_inspector;

media_inspector!(Mp3, "mp3", "media", ["mp3"], |c: &[u8]| c
    .starts_with(b"ID3")
    || (c.len() >= 2 && c[0] == 0xFF && (c[1] & 0xE0) == 0xE0));
