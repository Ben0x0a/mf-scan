//! AIFF audio inspector (media): classify by the `FORM....AIFF`/`AIFC` magic /
//! extension. Registered in `inspect::mod`; uses `media::media_inspector!`.

use super::media_inspector;

media_inspector!(Aiff, "aiff", "media", ["aiff", "aif"], |c: &[u8]| c.len()
    >= 12
    && &c[0..4] == b"FORM"
    && (&c[8..12] == b"AIFF" || &c[8..12] == b"AIFC"));
