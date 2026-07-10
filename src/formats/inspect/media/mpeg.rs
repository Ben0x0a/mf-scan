//! MPEG program/system-stream video inspector (media): classify by the
//! `00 00 01 BA`/`00 00 01 B3` start codes / extension. Registered in
//! `inspect::mod`; uses the shared `media::media_inspector!` macro.

use super::media_inspector;

media_inspector!(Mpeg, "mpeg", "media", ["mpg", "mpeg"], |c: &[u8]| c
    .starts_with(&[0x00, 0x00, 0x01, 0xBA])
    || c.starts_with(&[0x00, 0x00, 0x01, 0xB3]));
