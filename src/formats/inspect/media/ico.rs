//! ICO image inspector (media): classify by the `00 00 01 00` magic / extension.
//! Registered in `inspect::mod`; uses the shared `media::media_inspector!` macro.

use super::media_inspector;

media_inspector!(Ico, "ico", "media", ["ico"], |c: &[u8]| c
    .starts_with(&[0x00, 0x00, 0x01, 0x00]));
