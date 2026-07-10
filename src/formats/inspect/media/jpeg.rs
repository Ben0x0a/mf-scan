//! JPEG image inspector (media): classify by `FF D8 FF` magic / extension.
//! Registered in `inspect::mod`; uses the shared `media::media_inspector!` macro.

use super::media_inspector;

media_inspector!(Jpeg, "jpeg", "media", ["jpg", "jpeg"], |c: &[u8]| c
    .starts_with(&[0xFF, 0xD8, 0xFF]));
