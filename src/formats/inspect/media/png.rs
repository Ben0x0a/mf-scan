//! PNG image inspector (media): classify by the 8-byte PNG magic / extension.
//! Registered in `inspect::mod`; uses the shared `media::media_inspector!` macro.

use super::media_inspector;

media_inspector!(Png, "png", "media", ["png"], |c: &[u8]| c
    .starts_with(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]));
