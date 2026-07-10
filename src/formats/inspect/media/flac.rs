//! FLAC audio inspector (media): classify by the `fLaC` magic / extension.
//! Registered in `inspect::mod`; uses the shared `media::media_inspector!` macro.

use super::media_inspector;

media_inspector!(Flac, "flac", "media", ["flac"], |c: &[u8]| c
    .starts_with(b"fLaC"));
