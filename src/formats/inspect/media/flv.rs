//! FLV video inspector (media): classify by the `FLV` magic / extension.
//! Registered in `inspect::mod`; uses the shared `media::media_inspector!` macro.

use super::media_inspector;

media_inspector!(Flv, "flv", "media", ["flv"], |c: &[u8]| c
    .starts_with(b"FLV"));
