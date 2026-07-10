//! AMR audio inspector (media): classify by the `#!AMR` magic / extension.
//! Registered in `inspect::mod`; uses the shared `media::media_inspector!` macro.

use super::media_inspector;

media_inspector!(Amr, "amr", "media", ["amr"], |c: &[u8]| c
    .starts_with(b"#!AMR"));
