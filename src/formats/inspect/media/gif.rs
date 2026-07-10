//! GIF image inspector (media): classify by `GIF87a`/`GIF89a` magic / extension.
//! Registered in `inspect::mod`; uses the shared `media::media_inspector!` macro.

use super::media_inspector;

media_inspector!(Gif, "gif", "media", ["gif"], |c: &[u8]| c
    .starts_with(b"GIF87a")
    || c.starts_with(b"GIF89a"));
