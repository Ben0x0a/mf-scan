//! CAF (Core Audio Format) inspector (media): classify by the `caff` magic /
//! extension. Registered in `inspect::mod`; uses `media::media_inspector!`.

use super::media_inspector;

media_inspector!(Caf, "caf", "media", ["caf"], |c: &[u8]| c
    .starts_with(b"caff"));
