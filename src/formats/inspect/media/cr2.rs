//! Canon CR2 raw-image inspector (media): TIFF-based, so it classifies by
//! extension only. Registered in `inspect::mod`; uses `media::media_inspector!`.

use super::media_inspector;

media_inspector!(Cr2, "cr2", "media", ["cr2"], |_c: &[u8]| false);
