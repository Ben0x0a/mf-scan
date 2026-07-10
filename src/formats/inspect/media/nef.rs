//! Nikon NEF raw-image inspector (media): TIFF-based, so it classifies by
//! extension only. Registered in `inspect::mod`; uses `media::media_inspector!`.

use super::media_inspector;

media_inspector!(Nef, "nef", "media", ["nef"], |_c: &[u8]| false);
