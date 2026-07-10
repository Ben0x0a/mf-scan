//! WAV audio inspector (media): classify by RIFF `WAVE` form / extension.
//! Registered in `inspect::mod`; uses the shared `media::media_inspector!` macro.

use super::media_inspector;

media_inspector!(Wav, "wav", "media", ["wav"], |c: &[u8]| {
    crate::formats::inspect::riff_form(c, b"WAVE")
});
