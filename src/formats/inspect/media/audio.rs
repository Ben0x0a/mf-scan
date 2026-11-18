//! Audio formats (media category): classification only, by header magic (and the
//! extension list each declares). One `classify_inspector!` call per format.
//!
//! Defines: [`Mp3`], [`M4a`], [`Aac`], [`Wav`], [`Flac`], [`Opus`], [`Ogg`], [`Wma`], [`Amr`], [`Caf`], [`Aiff`].
//! Used by: `media` (re-export) → `inspect::mod` registry.
//! Uses: the `classify_inspector!` macro, `inspect::{riff_form, ftyp_brand, contains}`
//! and `media::{ASF_GUID, EBML}` where a format needs them.
//!
//! The order below is the registry's: a more specific container before the generic one
//! that shares its magic (WebM before Matroska, Opus before Ogg).

// MP3 audio inspector (media): an `ID3` tag, or two consecutive valid MPEG audio
// frame headers (see `mpeg_frames`).
classify_inspector!(Mp3, "mp3", "media", ["mp3"], |c: &[u8]| c
    .starts_with(b"ID3")
    || mpeg_frames(c));

/// A valid MPEG audio frame header at 0 and another, of the same version, layer and
/// sample rate, exactly one frame length later. WHY two: the 11-bit frame sync
/// (`FF Ex`) alone occurs by chance in about 1 binary file in 2,000; the second
/// header at the computed length is the standard check. Within the first 4 KiB (the
/// largest frame is 1,728 bytes), as detection must decide from those.
fn mpeg_frames(c: &[u8]) -> bool {
    let c = &c[..c.len().min(crate::formats::inspect::HEAD_LEN)];
    let Some(len) = frame_len(c) else {
        return false;
    };
    c.get(len..).is_some_and(|next| {
        frame_len(next).is_some()
            && (next[1] & 0x1E) == (c[1] & 0x1E)
            && (next[2] & 0x0C) == (c[2] & 0x0C)
    })
}

/// The length of the MPEG audio frame whose header starts `h`, when the header is
/// valid (sync, defined version, layer, bitrate and sample rate; free-format
/// bitrate excluded, as its length cannot be computed).
fn frame_len(h: &[u8]) -> Option<usize> {
    let &[b0, b1, b2, _] = h.first_chunk::<4>()?;
    if b0 != 0xFF || b1 & 0xE0 != 0xE0 {
        return None;
    }
    let version = (b1 >> 3) & 3; // 0: MPEG 2.5, 1: reserved, 2: MPEG 2, 3: MPEG 1
    let layer = (b1 >> 1) & 3; // 1: III, 2: II, 3: I, 0: reserved
    let bitrate_index = usize::from(b2 >> 4);
    let rate_index = usize::from((b2 >> 2) & 3);
    if version == 1 || layer == 0 || bitrate_index == 0 || bitrate_index == 15 || rate_index == 3 {
        return None;
    }
    const V1_L1: [u32; 14] = [
        32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448,
    ];
    const V1_L2: [u32; 14] = [
        32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384,
    ];
    const V1_L3: [u32; 14] = [
        32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320,
    ];
    const V2_L1: [u32; 14] = [
        32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256,
    ];
    const V2_L23: [u32; 14] = [8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160];
    let table = match (version, layer) {
        (3, 3) => &V1_L1,
        (3, 2) => &V1_L2,
        (3, _) => &V1_L3,
        (_, 3) => &V2_L1,
        _ => &V2_L23,
    };
    let bitrate = table[bitrate_index - 1] * 1000;
    let rate = [44_100u32, 48_000, 32_000][rate_index] >> [2u32, 0, 1, 0][usize::from(version)];
    let pad = u32::from((b2 >> 1) & 1);
    let len = match (version, layer) {
        (_, 3) => (12 * bitrate / rate + pad) * 4,
        (3, _) | (_, 2) => 144 * bitrate / rate + pad,
        _ => 72 * bitrate / rate + pad, // MPEG 2 / 2.5 layer III
    };
    usize::try_from(len).ok().filter(|&l| l >= 4)
}

// M4A audio inspector (media): classify by `ftyp M4A`/`M4B` brand / extension.
classify_inspector!(M4a, "m4a", "media", ["m4a"], |c: &[u8]| {
    crate::formats::inspect::ftyp_brand(c, &[b"M4A ", b"M4B "])
});

// AAC audio inspector (media): raw ADTS streams have no stable file signature that
// won't collide with MP3, so it classifies by extension only.
classify_inspector!(Aac, "aac", "media", ["aac"], |_c: &[u8]| false);

// WAV audio inspector (media): classify by RIFF `WAVE` form / extension.
classify_inspector!(Wav, "wav", "media", ["wav"], |c: &[u8]| {
    crate::formats::inspect::riff_form(c, b"WAVE")
});

// FLAC audio inspector (media): classify by the `fLaC` magic / extension.
classify_inspector!(Flac, "flac", "media", ["flac"], |c: &[u8]| c
    .starts_with(b"fLaC"));

// Opus audio inspector (media): Ogg container carrying an `OpusHead` (matched before
// generic Ogg).
classify_inspector!(Opus, "opus", "media", ["opus"], |c: &[u8]| c
    .starts_with(b"OggS")
    && crate::formats::inspect::contains(&c[..c.len().min(128)], b"OpusHead"));

// Ogg audio inspector (media): classify by the `OggS` magic / extension (listed after
// Opus, which shares the magic).
classify_inspector!(Ogg, "ogg", "media", ["ogg", "oga"], |c: &[u8]| c
    .starts_with(b"OggS"));

// WMA audio inspector (media): classify by the ASF container GUID / extension (shares
// the magic with WMV).
classify_inspector!(Wma, "wma", "media", ["wma"], |c: &[u8]| c
    .starts_with(&super::ASF_GUID));

// AMR audio inspector (media): classify by the `#!AMR` magic / extension.
classify_inspector!(Amr, "amr", "media", ["amr"], |c: &[u8]| c
    .starts_with(b"#!AMR"));

// CAF (Core Audio Format) inspector (media): classify by the `caff` magic /
// extension.
classify_inspector!(Caf, "caf", "media", ["caf"], |c: &[u8]| c
    .starts_with(b"caff"));

// AIFF audio inspector (media): classify by the `FORM....AIFF`/`AIFC` magic /
// extension.
classify_inspector!(Aiff, "aiff", "media", ["aiff", "aif"], |c: &[u8]| c.len()
    >= 12
    && &c[0..4] == b"FORM"
    && (&c[8..12] == b"AIFF" || &c[8..12] == b"AIFC"));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mp3_needs_two_consecutive_frames() {
        // MPEG 1 layer III, 128 kbit/s, 44.1 kHz, no padding: 144 * 128000 / 44100 = 417.
        let header = [0xFF, 0xFB, 0x90, 0x64];
        assert_eq!(frame_len(&header), Some(417));
        let mut two = header.to_vec();
        two.resize(417, 0);
        two.extend_from_slice(&header);
        assert!(mpeg_frames(&two));
        // One header alone, or a chance `FF Ex`, is not MP3.
        let mut one = header.to_vec();
        one.resize(900, 0x41);
        assert!(!mpeg_frames(&one));
        assert!(!mpeg_frames(&[0xFF, 0xE3, 0x00, 0x00, 0x10]));
    }
}
