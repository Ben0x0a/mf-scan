//! Identify-only cache formats.
//!
//! Defines: [`ChromiumCache`].
//! Used by: `identify` (re-export) → `inspect::mod` registry.
//! Uses: `identify::has_at`, the `classify_inspector!` macro.

use super::has_at;

// Chromium "simple" disk cache (Chrome and Android WebView `Cache_Data`): each entry
// file and the cache's `index` start with the initial magic 0xFCFB6D1BA7725C30.
classify_inspector!(
    ChromiumCache,
    "chromium-cache",
    "cache",
    [],
    |c: &[u8]| { has_at(c, 0, &[0x30, 0x5C, 0x72, 0xA7, 0x1B, 0x6D, 0xFB, 0xFC]) }
);
