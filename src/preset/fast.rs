//! Compiled-in fallback for the `--fast` preset.
//!
//! Defines: `FAST_EXCLUDE_GLOBS`, the fallback path-glob list used by `--fast`
//! when `presets/_fast.yml` cannot be found or read.
//! Used by: `run` (fallback path in the `--fast` preset-loading block).
//! Uses: nothing.
//!
//! The canonical source for `--fast` behaviour is now `presets/_fast.yml`, which
//! ships alongside the binary and can be edited without recompiling. This file
//! exists only so that `--fast` still works in environments where the `presets/`
//! directory is absent (e.g. a bare dev build without the folder copied in).
//! To customise `--fast`, edit `presets/_fast.yml` — changes here affect only
//! the fallback path.

/// Path globs skipped by `--fast`, in addition to the always-on speed options.
/// See the module docs for how to customise this.
pub const FAST_EXCLUDE_GLOBS: &[&str] = &[
    // (none yet — add path globs here to extend the --fast preset)
];
