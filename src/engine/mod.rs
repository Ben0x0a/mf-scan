//! Shared drive logic over a `Source` — the mechanics every operation reuses.
//!
//! Defines: the pieces common to *driving* a [`Source`](crate::core::source::Source),
//! independent of what the operation does with each entry:
//!   • [`is_selected`] — the one entry-selection rule (a non-directory file the path
//!     filter keeps), shared by `ops::search` (its progress total) and `ops::diff`
//!     (the files it compares).
//!   • [`Progress`] / [`NoProgress`] — the UI-free progress callback the engine calls
//!     and the UI implements.
//! Used by: `ops::search` and `ops::diff`; the binary's `cmd::support` implements
//! [`Progress`].
//! Uses: `crate::core` (the `Source` trait's `Entry` and the path filter) only.
//!
//! WHY a separate module: search and diff are distinct operations, but both walk a
//! source's entries and both must agree on *which* entries count. Keeping the
//! selection rule (and the progress contract) here means the two operations cannot
//! drift apart, and a future operation gets the same drive primitives for free.

use crate::core::filter::{EntryFilter, PathDecision};
use crate::core::models::Entry;

/// Whether `entry` is a file the path filter selects for processing.
///
/// The single definition of "an entry worth looking at": not a directory, and kept
/// by the `--path` / `--not-path` globs. `ops::search` uses it to size the progress
/// bar (every selected entry is read); `ops::diff` uses it to choose the files it
/// pairs across the two sides. Type/media filtering happens later, on content, and is
/// not part of this path-only rule.
pub fn is_selected(entry: &Entry, filter: &EntryFilter) -> bool {
    !entry.is_dir() && matches!(filter.select(&entry.name), PathDecision::Search)
}

/// Reports scan progress. Implemented by the UI; the engine only calls it.
///
/// Kept UI-free (no I/O, no formatting) so the library has no terminal
/// dependency — `main` provides the on-screen reporter.
pub trait Progress: Sync {
    /// Called once with the number of entries that will be searched.
    fn set_total(&self, total: usize);
    /// Called once per entry after it has been searched.
    fn inc(&self);
}

/// A `Progress` that does nothing — the default for tests and piped output.
pub struct NoProgress;

impl Progress for NoProgress {
    fn set_total(&self, _total: usize) {}
    fn inc(&self) {}
}
