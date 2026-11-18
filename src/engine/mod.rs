//! Shared drive logic over a `Source` — the mechanics every operation reuses.
//!
//! Defines: the pieces common to *driving* a [`Source`],
//! independent of what the operation does with each entry:
//!   • [`is_selected`] — the one entry-selection rule (a non-directory file the path
//!     filter keeps), shared by `ops::search` (its progress total) and `ops::diff`
//!     (the files it compares).
//!   • [`Progress`] / [`NoProgress`] — the UI-free progress callback the engine calls
//!     and the UI implements.
//!   • [`type_from_ends`] / [`Typing`] — an entry's type from a cheap read of its
//!     start (and its end, only when that can matter), shared by `ops::search` and
//!     `ops::find`.
//! Used by: `ops::search`, `ops::diff` and `ops::find`; the binary's `cmd::support`
//! implements [`Progress`].
//! Uses: `crate::core` (the `Source` trait, `Entry`, the path filter) and
//! `crate::formats::inspect` (type detection).
//!
//! WHY a separate module: search and diff are distinct operations, but both walk a
//! source's entries and both must agree on *which* entries count. Keeping the
//! selection rule (and the progress contract) here means the two operations cannot
//! drift apart, and a future operation gets the same drive primitives for free.

use anyhow::Result;

use crate::core::filter::{EntryFilter, PathDecision};
use crate::core::models::{Entry, TypeInfo};
use crate::core::source::Source;
use crate::formats::inspect;

/// What a cheap read could tell of an entry's type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Typing {
    /// The type (or that it has none), as far as the caller's decision goes.
    Known(Option<TypeInfo>),
    /// Only the whole content can tell, in a way that matters to the caller: read
    /// it and use [`inspect::detect_type`].
    Undecided,
}

/// `entry`'s type from a cheap read: its first [`inspect::HEAD_LEN`] bytes and, only
/// when needed, its last bytes (a format signed at its end, such as a LevelDB table).
///
/// `differs(a, b)` tells whether the caller would act differently on type `a` than
/// on type `b`. The end is read only when the start names nothing, a type the end
/// could name would change the caller's decision, and the source reads an end
/// cheaply; when it does not, the answer is [`Typing::Undecided`].
///
/// WHY so lazy: most files are named by their header (media above all), and for the
/// rest the end rarely matters (a LevelDB table is never media, so `--exclude-media`
/// never needs it). Reading the end of every unnamed file would cost an extra read
/// each, and on a compressed entry a whole inflate, for nothing.
pub fn type_from_ends(
    source: &dyn Source,
    entry: &Entry,
    differs: impl Fn(Option<TypeInfo>, Option<TypeInfo>) -> bool,
) -> Result<Typing> {
    let head = source.content_prefix(entry, inspect::HEAD_LEN)?;
    // A source that does not read prefixes hands over the whole file; so does any
    // source for a short file. Either way the end is in hand.
    let whole = !source.prefers_prefix_classification()
        || head.len() < inspect::HEAD_LEN
        || head.len() as u64 >= entry.uncompressed_size;
    if whole {
        return Ok(Typing::Known(inspect::detect_type(&entry.name, &head)));
    }
    let by_name = match inspect::type_from_start(&entry.name, &head) {
        Ok(found) => return Ok(Typing::Known(Some(found))),
        Err(by_name) => by_name,
    };
    if !inspect::end_types().any(|t| differs(Some(t), by_name)) {
        return Ok(Typing::Known(by_name));
    }
    if !source.cheap_suffix(entry) {
        return Ok(Typing::Undecided);
    }
    // An unreadable end just leaves the type to the name.
    let end = source.content_suffix(entry, inspect::TAIL_LEN).ok();
    Ok(Typing::Known(
        end.as_deref().and_then(inspect::type_from_end).or(by_name),
    ))
}

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
