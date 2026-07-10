//! Foundation primitives — the bottom of the dependency stack.
//!
//! Defines: the shared building blocks every higher layer depends on but which
//! depend on nothing else in the crate:
//!   • `models` — the data containers (`Method`, `Entry`/`Location`, `SearchHit`,
//!     `MatchRecord`, `Inspection`, `ContentDiff`, `RunInfo`, `TypeInfo`).
//!   • `source` — the `Source` trait the engine reads through, plus its
//!     implementations (ZIP mmap, ranged ZIP, folder, nested-archive expansion).
//!   • `filter` — `EntryFilter`: path-glob and type/media selection.
//!   • `util` — tiny crate-wide helpers (`sha256_hex`).
//! Used by: every other module in the library, and the binary's `cmd` tree.
//! Uses: external crates only (within the crate it is a leaf).
//!
//! WHY one folder: these are the shared foundations, not features. Grouping them
//! signals to a newcomer "start here — everything else is built on top," and keeps
//! the loose data/IO primitives from sitting un-marked beside the feature subsystems.

pub mod filter;
pub mod models;
pub mod source;
pub mod util;
