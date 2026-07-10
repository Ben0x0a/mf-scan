//! Low-level SQLite file-format reader: header, b-tree pages, records, values.
//!
//! Defines: the pure SQLite reading primitives shared across the crate, layered
//! into submodules and re-exported here as one flat surface.
//! Used by: `inspect::sqlite` (resolves a match offset to a table cell for
//! `--inspect`) and `ios::backup` (reads `Manifest.db`'s `Files` table). Both
//! consume THIS one reader so the SQLite record format has a single, audited
//! implementation rather than two that could drift.
//! Uses: only `std` — a dependency-free, bounds-checked byte reader. Nothing here
//! renders for display or resolves match offsets; those higher-level concerns
//! belong to the consumers.
//!
//! ── Layers (each its own file) ──────────────────────────────────────────────
//!   • `page`   — the database header (`Db`) and the b-tree page walk.
//!   • `record` — table-leaf cell/record decoding and the typed `Value`.
//!   • `schema` — the `sqlite_schema` table (names, root pages, column lists).
//!   • `table`  — the high-level `read_table` row reader built on the above.
//!
//! The reader is deliberately lenient: anything it cannot parse degrades to
//! `None`/empty rather than erroring, because forensic databases are frequently
//! partial or corrupt. References: the SQLite file format spec (database header,
//! b-tree pages, record format, varints).

mod page;
mod record;
mod schema;
mod table;

pub(crate) use page::{
    Db, TABLE_LEAF, btree_header_offset, for_each_leaf_cell, pages_of, parse_header, read_u16,
};
pub(crate) use record::{Col, Value, col_int, col_text, is_blob, parse_cell, serial_type_name};
pub(crate) use schema::{Table, parse_column_spans, read_schema};
pub(crate) use table::read_table;
