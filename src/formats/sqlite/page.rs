//! Database header and b-tree page walk.
//!
//! Defines: the parsed [`Db`] header ([`parse_header`]), the leaf page-type
//! constant [`TABLE_LEAF`], [`btree_header_offset`], and the b-tree traversals
//! ([`pages_of`], [`for_each_leaf_cell`]) that enumerate a table's pages and the
//! file offsets of its cells. Plus the big-endian integer readers the walk needs.
//! Used by: the sibling `record` / `schema` / `table` submodules and, via the
//! `sqlite` module's re-exports, the SQLite inspector.
//! Uses: only `std` — bounds-checked byte reads, no SQLite library.

use std::collections::HashSet;

pub(crate) const TABLE_LEAF: u8 = 0x0d;
const TABLE_INTERIOR: u8 = 0x05;
const HEADER_LEN: usize = 100; // database header, present only on page 1

/// Parsed database header essentials.
pub(crate) struct Db {
    pub(crate) page_size: usize,
    pub(crate) usable: usize, // page_size minus reserved per-page bytes
}

/// Parse the 100-byte database header.
pub(crate) fn parse_header(content: &[u8]) -> Option<Db> {
    if !content.starts_with(b"SQLite format 3\x00") {
        return None;
    }
    let raw = read_u16(content, 16)?;
    let page_size = if raw == 1 { 65536 } else { raw };
    // Page size must be a power of two of at least 512.
    if page_size < 512 || (page_size & (page_size - 1)) != 0 {
        return None;
    }
    let reserved = *content.get(20)? as usize;
    Some(Db {
        page_size,
        usable: page_size - reserved,
    })
}

/// The b-tree header starts after the database header on page 1, at byte 0
/// elsewhere.
pub(crate) fn btree_header_offset(page: u32) -> usize {
    if page == 1 { HEADER_LEN } else { 0 }
}

/// Collect every page belonging to the b-tree rooted at `root` (interior +
/// leaf), so a caller can test whether a target page belongs to a table.
pub(crate) fn pages_of(content: &[u8], db: &Db, root: u32) -> HashSet<u32> {
    let mut seen = HashSet::new();
    let mut stack = vec![root];
    while let Some(pg) = stack.pop() {
        if pg == 0 || !seen.insert(pg) {
            continue;
        }
        let page_start = (pg as usize - 1) * db.page_size;
        let header_off = btree_header_offset(pg);
        if content.get(page_start + header_off) == Some(&TABLE_INTERIOR)
            && let Some(children) = interior_children(content, db, pg)
        {
            stack.extend(children);
        }
    }
    seen
}

/// Visit the file offset of each cell of every leaf page in the b-tree rooted at
/// `root`. The caller parses each cell ([`super::record::parse_cell`]).
pub(crate) fn for_each_leaf_cell(content: &[u8], db: &Db, root: u32, visit: &mut dyn FnMut(usize)) {
    let mut seen = HashSet::new();
    let mut stack = vec![root];
    while let Some(pg) = stack.pop() {
        if pg == 0 || !seen.insert(pg) {
            continue;
        }
        let page_start = (pg as usize - 1) * db.page_size;
        let header_off = btree_header_offset(pg);
        match content.get(page_start + header_off) {
            Some(&TABLE_INTERIOR) => {
                if let Some(children) = interior_children(content, db, pg) {
                    stack.extend(children);
                }
            }
            Some(&TABLE_LEAF) => {
                let Some(num_cells) = read_u16(content, page_start + header_off + 3) else {
                    continue;
                };
                let ptr_base = page_start + header_off + 8;
                for i in 0..num_cells {
                    if let Some(cp) = read_u16(content, ptr_base + i * 2) {
                        visit(page_start + cp);
                    }
                }
            }
            _ => {}
        }
    }
}

/// Child page numbers of an interior table page (right pointer + each cell's
/// left-child pointer).
fn interior_children(content: &[u8], db: &Db, pg: u32) -> Option<Vec<u32>> {
    let page_start = (pg as usize - 1) * db.page_size;
    let header_off = btree_header_offset(pg);
    let right = read_u32(content, page_start + header_off + 8)?;
    let num_cells = read_u16(content, page_start + header_off + 3)?;
    let ptr_base = page_start + header_off + 12; // interior header is 12 bytes
    let mut children = vec![right];
    for i in 0..num_cells {
        let cp = read_u16(content, ptr_base + i * 2)?;
        children.push(read_u32(content, page_start + cp)?);
    }
    Some(children)
}

/// Read a big-endian u16 at `off` (bounds-checked).
pub(crate) fn read_u16(content: &[u8], off: usize) -> Option<usize> {
    Some(((*content.get(off)? as usize) << 8) | *content.get(off + 1)? as usize)
}

/// Read a big-endian u32 at `off` (bounds-checked).
fn read_u32(content: &[u8], off: usize) -> Option<u32> {
    Some(
        ((*content.get(off)? as u32) << 24)
            | ((*content.get(off + 1)? as u32) << 16)
            | ((*content.get(off + 2)? as u32) << 8)
            | (*content.get(off + 3)? as u32),
    )
}
