//! SQLite inspector: map a byte offset to a table cell, or fall back to page.
//!
//! Defines: `inspect`, which resolves a match offset inside a SQLite database
//! to `table + rowid + column [TYPE]` when the byte lies in a live table-leaf
//! cell, and otherwise reports just the page number and offset-in-page (freelist
//! pages, free blocks, interior/overflow pages, unallocated space). When the
//! matched cell is a BLOB, its bytes are re-classified through the inspector
//! registry (`super::detect_by_header`) so an embedded format (e.g. a `bplist`)
//! is recognised and resolved too.
//! Used by: `inspect::inspect` (dispatch).
//! Uses: `crate::formats::sqlite` (the low-level SQLite reader — header, b-tree walk,
//! record parsing), `crate::core::models::Inspection`, `serde_json`.
//!
//! This is the *display/resolution* half of SQLite support: it turns a byte
//! offset into a human/JSON location and renders cell values for output. The raw
//! format parsing lives in `crate::formats::sqlite` so the inspector and the iOS-backup
//! `Manifest.db` reader share one audited reader. Resolution is deliberately
//! lenient: anything it cannot place degrades to the page+offset fallback rather
//! than erroring, because forensic databases are frequently partial or corrupt.

use std::collections::{BTreeMap, HashSet};

use serde_json::json;

use crate::core::models::{ContentDiff, Inspection};
use crate::formats::sqlite::{
    Col, Db, TABLE_LEAF, Table, btree_header_offset, cell_record_prefix, checkpoint, col_int,
    for_each_leaf_cell, is_blob, pages_of, parse_cell, parse_column_spans, parse_header,
    read_schema, read_u16, serial_type_name,
};

/// SQLite inspector — recognised by the `SQLite format 3\0` header.
pub struct Sqlite;

impl super::Inspector for Sqlite {
    fn name(&self) -> &'static str {
        "sqlite"
    }
    fn category(&self) -> &'static str {
        "database"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["sqlite", "sqlite3", "db", "sqlitedb"]
    }
    fn detect(&self, content: &[u8]) -> bool {
        content.starts_with(b"SQLite format 3\x00")
    }
    fn inspect(&self, content: &[u8], offset: usize) -> Option<Inspection> {
        self.inspect_many(content, &[offset]).pop().flatten()
    }
    /// Batch resolution: the schema and each table's page set are derived once
    /// per file instead of once per match — a message DB with thousands of
    /// matches would otherwise re-walk the schema b-trees for every one
    /// (review finding P1). Likewise each BLOB holding matches is read (overflow
    /// pages included) and described once, all its matches resolved together.
    fn inspect_many(&self, content: &[u8], offsets: &[usize]) -> Vec<Option<Inspection>> {
        let Some(db) = parse_header(content) else {
            return offsets.iter().map(|_| None).collect();
        };
        let schema = SchemaMap::build(content, &db);
        let mut results = Vec::with_capacity(offsets.len());
        // BLOB matches, grouped by their cell's position and the column's offset.
        let mut blobs: BTreeMap<(usize, usize), BlobHits> = BTreeMap::new();
        for (i, &offset) in offsets.iter().enumerate() {
            let (found, blob) = locate_with(content, &db, &schema, offset);
            if let Some(blob) = blob {
                let rel = offset - blob.col.start;
                blobs
                    .entry((blob.cell_file, blob.col.start))
                    .or_insert_with(|| (blob, Vec::new()))
                    .1
                    .push((i, rel));
            }
            results.push(found);
        }
        for (blob, hits) in blobs.into_values() {
            let value = full_value(content, &db, &blob);
            let rels: Vec<usize> = hits.iter().map(|&(_, rel)| rel).collect();
            // A BLOB may itself be a recognised format (e.g. a bplist stored in a
            // cell): classified by signature and, when an inspector claims it, the
            // match resolved inside it too — the same registry, no SQLite-specific
            // parsing. With no signature, it is tried as JSON then protobuf, as a
            // hint only (`blob: protobuf (by structure)`): the examiner exports the
            // database and decodes the value with its real schema.
            let notes = super::describe_nested_many(&value, "blob", &rels);
            for ((i, _), note) in hits.into_iter().zip(notes) {
                if let (Some(note), Some(Some(found))) = (note, results.get_mut(i)) {
                    note.apply(found);
                }
            }
        }
        results
    }
    fn sidecars(&self) -> &'static [&'static str] {
        // Uncommitted rows live in the WAL; export these so the DB opens complete.
        &["-wal", "-shm", "-journal"]
    }
    fn diff(&self, old: &[u8], new: &[u8]) -> Option<ContentDiff> {
        table_diff(old, new)
    }
}

/// Diff two databases at the table level: which tables were added/removed and which
/// changed row count. Row identity (which *rows* changed) is out of scope; a
/// row-count delta is the high-value "what changed inside" for a forensic DB.
fn table_diff(old: &[u8], new: &[u8]) -> Option<ContentDiff> {
    let counts_old = table_counts(old, &parse_header(old)?);
    let counts_new = table_counts(new, &parse_header(new)?);

    let mut added: Vec<String> = Vec::new();
    let mut removed: Vec<String> = Vec::new();
    let mut changed: Vec<(String, usize, usize)> = Vec::new();
    for (name, &rows_new) in &counts_new {
        match counts_old.get(name) {
            None => added.push(name.clone()),
            Some(&rows_old) if rows_old != rows_new => {
                changed.push((name.clone(), rows_old, rows_new))
            }
            Some(_) => {}
        }
    }
    for name in counts_old.keys() {
        if !counts_new.contains_key(name) {
            removed.push(name.clone());
        }
    }

    // One-line summary: the first few row-count changes, then table add/remove tallies.
    let mut parts: Vec<String> = changed
        .iter()
        .take(5)
        .map(|(name, a, b)| format!("{name} {a}→{b} rows"))
        .collect();
    if changed.len() > 5 {
        parts.push(format!("+{} more table(s)", changed.len() - 5));
    }
    if !added.is_empty() {
        parts.push(format!("+{} table(s)", added.len()));
    }
    if !removed.is_empty() {
        parts.push(format!("-{} table(s)", removed.len()));
    }
    let summary = if parts.is_empty() {
        // The file differs (the caller only diffs modified files), but row counts and
        // the table set are unchanged — e.g. in-place cell edits, which this
        // table-level view does not resolve.
        "no table or row-count changes detected (in-place edits)".to_string()
    } else {
        parts.join("; ")
    };

    let detail = json!({
        "tables_added": added,
        "tables_removed": removed,
        "tables_changed": changed
            .iter()
            .map(|(name, a, b)| json!({ "table": name, "rows_a": a, "rows_b": b }))
            .collect::<Vec<_>>(),
    });
    Some(ContentDiff {
        format: "sqlite".into(),
        summary,
        detail,
    })
}

/// Map every table name to its row count (number of table-leaf cells under its root).
fn table_counts(content: &[u8], db: &Db) -> BTreeMap<String, usize> {
    read_schema(content, db)
        .into_iter()
        .map(|t| {
            let mut rows = 0usize;
            for_each_leaf_cell(content, db, t.rootpage, &mut |_| rows += 1);
            (t.name, rows)
        })
        .collect()
}

/// Per-file resolution state: every table with the set of pages its b-tree
/// owns. Built once per file (one schema read + one page walk per table) and
/// reused for every offset resolved in that file.
struct SchemaMap {
    tables: Vec<(Table, HashSet<u32>)>,
}

impl SchemaMap {
    fn build(content: &[u8], db: &Db) -> Self {
        let tables = read_schema(content, db)
            .into_iter()
            .map(|t| {
                let pages = pages_of(content, db, t.rootpage);
                (t, pages)
            })
            .collect();
        Self { tables }
    }

    /// The table whose b-tree owns `page`, if any.
    fn owner(&self, page: u32) -> Option<&Table> {
        self.tables
            .iter()
            .find(|(_, pages)| pages.contains(&page))
            .map(|(t, _)| t)
    }
}

/// A BLOB and its matches: (result index, offset in the BLOB) for each.
type BlobHits = (BlobAt, Vec<(usize, usize)>);

/// Where a BLOB value holding a match lies, for describing it after all matches are
/// placed (see `inspect_many`).
struct BlobAt {
    cell_file: usize,
    record_start: usize,
    local_end: usize,
    col: Col,
}

/// Resolve `offset` to a table cell, or fall back to page + offset-in-page; plus
/// the BLOB it falls in, when it does.
fn locate_with(
    content: &[u8],
    db: &Db,
    schema: &SchemaMap,
    offset: usize,
) -> (Option<Inspection>, Option<BlobAt>) {
    if offset >= content.len() {
        return (None, None);
    }
    let page = (offset / db.page_size + 1) as u32;
    let page_off = offset % db.page_size;

    match resolve(content, db, schema, offset, page, page_off) {
        Some((found, blob)) => (Some(found), blob),
        None => (
            Some(Inspection {
                format: "sqlite".into(),
                summary: format!("page: {page}  offset: {page_off}  (not in a table cell)"),
                detail: json!({ "page": page, "page_offset": page_off }),
            }),
            None,
        ),
    }
}

/// Full resolution to table/rowid/column, plus the BLOB holding the match (described
/// later, once per BLOB); `None` whenever the byte is not in a live table-leaf cell
/// (the caller then emits the page+offset fallback).
fn resolve(
    content: &[u8],
    db: &Db,
    schema: &SchemaMap,
    offset: usize,
    page: u32,
    page_off: usize,
) -> Option<(Inspection, Option<BlobAt>)> {
    let page_start = (page as usize - 1) * db.page_size;
    let header_off = btree_header_offset(page);

    // Only table-leaf pages carry row data; everything else falls back.
    if *content.get(page_start + header_off)? != TABLE_LEAF {
        return None;
    }

    // Which table's b-tree owns this page?
    let table = schema.owner(page)?;

    let num_cells = read_u16(content, page_start + header_off + 3)?;
    let ptr_base = page_start + header_off + 8; // leaf header is 8 bytes
    for i in 0..num_cells {
        let cp = read_u16(content, ptr_base + i * 2)?;
        let cell = match parse_cell(content, db, page_start + cp) {
            Some(c) => c,
            None => continue,
        };
        if page_off < cp || page_off >= cp + cell.total_len {
            continue; // offset is elsewhere on the page (e.g. a free block)
        }

        // Inside this cell: find the column whose value bytes cover the offset.
        for (idx, col) in cell.columns.iter().enumerate() {
            // Only the on-page part of a value: past `local_end` lie the overflow
            // pointer and other cells, which are not this value.
            if offset >= col.start && offset < (col.start + col.len).min(cell.local_end) {
                let column = table
                    .columns
                    .get(idx)
                    .cloned()
                    .unwrap_or_else(|| format!("column{idx}"));
                let ty = serial_type_name(col.serial);
                let at = BlobAt {
                    cell_file: page_start + cp,
                    record_start: cell.record_start,
                    local_end: cell.local_end,
                    col: *col,
                };
                // What is shown: the value's start, from its page when that holds
                // enough to display; its complete bytes (overflow pages included)
                // only when the page holds too little, or for a schema's SQL, which
                // is parsed whole. Never the bytes after the on-page part, which are
                // the overflow pointer and other cells.
                let schema_sql = table.name == "sqlite_schema" && column == "sql";
                let on_page = content
                    .get(col.start..(col.start + col.len).min(cell.local_end))
                    .unwrap_or_default();
                let shown: std::borrow::Cow<'_, [u8]> = if schema_sql
                    || (on_page.len() < col.len
                        && on_page.len() < SHOWN_BYTES
                        && !is_blob(col.serial))
                {
                    full_value(content, db, &at)
                } else {
                    on_page.into()
                };
                let cell_value = render_cell(&shown, col.serial, col.len);

                // When the match is in sqlite_schema.sql, check if it lands
                // on a column name token in the CREATE TABLE definition.
                let defines_column = if schema_sql {
                    let rel = offset - col.start;
                    parse_column_spans(&String::from_utf8_lossy(&shown))
                        .into_iter()
                        .find(|(_, s, e)| rel >= *s && rel < *e)
                        .map(|(name, _, _)| name)
                } else {
                    None
                };

                let summary = match &defines_column {
                    Some(def_col) => format!(
                        "table: {}  column: {} [{}]  (defines column: {})  row: {}  cell: {}",
                        table.name, column, ty, def_col, cell.rowid, cell_value
                    ),
                    None => format!(
                        "table: {}  column: {} [{}]  row: {}  cell: {}",
                        table.name, column, ty, cell.rowid, cell_value
                    ),
                };
                let detail = match &defines_column {
                    Some(def_col) => json!({
                        "page": page,
                        "table": table.name,
                        "rowid": cell.rowid,
                        "column": column,
                        "type": ty,
                        "defines_column": def_col,
                        "cell": cell_value,
                    }),
                    None => json!({
                        "page": page,
                        "table": table.name,
                        "rowid": cell.rowid,
                        "column": column,
                        "type": ty,
                        "cell": cell_value,
                    }),
                };

                let found = Inspection {
                    format: "sqlite".into(),
                    summary,
                    detail,
                };
                return Some((found, is_blob(col.serial).then_some(at)));
            }
        }

        // In the cell but in its varints/record header, not a value.
        let found = Inspection {
            format: "sqlite".into(),
            summary: format!(
                "table: {}  row: {}  (record metadata)",
                table.name, cell.rowid
            ),
            detail: json!({ "page": page, "table": table.name, "rowid": cell.rowid }),
        };
        return Some((found, None));
    }
    None
}

/// The complete bytes of the value at `at`, overflow pages included: borrowed when it
/// lies on its page, else read from the overflow chain only as far as its end.
///
/// WHY: a value too large for its leaf cell continues on overflow pages, so the bytes
/// after its on-page part are not the value (they are the overflow pointer, then the
/// next cell). A match is always in the on-page part, which is the value's start, so
/// its position in the value is unchanged. When the overflow chain cannot be read
/// (damaged or carved evidence), the on-page part alone is used, cut at `local_end`
/// (before the overflow page pointer): a signature at its start still identifies it,
/// and a structural parse fails, rather than reading a neighbouring cell as part of
/// the value.
fn full_value<'c>(content: &'c [u8], db: &Db, at: &BlobAt) -> std::borrow::Cow<'c, [u8]> {
    let col = &at.col;
    let end = col.start + col.len;
    let on_page = content
        .get(col.start..end.min(at.local_end))
        .unwrap_or_default();
    if end <= at.local_end {
        return on_page.into();
    }
    let Some(in_record) = col.start.checked_sub(at.record_start) else {
        return on_page.into();
    };
    cell_record_prefix(content, db, at.cell_file, in_record + col.len)
        .and_then(|(_, record)| {
            record
                .get(in_record..in_record + col.len)
                .map(<[u8]>::to_vec)
        })
        .map_or_else(|| on_page.into(), Into::into)
}

/// The most bytes of a text value decoded for display: enough for `render_cell`'s
/// 80 characters at up to 4 bytes each.
const SHOWN_BYTES: usize = 80 * 4;

/// Render a column value as a short, text-safe string for display.
///
/// Decodes by serial type (NULL / integer / real / text / blob). Text is
/// length-capped and control characters are stripped, so a cell value never
/// dumps raw or runaway bytes into the output.
fn render_cell(value: &[u8], serial: u64, len: usize) -> String {
    const MAX: usize = SHOWN_BYTES / 4;
    let col = Col {
        serial,
        start: 0,
        len: value.len(),
    };
    match serial {
        0 => "NULL".into(),
        8 => "0".into(),
        9 => "1".into(),
        1..=6 => col_int(value, Some(&col)).map_or_else(String::new, |v| v.to_string()),
        7 => value
            .get(..8)
            .and_then(|b| <[u8; 8]>::try_from(b).ok())
            .map_or_else(String::new, |a| f64::from_be_bytes(a).to_string()),
        s if s >= 13 && s % 2 == 1 => {
            // Only the bytes that can be shown are decoded, not a long value whole.
            let head = &value[..value.len().min(SHOWN_BYTES)];
            let text = String::from_utf8_lossy(head);
            let mut chars = text.chars().map(|c| if c.is_control() { ' ' } else { c });
            let mut out: String = chars.by_ref().take(MAX).collect();
            if chars.next().is_some() || len > head.len() {
                out.push('…');
            }
            out
        }
        _ => format!("<blob {len} bytes>"), // even serial >= 12
    }
}

/// Resolve matches inside a database's `-wal` file to a table, column and row.
///
/// HOW: a WAL is a 32-byte header, then frames of a 24-byte header (whose first four
/// bytes are the page number, big-endian) followed by one page. A match at a WAL
/// offset is in frame `f`, so it is that page, at the same position, in the database
/// as it stood with that frame applied: the WAL is replayed on `main` (so the schema
/// and every other page are current), the frame's own page is laid over it (it may be
/// an older or uncommitted version of the page), and the usual inspection runs there.
/// The result says which frame and page it came from. A match in a WAL or frame
/// header is not in a page, so it gets `None`.
///
/// WHY: apps keep their newest rows in the `-wal` (WhatsApp, Signal, iOS system
/// databases), so a match there is common, and without this it had no table at all.
pub(crate) fn inspect_wal(main: &[u8], wal: &[u8], offsets: &[usize]) -> Vec<Option<Inspection>> {
    const WAL_HEADER: usize = 32;
    const FRAME_HEADER: usize = 24;
    let mut out: Vec<Option<Inspection>> = offsets.iter().map(|_| None).collect();
    let be32 = |b: &[u8]| u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize;
    let Some(page_size) = wal.get(8..12).map(be32) else {
        return out;
    };
    if !main.starts_with(b"SQLite format 3\x00")
        || !(512..=65536).contains(&page_size)
        || !page_size.is_power_of_two()
    {
        return out;
    }
    let frame_len = FRAME_HEADER + page_size;
    // One working copy: each frame's page is swapped in, its matches resolved, and
    // the page swapped back out — never a copy of the whole database per frame.
    let mut image = checkpoint(main, wal).unwrap_or_else(|| main.to_vec());

    // Group the matches by frame, so each frame's image is built once.
    let mut by_frame: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for (i, &offset) in offsets.iter().enumerate() {
        if offset < WAL_HEADER || (offset - WAL_HEADER) % frame_len < FRAME_HEADER {
            continue;
        }
        by_frame
            .entry((offset - WAL_HEADER) / frame_len)
            .or_default()
            .push(i);
    }
    for (frame, indices) in by_frame {
        let start = WAL_HEADER + frame * frame_len;
        let (Some(header), Some(page)) = (
            wal.get(start..start + 4),
            wal.get(start + FRAME_HEADER..start + frame_len),
        ) else {
            continue;
        };
        let page_no = be32(header);
        if page_no == 0 {
            continue;
        }
        let page_start = (page_no - 1) * page_size;
        let replayed_len = image.len();
        if image.len() < page_start + page_size {
            image.resize(page_start + page_size, 0);
        }
        let saved = image[page_start..page_start + page_size].to_vec();
        image[page_start..page_start + page_size].copy_from_slice(page);
        let mapped: Vec<usize> = indices
            .iter()
            .map(|&i| page_start + offsets[i] - start - FRAME_HEADER)
            .collect();
        let results = <Sqlite as super::Inspector>::inspect_many(&Sqlite, &image, &mapped);
        image[page_start..page_start + page_size].copy_from_slice(&saved);
        image.truncate(replayed_len);
        for (&i, result) in indices.iter().zip(results) {
            out[i] = result.map(|mut inspection| {
                inspection.summary = format!(
                    "-wal frame {}, page {page_no}: {}",
                    frame + 1,
                    inspection.summary
                );
                if let serde_json::Value::Object(detail) = &mut inspection.detail {
                    detail.insert("wal_frame".into(), json!(frame + 1));
                    detail.insert("wal_page".into(), json!(page_no));
                }
                inspection
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_match_in_the_wal_resolves_through_the_main_database() {
        let main = std::fs::read("tests/fixtures/wal_main.sqlite3").unwrap();
        let wal = std::fs::read("tests/fixtures/wal_main.sqlite3-wal").unwrap();
        let at = wal
            .windows(13)
            .position(|w| w == b"only-in-wal-1")
            .expect("the fixture's WAL holds the value");
        let header = 3; // inside the WAL header: not in any page
        let found = super::inspect_wal(&main, &wal, &[at, header]);
        let inspection = found[0]
            .as_ref()
            .expect("resolved through the main database");
        assert!(
            inspection.summary.contains("table: t"),
            "{}",
            inspection.summary
        );
        assert!(
            inspection.summary.starts_with("-wal frame "),
            "{}",
            inspection.summary
        );
        assert_eq!(inspection.detail["wal_page"], 2);
        assert!(found[1].is_none());
    }
}
