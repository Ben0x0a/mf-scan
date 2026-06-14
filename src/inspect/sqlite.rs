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
//! Uses: `crate::sqlite` (the low-level SQLite reader — header, b-tree walk,
//! record parsing), `crate::models::Inspection`, `serde_json`.
//!
//! This is the *display/resolution* half of SQLite support: it turns a byte
//! offset into a human/JSON location and renders cell values for output. The raw
//! format parsing lives in `crate::sqlite` so the inspector and the iOS-backup
//! `Manifest.db` reader share one audited reader. Resolution is deliberately
//! lenient: anything it cannot place degrades to the page+offset fallback rather
//! than erroring, because forensic databases are frequently partial or corrupt.

use std::collections::{BTreeMap, HashSet};

use serde_json::json;

use crate::models::{ContentDiff, Inspection};
use crate::sqlite::{
    Col, Db, TABLE_LEAF, Table, btree_header_offset, col_int, col_text, for_each_leaf_cell,
    is_blob, pages_of, parse_cell, parse_column_spans, parse_header, read_schema, read_u16,
    serial_type_name,
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
        locate(content, offset)
    }
    /// Batch resolution: the schema and each table's page set are derived once
    /// per file instead of once per match — a message DB with thousands of
    /// matches would otherwise re-walk the schema b-trees for every one
    /// (review finding P1).
    fn inspect_many(&self, content: &[u8], offsets: &[usize]) -> Vec<Option<Inspection>> {
        let Some(db) = parse_header(content) else {
            return offsets.iter().map(|_| None).collect();
        };
        let schema = SchemaMap::build(content, &db);
        offsets
            .iter()
            .map(|&o| locate_with(content, &db, &schema, o))
            .collect()
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

/// Resolve `offset` to a table cell, or fall back to page + offset-in-page.
fn locate(content: &[u8], offset: usize) -> Option<Inspection> {
    let db = parse_header(content)?;
    let schema = SchemaMap::build(content, &db);
    locate_with(content, &db, &schema, offset)
}

/// [`locate`] against pre-built per-file state (the batch path shares it).
fn locate_with(content: &[u8], db: &Db, schema: &SchemaMap, offset: usize) -> Option<Inspection> {
    if offset >= content.len() {
        return None;
    }
    let page = (offset / db.page_size + 1) as u32;
    let page_off = offset % db.page_size;

    Some(
        resolve(content, db, schema, offset, page, page_off).unwrap_or_else(|| Inspection {
            format: "sqlite".into(),
            summary: format!("page: {page}  offset: {page_off}  (not in a table cell)"),
            detail: json!({ "page": page, "page_offset": page_off }),
        }),
    )
}

/// Full resolution to table/rowid/column; `None` whenever the byte is not in a
/// live table-leaf cell (the caller then emits the page+offset fallback).
fn resolve(
    content: &[u8],
    db: &Db,
    schema: &SchemaMap,
    offset: usize,
    page: u32,
    page_off: usize,
) -> Option<Inspection> {
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
            if offset >= col.start && offset < col.start + col.len {
                let column = table
                    .columns
                    .get(idx)
                    .cloned()
                    .unwrap_or_else(|| format!("column{idx}"));
                let ty = serial_type_name(col.serial);
                let cell_value = render_cell(content, col);

                // When the match is in sqlite_schema.sql, check if it lands
                // on a column name token in the CREATE TABLE definition.
                let defines_column = if table.name == "sqlite_schema" && column == "sql" {
                    col_text(content, Some(col)).and_then(|sql_text| {
                        let rel = offset - col.start;
                        parse_column_spans(&sql_text)
                            .into_iter()
                            .find(|(_, s, e)| rel >= *s && rel < *e)
                            .map(|(name, _, _)| name)
                    })
                } else {
                    None
                };

                let mut summary = match &defines_column {
                    Some(def_col) => format!(
                        "table: {}  column: {} [{}]  (defines column: {})  row: {}  cell: {}",
                        table.name, column, ty, def_col, cell.rowid, cell_value
                    ),
                    None => format!(
                        "table: {}  column: {} [{}]  row: {}  cell: {}",
                        table.name, column, ty, cell.rowid, cell_value
                    ),
                };
                let mut detail = match &defines_column {
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

                // A BLOB may itself be a recognised format (e.g. a bplist stored
                // in a cell). Classify it by signature and, when an inspector
                // claims it, resolve the match position inside the blob as well —
                // reusing the same inspector registry, no SQLite-specific parsing.
                if is_blob(col.serial)
                    && let Some(blob) = content.get(col.start..col.start + col.len)
                    && let Some(insp) = super::detect_by_header(blob)
                {
                    let nested = insp.inspect(blob, offset - col.start);
                    let blob_format = nested
                        .as_ref()
                        .map_or_else(|| insp.name().to_string(), |n| n.format.clone());
                    summary.push_str(&format!("  blob: {blob_format}"));
                    if let Some(n) = &nested {
                        summary.push_str(&format!("  {}", n.summary));
                    }
                    if let Some(obj) = detail.as_object_mut() {
                        obj.insert("blob_format".into(), json!(blob_format));
                        if let Some(n) = nested {
                            obj.insert("blob_context".into(), n.detail);
                        }
                    }
                }

                return Some(Inspection {
                    format: "sqlite".into(),
                    summary,
                    detail,
                });
            }
        }

        // In the cell but in its varints/record header, not a value.
        return Some(Inspection {
            format: "sqlite".into(),
            summary: format!(
                "table: {}  row: {}  (record metadata)",
                table.name, cell.rowid
            ),
            detail: json!({ "page": page, "table": table.name, "rowid": cell.rowid }),
        });
    }
    None
}

/// Render a column value as a short, text-safe string for display.
///
/// Decodes by serial type (NULL / integer / real / text / blob). Text is
/// length-capped and control characters are stripped, so a cell value never
/// dumps raw or runaway bytes into the output.
fn render_cell(content: &[u8], col: &Col) -> String {
    const MAX: usize = 80;
    match col.serial {
        0 => "NULL".into(),
        8 => "0".into(),
        9 => "1".into(),
        1..=6 => col_int(content, Some(col)).map_or_else(String::new, |v| v.to_string()),
        7 => content
            .get(col.start..col.start + 8)
            .and_then(|b| <[u8; 8]>::try_from(b).ok())
            .map_or_else(String::new, |a| f64::from_be_bytes(a).to_string()),
        s if s >= 13 && s % 2 == 1 => {
            let text = col_text(content, Some(col)).unwrap_or_default();
            let mut out: String = text
                .chars()
                .map(|c| if c.is_control() { ' ' } else { c })
                .collect();
            if out.chars().count() > MAX {
                out = out.chars().take(MAX).collect::<String>() + "…";
            }
            out
        }
        _ => format!("<blob {} bytes>", col.len), // even serial >= 12
    }
}
