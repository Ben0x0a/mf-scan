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
//! Uses: `crate::models::Inspection`, `serde_json`.
//!
//! The parser is deliberately lenient: anything it cannot resolve degrades to
//! the page+offset fallback rather than erroring, because forensic databases
//! are frequently partial or corrupt. References: the SQLite file format spec
//! (database header, b-tree pages, record format, varints).

use std::collections::{BTreeMap, HashSet};

use serde_json::json;

use crate::models::{ContentDiff, Inspection};

const TABLE_LEAF: u8 = 0x0d;
const TABLE_INTERIOR: u8 = 0x05;
const HEADER_LEN: usize = 100; // database header, present only on page 1

/// Parsed database header essentials.
struct Db {
    page_size: usize,
    usable: usize, // page_size minus reserved per-page bytes
}

/// A table definition recovered from the schema.
struct Table {
    name: String,
    rootpage: u32,
    columns: Vec<String>,
}

/// One column slot within a parsed record: its serial type and byte span.
struct Col {
    serial: u64,
    start: usize, // absolute file offset of the value bytes
    len: usize,
}

/// A parsed table-leaf cell.
struct Cell {
    rowid: u64,
    total_len: usize, // bytes occupied by the whole cell within the page
    columns: Vec<Col>,
}

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

/// Resolve `offset` to a table cell, or fall back to page + offset-in-page.
fn locate(content: &[u8], offset: usize) -> Option<Inspection> {
    let db = parse_header(content)?;
    if offset >= content.len() {
        return None;
    }
    let page = (offset / db.page_size + 1) as u32;
    let page_off = offset % db.page_size;

    Some(
        resolve(content, &db, offset, page, page_off).unwrap_or_else(|| Inspection {
            format: "sqlite".into(),
            summary: format!("page: {page}  offset: {page_off}  (not in a table cell)"),
            detail: json!({ "page": page, "page_offset": page_off }),
        }),
    )
}

/// Parse the 100-byte database header.
fn parse_header(content: &[u8]) -> Option<Db> {
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

/// Full resolution to table/rowid/column; `None` whenever the byte is not in a
/// live table-leaf cell (the caller then emits the page+offset fallback).
fn resolve(
    content: &[u8],
    db: &Db,
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
    let tables = read_schema(content, db);
    let table = tables
        .into_iter()
        .find(|t| pages_of(content, db, t.rootpage).contains(&page))?;

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

/// The b-tree header starts after the database header on page 1, at byte 0
/// elsewhere.
fn btree_header_offset(page: u32) -> usize {
    if page == 1 { HEADER_LEN } else { 0 }
}

/// Read the schema (`sqlite_schema`) into table definitions, including a
/// synthetic entry for the schema table itself (rootpage 1).
fn read_schema(content: &[u8], db: &Db) -> Vec<Table> {
    let mut tables = vec![Table {
        name: "sqlite_schema".into(),
        rootpage: 1,
        columns: ["type", "name", "tbl_name", "rootpage", "sql"]
            .iter()
            .map(|s| s.to_string())
            .collect(),
    }];

    let mut found = Vec::new();
    for_each_leaf_cell(content, db, 1, &mut |cell_file| {
        let Some(cell) = parse_cell(content, db, cell_file) else {
            return;
        };
        // schema columns: type, name, tbl_name, rootpage, sql
        if col_text(content, cell.columns.first()).as_deref() != Some("table") {
            return;
        }
        let name = col_text(content, cell.columns.get(1));
        let root = col_int(content, cell.columns.get(3));
        let sql = col_text(content, cell.columns.get(4));
        if let (Some(name), Some(root), Some(sql)) = (name, root, sql) {
            found.push((name, root as u32, parse_columns(&sql)));
        }
    });

    for (name, rootpage, columns) in found {
        tables.push(Table {
            name,
            rootpage,
            columns,
        });
    }
    tables
}

/// Collect every page belonging to the b-tree rooted at `root` (interior +
/// leaf), so we can test whether a target page belongs to a table.
fn pages_of(content: &[u8], db: &Db, root: u32) -> HashSet<u32> {
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

/// Visit each cell of every leaf page in the b-tree rooted at `root`.
fn for_each_leaf_cell(content: &[u8], db: &Db, root: u32, visit: &mut dyn FnMut(usize)) {
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

/// Parse a table-leaf cell at `cell_file`.
fn parse_cell(content: &[u8], db: &Db, cell_file: usize) -> Option<Cell> {
    let (payload_len, n1) = varint(content, cell_file)?;
    let (rowid, n2) = varint(content, cell_file + n1)?;
    let record_start = cell_file + n1 + n2;
    let payload = payload_len as usize;

    // Local payload size (the rest, if any, lives on overflow pages — which are
    // separate pages, so a match on *this* page is always within local bytes).
    let usable = db.usable;
    let max_local = usable.checked_sub(35)?;
    let local = if payload <= max_local {
        payload
    } else {
        let min_local = (usable - 12) * 32 / 255 - 23;
        let k = min_local + (payload - min_local) % (usable - 4);
        if k <= max_local { k } else { min_local }
    };
    let overflow = payload > local;
    let total_len = n1 + n2 + local + if overflow { 4 } else { 0 };

    // Record header: a varint header length, then one serial type per column.
    let (header_len, h1) = varint(content, record_start)?;
    let header_end = record_start + header_len as usize;
    let mut p = record_start + h1;
    let mut body = header_end;
    let mut columns = Vec::new();
    while p < header_end {
        let (serial, sn) = varint(content, p)?;
        p += sn;
        let len = serial_len(serial);
        columns.push(Col {
            serial,
            start: body,
            len,
        });
        body += len;
    }

    Some(Cell {
        rowid,
        total_len,
        columns,
    })
}

/// SQLite storage-class name for a record serial type (for `column [TYPE]`).
fn serial_type_name(serial: u64) -> &'static str {
    match serial {
        0 => "NULL",
        1..=6 | 8 | 9 => "INTEGER",
        7 => "REAL",
        s if s >= 12 && s.is_multiple_of(2) => "BLOB",
        s if s >= 13 => "TEXT",
        _ => "?", // 10, 11 are reserved and unused in practice
    }
}

/// True if the serial type denotes a BLOB value (even, ≥ 12).
fn is_blob(serial: u64) -> bool {
    serial >= 12 && serial.is_multiple_of(2)
}

/// Byte length of a value with the given record serial type.
fn serial_len(serial: u64) -> usize {
    match serial {
        0 | 8 | 9 | 10 | 11 => 0,
        1 => 1,
        2 => 2,
        3 => 3,
        4 => 4,
        5 => 6,
        6 | 7 => 8,
        s if s.is_multiple_of(2) => ((s - 12) / 2) as usize, // BLOB
        s => ((s - 13) / 2) as usize,                        // TEXT
    }
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

/// Decode a TEXT column value (lossily) when the slot holds text.
fn col_text(content: &[u8], col: Option<&Col>) -> Option<String> {
    let c = col?;
    if c.serial >= 13 && c.serial % 2 == 1 {
        let bytes = content.get(c.start..c.start + c.len)?;
        Some(String::from_utf8_lossy(bytes).into_owned())
    } else {
        None
    }
}

/// Decode an INTEGER column value when the slot holds one.
fn col_int(content: &[u8], col: Option<&Col>) -> Option<i64> {
    let c = col?;
    match c.serial {
        8 => Some(0),
        9 => Some(1),
        1..=6 => {
            let bytes = content.get(c.start..c.start + c.len)?;
            // Two's-complement big-endian sign extension.
            let mut value: i64 = if bytes.first().is_some_and(|b| b & 0x80 != 0) {
                -1
            } else {
                0
            };
            for &b in bytes {
                value = (value << 8) | b as i64;
            }
            Some(value)
        }
        _ => None,
    }
}

/// Extract column names from a `CREATE TABLE` statement.
fn parse_columns(sql: &str) -> Vec<String> {
    parse_column_spans(sql)
        .into_iter()
        .map(|(name, _, _)| name)
        .collect()
}

/// Like `parse_columns` but also returns each name's byte span `[start, end)`
/// within `sql`, so callers can check whether a match offset lands in a column
/// name token.
fn parse_column_spans(sql: &str) -> Vec<(String, usize, usize)> {
    let Some(open) = sql.find('(') else {
        return Vec::new();
    };
    let Some(close) = sql.rfind(')') else {
        return Vec::new();
    };
    let inner = &sql[open + 1..close];
    let base = open + 1;

    let mut depth = 0i32;
    let mut seg_start = 0usize;
    let mut parts: Vec<(usize, usize)> = Vec::new();
    for (i, ch) in inner.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => depth -= 1,
            ',' if depth == 0 => {
                parts.push((seg_start, i));
                seg_start = i + 1;
            }
            _ => {}
        }
    }
    parts.push((seg_start, inner.len()));

    let mut result = Vec::new();
    for (ps, pe) in parts {
        let part = &inner[ps..pe];
        let trimmed = part.trim_start();
        if trimmed.is_empty() {
            continue;
        }
        let leading = part.len() - trimmed.len();
        let (name, name_byte_len) = first_token_with_len(trimmed);
        if name.is_empty() {
            continue;
        }
        let upper = name.to_ascii_uppercase();
        if matches!(
            upper.as_str(),
            "PRIMARY" | "UNIQUE" | "CHECK" | "FOREIGN" | "CONSTRAINT" | "KEY"
        ) {
            continue;
        }
        let tok_start = base + ps + leading;
        result.push((name, tok_start, tok_start + name_byte_len));
    }
    result
}

/// Read the first identifier of a column definition, honouring the quoting
/// styles SQLite accepts (`"x"`, `` `x` ``, `[x]`, or bare). Returns the name
/// and its byte length in `part` (including surrounding quotes when present).
fn first_token_with_len(part: &str) -> (String, usize) {
    let mut chars = part.chars();
    match chars.next() {
        Some('"') => {
            let name: String = chars.take_while(|&c| c != '"').collect();
            let byte_len = name.len() + 2;
            (name, byte_len)
        }
        Some('`') => {
            let name: String = chars.take_while(|&c| c != '`').collect();
            let byte_len = name.len() + 2;
            (name, byte_len)
        }
        Some('[') => {
            let name: String = chars.take_while(|&c| c != ']').collect();
            let byte_len = name.len() + 2;
            (name, byte_len)
        }
        Some(first) => {
            let mut s = String::from(first);
            for c in chars {
                if c.is_whitespace() || c == '(' {
                    break;
                }
                s.push(c);
            }
            let byte_len = s.len();
            (s, byte_len)
        }
        None => (String::new(), 0),
    }
}

/// Read a SQLite varint (1–9 bytes, big-endian) at `off`, returning the value
/// and the number of bytes consumed.
fn varint(content: &[u8], off: usize) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    for i in 0..9 {
        let byte = *content.get(off + i)?;
        if i == 8 {
            return Some(((value << 8) | byte as u64, 9));
        }
        value = (value << 7) | (byte & 0x7f) as u64;
        if byte & 0x80 == 0 {
            return Some((value, i + 1));
        }
    }
    Some((value, 9))
}

fn read_u16(content: &[u8], off: usize) -> Option<usize> {
    Some(((*content.get(off)? as usize) << 8) | *content.get(off + 1)? as usize)
}

fn read_u32(content: &[u8], off: usize) -> Option<u32> {
    Some(
        ((*content.get(off)? as u32) << 24)
            | ((*content.get(off + 1)? as u32) << 16)
            | ((*content.get(off + 2)? as u32) << 8)
            | (*content.get(off + 3)? as u32),
    )
}
