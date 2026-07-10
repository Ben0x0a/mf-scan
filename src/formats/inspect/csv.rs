//! CSV inspector: map a byte offset to a row, column, and header field name.
//!
//! Defines: `inspect`, returning the 1-based row and column of a match plus the
//! column's header name (the value of that column in the first row).
//! Used by: `inspect::inspect` (dispatch).
//! Uses: `crate::core::models::Inspection`, `serde_json`.
//!
//! Quoting follows RFC 4180: a field may be wrapped in double quotes, inside
//! which commas and newlines are literal and `""` is an escaped quote. The
//! scanner tracks that state so separators inside quotes don't miscount the
//! row/column.

use serde_json::json;

use crate::core::models::Inspection;

/// CSV inspector — detected by `.csv` extension (CSV has no header magic).
pub struct Csv;

impl super::Inspector for Csv {
    fn name(&self) -> &'static str {
        "csv"
    }
    fn category(&self) -> &'static str {
        "text"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["csv"]
    }
    fn detect(&self, _content: &[u8]) -> bool {
        false // no signature
    }
    fn inspect(&self, content: &[u8], offset: usize) -> Option<Inspection> {
        resolve(content, offset)
    }
}

/// Locate the row/column of the match at `offset` in a CSV document.
fn resolve(content: &[u8], offset: usize) -> Option<Inspection> {
    if offset >= content.len() {
        return None;
    }
    let (row, col) = row_col_at(content, offset);
    let header = header_field(content, col);

    let summary = match (&header, row) {
        (_, 1) => format!("row: {row}  col: {col}  (header row)"),
        (Some(h), _) => format!("row: {row}  col: {col}  header: {h}"),
        (None, _) => format!("row: {row}  col: {col}"),
    };
    let detail = json!({
        "row": row,
        "col": col,
        "header": header,
    });
    Some(Inspection {
        format: "csv".into(),
        summary,
        detail,
    })
}

/// Scan to `target`, returning its 1-based (row, column), honouring quoting.
fn row_col_at(content: &[u8], target: usize) -> (usize, usize) {
    let mut row = 1usize;
    let mut col = 1usize;
    let mut in_quotes = false;
    let mut i = 0usize;

    while i < content.len() {
        if i == target {
            break;
        }
        let b = content[i];
        if in_quotes {
            if b == b'"' {
                if content.get(i + 1) == Some(&b'"') {
                    // Escaped quote (""). Both bytes stay in this field.
                    if i + 1 == target {
                        break;
                    }
                    i += 2;
                    continue;
                }
                in_quotes = false;
            }
            // Commas/newlines inside quotes are literal — no counting.
        } else {
            match b {
                b'"' => in_quotes = true,
                b',' => col += 1,
                b'\n' => {
                    row += 1;
                    col = 1;
                }
                _ => {}
            }
        }
        i += 1;
    }

    (row, col)
}

/// The header value for column `col` (1-based): that column's field in row 1.
fn header_field(content: &[u8], col: usize) -> Option<String> {
    let fields = first_row_fields(content);
    fields.get(col - 1).cloned()
}

/// Parse the first row into field values, honouring quoting and `""` escapes.
fn first_row_fields(content: &[u8]) -> Vec<String> {
    let mut fields = Vec::new();
    let mut field = Vec::new();
    let mut in_quotes = false;
    let mut i = 0usize;

    while i < content.len() {
        let b = content[i];
        if in_quotes {
            match b {
                b'"' if content.get(i + 1) == Some(&b'"') => {
                    field.push(b'"');
                    i += 2;
                    continue;
                }
                b'"' => in_quotes = false,
                _ => field.push(b),
            }
        } else {
            match b {
                b'"' => in_quotes = true,
                b',' => {
                    fields.push(take_field(&mut field));
                }
                b'\n' => break,
                b'\r' => {}
                _ => field.push(b),
            }
        }
        i += 1;
    }
    fields.push(take_field(&mut field));
    fields
}

/// Drain `field` into a lossily-decoded, trimmed string.
fn take_field(field: &mut Vec<u8>) -> String {
    let s = String::from_utf8_lossy(field).trim().to_string();
    field.clear();
    s
}
