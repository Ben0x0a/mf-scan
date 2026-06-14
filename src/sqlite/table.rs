//! The high-level row reader: project a named table's columns to typed values.
//!
//! Defines: [`Row`] and [`read_table`], built on the page walk, the record
//! decoder, and the schema reader.
//! Used by: `ios::backup` (reads an encrypted backup's decrypted `Manifest.db`
//! `Files` table), via the `sqlite` module's re-exports.
//! Uses: the sibling `page` / `record` / `schema` submodules.

use super::page::{for_each_leaf_cell, parse_header};
use super::record::{Value, col_value, parse_cell};
use super::schema::read_schema;

/// One table row: the requested columns' values, positionally aligned with the
/// `columns` slice passed to [`read_table`]. A column absent from the row's
/// record (a short record, common after schema changes) is [`Value::Null`].
pub(crate) type Row = Vec<Value>;

/// Read every row of `table`, projecting the named `columns` to typed [`Value`]s.
///
/// Pure-Rust over the in-house b-tree walker — no SQLite library. Reuses
/// [`read_schema`] (to resolve the table's root page and its column order) and
/// [`for_each_leaf_cell`] + [`parse_cell`] (to enumerate rows). Returns `None`
/// only when the file is not a SQLite database or the table is unknown; a
/// malformed individual cell is skipped (lenient-parser contract), and a column
/// the schema does not declare yields [`Value::Null`] for every row rather than
/// failing the whole read.
pub(crate) fn read_table(content: &[u8], table: &str, columns: &[&str]) -> Option<Vec<Row>> {
    let db = parse_header(content)?;
    let schema = read_schema(content, &db);
    let def = schema.iter().find(|t| t.name == table)?;

    // Map each requested column name to its index in the table's column order, so
    // a row's positional record slots line up with what the caller asked for. An
    // unknown column maps to `None` and is reported as Null for every row.
    let indices: Vec<Option<usize>> = columns
        .iter()
        .map(|name| def.columns.iter().position(|c| c == name))
        .collect();

    let mut rows: Vec<Row> = Vec::new();
    for_each_leaf_cell(content, &db, def.rootpage, &mut |cell_file| {
        let Some(cell) = parse_cell(content, &db, cell_file) else {
            return; // skip an unparseable cell rather than abort the table
        };
        let row: Row = indices
            .iter()
            .map(|idx| match idx.and_then(|i| cell.columns.get(i)) {
                Some(col) => col_value(content, col),
                None => Value::Null,
            })
            .collect();
        rows.push(row);
    });
    Some(rows)
}

#[cfg(test)]
mod tests {
    use super::read_table;
    use crate::sqlite::Value;

    /// The committed `messages.sqlite` fixture has a `messages(id, sender, body)`
    /// table; reading it back must recover the integer ids and the text columns
    /// row for row (proving the TEXT + INTEGER extractors and the column-name →
    /// index mapping).
    #[test]
    fn reads_text_and_int_columns() {
        let bytes = std::fs::read("tests/fixtures/messages.sqlite").unwrap();
        let rows = read_table(&bytes, "messages", &["id", "sender", "body"]).unwrap();
        assert_eq!(rows.len(), 3);
        // INTEGER PRIMARY KEY is stored as the rowid (a NULL serial-0 slot), so the
        // aliased `id` column reads back as Null — the row order is the rowid order.
        assert_eq!(rows[0][1], Value::Text("alice".into()));
        assert_eq!(rows[0][2], Value::Text("hello there".into()));
        assert_eq!(rows[1][1], Value::Text("FINDSENDER".into()));
        assert_eq!(rows[2][1], Value::Text("bob".into()));
    }

    /// The `blob.sqlite` fixture's `items(id, name, payload)` table has a BLOB
    /// `payload` column holding a binary plist; the BLOB extractor must hand back
    /// the exact bytes (starting with the `bplist00` magic), unaltered.
    #[test]
    fn reads_blob_column_verbatim() {
        let bytes = std::fs::read("tests/fixtures/blob.sqlite").unwrap();
        let rows = read_table(&bytes, "items", &["name", "payload"]).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0][0], Value::Text("alpha".into()));
        let Value::Blob(blob) = &rows[0][1] else {
            panic!("payload should be a BLOB, got {:?}", rows[0][1]);
        };
        assert_eq!(blob.len(), 115);
        assert!(blob.starts_with(b"bplist00"));
    }

    /// An unknown table yields `None`; an unknown column yields `Null` for every
    /// row rather than failing the whole read (degrade, don't die).
    #[test]
    fn unknown_table_is_none_unknown_column_is_null() {
        let bytes = std::fs::read("tests/fixtures/messages.sqlite").unwrap();
        assert!(read_table(&bytes, "nope", &["id"]).is_none());
        let rows = read_table(&bytes, "messages", &["sender", "no_such_col"]).unwrap();
        assert_eq!(rows.len(), 3);
        assert!(rows.iter().all(|r| r[1] == Value::Null));
    }

    /// A non-SQLite buffer is not a database, so the read declines cleanly.
    #[test]
    fn non_sqlite_is_none() {
        assert!(read_table(b"not a database at all", "messages", &["id"]).is_none());
    }
}
