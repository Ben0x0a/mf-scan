//! The `sqlite_schema` table: recover table names, root pages, and column lists.
//!
//! Defines: a [`Table`] definition and [`read_schema`] (which reads the schema
//! b-tree into table definitions), plus [`parse_column_spans`] — the `CREATE
//! TABLE` column-name parser the inspector uses to tell whether a match lands on
//! a column-name token.
//! Used by: the sibling `table` submodule and, via the `sqlite` module's
//! re-exports, the SQLite inspector.
//! Uses: [`super::page`] (the b-tree walk) and [`super::record`] (cell decoding).

use super::page::{Db, for_each_leaf_cell};
use super::record::{col_int, col_text, parse_cell};

/// A table definition recovered from the schema.
pub(crate) struct Table {
    pub(crate) name: String,
    pub(crate) rootpage: u32,
    pub(crate) columns: Vec<String>,
}

/// Read the schema (`sqlite_schema`) into table definitions, including a
/// synthetic entry for the schema table itself (rootpage 1).
pub(crate) fn read_schema(content: &[u8], db: &Db) -> Vec<Table> {
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

/// Extract column names from a `CREATE TABLE` statement.
fn parse_columns(sql: &str) -> Vec<String> {
    parse_column_spans(sql)
        .into_iter()
        .map(|(name, _, _)| name)
        .collect()
}

/// Like [`parse_columns`] but also returns each name's byte span `[start, end)`
/// within `sql`, so a caller can check whether a match offset lands in a column
/// name token of the `CREATE TABLE` definition.
pub(crate) fn parse_column_spans(sql: &str) -> Vec<(String, usize, usize)> {
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
