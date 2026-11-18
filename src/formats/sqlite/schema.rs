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
use super::record::{cell_record, col_int, col_text, parse_cell, parse_record_columns};

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
        // The whole record, overflow pages included: a long `CREATE TABLE` (4.5 KB
        // in Snapchat's arroyo.db, over one 4 KB page) would otherwise be cut, and
        // its later columns lost. When the overflow chain cannot be followed
        // (damaged or carved evidence), the on-page part is read as before, so the
        // table and its first columns are still mapped.
        let whole = cell_record(content, db, cell_file).and_then(|(_, record)| {
            let columns = parse_record_columns(&record)?;
            Some((record, [0, 1, 3, 4].map(|i| columns.get(i).cloned())))
        });
        let (kind, name, root, sql) = match &whole {
            Some((record, [kind, name, root, sql])) => (
                col_text(record, kind.as_ref()),
                col_text(record, name.as_ref()),
                col_int(record, root.as_ref()),
                col_text(record, sql.as_ref()),
            ),
            None => {
                let Some(cell) = parse_cell(content, db, cell_file) else {
                    return;
                };
                (
                    col_text(content, cell.columns.first()),
                    col_text(content, cell.columns.get(1)),
                    col_int(content, cell.columns.get(3)),
                    col_text(content, cell.columns.get(4)),
                )
            }
        };
        // schema columns: type, name, tbl_name, rootpage, sql
        if kind.as_deref() != Some("table") {
            return;
        }
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
    // Comments and string literals can hold commas, parentheses and words; blanked
    // to spaces (byte for byte, so every offset stays the same), they cannot split
    // a column or pass for its name.
    let masked = blank_comments_and_strings(sql, true);
    // WHY a second, comments-only mask: SQLite reads a single-quoted word where only
    // a name can stand (`CREATE TABLE t('a' TEXT)`) as that name, so a part's first
    // token is looked for with string literals still visible.
    let names = blank_comments_and_strings(sql, false);
    let Some(open) = masked.find('(') else {
        return Vec::new();
    };
    let Some(close) = masked.rfind(')') else {
        return Vec::new();
    };
    let inner = &sql[open + 1..close];
    let inner_masked = &masked.as_bytes()[open + 1..close];
    let base = open + 1;

    let mut depth = 0i32;
    let mut seg_start = 0usize;
    let mut parts: Vec<(usize, usize)> = Vec::new();
    let mut i = 0;
    while i < inner_masked.len() {
        match inner_masked[i] {
            b'(' => depth += 1,
            b')' => depth -= 1,
            b',' if depth == 0 => {
                parts.push((seg_start, i));
                seg_start = i + 1;
            }
            // A quoted identifier may hold a comma: step over it whole.
            b'"' | b'`' | b'[' => i = quoted_end(inner_masked, i) - 1,
            _ => {}
        }
        i += 1;
    }
    parts.push((seg_start, inner.len()));

    let mut result = Vec::new();
    for (ps, pe) in parts {
        let part = &names[base + ps..base + pe];
        let trimmed = part.trim_start();
        if trimmed.is_empty() {
            continue;
        }
        let leading = part.len() - trimmed.len();
        // Read from the comment-blanked text, so a comment touching the name
        // (`id--pk`) is not part of it; quoted identifiers are left intact there.
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

/// The position just after the quoted identifier that opens at `b[i]` (`"…"`,
/// `` `…` `` or `[…]`), or the end of `b` when it is never closed. The one rule both
/// the blanking pass and the column splitter use to step over an identifier.
fn quoted_end(b: &[u8], i: usize) -> usize {
    let close = if b[i] == b'[' { b']' } else { b[i] };
    b[i + 1..]
        .iter()
        .position(|&c| c == close)
        .map_or(b.len(), |p| i + 1 + p + 1)
}

/// `sql` with every comment (`-- …` to the end of the line, `/* … */`) and, when
/// `strings`, every string literal (`'…'`, `''` escaping a quote) replaced by
/// spaces, byte for byte. A literal is always stepped over whole, so a `--` inside
/// it is not taken for a comment.
///
/// WHY: real schemas carry comments. Snapchat's `arroyo.db` has
/// `server_message_id integer,   -- server monotonically increasing id, nullable…`,
/// whose comma split a bogus column and shifted every later column name. Quoted
/// identifiers (`"…"`, `` `…` ``, `[…]`) are left as they are: they are names.
fn blank_comments_and_strings(sql: &str, strings: bool) -> String {
    let b = sql.as_bytes();
    let mut out = b.to_vec();
    let mut i = 0;
    while i < b.len() {
        let end = match b[i] {
            b'-' if b.get(i + 1) == Some(&b'-') => {
                let end = b[i..]
                    .iter()
                    .position(|&c| c == b'\n')
                    .map_or(b.len(), |p| i + p);
                out[i..end].fill(b' ');
                end
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                let end = b[i + 2..]
                    .windows(2)
                    .position(|w| w == b"*/")
                    .map_or(b.len(), |p| i + 2 + p + 2);
                out[i..end].fill(b' ');
                end
            }
            b'\'' => {
                let mut j = i + 1;
                while j < b.len() {
                    if b[j] == b'\'' {
                        if b.get(j + 1) == Some(&b'\'') {
                            j += 2;
                            continue;
                        }
                        j += 1;
                        break;
                    }
                    j += 1;
                }
                if strings {
                    out[i..j].fill(b' ');
                }
                j
            }
            b'"' | b'`' | b'[' => quoted_end(b, i),
            _ => i + 1,
        };
        i = end;
    }
    // Only whole regions bounded by ASCII were blanked, so the bytes stay UTF-8.
    String::from_utf8(out).expect("blanking whole ASCII-delimited regions keeps UTF-8")
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
        // A single-quoted name (SQLite reads it as one where a name must stand).
        Some('\'') => {
            let name: String = chars.take_while(|&c| c != '\'').collect();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comments_and_string_literals_do_not_split_or_name_columns() {
        // The shape of Snapchat's arroyo.db schema, plus a literal with a comma.
        let sql = "CREATE TABLE conversation_message (\n    client_conversation_id text not null,\n    server_message_id integer,   -- server id, nullable if pending (sic)\n\n    /* a block, with (parens) */ kind text default 'a,b',\n    \"odd, name\" blob,\n    message_content blob\n)";
        let names: Vec<String> = parse_column_spans(sql)
            .into_iter()
            .map(|(n, _, _)| n)
            .collect();
        assert_eq!(
            names,
            [
                "client_conversation_id",
                "server_message_id",
                "kind",
                "odd, name",
                "message_content"
            ]
        );
        for (name, start, end) in parse_column_spans(sql) {
            assert!(sql[start..end].contains(name.as_str()), "span of {name}");
        }
        // A comment touching a name is not part of it.
        let touching = "CREATE TABLE t (id--pk\n integer, b/*x*/ text)";
        let names: Vec<String> = parse_column_spans(touching)
            .into_iter()
            .map(|(n, _, _)| n)
            .collect();
        assert_eq!(names, ["id", "b"]);

        // A single-quoted name is a name (SQLite's rule where a literal cannot
        // stand), while a single-quoted default is still a literal.
        let quoted = "CREATE TABLE t('a' TEXT, 'b' INTEGER DEFAULT 'x,y', c)";
        let spans = parse_column_spans(quoted);
        let names: Vec<&str> = spans.iter().map(|(n, _, _)| n.as_str()).collect();
        assert_eq!(names, ["a", "b", "c"]);
        assert_eq!(&quoted[spans[0].1..spans[0].2], "'a'");
    }

    #[test]
    fn a_real_commented_schema_yields_sqlites_own_column_list() {
        // Snapchat's arroyo.db `conversation_message`: comments with commas, quotes
        // and a dashed separator line. Expected: SQLite's `PRAGMA table_info`.
        let sql = include_str!("../../../tests/fixtures/arroyo_conversation_message.sql");
        let names: Vec<String> = parse_column_spans(sql)
            .into_iter()
            .map(|(n, _, _)| n)
            .collect();
        let expected = [
            "client_conversation_id",
            "client_message_id",
            "server_message_id",
            "client_resolution_id",
            "local_message_content_id",
            "message_content",
            "message_state_type",
            "creation_timestamp",
            "read_timestamp",
            "local_message_references",
            "quoted_server_message_id",
            "quoted_message_status",
            "latest_reaction_id",
            "is_dryrun_eel_reencrypt_required",
            "last_decryption_failure",
            "bundle_id",
            "watermark_status",
            "created_on_device",
            "epoch_number",
            "is_saved",
            "is_viewed_by_user",
            "remote_media_count",
            "content_type",
            "content_read_release_policy",
            "released_by_count",
            "sender_id",
            "is_released_by_user",
            "release_state",
            "hidden_from_platform",
            "has_eel_re_encryption_requests",
            "replies_count",
            "post_open_viewing_policy",
        ];
        assert_eq!(names, expected);
    }

    #[test]
    fn a_create_table_spilling_onto_overflow_pages_is_read_whole() {
        // 512-byte pages and a 3 KB `CREATE TABLE`: the statement lives mostly on
        // overflow pages, and the last column's name must still be read.
        let content = std::fs::read("tests/fixtures/long_schema.sqlite").unwrap();
        let db = super::super::parse_header(&content).unwrap();
        let tables = read_schema(&content, &db);
        let long = tables.iter().find(|t| t.name == "long_one").unwrap();
        assert_eq!(long.columns.len(), 40);
        assert_eq!(long.columns[39], "column_number_039");
    }
}
