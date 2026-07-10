//! Table-leaf cell + record decoding, and typed column values.
//!
//! Defines: a parsed [`Cell`] / [`Col`] ([`parse_cell`]), the serial-type helpers
//! ([`serial_type_name`], [`is_blob`]), the raw column decoders ([`col_text`],
//! [`col_int`]), and the lossless [`Value`] a row reader projects to
//! ([`col_value`]).
//! Used by: the sibling `schema` / `table` submodules and, via the `sqlite`
//! module's re-exports, the SQLite inspector (display + offset resolution).
//! Uses: [`super::page::Db`] and `std`.

use super::page::Db;

/// One column slot within a parsed record: its serial type and byte span.
pub(crate) struct Col {
    pub(crate) serial: u64,
    pub(crate) start: usize, // absolute file offset of the value bytes
    pub(crate) len: usize,
}

/// A parsed table-leaf cell.
pub(crate) struct Cell {
    pub(crate) rowid: u64,
    pub(crate) total_len: usize, // bytes occupied by the whole cell within the page
    pub(crate) columns: Vec<Col>,
}

/// Parse a table-leaf cell at `cell_file`.
///
/// All offset and length arithmetic uses `checked_add` (and `checked_sub` for
/// `max_local`).  The lengths derive from untrusted varints in the database
/// file: in debug builds unchecked `usize` addition wraps and panics; in
/// release builds it wraps silently and the subsequent `content.get(…)` slice
/// is bounds-checked — but debug/release parity matters for a forensic tool
/// that may be run in either mode.  Returning `None` on overflow lets the
/// caller fall back to the page+offset summary, consistent with the
/// lenient-parser contract.
pub(crate) fn parse_cell(content: &[u8], db: &Db, cell_file: usize) -> Option<Cell> {
    let (payload_len, n1) = varint(content, cell_file)?;
    let after_payload = cell_file.checked_add(n1)?;
    let (rowid, n2) = varint(content, after_payload)?;
    let record_start = after_payload.checked_add(n2)?;
    let payload = payload_len as usize;

    // Local payload size (the rest, if any, lives on overflow pages — which are
    // separate pages, so a match on *this* page is always within local bytes).
    let usable = db.usable;
    let max_local = usable.checked_sub(35)?;
    let local = if payload <= max_local {
        payload
    } else {
        let min_local = (usable.checked_sub(12)? * 32 / 255).checked_sub(23)?;
        let excess = payload.checked_sub(min_local)?;
        let divisor = usable.checked_sub(4)?;
        let k = min_local.checked_add(excess % divisor)?;
        if k <= max_local { k } else { min_local }
    };
    let overflow = payload > local;
    let total_len = n1
        .checked_add(n2)?
        .checked_add(local)?
        .checked_add(if overflow { 4 } else { 0 })?;

    // Record header: a varint header length, then one serial type per column.
    let (header_len, h1) = varint(content, record_start)?;
    let header_end = record_start.checked_add(header_len as usize)?;
    let mut p = record_start.checked_add(h1)?;
    let mut body = header_end;
    let mut columns = Vec::new();
    while p < header_end {
        let (serial, sn) = varint(content, p)?;
        p = p.checked_add(sn)?;
        let len = serial_len(serial);
        columns.push(Col {
            serial,
            start: body,
            len,
        });
        body = body.checked_add(len)?;
    }

    Some(Cell {
        rowid,
        total_len,
        columns,
    })
}

/// SQLite storage-class name for a record serial type (for a `column [TYPE]` label).
pub(crate) fn serial_type_name(serial: u64) -> &'static str {
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
pub(crate) fn is_blob(serial: u64) -> bool {
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

/// Decode a TEXT column value (lossily) when the slot holds text.
pub(crate) fn col_text(content: &[u8], col: Option<&Col>) -> Option<String> {
    let c = col?;
    if c.serial >= 13 && c.serial % 2 == 1 {
        let bytes = content.get(c.start..c.start + c.len)?;
        Some(String::from_utf8_lossy(bytes).into_owned())
    } else {
        None
    }
}

/// Decode an INTEGER column value when the slot holds one.
pub(crate) fn col_int(content: &[u8], col: Option<&Col>) -> Option<i64> {
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

/// One decoded cell value, across all five SQLite storage classes.
///
/// WHY a typed enum rather than a display string: programmatic callers (e.g. the
/// backup `Manifest.db` reader) need the raw BLOB bytes and integers at full
/// fidelity — a display rendering would truncate text and strip control
/// characters, corrupting either. This is the lossless counterpart used by
/// [`super::table::read_table`]; display formatting is the consumer's concern.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Value {
    Null,
    Int(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
}

/// Decode a parsed column slot losslessly into a typed [`Value`].
///
/// Integers, reals, text and blobs come back as their exact stored values — no
/// truncation, no control-byte stripping. A serial-0 slot (which SQLite also uses
/// for an INTEGER PRIMARY KEY aliasing the rowid) decodes to [`Value::Null`];
/// callers needing the rowid read it separately.
pub(super) fn col_value(content: &[u8], col: &Col) -> Value {
    match col.serial {
        0 => Value::Null,
        8 => Value::Int(0),
        9 => Value::Int(1),
        1..=6 => col_int(content, Some(col)).map_or(Value::Null, Value::Int),
        7 => content
            .get(col.start..col.start + 8)
            .and_then(|b| <[u8; 8]>::try_from(b).ok())
            .map_or(Value::Null, |a| Value::Real(f64::from_be_bytes(a))),
        s if s >= 13 && s % 2 == 1 => {
            let bytes = content.get(col.start..col.start + col.len).unwrap_or(&[]);
            Value::Text(String::from_utf8_lossy(bytes).into_owned())
        }
        s if s >= 12 && s.is_multiple_of(2) => {
            // Even serial ≥ 12 is a BLOB of (serial-12)/2 bytes — the raw bytes,
            // taken verbatim (an embedded archive must not be altered).
            let bytes = content.get(col.start..col.start + col.len).unwrap_or(&[]);
            Value::Blob(bytes.to_vec())
        }
        _ => Value::Null, // 10, 11 reserved
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
