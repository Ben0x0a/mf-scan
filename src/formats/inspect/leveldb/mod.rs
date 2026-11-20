//! LevelDB inspector: map a byte offset in a LevelDB log, manifest or table to the
//! record or block, and the entry, it falls in.
//!
//! Defines: [`Leveldb`] (the inspector), `masked_crc` (the check logs and tables
//! share), and `TABLE_MAGIC`.
//! Used by: `inspect::mod` (registered in `INSPECTORS`).
//! Uses: `log` (logs and manifests), `table` (tables, decompressed by `snappy`),
//! `crate::formats::inspect::HEAD_LEN`, `crate::core::models::Inspection`.
//!
//! ── Detection ────────────────────────────────────────────────────────────────
//! - logs and manifests have no magic, but start with a log record whose masked
//!   CRC-32C covers it (checked within the first [`HEAD_LEN`] bytes);
//! - table files (`.ldb`, `.sst`) end with a footer whose last 8 bytes are the table
//!   magic 0xDB4775248B80FB57.
//!
//! WHY one module per format: logs and tables share only the checksum and the key
//! layout; each is read on its own terms, and Snappy only by tables.

mod log;
mod snappy;
mod table;

use crate::core::models::Inspection;
use crate::formats::inspect::HEAD_LEN;

/// The table footer's magic, little-endian, as the file's last 8 bytes.
const TABLE_MAGIC: [u8; 8] = [0x57, 0xFB, 0x80, 0x8B, 0x24, 0x75, 0x47, 0xDB];

/// LevelDB inspector (see the module doc).
pub struct Leveldb;

impl super::Inspector for Leveldb {
    fn name(&self) -> &'static str {
        "leveldb"
    }
    fn category(&self) -> &'static str {
        "database"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &[]
    }
    fn detect(&self, content: &[u8]) -> bool {
        first_log_record_checks(content)
    }
    fn detect_tail(&self, tail: &[u8]) -> bool {
        tail == TABLE_MAGIC
    }
    fn has_tail_signature(&self) -> bool {
        true
    }
    fn inspect(&self, content: &[u8], offset: usize) -> Option<Inspection> {
        self.inspect_many(content, &[offset]).pop().flatten()
    }
    /// The file is read once (a log's records decoded, a table's blocks listed);
    /// each match is then a lookup.
    fn inspect_many(&self, content: &[u8], offsets: &[usize]) -> Vec<Option<Inspection>> {
        if content.ends_with(&TABLE_MAGIC)
            && let Some(table) = table::Table::read(content)
        {
            return table.locate_many(content, offsets);
        }
        let log = log::read(content);
        offsets.iter().map(|&o| log::locate(&log, o)).collect()
    }
}

/// The first record of a LevelDB log: a 7-byte header (masked CRC-32C, length,
/// type "full") whose CRC matches the type byte and payload that follow. A "first"
/// fragment at offset 0 always fills its 32 KiB block, so it can never be checked
/// within [`HEAD_LEN`]: only a "full" record is accepted.
///
/// WHY only the first [`HEAD_LEN`] bytes, even when more are given: `--type` sees no
/// more than that on some sources, and a file must be named the same however it is
/// read. A log whose first record is longer (a large first write) is not named.
fn first_log_record_checks(c: &[u8]) -> bool {
    let c = &c[..c.len().min(HEAD_LEN)];
    let Some(&[c0, c1, c2, c3, l0, l1, kind]) = c.first_chunk::<7>() else {
        return false;
    };
    let len = usize::from(u16::from_le_bytes([l0, l1]));
    if kind != 1 || len == 0 {
        return false;
    }
    let Some(record) = c.get(6..7 + len) else {
        return false;
    };
    masked_crc(record) == u32::from_le_bytes([c0, c1, c2, c3])
}

/// The masked CRC-32C LevelDB stores with each log record and table block:
/// rotated so that a CRC of data holding CRCs is not itself a likely one.
pub(super) fn masked_crc(bytes: &[u8]) -> u32 {
    crc32c(bytes).rotate_right(15).wrapping_add(0xA282_EAD8)
}

/// CRC-32C (Castagnoli), as LevelDB uses, by a 256-entry table: the check may run
/// on any unnamed file's first record while classifying, so it is kept cheap.
fn crc32c(bytes: &[u8]) -> u32 {
    !bytes.iter().fold(!0u32, |crc, &b| {
        CRC32C_TABLE[usize::from((crc as u8) ^ b)] ^ (crc >> 8)
    })
}

/// The CRC-32C byte table (reflected polynomial 0x82F63B78), built at compile time.
const CRC32C_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0x82F6_3B78
            } else {
                crc >> 1
            };
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
};

#[cfg(test)]
pub(super) mod testing {
    /// Where `needle` first is in `f`.
    pub(crate) fn at(f: &[u8], needle: &[u8]) -> usize {
        f.windows(needle.len()).position(|w| w == needle).unwrap()
    }

    /// `n` as a varint.
    pub(crate) fn varint_bytes(mut n: usize) -> Vec<u8> {
        let mut out = Vec::new();
        while n >= 0x80 {
            out.push((n as u8) | 0x80);
            n >>= 7;
        }
        out.push(n as u8);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::inspect::Inspector;

    #[test]
    fn crc32c_matches_the_standard_check_value() {
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
    }
    #[test]
    fn leveldb_table_is_known_by_its_footer_magic() {
        let mut table = vec![0x00, 0x1E, 0x00, 0x49];
        table.extend_from_slice(&[0u8; 40]);
        table.extend_from_slice(&TABLE_MAGIC);
        assert!(!Leveldb.detect(&table));
        let info = crate::formats::inspect::detect_type("x", &table).unwrap();
        assert_eq!(info.name, "leveldb");
        // In two steps: the start alone says nothing; the end names it.
        use crate::formats::inspect::{end_types, type_from_end, type_from_start};
        assert!(type_from_start("x", &table[..8]).unwrap_err().is_none());
        assert_eq!(type_from_end(&TABLE_MAGIC).unwrap().name, "leveldb");
        assert!(end_types().any(|t| t.name == "leveldb"));
        // A footer whose handles point nowhere: named, its data blocks not located.
        let found = crate::formats::inspect::inspect("000005.ldb", &table, 1).unwrap();
        assert_eq!(
            (found.format.as_str(), found.summary.as_str()),
            (
                "leveldb",
                "data blocks, not located: the index block does not decode"
            )
        );
    }
}
