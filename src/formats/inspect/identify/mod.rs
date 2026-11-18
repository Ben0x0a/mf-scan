//! Identify-only formats: recognised by a signature in the file, but
//! not inspected further. A match in such a file is reported as `[leveldb]`,
//! `[realm]`, … so the examiner knows what the file is and which tool to open it
//! with; the match's position inside it is not resolved. The exception is the text
//! formats (vCard, iCalendar, PEM), whose matches resolve to a line and column.
//!
//! Defines: one inspector per format, grouped by category, one file per category
//! (`database`, `archive`, `executable`, `document`, `structured`, `cache`, `text`,
//! `log`),
//! most built on the shared `classify_inspector!` macro. The structs are re-exported
//! here so `inspect::mod`'s registry lists them as `identify::Lmdb`, …
//! Used by: `inspect::mod` (registers the re-exported structs in `INSPECTORS`).
//!
//! WHY a fixed place at the start (or, for LevelDB tables, the last 8 bytes): those
//! are what `--type` reads on every source (`engine::type_from_ends`), so a file is
//! classified the same however it was read. And WHY no extensions: a name proves
//! nothing, and these formats all have a signature (see `docs/inspectors.md`).
//!
//! Each signature was checked on real Android and iOS file systems (Pixel 9a,
//! Samsung A53, iPhone 14 Plus): it matched only files of that format. The few
//! not found there (noted in each file) are the magic numbers of the format's own
//! specification.

mod archive;
mod cache;
mod database;
mod document;
mod executable;
mod log;
mod structured;
mod text;

pub(crate) use archive::{Aea, Bzip2, Gzip, Lz4, Lzfse, SevenZip, Tar, Xz, Zip, Zstd};
pub(crate) use cache::ChromiumCache;
pub(crate) use database::{Lmdb, SqliteJournal, SqliteShm, SqliteWal};
pub(crate) use document::{Ole, Pdf};
pub(crate) use executable::{Dex, Elf, Hermes, MachO};
pub(crate) use log::{Dsc, Tracev3};
pub(crate) use structured::{BinaryCookies, Bom};
pub(crate) use text::{Icalendar, Pem, Vcard};

/// `c[at..]` starts with `magic`.
fn has_at(c: &[u8], at: usize, magic: &[u8]) -> bool {
    c.get(at..at + magic.len()) == Some(magic)
}

/// `c` starts with `magic`, ignoring ASCII case and an optional UTF-8 byte-order
/// mark (for text formats whose keywords are case-insensitive).
fn starts_text(c: &[u8], magic: &[u8]) -> bool {
    let c = c.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(c);
    c.get(..magic.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(magic))
}

#[cfg(test)]
mod tests {
    use crate::formats::inspect::{detect_type, inspect};

    #[test]
    fn a_header_names_the_format_and_a_file_name_does_not() {
        // An LMDB meta page: flag 0x08 at 10, magic and version 1 at 16.
        let mut lmdb = vec![0u8; 32];
        lmdb[10] = 0x08;
        lmdb[16..24].copy_from_slice(&[0xDE, 0xC0, 0xEF, 0xBE, 1, 0, 0, 0]);

        let found = inspect("any/name", &lmdb, 20).expect("identified by header");
        assert_eq!(found.format, "lmdb");
        assert!(found.summary.is_empty());
        let info = detect_type("any/name", &lmdb).unwrap();
        assert_eq!((info.name, info.category), ("lmdb", "database"));

        // The name alone proves nothing.
        assert!(inspect("data.mdb", &[0u8; 32], 20).is_none());
        assert!(detect_type("data.mdb", &[0u8; 32]).is_none());
    }

    #[test]
    fn text_signatures_accept_case_and_a_byte_order_mark() {
        let info = detect_type("c", b"\xEF\xBB\xBFbegin:vcard\r\nVERSION:3.0").unwrap();
        assert_eq!(info.name, "vcard");
    }
}
