//! Identify-only database formats: LMDB, and SQLite's `-wal`, `-shm` and rollback
//! journal. (LevelDB and Realm have their own inspectors: `inspect::leveldb`,
//! `inspect::realm`.)
//!
//! Defines: [`Lmdb`], [`SqliteWal`], [`SqliteShm`], [`SqliteJournal`].
//! Used by: `identify` (re-export) → `inspect::mod` registry.
//! Uses: `identify::has_at`, the `classify_inspector!` macro.

use super::has_at;

// LMDB (`data.mdb`, also used by ObjectBox): the first meta page has the meta flag
// (0x08) in its page header, then the magic 0xBEEFC0DE and data version 1.
classify_inspector!(Lmdb, "lmdb", "database", [], |c: &[u8]| has_at(
    c,
    10,
    &[0x08, 0x00]
) && has_at(
    c,
    16,
    &[0xDE, 0xC0, 0xEF, 0xBE, 0x01, 0x00, 0x00, 0x00]
));

// SQLite write-ahead log: magic 0x377F0682 or 0x377F0683, then format version 3007000.
classify_inspector!(SqliteWal, "sqlite-wal", "database", [], |c: &[u8]| (has_at(
    c,
    0,
    &[0x37, 0x7F, 0x06, 0x82]
)
    || has_at(c, 0, &[0x37, 0x7F, 0x06, 0x83]))
    && has_at(c, 4, &[0x00, 0x2D, 0xE2, 0x18]));

// SQLite rollback journal (`-journal`): the 8-byte header magic of the SQLite file
// format. Not found in the test file systems (they use WAL); from the specification.
classify_inspector!(
    SqliteJournal,
    "sqlite-journal",
    "database",
    [],
    |c: &[u8]| { has_at(c, 0, &[0xD9, 0xD5, 0x05, 0xF9, 0x20, 0xA1, 0x63, 0xD7]) }
);

// SQLite shared-memory WAL index (`-shm`): the 48-byte header is written twice, each
// copy starting with the format version 3007000 (little-endian, as the host writes it).
// Both copies are checked. Seen on 839 files of an iPhone, all matching.
classify_inspector!(SqliteShm, "sqlite-shm", "database", [], |c: &[u8]| has_at(
    c,
    0,
    &[0x18, 0xE2, 0x2D, 0x00]
)
    && has_at(c, 48, &[0x18, 0xE2, 0x2D, 0x00]));

#[cfg(test)]
mod tests {
    use super::super::super::Inspector;
    use super::*;

    #[test]
    fn signatures_need_their_second_field() {
        let mut wal = vec![0x37, 0x7F, 0x06, 0x82, 0x00, 0x2D, 0xE2, 0x18];
        assert!(SqliteWal.detect(&wal));
        wal[7] = 0;
        assert!(!SqliteWal.detect(&wal));

        let mut mdb = vec![0u8; 24];
        mdb[10] = 0x08;
        mdb[16..24].copy_from_slice(&[0xDE, 0xC0, 0xEF, 0xBE, 1, 0, 0, 0]);
        assert!(Lmdb.detect(&mdb));
        mdb[10] = 0x01;
        assert!(!Lmdb.detect(&mdb));

        let mut shm = vec![0u8; 96];
        shm[..4].copy_from_slice(&[0x18, 0xE2, 0x2D, 0x00]);
        assert!(!SqliteShm.detect(&shm));
        shm[48..52].copy_from_slice(&[0x18, 0xE2, 0x2D, 0x00]);
        assert!(SqliteShm.detect(&shm));
    }
}
