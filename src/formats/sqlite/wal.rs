//! Write-ahead log replay: fold a `-wal` sidecar into the database image.
//!
//! Defines: [`checkpoint`], which applies a WAL's committed frames onto a copy of
//! the main database file and returns the resulting image — the state SQLite
//! itself would read.
//! Used by: `formats::sqlite`'s consumers that are handed both files (see
//! `ios::references`), via the `sqlite` module's re-exports.
//! Uses: only `std`.
//!
//! ── Why this is not optional for a forensic read ────────────────────────────
//! A database captured live is routinely mid-WAL: rows written since the last
//! checkpoint exist ONLY in the sidecar. Reading the main file alone silently
//! returns a stale image. Measured on a real iPhone FFS acquisition's
//! MobileContainerManager database: the main file held 1077 code-signing records,
//! the WAL added 12 more and superseded 8 — including replacing an "Unsigned
//! Placeholder" stub for an installed messaging app with its real record and its
//! App Group. Reporting that as "no groups" would have dropped a shared container
//! full of evidence from an export.
//!
//! ── Format (SQLite file format §4) ──────────────────────────────────────────
//! ```text
//! 32-byte WAL header: magic, format, page size, checkpoint seq, salt1, salt2,
//!                     checksum1, checksum2
//! then repeated: 24-byte frame header (page no, db size after commit, salt1,
//!                salt2, checksum1, checksum2) + one page of data
//! ```
//! A frame belongs to the current WAL generation only if its salts match the
//! header's; a page's LAST such frame wins. `db size after commit` is non-zero
//! only on a commit frame, and frames after the final commit are uncommitted and
//! must be ignored — they are a transaction that never landed.
//!
//! The rolling checksum covers the frame header's first 8 bytes plus the page
//! data, seeded from the previous frame's checksum (the WAL header's, for the
//! first frame). Byte order comes from the magic's low bit. A frame whose
//! checksum does not verify ends the valid run — that is how SQLite finds the end
//! of the log, and how a truncated or torn capture is handled here too.
//!
//! Degrade-don't-die: a malformed or unreadable WAL yields `None`, and the caller
//! reads the main database alone rather than failing.

/// WAL header magic; the low bit selects the checksum byte order.
const WAL_MAGIC_LE: u32 = 0x377f_0682;
const WAL_MAGIC_BE: u32 = 0x377f_0683;

const WAL_HEADER_LEN: usize = 32;
const FRAME_HEADER_LEN: usize = 24;

/// Apply `wal`'s committed frames onto `main`, returning the checkpointed image.
///
/// Returns `None` when the WAL is absent-in-effect (not a WAL, unreadable header,
/// mismatched page size, or no committed frame), so the caller keeps using `main`.
pub(crate) fn checkpoint(main: &[u8], wal: &[u8]) -> Option<Vec<u8>> {
    let header = wal.get(..WAL_HEADER_LEN)?;
    let magic = be32(header, 0)?;
    let big_endian_checksums = match magic {
        WAL_MAGIC_LE => false,
        WAL_MAGIC_BE => true,
        _ => return None,
    };
    let page_size = be32(header, 8)? as usize;
    // A page size that is not a sane power of two would make every frame offset
    // meaningless; refuse rather than read at wild offsets.
    if !(512..=65536).contains(&page_size) || !page_size.is_power_of_two() {
        return None;
    }
    let salt1 = be32(header, 16)?;
    let salt2 = be32(header, 20)?;

    // Seed the rolling checksum from the header's own checksum fields.
    let mut running = (be32(header, 24)?, be32(header, 28)?);

    // Collect the winning frame for each page, but only up to the LAST commit —
    // hence the two-stage `pending`/`committed` split below.
    let mut committed: Vec<(u32, usize)> = Vec::new(); // (page no, frame data offset)
    let mut pending: Vec<(u32, usize)> = Vec::new();
    let mut db_pages_after_commit: Option<u32> = None;

    let frame_len = FRAME_HEADER_LEN + page_size;
    let mut off = WAL_HEADER_LEN;
    while off + frame_len <= wal.len() {
        let page_no = be32(wal, off)?;
        let db_size = be32(wal, off + 4)?;
        let (fs1, fs2) = (be32(wal, off + 8)?, be32(wal, off + 12)?);
        let (fc1, fc2) = (be32(wal, off + 16)?, be32(wal, off + 20)?);

        // A salt mismatch means this frame belongs to a previous WAL generation
        // that was overwritten in place — everything from here on is stale.
        if fs1 != salt1 || fs2 != salt2 {
            break;
        }

        // Verify the rolling checksum over the frame header's first 8 bytes and
        // the page data. A mismatch is the documented end-of-log marker.
        let mut sum = running;
        sum = accumulate(sum, &wal[off..off + 8], big_endian_checksums)?;
        sum = accumulate(
            sum,
            &wal[off + FRAME_HEADER_LEN..off + frame_len],
            big_endian_checksums,
        )?;
        if sum != (fc1, fc2) {
            break;
        }
        running = sum;

        pending.push((page_no, off + FRAME_HEADER_LEN));
        // A non-zero db size marks a commit: everything up to here is durable.
        if db_size != 0 {
            committed.append(&mut pending);
            db_pages_after_commit = Some(db_size);
            pending.clear();
        }
        off += frame_len;
    }

    // Nothing committed means the WAL adds nothing readable.
    let db_pages = db_pages_after_commit?;
    if committed.is_empty() {
        return None;
    }

    // The committed database is exactly `db_pages` pages long — a checkpoint can
    // shrink the file (after a VACUUM) as well as grow it.
    let mut image = vec![0u8; (db_pages as usize).checked_mul(page_size)?];
    let copy = image.len().min(main.len());
    image[..copy].copy_from_slice(&main[..copy]);

    // Apply in order so a page written several times ends on its last version.
    for (page_no, data_off) in committed {
        let start = (page_no as usize).checked_sub(1)?.checked_mul(page_size)?;
        let end = start.checked_add(page_size)?;
        // A frame for a page beyond the committed size is not part of this image.
        if end > image.len() {
            continue;
        }
        image[start..end].copy_from_slice(wal.get(data_off..data_off + page_size)?);
    }
    Some(image)
}

/// Fold `bytes` (a multiple of 8 bytes long) into the rolling WAL checksum.
///
/// The algorithm is SQLite's: walk 32-bit words in pairs, `s0 += x[i] + s1` then
/// `s1 += x[i+1] + s0`, with wrapping arithmetic.
fn accumulate(seed: (u32, u32), bytes: &[u8], big_endian: bool) -> Option<(u32, u32)> {
    if !bytes.len().is_multiple_of(8) {
        return None;
    }
    let (mut s0, mut s1) = seed;
    for chunk in bytes.as_chunks::<8>().0 {
        let raw = |a: &[u8]| -> u32 {
            let w: [u8; 4] = a.try_into().unwrap_or([0; 4]);
            if big_endian {
                u32::from_be_bytes(w)
            } else {
                u32::from_le_bytes(w)
            }
        };
        s0 = s0.wrapping_add(raw(&chunk[0..4]).wrapping_add(s1));
        s1 = s1.wrapping_add(raw(&chunk[4..8]).wrapping_add(s0));
    }
    Some((s0, s1))
}

/// Read a big-endian `u32` at `off` (every WAL header/frame field is big-endian).
fn be32(bytes: &[u8], off: usize) -> Option<u32> {
    let raw: [u8; 4] = bytes.get(off..off.checked_add(4)?)?.try_into().ok()?;
    Some(u32::from_be_bytes(raw))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::sqlite::read_table;

    /// The committed fixture pair is a real WAL captured mid-write: the main file
    /// alone reports the OLD row, and only replaying the log reveals the new one.
    /// (Generated by `tests/fixtures/README.md`'s recipe — synthetic data.)
    #[test]
    fn replay_reveals_rows_only_present_in_the_log() {
        let main = std::fs::read("tests/fixtures/wal_main.sqlite3").unwrap();
        let wal = std::fs::read("tests/fixtures/wal_main.sqlite3-wal").unwrap();

        // Before replay: the pre-WAL state.
        let before = read_table(&main, "t", &["v"]).unwrap();
        assert_eq!(before.len(), 1);

        let image = checkpoint(&main, &wal).expect("WAL replays");
        let after = read_table(&image, "t", &["v"]).unwrap();
        assert!(
            after.len() > before.len(),
            "replay must surface the logged rows: {before:?} -> {after:?}"
        );
    }

    /// A buffer that is not a WAL leaves the caller on the main database.
    #[test]
    fn non_wal_declines() {
        assert!(checkpoint(b"main", b"not a write-ahead log at all....").is_none());
    }

    /// A WAL header with no frames commits nothing.
    #[test]
    fn header_without_frames_declines() {
        let mut header = vec![0u8; WAL_HEADER_LEN];
        header[..4].copy_from_slice(&WAL_MAGIC_LE.to_be_bytes());
        header[8..12].copy_from_slice(&4096u32.to_be_bytes());
        assert!(checkpoint(b"main", &header).is_none());
    }

    /// A truncated frame is not read past the end of the buffer.
    #[test]
    fn truncated_frame_is_ignored() {
        let mut wal = vec![0u8; WAL_HEADER_LEN];
        wal[..4].copy_from_slice(&WAL_MAGIC_LE.to_be_bytes());
        wal[8..12].copy_from_slice(&4096u32.to_be_bytes());
        wal.extend_from_slice(&[0u8; 10]); // half a frame header
        assert!(checkpoint(b"main", &wal).is_none());
    }
}
