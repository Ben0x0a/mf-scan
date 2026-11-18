//! SEGB inspector: map a byte offset in an Apple SEGB file (the segment files of
//! Biome streams on iOS and macOS) to the entry it falls in.
//!
//! Defines: [`Segb`] (the inspector).
//! Used by: `inspect::mod` (registered in `INSPECTORS`).
//! Uses: `crate::core::models::Inspection`, `crate::core::util::UtcTime`,
//! `crc32fast` (entry checksums), `serde_json`, and the inspector registry again for
//! an entry's own data (usually protobuf).
//!
//! ── Format ───────────────────────────────────────────────────────────────────
//! Layouts as documented by CCL Forensics' `ccl-segb` reader (MIT licence). All
//! numbers are little-endian; times are Cocoa seconds (since 2001-01-01 UTC).
//!
//! **Version 2** (iOS 17 and later): "SEGB" at offset 0 and an entry count (i32) at 4,
//! in a 32-byte header. The trailer, at the end of the file, holds one 16-byte record
//! per entry: end offset (i32, counted from the end of the header), state (i32: 1
//! written, 3 deleted, 4 skipped as the reference reader does; other values are
//! unused slots) and time (f64). Entries
//! follow the header in end-offset order, each an 8-byte entry header (CRC-32 of the
//! data, then an unknown i32) and the data, aligned to 4 bytes. Two trailer records
//! may share an end offset (one region, written then deleted).
//!
//! **Version 1** (iOS 16 and earlier): a 56-byte header with "SEGB" at offset 52 and
//! the end of the records (u32, from the file start) at offset 0. Each record is a
//! 32-byte header (data length i32, state i32, two f64 times, CRC-32 of the data
//! u32, unknown i32) and the data, aligned to 8 bytes.
//!
//! WHY these layouts are trusted: version 2 was checked on 528 real files from three
//! iPhone file systems, where every one of 224,480 written entries had a matching
//! CRC-32 with this walk, the 16 state-4 records seen skipped as above (had one
//! covered data, the entry after it would have failed its CRC). Deleted entries were
//! not CRC-checked there. No version 1 file was available, so version 1 follows the
//! reference reader only. The CRC result is shown for every entry, whatever its
//! state, so a wrong reading shows up as mismatches rather than passing silently; a
//! mismatch on a deleted entry may also mean its bytes were cleared.

use std::cell::OnceCell;
use std::collections::BTreeMap;
use std::ops::Range;

use serde_json::json;

use crate::core::models::Inspection;
use crate::core::util::UtcTime;

const MAGIC: &[u8; 4] = b"SEGB";
const V2_HEADER: usize = 32;
const V2_ENTRY_HEADER: usize = 8;
const V2_TRAILER_RECORD: usize = 16;
const V1_HEADER: usize = 56;
const V1_RECORD_HEADER: usize = 32;
/// Seconds from the Unix epoch to the Cocoa epoch (2001-01-01T00:00:00Z).
const COCOA_EPOCH: f64 = 978_307_200.0;

/// SEGB inspector — recognised by its header (see the module doc).
pub struct Segb;

impl super::Inspector for Segb {
    fn name(&self) -> &'static str {
        "segb"
    }
    fn category(&self) -> &'static str {
        "structured"
    }
    /// None: Biome segment files are named by number, with no extension.
    fn extensions(&self) -> &'static [&'static str] {
        &[]
    }
    fn detect(&self, content: &[u8]) -> bool {
        version(content).is_some()
    }
    fn inspect(&self, content: &[u8], offset: usize) -> Option<Inspection> {
        self.inspect_many(content, &[offset]).pop().flatten()
    }
    /// The file is walked once; each entry holding matches has its CRC checked and
    /// its data described once, all its matches resolved together.
    fn inspect_many(&self, content: &[u8], offsets: &[usize]) -> Vec<Option<Inspection>> {
        let Some(layout) = read(content) else {
            return offsets.iter().map(|_| None).collect();
        };
        let crcs: Vec<OnceCell<bool>> = layout.entries.iter().map(|_| OnceCell::new()).collect();
        let mut results = Vec::with_capacity(offsets.len());
        // Matches in an entry's data, grouped by entry: (result index, offset in data).
        let mut in_data: BTreeMap<usize, Vec<(usize, usize)>> = BTreeMap::new();
        for (i, &offset) in offsets.iter().enumerate() {
            let (found, data_hit) = locate(content, &layout, &crcs, offset);
            if let Some((entry, rel)) = data_hit {
                in_data.entry(entry).or_default().push((i, rel));
            }
            results.push(found);
        }
        // The entry's data is usually a protobuf message, which has no signature: the
        // registry by signature first, then by structure (a hint, as for a BLOB).
        for (entry, hits) in in_data {
            let data = &content[layout.entries[entry].data.clone()];
            let rels: Vec<usize> = hits.iter().map(|&(_, rel)| rel).collect();
            let notes = super::describe_nested_many(data, "data", &rels);
            for ((i, _), note) in hits.into_iter().zip(notes) {
                if let (Some(note), Some(Some(found))) = (note, results.get_mut(i)) {
                    note.apply(found);
                }
            }
        }
        results
    }
}

/// One state change recorded for an entry.
#[derive(Debug)]
struct Mark {
    state: i32,
    time: f64,
    /// Version 1 records carry a second time, of unknown meaning.
    time2: Option<f64>,
}

/// One entry's bytes and what the file records about it.
#[derive(Debug)]
struct Entry {
    /// 1-based, in file order.
    number: usize,
    /// The entry (v2) or record (v1) header.
    header: Range<usize>,
    data: Range<usize>,
    /// The CRC-32 recorded for the data; checked only for an entry holding a match.
    crc: u32,
    marks: Vec<Mark>,
}

/// A parsed SEGB file.
#[derive(Debug)]
struct Layout {
    version: u8,
    header: Range<usize>,
    entries: Vec<Entry>,
    /// Version 2 only.
    trailer: Option<Range<usize>>,
}

fn i32_at(c: &[u8], at: usize) -> Option<i32> {
    Some(i32::from_le_bytes(c.get(at..at + 4)?.try_into().ok()?))
}

fn u32_at(c: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(c.get(at..at + 4)?.try_into().ok()?))
}

fn f64_at(c: &[u8], at: usize) -> Option<f64> {
    Some(f64::from_le_bytes(c.get(at..at + 8)?.try_into().ok()?))
}

/// The SEGB version of `c`, from its header alone: the magic plus a non-negative
/// entry count (v2) or an end offset past the header (v1).
///
/// WHY not also "fits the file": detection may see only the first 4 KiB (`--type`
/// on a ranged source), where a large file's trailer or end offset lies beyond the
/// bytes given. The reader checks the fit against the whole file.
fn version(c: &[u8]) -> Option<u8> {
    if c.len() >= V2_HEADER && c.starts_with(MAGIC) && i32_at(c, 4)? >= 0 {
        return Some(2);
    }
    if c.len() >= V1_HEADER && &c[52..56] == MAGIC && u32_at(c, 0)? as usize >= V1_HEADER {
        return Some(1);
    }
    None
}

fn read(c: &[u8]) -> Option<Layout> {
    match version(c)? {
        2 => read_v2(c),
        _ => read_v1(c),
    }
}

/// Walk a version 2 file as the reference reader does (see the module doc).
fn read_v2(c: &[u8]) -> Option<Layout> {
    let count = usize::try_from(i32_at(c, 4)?).ok()?;
    let trailer_start = c
        .len()
        .checked_sub(count.checked_mul(V2_TRAILER_RECORD)?)
        .filter(|&t| t >= V2_HEADER)?;
    let mut slots = Vec::with_capacity(count);
    for k in 0..count {
        let at = trailer_start + k * V2_TRAILER_RECORD;
        let (end, state, time) = (i32_at(c, at)?, i32_at(c, at + 4)?, f64_at(c, at + 8)?);
        // WHY: other states are zeroed, unused slots that point at no data.
        if matches!(state, 1 | 3 | 4) {
            slots.push((end, state, time));
        }
    }
    // Stable, so records sharing an end offset keep their trailer order.
    slots.sort_by_key(|&(end, _, _)| end);

    let mut entries: Vec<Entry> = Vec::new();
    let mut pos = V2_HEADER;
    for (end, state, time) in slots {
        if state == 4 {
            continue; // an empty record: no data
        }
        let mark = Mark {
            state,
            time,
            time2: None,
        };
        let Some(stop) = usize::try_from(end).ok().map(|e| e + V2_HEADER) else {
            continue;
        };
        if let Some(last) = entries.last_mut()
            && last.data.end == stop
        {
            last.marks.push(mark);
            continue;
        }
        // WHY: a stale record can point inside data already read; its own bytes
        // are gone, so it is skipped, as the reference reader does.
        if stop < pos + V2_ENTRY_HEADER {
            continue;
        }
        if stop > trailer_start {
            break; // points past the entries: not this layout
        }
        let data = pos + V2_ENTRY_HEADER..stop;
        entries.push(Entry {
            number: entries.len() + 1,
            header: pos..pos + V2_ENTRY_HEADER,
            crc: u32_at(c, pos)?,
            data,
            marks: vec![mark],
        });
        pos = stop.next_multiple_of(4);
    }
    Some(Layout {
        version: 2,
        header: 0..V2_HEADER,
        entries,
        trailer: (count > 0).then_some(trailer_start..c.len()),
    })
}

/// Walk a version 1 file as the reference reader does (see the module doc).
fn read_v1(c: &[u8]) -> Option<Layout> {
    let end = usize::try_from(u32_at(c, 0)?).ok()?;
    if end > c.len() {
        return None;
    }
    let mut entries = Vec::new();
    let mut pos = V1_HEADER;
    while pos < end {
        let (Some(len), Some(state), Some(time), Some(time2), Some(crc)) = (
            i32_at(c, pos),
            i32_at(c, pos + 4),
            f64_at(c, pos + 8),
            f64_at(c, pos + 16),
            u32_at(c, pos + 24),
        ) else {
            break;
        };
        let start = pos + V1_RECORD_HEADER;
        let Some(stop) = usize::try_from(len).ok().map(|l| start + l) else {
            break;
        };
        if stop > c.len() {
            break;
        }
        entries.push(Entry {
            number: entries.len() + 1,
            header: pos..start,
            data: start..stop,
            crc,
            marks: vec![Mark {
                state,
                time,
                time2: Some(time2),
            }],
        });
        pos = stop.next_multiple_of(8);
    }
    Some(Layout {
        version: 1,
        header: 0..V1_HEADER,
        entries,
        trailer: None,
    })
}

fn state_name(state: i32) -> String {
    match state {
        1 => "written".into(),
        3 => "deleted".into(),
        other => format!("state {other}"),
    }
}

/// A Cocoa time as ISO 8601 UTC (whole seconds), or the raw number when it is not
/// a plausible time.
fn time_text(cocoa: f64) -> String {
    let unix = cocoa + COCOA_EPOCH;
    if unix.is_finite() && (0.0..=u64::MAX as f64).contains(&unix) {
        UtcTime::from_unix(unix as u64).iso()
    } else {
        cocoa.to_string()
    }
}

/// Resolve `offset`, and say which entry's data it falls in (index, offset in the
/// data) so the caller can describe that data once for all its matches. `crcs`
/// caches each entry's CRC check.
fn locate(
    c: &[u8],
    layout: &Layout,
    crcs: &[OnceCell<bool>],
    offset: usize,
) -> (Option<Inspection>, Option<(usize, usize)>) {
    if offset >= c.len() {
        return (None, None);
    }
    let v = layout.version;
    let plain = |part: String, detail: serde_json::Value| Inspection {
        format: "segb".into(),
        summary: format!("SEGB v{v}  {part}"),
        detail,
    };
    if layout.header.contains(&offset) {
        let found = plain(
            "file header".into(),
            json!({ "version": v, "part": "header" }),
        );
        return (Some(found), None);
    }
    if let Some(trailer) = &layout.trailer
        && trailer.contains(&offset)
    {
        let record = (offset - trailer.start) / V2_TRAILER_RECORD + 1;
        let found = plain(
            format!("trailer record {record}"),
            json!({ "version": v, "part": "trailer", "trailer_record": record }),
        );
        return (Some(found), None);
    }
    // Entries are in file order: the first that ends after `offset` is the only one
    // that can hold it.
    let index = layout.entries.partition_point(|e| e.data.end <= offset);
    let Some(entry) = layout
        .entries
        .get(index)
        .filter(|e| e.header.start <= offset)
    else {
        let found = plain(
            "outside any entry".into(),
            json!({ "version": v, "part": "unused" }),
        );
        return (Some(found), None);
    };
    let crc_ok = *crcs[index].get_or_init(|| crc32fast::hash(&c[entry.data.clone()]) == entry.crc);

    let marks: Vec<String> = entry
        .marks
        .iter()
        .map(|m| format!("{} {}", state_name(m.state), time_text(m.time)))
        .collect();
    let mut summary = format!("SEGB v{v}  entry {}: {}", entry.number, marks.join(", "));
    // Marks in trailer order (the on-disk evidence), not re-sorted by their times.
    summary.push_str(if crc_ok { "  crc ok" } else { "  crc mismatch" });
    let mut detail = json!({
        "version": v,
        "entry": entry.number,
        "states": entry.marks.iter().map(|m| state_name(m.state)).collect::<Vec<_>>(),
        "times": entry.marks.iter().map(|m| time_text(m.time)).collect::<Vec<_>>(),
        "crc_ok": crc_ok,
    });
    if let Some(time2) = entry.marks[0].time2
        && let Some(obj) = detail.as_object_mut()
    {
        obj.insert("time2".into(), json!(time_text(time2)));
    }

    if offset < entry.data.start {
        summary.push_str("  (entry header)");
    } else if let Some(obj) = detail.as_object_mut() {
        obj.insert("data_offset".into(), json!(offset - entry.data.start));
    }
    let data_hit = (offset >= entry.data.start).then(|| (index, offset - entry.data.start));
    let found = Inspection {
        format: "segb".into(),
        summary,
        detail,
    };
    (Some(found), data_hit)
}

#[cfg(test)]
mod tests {
    use super::super::Inspector;
    use super::*;

    /// A protobuf message: field 1, string `value`.
    fn message(value: &[u8]) -> Vec<u8> {
        let mut m = vec![0x0a, value.len() as u8];
        m.extend_from_slice(value);
        m
    }

    /// `(data, trailer records)`, each record `(state, cocoa time)`.
    type TestEntry<'a> = (&'a [u8], &'a [(i32, f64)]);

    /// Build a version 2 file from entries; `extra` trailer slots are appended as
    /// given. The entries' trailer records are written in reverse entry order (each
    /// entry's own records kept in order), as on disk they are not sorted.
    fn v2(entries: &[TestEntry<'_>], extra: &[(i32, i32, f64)]) -> Vec<u8> {
        let mut body = Vec::new();
        let mut groups = Vec::new();
        for (data, records) in entries {
            body.extend_from_slice(&crc32fast::hash(data).to_le_bytes());
            body.extend_from_slice(&0i32.to_le_bytes());
            body.extend_from_slice(data);
            let end = body.len() as i32;
            groups.push(
                records
                    .iter()
                    .map(|&(st, t)| (end, st, t))
                    .collect::<Vec<_>>(),
            );
            body.resize(body.len().next_multiple_of(4), 0);
        }
        let mut slots: Vec<(i32, i32, f64)> = groups.into_iter().rev().flatten().collect();
        slots.extend_from_slice(extra);
        let mut f = MAGIC.to_vec();
        f.extend_from_slice(&(slots.len() as i32).to_le_bytes());
        f.extend_from_slice(&0f64.to_le_bytes());
        f.extend_from_slice(&[0; 16]);
        f.extend_from_slice(&body);
        for (end, state, time) in &slots {
            f.extend_from_slice(&end.to_le_bytes());
            f.extend_from_slice(&state.to_le_bytes());
            f.extend_from_slice(&time.to_le_bytes());
        }
        f
    }

    /// Build a version 1 file from `(data, state, time)` records.
    fn v1(records: &[(&[u8], i32, f64)]) -> Vec<u8> {
        let mut f = vec![0; V1_HEADER];
        f[52..56].copy_from_slice(MAGIC);
        for (data, state, time) in records {
            f.extend_from_slice(&(data.len() as i32).to_le_bytes());
            f.extend_from_slice(&state.to_le_bytes());
            f.extend_from_slice(&time.to_le_bytes());
            f.extend_from_slice(&(time + 1.0).to_le_bytes());
            f.extend_from_slice(&crc32fast::hash(data).to_le_bytes());
            f.extend_from_slice(&0i32.to_le_bytes());
            f.extend_from_slice(data);
            f.resize(f.len().next_multiple_of(8), 0);
        }
        let end = f.len() as u32;
        f[0..4].copy_from_slice(&end.to_le_bytes());
        f
    }

    fn at(f: &[u8], needle: &[u8]) -> usize {
        f.windows(needle.len()).position(|w| w == needle).unwrap()
    }

    // 2024-01-01T00:00:00Z in Cocoa seconds.
    const T: f64 = 725_760_000.0;

    #[test]
    fn version_2_entries_resolve_with_state_time_and_crc() {
        let first = message(b"first entry");
        let second = message(b"second entry text");
        let f = v2(&[(&first, &[(1, T)]), (&second, &[(1, T + 60.0)])], &[]);
        assert!(Segb.detect(&f));

        let hit = Segb.inspect(&f, at(&f, b"second")).unwrap();
        assert_eq!(hit.format, "segb");
        assert!(
            hit.summary.starts_with(
                "SEGB v2  entry 2: written 2024-01-01T00:01:00Z  crc ok  data: protobuf (by structure)"
            ),
            "{}",
            hit.summary
        );
        assert_eq!(hit.detail["entry"], 2);
        assert_eq!(hit.detail["data_detection"], "structure");
        assert_eq!(hit.detail["data_context"]["path"], "1");
    }

    #[test]
    fn version_2_skips_empty_and_unused_slots_and_merges_shared_ends() {
        let data = message(b"was here");
        // Written then deleted (same end offset), plus a state-4 and a zeroed slot.
        let f = v2(
            &[(&data, &[(1, T), (3, T + 5.0)])],
            &[(0, 4, T), (0, 0, 0.0)],
        );
        let hit = Segb.inspect(&f, at(&f, b"was here")).unwrap();
        assert!(
            hit.summary.starts_with(
                "SEGB v2  entry 1: written 2024-01-01T00:00:00Z, deleted 2024-01-01T00:00:05Z  crc ok"
            ),
            "{}",
            hit.summary
        );
    }

    #[test]
    fn version_2_reports_header_trailer_and_a_changed_entry() {
        let mut f = v2(&[(&message(b"payload"), &[(1, T)])], &[]);
        assert!(
            Segb.inspect(&f, 2)
                .unwrap()
                .summary
                .ends_with("file header")
        );
        let last = f.len() - 1;
        assert!(
            Segb.inspect(&f, last)
                .unwrap()
                .summary
                .ends_with("trailer record 1")
        );
        let p = at(&f, b"payload");
        f[p] = b'P';
        let hit = Segb.inspect(&f, p).unwrap();
        assert!(hit.summary.contains("crc mismatch"), "{}", hit.summary);
        assert_eq!(hit.detail["crc_ok"], false);
    }

    #[test]
    fn version_1_records_resolve_with_8_byte_alignment() {
        let a = message(b"odd");
        let b = message(b"next record");
        let f = v1(&[(&a, 1, T), (&b, 3, T + 120.0)]);
        assert!(Segb.detect(&f));

        let hit = Segb.inspect(&f, at(&f, b"next")).unwrap();
        assert!(
            hit.summary.starts_with(
                "SEGB v1  entry 2: deleted 2024-01-01T00:02:00Z  crc ok  data: protobuf"
            ),
            "{}",
            hit.summary
        );
        assert_eq!(hit.detail["time2"], "2024-01-01T00:02:01Z");
        let header = Segb.inspect(&f, at(&f, b"next") - 10).unwrap();
        assert!(
            header.summary.ends_with("(entry header)"),
            "{}",
            header.summary
        );
    }

    #[test]
    fn detection_needs_only_the_start_of_the_file() {
        // 300 entries: the trailer lies far past the first 4 KiB.
        let data = message(b"x");
        let many: Vec<TestEntry<'_>> = (0..300).map(|_| (&data[..], &[(1, T)][..])).collect();
        let f = v2(&many, &[]);
        assert!(f.len() > 4096);
        assert!(Segb.detect(&f[..4096]));
        assert!(Segb.detect(&f));
    }

    #[test]
    fn marks_keep_their_trailer_order() {
        let data = message(b"kept");
        // Deleted recorded first in the trailer, with an earlier (zero) time.
        let f = v2(&[(&data, &[(3, 0.0), (1, T)])], &[]);
        let hit = Segb.inspect(&f, at(&f, b"kept")).unwrap();
        assert_eq!(hit.detail["states"], json!(["deleted", "written"]));
    }

    #[test]
    fn headers_that_do_not_fit_the_file_are_not_read() {
        // v2 magic with a count whose trailer would not fit, and v1 magic with an end
        // offset past the file: named SEGB by the header, but not walked.
        let mut f = MAGIC.to_vec();
        f.extend_from_slice(&1000i32.to_le_bytes());
        f.resize(64, 0);
        let mut g = vec![0; 64];
        g[52..56].copy_from_slice(MAGIC);
        g[0..4].copy_from_slice(&1000u32.to_le_bytes());
        for file in [&f, &g] {
            assert!(Segb.detect(file));
            assert!(Segb.inspect(file, 40).is_none());
            let found = crate::formats::inspect::inspect("x", file, 40).unwrap();
            assert_eq!(
                (found.format.as_str(), found.summary.as_str()),
                ("segb", "")
            );
        }
        // A negative count is not SEGB.
        f[4..8].copy_from_slice(&(-1i32).to_le_bytes());
        assert!(!Segb.detect(&f));
    }

    #[test]
    fn corrupt_offsets_never_panic() {
        // Every byte of a valid file overwritten in turn: parsing must not panic.
        let f = v2(
            &[
                (&message(b"abc"), &[(1, T)]),
                (&message(b"defgh"), &[(3, T)]),
            ],
            &[],
        );
        for i in 0..f.len() {
            for b in [0x00, 0x7f, 0xff] {
                let mut g = f.clone();
                g[i] = b;
                let _ = Segb.inspect_many(&g, &[0, i, g.len() - 1]);
            }
        }
        let f = v1(&[(&message(b"abc"), 1, T)]);
        for i in 0..f.len() {
            let mut g = f.clone();
            g[i] = 0xff;
            let _ = Segb.inspect_many(&g, &[0, i]);
        }
    }
}
