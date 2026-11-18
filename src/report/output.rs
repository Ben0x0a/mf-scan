//! Result formatting and writing (txt / json / csv).
//!
//! Defines: `OutputFormat`, `TxtStyle`, `write_results` (one line/object per match),
//! `write_counts` (one line per file, for `--count`), and `write_file_list` (one
//! line per file, for `--files-with-matches`), rendering to any `Write` sink in the
//! chosen format.
//! Used by: `cmd::run::grep` (picks the format from `--format`, the sink from
//! `--output`).
//!
//! Output rules: at most one line per match, and binary file content is never
//! raw-dumped. The matched line is shown only when it looks textual (see
//! `is_textual`); offsets in txt are hex (`0x…`). Richer per-format context is
//! opt-in via `--inspect` and appears as a labelled tag (txt) or `context`
//! (json/csv).
//! Uses: `crate::core::models::MatchRecord`, `serde`/`serde_json` (JSON), `csv` (CSV),
//! `anyhow` (errors).
//!
//! Why the format enum lives here and parses via `FromStr` (not clap's
//! `ValueEnum`): it keeps the library free of any CLI-framework dependency, so
//! the core can be reused without pulling in clap. `main.rs` wires it to the
//! flag.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::io::Write;
use std::str::FromStr;

use anyhow::{Context, Result};
use serde::Serialize;

use crate::core::models::{Encoding, MatchRecord, RunInfo};
use crate::core::stats::ScanStats;
use crate::core::util::UtcTime;
use crate::decrypt::DecryptionRecord;

// ANSI escapes for match highlighting: bold red on, all attributes off. Bytes
// are plain ASCII, so they splice into raw line bytes safely.
const COLOUR_ON: &[u8] = b"\x1b[1;31m";
const COLOUR_OFF: &[u8] = b"\x1b[0m";

/// Output format for results.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Txt,
    Json,
    Csv,
}

impl FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "txt" | "text" => Ok(Self::Txt),
            "json" => Ok(Self::Json),
            "csv" => Ok(Self::Csv),
            other => Err(format!(
                "unknown format '{other}' (expected txt, json, or csv)"
            )),
        }
    }
}

/// What a txt result line shows after its location.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxtStyle {
    /// `path:0x<offset>:<matched line>` — the default.
    Line,
    /// `path:0x<offset>:<matched text>` — `--only-matching`.
    OnlyMatching,
    /// Just the path — `--match-path`, where the file's path IS the match, so there
    /// is no in-file offset or line to show.
    PathOnly,
}

/// Write all `records` to `w` in `format`.
///
/// `colourise` and `style` apply only to the txt format; JSON/CSV are
/// machine-readable and never receive ANSI escapes.
///
/// `stats` is the run's coverage tally; JSON embeds it so the result file is
/// self-describing (txt/csv stay line-oriented and rely on the stderr summary
/// and the sidecar report instead).
pub fn write_results(
    records: &[MatchRecord],
    format: OutputFormat,
    colourise: bool,
    style: TxtStyle,
    run: &RunInfo,
    stats: &ScanStats,
    w: &mut dyn Write,
) -> Result<()> {
    match format {
        OutputFormat::Txt => write_txt(records, colourise, style, w),
        OutputFormat::Json => write_json(run, stats, records, w),
        OutputFormat::Csv => write_csv(records, w),
    }
}

// The matched line is shown only when it looks textual; for binary files the
// exact bytes remain recoverable from the offsets (and via the export step), so a
// display-oriented format never raw-dumps binary content.

/// Heuristic: does this line look like text rather than binary?
///
/// Binary if it contains a NUL or any C0 control byte other than the usual
/// whitespace (tab, LF, VT, FF, CR). High bytes (>= 0x80) are allowed as
/// possible UTF-8. A single stray control byte marks the line binary — which is
/// what suppresses content for SQLite, bplist, and other binary files.
fn is_textual(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .all(|&b| b >= 0x20 || matches!(b, b'\t' | b'\n' | 0x0b | 0x0c | b'\r'))
}

/// The matched line, lossily decoded, but only when textual (else `None`).
fn textual_line(r: &MatchRecord) -> Option<Cow<'_, str>> {
    is_textual(&r.line).then(|| String::from_utf8_lossy(&r.line))
}

/// Format a byte offset as `0x…` hex — how analysts read offsets, and used for
/// every offset in every machine-readable format (not just txt).
fn hex(n: u64) -> String {
    format!("0x{n:x}")
}

/// `skip_serializing_if` predicate: omit a `false` flag from JSON output.
fn is_false(b: &bool) -> bool {
    !*b
}

/// JSON projection: offsets are `0x…` hex strings; `archive` is the source's full
/// path; `line` appears only for textual matches; `format`/`context` only when
/// the match was inspected (`--inspect`); `bundle_id` only for iOS container matches.
#[derive(Serialize)]
struct JsonView<'a> {
    /// Full filesystem path of the source archive this result came from.
    #[serde(skip_serializing_if = "Option::is_none")]
    archive: Option<&'a str>,
    path: &'a str,
    file_start: String,
    file_offset: String,
    /// The match's line number, present only with `-n`.
    #[serde(skip_serializing_if = "Option::is_none")]
    line_number: Option<u64>,
    /// Absolute archive byte of the match; omitted for a loose file, a DEFLATE
    /// entry, or decrypted content (where no single archive byte exists).
    #[serde(skip_serializing_if = "Option::is_none")]
    archive_offset: Option<String>,
    /// True for DEFLATE entries, where `archive_offset` is the blob start.
    compressed: bool,
    /// True when found in decrypted content; offsets are within the plaintext and
    /// `archive_offset` is the entry's data start. Omitted when false.
    #[serde(skip_serializing_if = "is_false")]
    decrypted: bool,
    /// Encoding of the matched bytes; present only for non-plain matches (base64).
    #[serde(skip_serializing_if = "Option::is_none")]
    encoding: Option<&'a str>,
    /// The decoded value, present only for encoded (non-plain) matches.
    #[serde(skip_serializing_if = "Option::is_none")]
    decoded: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    format: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    context: Option<&'a serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    line: Option<Cow<'a, str>>,
    /// iOS app bundle ID — present only when the match is inside an iOS container
    /// whose metadata plist was found in the source.
    #[serde(skip_serializing_if = "Option::is_none")]
    bundle_id: Option<&'a str>,
    /// True when the match is in the file's path, not its content. Omitted when false.
    #[serde(skip_serializing_if = "is_false")]
    path_match: bool,
}

impl<'a> From<&'a MatchRecord> for JsonView<'a> {
    fn from(r: &'a MatchRecord) -> Self {
        Self {
            archive: r.archive_path.as_deref(),
            path: &r.path,
            file_start: hex(r.file_start),
            file_offset: hex(r.file_offset),
            line_number: r.line_number,
            archive_offset: r.archive_offset.map(hex),
            compressed: r.compressed,
            decrypted: r.decrypted,
            encoding: match r.encoding {
                Encoding::Plain => None,
                other => Some(other.as_str()),
            },
            decoded: r.decoded.as_deref(),
            format: r.inspection.as_ref().map(|i| i.format.as_str()),
            context: r.inspection.as_ref().map(|i| &i.detail),
            line: textual_line(r),
            bundle_id: r.bundle_id.as_deref(),
            path_match: r.path_match,
        }
    }
}

/// A complete JSON report: the run metadata, the coverage statistics, and the
/// result records. The CLI's JSON output uses this so the file is self-describing
/// (which archives/pattern/filters produced it, and what was scanned vs skipped).
#[derive(Serialize)]
struct JsonReport<'a> {
    run: &'a RunInfo,
    stats: &'a ScanStats,
    results: Vec<JsonView<'a>>,
}

/// The scan report written to the sidecar file: run metadata, coverage
/// statistics, the decryption audit trail, and — when the source was an encrypted
/// iOS backup — the backup-decryption record, with no result records (those go to
/// the main output). Always written so a run leaves a record of what it did and did
/// not look at — including which encrypted databases it decrypted (with key
/// provenance and ciphertext/plaintext hashes) or failed to, and whether a whole
/// backup was unlocked (and with a default password, which one).
#[derive(Serialize)]
struct ScanReport<'a> {
    run: &'a RunInfo,
    stats: &'a ScanStats,
    decryptions: &'a [DecryptionRecord],
    /// Backup-level decryption provenance; omitted when the source was not an
    /// encrypted backup, so existing reports are byte-for-byte unchanged.
    #[serde(skip_serializing_if = "Option::is_none")]
    backup: Option<&'a crate::platform::ios::backup::password::BackupRecord>,
}

/// Write the sidecar scan report (`{ run, stats, decryptions[, backup] }`) as
/// pretty JSON. `backup` is the encrypted-backup unlock record, or `None`.
pub fn write_scan_report(
    run: &RunInfo,
    stats: &ScanStats,
    decryptions: &[DecryptionRecord],
    backup: Option<&crate::platform::ios::backup::password::BackupRecord>,
    w: &mut dyn Write,
) -> Result<()> {
    let report = ScanReport {
        run,
        stats,
        decryptions,
        backup,
    };
    serde_json::to_writer_pretty(&mut *w, &report).context("failed writing scan report")?;
    writeln!(w).context("failed writing scan report")?;
    Ok(())
}

/// CSV projection: flat, fixed columns (so the column set never varies). Offsets
/// are `0x…` hex strings. `format`/`context` are empty unless inspected; `line`
/// is empty for binary.
#[derive(Serialize)]
struct CsvView<'a> {
    /// Source archive label (empty unless several archives were searched).
    archive: &'a str,
    path: &'a str,
    file_start: String,
    file_offset: String,
    /// Absolute archive byte of the match; empty for a loose file, a DEFLATE entry,
    /// or decrypted content (where no single archive byte exists).
    archive_offset: String,
    compressed: bool,
    /// True when found in decrypted content (offsets are within the plaintext).
    decrypted: bool,
    /// Always present: `plain` or `base64` (so the column set never varies).
    encoding: &'a str,
    /// The decoded value for encoded (non-plain) matches; empty otherwise.
    decoded: &'a str,
    format: &'a str,
    context: &'a str,
    line: Cow<'a, str>,
    /// The match's line number; empty unless `-n` was given.
    line_number: Option<u64>,
    /// True when the match is in the file's path, not its content.
    path_match: bool,
}

impl<'a> From<&'a MatchRecord> for CsvView<'a> {
    fn from(r: &'a MatchRecord) -> Self {
        Self {
            archive: r.archive.as_deref().unwrap_or(""),
            path: &r.path,
            file_start: hex(r.file_start),
            file_offset: hex(r.file_offset),
            archive_offset: r.archive_offset.map(hex).unwrap_or_default(),
            compressed: r.compressed,
            decrypted: r.decrypted,
            encoding: r.encoding.as_str(),
            decoded: r.decoded.as_deref().unwrap_or(""),
            format: r.inspection.as_ref().map_or("", |i| i.format.as_str()),
            context: r.inspection.as_ref().map_or("", |i| i.summary.as_str()),
            line: textual_line(r).unwrap_or(Cow::Borrowed("")),
            line_number: r.line_number,
            path_match: r.path_match,
        }
    }
}

/// txt: one line per match — `path:0x<file_offset>` plus, for textual files, the
/// matched line, plus a labelled `[format summary]` tag when inspected.
///
/// The offset is hex (`0x…`) to match how analysts read a hex editor. Binary
/// files contribute only `path:0x<offset>` — their bytes are never dumped.
fn write_txt(
    records: &[MatchRecord],
    colourise: bool,
    style: TxtStyle,
    w: &mut dyn Write,
) -> Result<()> {
    for r in records {
        // --match-path: the "match" is the file's path itself, so print just the
        // path (the source archive joined like a folder), highlighting the part
        // the pattern matched. No in-file offset — there is no content position.
        if style == TxtStyle::PathOnly || r.path_match {
            let out = match &r.archive {
                Some(a) => format!("{a}/{}", render_line(r, colourise)),
                None => render_line(r, colourise),
            };
            writeln!(w, "{out}").context("failed writing txt output")?;
            continue;
        }

        // Like grep -o, an empty match (`x*` between characters) shows nothing.
        let matched = &r.line[r.match_in_line.clone()];
        if style == TxtStyle::OnlyMatching && matched.is_empty() {
            continue;
        }

        // The source archive (when set) joins the internal path like a folder,
        // so a match reads as `case.zip/internal/file:0x<off>`.
        let mut out = match &r.archive {
            Some(a) => format!("{a}/{}", r.path),
            None => r.path.clone(),
        };
        // With -n the line number takes the place grep gives it, right after the path,
        // and the offset stays: the "where" is always present.
        if let Some(line) = r.line_number {
            out.push_str(&format!(":{line}"));
        }
        out.push_str(&format!(":0x{:x}", r.file_offset));
        // WHY --only-matching tests the match, not the line: a readable match inside
        // a binary line (a string in a SQLite page) is exactly what the flag is for,
        // and showing only those bytes cannot dump the binary around it.
        if style == TxtStyle::OnlyMatching {
            if is_textual(matched) {
                out.push(':');
                out.push_str(&render_match(matched, colourise));
                // The preview holds a match whole up to a cap; one the cap cut ends
                // right before the `…` marker, which is then shown too.
                if r.line[r.match_in_line.end..] == *crate::ops::search::ELLIPSIS {
                    out.push('…');
                }
            }
        } else if is_textual(&r.line) {
            out.push(':');
            out.push_str(&render_line(r, colourise));
        }
        // Mark a match found in decrypted content so the analyst knows the offset
        // is within the plaintext, not the archive on disk.
        if r.decrypted {
            out.push_str("  [decrypted]");
        }
        match &r.inspection {
            // Identified by its header, position not resolved: the format alone.
            Some(i) if i.summary.is_empty() => out.push_str(&format!("  [{}]", i.format)),
            Some(i) => out.push_str(&format!("  [{}  {}]", i.format, i.summary)),
            None => {}
        }
        // Flag an encoded hit (UTF-16, base64) and show what it decodes to, so the
        // analyst sees the value rather than the encoded bytes that matched.
        if r.encoding != Encoding::Plain {
            out.push_str(&format!(
                "  [{} → \"{}\"]",
                r.encoding.as_str(),
                r.decoded.as_deref().unwrap_or("")
            ));
        }
        // iOS container annotation: identify the owning app when known, so the
        // analyst immediately sees which app a hit belongs to without having to
        // look up the GUID separately.
        if let Some(id) = &r.bundle_id {
            out.push_str(&format!("  [app: {id}]"));
        }
        writeln!(w, "{out}").context("failed writing txt output")?;
    }
    Ok(())
}

/// One file in a `-l`/`-c` listing: its path, and what `--long` adds.
pub struct ListedFile {
    pub path: String,
    pub size: u64,
    /// Modification time (Unix seconds), when the source records one.
    pub mtime: Option<u64>,
    /// Matches per encoding, when other encodings than plain were searched and found
    /// (see `MatchedFile::encodings`); empty otherwise.
    pub encodings: Vec<(Encoding, usize)>,
}

impl ListedFile {
    /// The count per encoding as `plain 7, utf16le 5`; `None` when all are plain.
    fn encoding_counts(&self) -> Option<String> {
        (!self.encodings.is_empty()).then(|| {
            self.encodings
                .iter()
                .map(|(e, n)| format!("{} {n}", e.as_str()))
                .collect::<Vec<_>>()
                .join(", ")
        })
    }

    /// The `--long` prefix, as `find --long` prints it: type, size, modified (UTC).
    fn long_prefix(&self) -> String {
        let modified = self.modified_utc().unwrap_or_else(|| "-".to_string());
        format!("f\t{}\t{modified}\t", self.size)
    }

    fn modified_utc(&self) -> Option<String> {
        self.mtime.map(|m| UtcTime::from_unix(m).iso())
    }
}

/// One file of a `-l`/`-c` listing in JSON/CSV. `size`/`modified_utc` are present
/// only with `--long`, so a plain listing keeps its shape. `E` is how the count per
/// encoding is written: a map in JSON (as in the manifest), text in CSV (a CSV cell
/// cannot hold a map).
#[derive(Serialize)]
struct ListedView<'a, E> {
    path: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    modified_utc: Option<String>,
    /// With `-c`, the count per encoding when other encodings than plain were found.
    #[serde(skip_serializing_if = "Option::is_none")]
    encodings: Option<E>,
}

impl<'a, E> ListedView<'a, E> {
    fn new(file: &'a ListedFile, count: Option<usize>, long: bool, encodings: Option<E>) -> Self {
        Self {
            path: &file.path,
            count,
            size: long.then_some(file.size),
            modified_utc: if long { file.modified_utc() } else { None },
            encodings: count.and(encodings),
        }
    }
}

/// Write one `path:count` per file (txt), or a structured equivalent (json/csv).
/// With `long`, each line also gives the file's type, size and modified time.
pub fn write_counts(
    counts: &[(ListedFile, usize)],
    long: bool,
    format: OutputFormat,
    w: &mut dyn Write,
) -> Result<()> {
    write_listing(counts.iter().map(|(f, c)| (f, Some(*c))), long, format, w)
}

/// Write one path per file (txt), or a structured equivalent (json/csv). With
/// `long`, each line also gives the file's type, size and modified time.
pub fn write_file_list(
    files: &[ListedFile],
    long: bool,
    format: OutputFormat,
    w: &mut dyn Write,
) -> Result<()> {
    write_listing(files.iter().map(|f| (f, None)), long, format, w)
}

/// The shared body of [`write_counts`] and [`write_file_list`].
fn write_listing<'a>(
    files: impl Iterator<Item = (&'a ListedFile, Option<usize>)>,
    long: bool,
    format: OutputFormat,
    w: &mut dyn Write,
) -> Result<()> {
    match format {
        OutputFormat::Txt => {
            for (file, count) in files {
                let prefix = if long {
                    file.long_prefix()
                } else {
                    String::new()
                };
                match (count, file.encoding_counts()) {
                    (Some(count), Some(by)) => {
                        writeln!(w, "{prefix}{}:{count}  [{by}]", file.path)
                    }
                    (Some(count), None) => writeln!(w, "{prefix}{}:{count}", file.path),
                    (None, _) => writeln!(w, "{prefix}{}", file.path),
                }
                .context("failed writing the file list")?;
            }
            Ok(())
        }
        OutputFormat::Json => {
            let views: Vec<ListedView<BTreeMap<&str, usize>>> = files
                .map(|(file, count)| {
                    let by: Option<BTreeMap<&str, usize>> =
                        (!file.encodings.is_empty()).then(|| {
                            file.encodings
                                .iter()
                                .map(|(e, n)| (e.as_str(), *n))
                                .collect()
                        });
                    ListedView::new(file, count, long, by)
                })
                .collect();
            serde_json::to_writer_pretty(&mut *w, &views)
                .context("failed writing the file list")?;
            writeln!(w).context("failed writing the file list")?;
            Ok(())
        }
        OutputFormat::Csv => {
            let mut wtr = csv::Writer::from_writer(w);
            for (file, count) in files {
                wtr.serialize(ListedView::new(file, count, long, file.encoding_counts()))
                    .context("failed writing a file list row")?;
            }
            wtr.flush().context("failed flushing the file list")?;
            Ok(())
        }
    }
}

/// json: a single pretty-printed `{ run, stats, results }` object — the run
/// metadata (archives, pattern, filters), the coverage statistics, then one
/// object per match.
fn write_json(
    run: &RunInfo,
    stats: &ScanStats,
    records: &[MatchRecord],
    w: &mut dyn Write,
) -> Result<()> {
    let report = JsonReport {
        run,
        stats,
        results: records.iter().map(JsonView::from).collect(),
    };
    serde_json::to_writer_pretty(&mut *w, &report).context("failed writing JSON output")?;
    writeln!(w).context("failed writing JSON output")?;
    Ok(())
}

/// csv: header row plus one row per match.
fn write_csv(records: &[MatchRecord], w: &mut dyn Write) -> Result<()> {
    let mut wtr = csv::Writer::from_writer(w);
    for r in records {
        wtr.serialize(CsvView::from(r))
            .context("failed writing CSV row")?;
    }
    wtr.flush().context("failed flushing CSV output")?;
    Ok(())
}

/// Render just the matched bytes for display, optionally in colour.
fn render_match(matched: &[u8], colourise: bool) -> String {
    let text = String::from_utf8_lossy(matched);
    if colourise {
        // The escapes are plain ASCII constants, so this conversion cannot fail.
        let on = std::str::from_utf8(COLOUR_ON).unwrap_or_default();
        let off = std::str::from_utf8(COLOUR_OFF).unwrap_or_default();
        format!("{on}{text}{off}")
    } else {
        text.into_owned()
    }
}

/// Render a record's line for display, optionally wrapping the matched bytes in
/// colour escapes.
///
/// HOW: the escapes are spliced into the raw line bytes at the match boundaries
/// and the whole thing is lossily decoded once — decoding the three pieces
/// separately could introduce replacement characters at the seams.
fn render_line(r: &MatchRecord, colourise: bool) -> String {
    if !colourise {
        return String::from_utf8_lossy(&r.line).into_owned();
    }
    let m = &r.match_in_line;
    let mut buf = Vec::with_capacity(r.line.len() + COLOUR_ON.len() + COLOUR_OFF.len());
    buf.extend_from_slice(&r.line[..m.start]);
    buf.extend_from_slice(COLOUR_ON);
    buf.extend_from_slice(&r.line[m.start..m.end]);
    buf.extend_from_slice(COLOUR_OFF);
    buf.extend_from_slice(&r.line[m.end..]);
    String::from_utf8_lossy(&buf).into_owned()
}
