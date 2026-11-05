//! Operator-facing reporting and output plumbing.
//!
//! Defines: the stderr status surfaces (skip rules, the coverage summary, the
//! `--verify` integrity attestation), the sidecar scan-report writer, the SHA-256
//! helper, and the result [`emit`] sink (file or stdout).
//! Used by: `run::search` (all of it) and `run::export` (`sha256_hex`,
//! `report_verify`).
//! Uses: `mf_scan::{models, output, stats, decrypt}` and `crate::cmd::cli`.

use std::fs::File;
use std::io::{BufWriter, ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::{Context, Result};

use mf_scan::core::models::RunInfo;
use mf_scan::core::util::UtcTime;
use mf_scan::decrypt::DecryptionRecord;
use mf_scan::report::output::write_scan_report;
use mf_scan::report::stats::ScanStats;

use crate::cmd::cli::GrepArgs;

/// Print the active skip rules to stderr before the search begins.
///
/// WHY up front: `--fast` and presets can exclude whole subtrees of an
/// acquisition; surfacing the rules first means the analyst is never surprised by
/// silently missing data. Goes to stderr so it never mixes with results on stdout.
pub(crate) fn log_skip_rules(run: &RunInfo) {
    if !run.path_globs.is_empty() {
        eprintln!(
            "filter: --path includes only: {}",
            run.path_globs.join(", ")
        );
    }
    if !run.not_path_globs.is_empty() {
        eprintln!(
            "filter: skipping {} path glob(s): {}",
            run.not_path_globs.len(),
            run.not_path_globs.join(", ")
        );
    }
    if !run.types.is_empty() {
        eprintln!("filter: --type allows only: {}", run.types.join(", "));
    }
    if run.exclude_media {
        eprintln!("filter: excluding media files (image/video/audio)");
    }
    if run.loose_files_skipped > 0 {
        eprintln!(
            "⚠ -r searches archives only: {} loose file(s) NOT searched (use --dir-mode to search them)",
            run.loose_files_skipped
        );
    }
}

/// Print the end-of-run coverage summary to stderr.
///
/// Goes to stderr (like the verify/export status) so it never pollutes the
/// results on stdout. Shows the headline scanned/skipped figures, the per-rule
/// skip breakdown, the scanned-type breakdown, and bytes scanned vs total.
pub(crate) fn print_stats_summary(stats: &ScanStats, match_path: bool) {
    eprintln!("── scan statistics ──────────────────────────────");
    // --match-path reads no content, so it must not claim to have scanned any.
    let scanned_label = if match_path {
        "paths checked"
    } else {
        "files scanned"
    };
    eprintln!(
        "entries: {} ({} dir), {scanned_label}: {}, skipped: {}",
        stats.total_entries, stats.directories, stats.files_scanned, stats.files_skipped
    );
    eprintln!(
        "matches: {} in {} file(s)",
        stats.total_matches, stats.files_with_matches
    );
    if stats.skipped_not_included.count > 0 {
        eprintln!(
            "  skipped (not in --path): {} file(s), {}",
            stats.skipped_not_included.count,
            human_bytes(stats.skipped_not_included.bytes)
        );
    }
    if stats.skipped_media.count > 0 {
        eprintln!(
            "  skipped (media): {} file(s), {}",
            stats.skipped_media.count,
            human_bytes(stats.skipped_media.bytes)
        );
    }
    if stats.skipped_type.count > 0 {
        eprintln!(
            "  skipped (--type): {} file(s), {}",
            stats.skipped_type.count,
            human_bytes(stats.skipped_type.bytes)
        );
    }
    for tally in &stats.skipped_not_path {
        eprintln!(
            "  skipped ({}): {} file(s), {}",
            tally.glob,
            tally.count,
            human_bytes(tally.bytes)
        );
    }
    print_coverage_gaps(stats);
    if !stats.scanned_by_type.is_empty() {
        let breakdown: Vec<String> = stats
            .scanned_by_type
            .iter()
            .map(|(name, count)| format!("{name} {count}"))
            .collect();
        eprintln!("scanned by type: {}", breakdown.join(", "));
    }
    let secs = stats.elapsed.as_secs_f64();
    if match_path {
        eprintln!("elapsed: {secs:.2}s");
        return;
    }
    eprintln!(
        "bytes scanned: {} / {} total (archive on disk: {})",
        human_bytes(stats.bytes_scanned),
        human_bytes(stats.bytes_total),
        human_bytes(stats.archive_bytes)
    );
    let rate = if secs > 0.0 {
        human_bytes((stats.bytes_scanned as f64 / secs) as u64)
    } else {
        human_bytes(stats.bytes_scanned)
    };
    eprintln!("elapsed: {secs:.2}s ({rate}/s scanned)");
}

/// Print what a run selected but could not fully search, if anything.
///
/// WHY separate from the summary: `--no-stats` silences the summary, but these lines
/// mean the results are incomplete, so they are printed either way. Rules the operator
/// chose (filters, `--fast`) are not gaps and are announced up front instead.
pub(crate) fn print_coverage_gaps(stats: &ScanStats) {
    if stats.files_truncated > 0 {
        eprintln!(
            "  match list truncated after {} match(es) in {} file(s) — more matches exist",
            mf_scan::ops::search::MAX_HITS_PER_FILE,
            stats.files_truncated
        );
    }
    if stats.unreadable.count > 0 {
        eprintln!(
            "  unreadable (read failed, NOT searched): {} file(s), {}",
            stats.unreadable.count,
            human_bytes(stats.unreadable.bytes)
        );
    }
    if stats.decrypt_failed.count > 0 {
        eprintln!(
            "  decryption failed (ciphertext NOT searched): {} file(s), {}",
            stats.decrypt_failed.count,
            human_bytes(stats.decrypt_failed.bytes)
        );
    }
}

/// Format a byte count as a human-readable size (1024-based), e.g. `1.5 MiB`.
fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// Write the scan report sidecar unless `--no-report` was given.
///
/// The location is `--report` if set, else a timestamped name beside `--output`, else
/// a timestamped name in the current directory (see [`default_report_path`]). The
/// path is printed to stderr (like the export report) so the operator knows where the
/// record landed.
///
/// WHY a failure is only a warning unless `--report` was given: the search has
/// finished and its results are already out, so an unwritable current directory (a
/// read-only evidence mount) must not turn a good run into a failed one. A path the
/// operator asked for by name is different — they are relying on that record — so
/// failing to write it stays an error.
pub(crate) fn write_scan_report_if_enabled(
    cli: &GrepArgs,
    run: &RunInfo,
    stats: &ScanStats,
    decryptions: &[DecryptionRecord],
    backup: Option<&mf_scan::platform::ios::backup::password::BackupRecord>,
) -> Result<()> {
    if cli.no_report {
        return Ok(());
    }
    let written = create_report_file(cli).and_then(|(file, path)| {
        let mut w = BufWriter::new(file);
        write_scan_report(run, stats, decryptions, backup, &mut w)?;
        w.flush().context("failed flushing scan report")?;
        Ok(path)
    });
    match written {
        Ok(path) => eprintln!("scan report -> {}", path.display()),
        Err(err) if cli.report.is_some() => return Err(err),
        Err(err) => eprintln!(
            "⚠ scan report NOT written, so this run's coverage record is not saved: {err:#} \
             (choose a location with --report FILE)"
        ),
    }
    Ok(())
}

/// Open the scan report file for writing.
///
/// A path given with `--report` is the operator's own choice and is overwritten, like
/// `--output`. A default name is never overwritten: it carries the run's UTC time, and
/// `create_new` plus a numeric suffix keeps two runs in the same second apart, even
/// when they race.
fn create_report_file(cli: &GrepArgs) -> Result<(File, PathBuf)> {
    if let Some(path) = &cli.report {
        let file = File::create(path)
            .with_context(|| format!("cannot create scan report {}", path.display()))?;
        return Ok((file, path.clone()));
    }
    let stamp = utc_stamp(SystemTime::now());
    for attempt in 1u32.. {
        let path = default_report_path(cli.output.as_deref(), &stamp, attempt);
        match File::options().write(true).create_new(true).open(&path) {
            Ok(file) => return Ok((file, path)),
            Err(err) if err.kind() == ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("cannot create scan report {}", path.display()));
            }
        }
    }
    unreachable!("the attempt counter is unbounded, so the loop only exits by returning")
}

/// The default report name for one run: `<output>.<stamp>.report.json` beside
/// `--output` (keeping the output's whole name, so the two stay visibly paired), else
/// `mf-scan-report-<stamp>.json` in the current directory. `attempt` above 1 adds a
/// `-<attempt>` suffix to the stamp.
fn default_report_path(output: Option<&Path>, stamp: &str, attempt: u32) -> PathBuf {
    let stamp = if attempt > 1 {
        format!("{stamp}-{attempt}")
    } else {
        stamp.to_string()
    };
    match output {
        Some(output) => {
            let mut name = output.file_name().unwrap_or_default().to_os_string();
            name.push(format!(".{stamp}.report.json"));
            output.with_file_name(name)
        }
        None => PathBuf::from(format!("mf-scan-report-{stamp}.json")),
    }
}

/// `time` as a compact UTC stamp, e.g. `20261105T181403Z`. A time before the Unix
/// epoch (a badly wrong system clock) renders as the epoch.
///
/// WHY UTC: it keeps evidence records from different machines comparable.
fn utc_stamp(time: SystemTime) -> String {
    let secs = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    UtcTime::from_unix(secs).compact()
}

/// SHA-256 of `bytes` as lowercase hex (single definition in the library).
pub(crate) use mf_scan::core::util::sha256_hex;

/// Print the before/after archive hashes and whether the evidence was unchanged.
///
/// mf-scan opens the archive read-only and never writes to it, so the hashes
/// match by construction; this records that fact as an attestation. Goes to
/// stderr so it never mixes with results on stdout.
pub(crate) fn report_verify(before: &str, after: &str) {
    eprintln!("verify: archive sha256 before  {before}");
    eprintln!("verify: archive sha256 after   {after}");
    if before == after {
        eprintln!("verify: archive unchanged during the run (read-only integrity confirmed)");
    } else {
        eprintln!("verify: WARNING — archive changed during the run");
    }
}

/// Whether any cause in `err`'s chain is a closed pipe.
fn is_broken_pipe(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == ErrorKind::BrokenPipe)
    })
}

/// Run `render` against the chosen sink: a file when `--output` was given, else
/// stdout. Shared by the match output and the `--count` output.
///
/// WHY a closed stdout is not an error: `mf-scan grep … | head` closing the pipe is
/// the reader saying it has seen enough, not a failed run. The run carries on, so the
/// coverage summary and the scan report are still produced.
pub(crate) fn emit(
    output: Option<&std::path::Path>,
    render: impl FnOnce(&mut dyn Write) -> Result<()>,
) -> Result<()> {
    match output {
        Some(path) => {
            let file =
                File::create(path).with_context(|| format!("cannot create {}", path.display()))?;
            let mut w = BufWriter::new(file);
            render(&mut w)?;
            w.flush().context("failed flushing output file")
        }
        None => {
            let stdout = std::io::stdout();
            let mut w = stdout.lock();
            match render(&mut w) {
                Err(err) if is_broken_pipe(&err) => Ok(()),
                result => result,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_stamp_is_compact_utc() {
        let time = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(951_782_400);
        assert_eq!(utc_stamp(time), "20000229T000000Z");
    }

    #[test]
    fn default_report_names_carry_the_stamp() {
        let stamp = "20261105T181403Z";
        assert_eq!(
            default_report_path(None, stamp, 1),
            PathBuf::from("mf-scan-report-20261105T181403Z.json")
        );
        assert_eq!(
            default_report_path(None, stamp, 2),
            PathBuf::from("mf-scan-report-20261105T181403Z-2.json")
        );
        assert_eq!(
            default_report_path(Some(Path::new("out/hits.json")), stamp, 1),
            PathBuf::from("out/hits.json.20261105T181403Z.report.json")
        );
    }

    #[test]
    fn broken_pipe_is_recognised_through_context() {
        let pipe = std::io::Error::from(ErrorKind::BrokenPipe);
        assert!(is_broken_pipe(
            &anyhow::Error::new(pipe).context("failed writing")
        ));
        let denied = std::io::Error::from(ErrorKind::PermissionDenied);
        assert!(!is_broken_pipe(
            &anyhow::Error::new(denied).context("failed writing")
        ));
    }
}
