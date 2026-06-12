//! Operator-facing reporting and output plumbing.
//!
//! Defines: the stderr status surfaces (skip rules, the coverage summary, the
//! `--verify` integrity attestation), the sidecar scan-report writer, the SHA-256
//! helper, and the result [`emit`] sink (file or stdout).
//! Used by: `run::search` (all of it) and `run::export` (`sha256_hex`,
//! `report_verify`).
//! Uses: `mf_scan::{models, output, stats, decrypt}` and `crate::cli`.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};

use mf_scan::decrypt::DecryptionRecord;
use mf_scan::models::RunInfo;
use mf_scan::report::output::write_scan_report;
use mf_scan::report::stats::ScanStats;

use crate::cli::GrepArgs;

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
}

/// Print the end-of-run coverage summary to stderr.
///
/// Goes to stderr (like the verify/export status) so it never pollutes the
/// results on stdout. Shows the headline scanned/skipped figures, the per-rule
/// skip breakdown, the scanned-type breakdown, and bytes scanned vs total.
pub(crate) fn print_stats_summary(stats: &ScanStats) {
    eprintln!("── scan statistics ──────────────────────────────");
    eprintln!(
        "entries: {} ({} dir), files scanned: {}, skipped: {}",
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
    if !stats.scanned_by_type.is_empty() {
        let breakdown: Vec<String> = stats
            .scanned_by_type
            .iter()
            .map(|(name, count)| format!("{name} {count}"))
            .collect();
        eprintln!("scanned by type: {}", breakdown.join(", "));
    }
    eprintln!(
        "bytes scanned: {} / {} total (archive on disk: {})",
        human_bytes(stats.bytes_scanned),
        human_bytes(stats.bytes_total),
        human_bytes(stats.archive_bytes)
    );
    let secs = stats.elapsed.as_secs_f64();
    let rate = if secs > 0.0 {
        human_bytes((stats.bytes_scanned as f64 / secs) as u64)
    } else {
        human_bytes(stats.bytes_scanned)
    };
    eprintln!("elapsed: {secs:.2}s ({rate}/s scanned)");
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
/// The location is `--report` if set, else `<output>.report.json` beside `-o`,
/// else `mf-scan-report.json` in the current directory. The path is printed to
/// stderr (like the export report) so the operator knows where the record landed.
pub(crate) fn write_scan_report_if_enabled(
    cli: &GrepArgs,
    run: &RunInfo,
    stats: &ScanStats,
    decryptions: &[DecryptionRecord],
) -> Result<()> {
    if cli.no_report {
        return Ok(());
    }
    let path = scan_report_path(cli);
    let file = File::create(&path)
        .with_context(|| format!("cannot create scan report {}", path.display()))?;
    let mut w = BufWriter::new(file);
    write_scan_report(run, stats, decryptions, &mut w)?;
    w.flush().context("failed flushing scan report")?;
    eprintln!("scan report -> {}", path.display());
    Ok(())
}

/// Resolve the scan report path from `--report`, the `-o` output, or the default.
fn scan_report_path(cli: &GrepArgs) -> PathBuf {
    if let Some(path) = &cli.report {
        return path.clone();
    }
    if let Some(output) = &cli.output {
        // Sit beside the output file: `<output>.report.json` (keeps any extension
        // so `results.json` → `results.json.report.json`, unambiguously paired).
        let mut name = output.file_name().unwrap_or_default().to_os_string();
        name.push(".report.json");
        return output.with_file_name(name);
    }
    PathBuf::from("mf-scan-report.json")
}

/// SHA-256 of `bytes` as lowercase hex (single definition in the library).
pub(crate) use mf_scan::util::sha256_hex;

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

/// Run `render` against the chosen sink: a file when `-o` was given, else
/// stdout. Shared by the match output and the `--count` output.
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
            render(&mut w)
        }
    }
}
