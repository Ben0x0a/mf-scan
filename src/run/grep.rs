//! The `grep` subcommand orchestration.
//!
//! Defines: [`run_grep`], which wires the parsed CLI arguments through preset
//! application, query building, source resolution, decryption setup, the search
//! itself, and result/report output.
//! Used by: `run` (dispatched from `main`).
//! Uses: the `mf_scan` library plus the `crate::support::{sources, presets,
//! decryption, progress, reporting, exporting}` modules — each owning one concern.

use std::io::IsTerminal;
use std::path::Path;
use std::time::Instant;

use anyhow::{Context, Result};
use regex::bytes::RegexBuilder;

use mf_scan::decrypt::DecryptionRecord;
use mf_scan::engine::Query;
use mf_scan::filter::EntryFilter;
use mf_scan::inspect::{is_known_type, type_names};
use mf_scan::models::RunInfo;
use mf_scan::preset::fast::FAST_EXCLUDE_GLOBS;
use mf_scan::report::output::{OutputFormat, write_counts, write_results};
use mf_scan::report::stats::ScanStats;
use mf_scan::search;
use mf_scan::source::Source;
use mf_scan::source::folder::FolderSource;
use mf_scan::source::zip::ZipSource;

use crate::cli::{ColourWhen, GrepArgs};
use crate::support::decryption::{build_decryption_context, report_decryptions};
use crate::support::exporting::export_if_requested;
use crate::support::presets::{apply_preset, load_named_preset};
use crate::support::progress::search_with_reporter;
use crate::support::reporting::{
    emit, log_skip_rules, print_stats_summary, report_verify, sha256_hex,
    write_scan_report_if_enabled,
};
use crate::support::sources::{ResolvedKind, ResolvedSource, open_archive, resolve_sources};

/// Run the `grep` subcommand.
pub(crate) fn run_grep(mut cli: GrepArgs) -> Result<()> {
    // -E is a no-op: our regex flavour is already extended. Consume the field
    // so it counts as read while documenting that acceptance is deliberate.
    let _ = cli.extended_regexp;

    // Apply named preset first so CLI flags can override it.
    if let Some(name) = cli.preset.clone() {
        let preset =
            load_named_preset(&name).with_context(|| format!("failed to load preset '{name}'"))?;
        apply_preset(&mut cli, &preset);
    }

    // --fast loads _fast.yml; falls back to compiled-in behaviour if the file
    // is absent (e.g. dev build without the presets folder copied in).
    if cli.fast {
        match load_named_preset("_fast") {
            Ok(preset) => apply_preset(&mut cli, &preset),
            Err(_) => {
                cli.filter
                    .not_path
                    .extend(FAST_EXCLUDE_GLOBS.iter().map(|s| s.to_string()));
                cli.filter.exclude_media = true;
            }
        }
    }

    // -l means "match this exact text", so escape any regex metacharacters.
    let pattern = if cli.literal_string {
        regex::escape(&cli.pattern)
    } else {
        cli.pattern.clone()
    };
    let re = RegexBuilder::new(&pattern)
        .case_insensitive(cli.ignore_case)
        .build()
        .context("invalid regular expression")?;

    // --base64 also searches for the pattern's base64 encoding. Only a literal
    // can be encoded (a regex has no byte form), and a path is not base64, so the
    // mode requires -l and is incompatible with --match-path.
    let base64_enabled = cli.base64 || cli.base64_urlsafe;
    let base64_re = if base64_enabled {
        if !cli.literal_string {
            anyhow::bail!(
                "--base64 requires -l/--literal-string (a regex cannot be base64-encoded)"
            );
        }
        if cli.match_path {
            anyhow::bail!("--base64 cannot be combined with --match-path (a path is not base64)");
        }
        let frags = search::base64::fragments(cli.pattern.as_bytes(), cli.base64_urlsafe);
        if frags.is_empty() {
            anyhow::bail!("pattern is too short to search as base64; give a longer literal");
        }
        if frags.iter().map(String::len).min().unwrap_or(0) < 4 {
            eprintln!(
                "warning: base64 fragments are very short; base64 matches may be unreliable for such a short term"
            );
        }
        // Alternation of the (already alphabet-correct) fragments. Base64 is
        // case-sensitive, so this regex never takes the -i flag even if set.
        let alt = frags
            .iter()
            .map(|f| regex::escape(f))
            .collect::<Vec<_>>()
            .join("|");
        Some(
            RegexBuilder::new(&alt)
                .build()
                .context("failed to build base64 search pattern")?,
        )
    } else {
        None
    };
    let query = Query {
        plain: &re,
        base64: base64_re.as_ref(),
        decoded: base64_enabled.then_some(cli.pattern.as_str()),
    };

    // Colour is meaningful only for txt sent to a terminal; never inject ANSI
    // into a file or a machine-readable format.
    let to_stdout = cli.output.is_none();
    let colourise = to_stdout
        && cli.format == OutputFormat::Txt
        && match cli.colour {
            ColourWhen::Always => true,
            ColourWhen::Never => false,
            ColourWhen::Auto => std::io::stdout().is_terminal(),
        };

    if let Some(n) = cli.threads {
        rayon::ThreadPoolBuilder::new()
            .num_threads(n)
            .build_global()
            .context("failed to configure thread pool")?;
    }

    // Resolve the operands into sources (archive files and/or folders), each with a
    // display label, applying --dir-mode to any directory operand.
    let sources = resolve_sources(&cli.archives, cli.dir_mode, cli.recursive)?;
    if sources.is_empty() {
        anyhow::bail!(
            "no sources given — list archive files or directories (with --dir-mode for a directory)"
        );
    }
    let multi = sources.len() > 1;
    if multi && (cli.sink.export.is_some() || cli.sink.manifest.is_some()) {
        anyhow::bail!("--export/--manifest require a single source");
    }

    // Preset and --fast have already merged their values into cli.filter.not_path
    // and cli.filter.exclude_media, so use those fields directly.
    let excludes = cli.filter.not_path.clone();
    let exclude_media = cli.filter.exclude_media;
    for t in &cli.filter.file_type {
        if !is_known_type(t) {
            anyhow::bail!(
                "unknown --type '{t}'; valid values: {}",
                type_names().join(", ")
            );
        }
    }

    // --match-path reads no content, so anything needing the file's bytes is
    // meaningless alongside it.
    if cli.match_path {
        if cli.inspect {
            anyhow::bail!("--match-path cannot be combined with --inspect (no content is read)");
        }
        if !cli.filter.file_type.is_empty() {
            anyhow::bail!("--match-path cannot be combined with --type (no content is read)");
        }
    }

    let filter = EntryFilter::new(
        &cli.filter.path,
        &excludes,
        &cli.filter.file_type,
        exclude_media,
    );

    // Run metadata: the query and every filter in effect, recorded so JSON output
    // and the export report are self-describing.
    let run = RunInfo {
        tool: "mf-scan".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        pattern: cli.pattern.clone(),
        literal: cli.literal_string,
        ignore_case: cli.ignore_case,
        match_path: cli.match_path,
        inspect: cli.inspect,
        archives: sources
            .iter()
            .map(|s| s.path.display().to_string())
            .collect(),
        path_globs: cli.filter.path.clone(),
        not_path_globs: cli.filter.not_path.clone(),
        types: cli.filter.file_type.clone(),
        exclude_media,
        base64: base64_enabled,
        base64_urlsafe: cli.base64_urlsafe,
        keyfiles: cli
            .decrypt
            .keyfile
            .iter()
            .map(|p| p.display().to_string())
            .collect(),
        platform: cli
            .decrypt
            .platform
            .map(|p| p.to_platform().as_str().to_string()),
    };

    // Announce the active skip rules before any result, so the analyst knows what
    // --fast/presets will exclude up front rather than discovering it afterwards.
    log_skip_rules(&run);

    // Build the decryption context once: keys from --keyfile and/or a keyfile
    // dump found next to each archive. The engine consults it per entry.
    let archive_paths: Vec<&Path> = sources.iter().map(|s| s.path.as_path()).collect();
    let decrypt_ctx = build_decryption_context(&cli.decrypt, &archive_paths)?;

    // Coverage statistics aggregated across every searched archive, the decryption
    // audit trail, and the wall clock around the search for throughput.
    let mut stats = ScanStats::default();
    let mut decryptions: Vec<DecryptionRecord> = Vec::new();
    let started = Instant::now();

    if cli.count {
        // Per-file counts aggregated across sources (path tagged when multi).
        let mut counts: Vec<(String, usize)> = Vec::new();
        for src in &sources {
            with_source(src, cli.archive_depth, |source, raw| {
                let verify_before = (cli.verify).then(|| raw.map(sha256_hex)).flatten();
                let findings = search_with_reporter(
                    source,
                    &query,
                    false,
                    cli.match_path,
                    &filter,
                    decrypt_ctx.as_ref(),
                )?;
                for f in &findings.files {
                    let path = if multi {
                        format!("{}/{}", src.label, f.entry.name)
                    } else {
                        f.entry.name.clone()
                    };
                    counts.push((path, f.offsets.len()));
                }
                decryptions.extend(findings.decryptions);
                stats.merge(findings.stats);
                report_verify_for(cli.verify, verify_before, raw);
                Ok(())
            })?;
        }
        let pairs: Vec<(&str, usize)> = counts.iter().map(|(p, c)| (p.as_str(), *c)).collect();
        emit(cli.output.as_deref(), |w| {
            write_counts(&pairs, cli.format, w)
        })?;
    } else {
        // Match records aggregated across sources (tagged when multi).
        let mut records = Vec::new();
        for src in &sources {
            with_source(src, cli.archive_depth, |source, raw| {
                let verify_before = (cli.verify).then(|| raw.map(sha256_hex)).flatten();
                let mut findings = search_with_reporter(
                    source,
                    &query,
                    cli.inspect,
                    cli.match_path,
                    &filter,
                    decrypt_ctx.as_ref(),
                )?;
                // Every record carries its source's full path (for JSON); multi-source
                // runs also get the short display label (for txt/csv).
                let full = src.path.display().to_string();
                for r in &mut findings.records {
                    r.archive_path = Some(full.clone());
                    if multi {
                        r.archive = Some(src.label.clone());
                    }
                }
                if !multi {
                    // --manifest/--export only apply to a single source (guarded above).
                    export_if_requested(&cli.sink, source, &findings, &run)?;
                }
                records.append(&mut findings.records);
                decryptions.append(&mut findings.decryptions);
                stats.merge(findings.stats);
                report_verify_for(cli.verify, verify_before, raw);
                Ok(())
            })?;
        }
        emit(cli.output.as_deref(), |w| {
            write_results(
                &records,
                cli.format,
                colourise,
                cli.match_path,
                &run,
                &stats,
                w,
            )
        })?;
    }

    // The merged stats carry per-source elapsed sums; replace that with the true
    // wall-clock of the whole run (sources are searched sequentially here).
    stats.elapsed = started.elapsed();
    print_stats_summary(&stats);
    report_decryptions(&decryptions);
    write_scan_report_if_enabled(&cli, &run, &stats, &decryptions)?;

    Ok(())
}

/// Open `resolved` as a live [`Source`] and run `f` with it, plus the raw archive
/// bytes for an archive operand (so `--verify` can hash them). A folder has no
/// single backing buffer, so it passes `None`.
///
/// Centralising the open here keeps the borrow of the mmap and the `ZipSource` that
/// reads from it in the same scope, and lets the two output branches share one
/// archive-vs-folder dispatch.
fn with_source<R>(
    resolved: &ResolvedSource,
    archive_depth: u32,
    f: impl FnOnce(&dyn Source, Option<&[u8]>) -> Result<R>,
) -> Result<R> {
    match resolved.kind {
        ResolvedKind::Archive => {
            let mmap = open_archive(&resolved.path)?;
            let source = ZipSource::open(&mmap)?;
            f(&source, Some(&mmap))
        }
        ResolvedKind::Folder => {
            let source = FolderSource::open(&resolved.path, archive_depth)?;
            f(&source, None)
        }
    }
}

/// Emit the `--verify` attestation for one source: the before/after archive hash
/// for an archive, or a note that it is skipped for a folder (which has no single
/// archive file to hash).
fn report_verify_for(verify: bool, before: Option<String>, raw: Option<&[u8]>) {
    if !verify {
        return;
    }
    match (before, raw) {
        (Some(before), Some(bytes)) => report_verify(&before, &sha256_hex(bytes)),
        _ => eprintln!("verify: skipped (a folder source has no single archive file to hash)"),
    }
}
