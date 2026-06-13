//! The `grep` subcommand orchestration.
//!
//! Defines: [`run_grep`] (the orchestration) and its phase helpers — preset
//! application (`apply_presets`), query building (`BuiltQuery`), flag
//! cross-validation (`validate_flags`), run metadata (`build_run_info`), and the
//! shared per-source search skeleton (`with_searched_source`).
//! Used by: `run` (dispatched from `main`).
//! Uses: the `mf_scan` library plus the `crate::support::{sources, presets,
//! decryption, progress, reporting, exporting}` modules — each owning one concern.

use std::io::IsTerminal;
use std::path::Path;
use std::time::Instant;

use anyhow::{Context, Result};
use regex::bytes::{Regex, RegexBuilder};

use mf_scan::decrypt::DecryptionRecord;
use mf_scan::engine::Query;
use mf_scan::filter::EntryFilter;
use mf_scan::inspect::{is_known_type, type_names};
use mf_scan::ios::containers::AppContainerMap;
use mf_scan::models::RunInfo;
use mf_scan::preset::fast::FAST_EXCLUDE_GLOBS;
use mf_scan::report::output::{OutputFormat, write_counts, write_results};
use mf_scan::report::stats::ScanStats;
use mf_scan::search;
use mf_scan::source::Source;

use crate::cli::{ColourWhen, GrepArgs};
use crate::support::decryption::{build_decryption_context, report_decryptions};
use crate::support::exporting::export_if_requested;
use crate::support::presets::{apply_preset, load_preset};
use crate::support::progress::search_with_reporter;
use crate::support::reporting::{
    emit, log_skip_rules, print_stats_summary, report_verify, sha256_hex,
    write_scan_report_if_enabled,
};
use crate::support::sources::{
    Operand, ResolvedKind, ResolvedSource, resolve_sources, with_operand_source,
};

/// Run the `grep` subcommand.
pub(crate) fn run_grep(mut cli: GrepArgs) -> Result<()> {
    // -E is a no-op: our regex flavour is already extended. Consume the field
    // so it counts as read while documenting that acceptance is deliberate.
    let _ = cli.extended_regexp;

    apply_presets(&mut cli)?;

    // The compiled regexes outlive `query`, which borrows them.
    let built = BuiltQuery::build(&cli)?;
    let query = built.query(&cli);

    let colourise = should_colourise(&cli);

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

    validate_flags(&cli)?;

    // Preset and --fast have already merged their values into cli.filter.not_path
    // and cli.filter.exclude_media, so use those fields directly.
    let filter = EntryFilter::new(
        &cli.filter.path,
        &cli.filter.not_path,
        &cli.filter.file_type,
        cli.filter.exclude_media,
    );

    let run = build_run_info(&cli, &sources, built.base64_enabled);

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
        // Counting needs no inspection, so `deep` is always false here.
        let mut counts: Vec<(String, usize)> = Vec::new();
        for src in &sources {
            let ctx = SearchCtx {
                cli: &cli,
                query: &query,
                filter: &filter,
                decrypt_ctx: decrypt_ctx.as_ref(),
                deep: false,
                stats: &mut stats,
                decryptions: &mut decryptions,
            };
            with_searched_source(src, ctx, |findings, _source| {
                for f in &findings.files {
                    let path = if multi {
                        format!("{}/{}", src.label, f.entry.name)
                    } else {
                        f.entry.name.clone()
                    };
                    counts.push((path, f.offsets.len()));
                }
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
            let ctx = SearchCtx {
                cli: &cli,
                query: &query,
                filter: &filter,
                decrypt_ctx: decrypt_ctx.as_ref(),
                deep: cli.inspect,
                stats: &mut stats,
                decryptions: &mut decryptions,
            };
            with_searched_source(src, ctx, |findings, source| {
                // Every record carries its source's full path (for JSON); multi-source
                // runs also get the short display label (for txt/csv).
                let full = src.path.display().to_string();
                for r in &mut findings.records {
                    r.archive_path = Some(full.clone());
                    if multi {
                        r.archive = Some(src.label.clone());
                    }
                }

                // iOS container annotation: build the container map once per source
                // (reads only the small metadata plists), then set bundle_id on every
                // record whose path falls inside a known container directory.
                // WHY post-search, not in the hot parallel path: this is a cheap
                // sequential pass; container metadata plists are tiny; and the parallel
                // engine must remain oblivious to iOS-specific enrichment.
                let container_map = AppContainerMap::build(source);
                if !container_map.is_empty() {
                    for r in &mut findings.records {
                        r.bundle_id = container_map.resolve(&r.path).map(str::to_string);
                    }
                }

                if !multi {
                    // --manifest/--export only apply to a single source (guarded above).
                    export_if_requested(&cli.sink, source, findings, &run)?;
                }
                records.append(&mut findings.records);
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

/// Merge `--preset` and `--fast` values into the CLI arguments.
///
/// The preset is applied first so explicit CLI flags can override it. `--fast`
/// loads `_fast.yml`, falling back to the compiled-in exclude list if the file
/// is absent (e.g. a dev build without the presets folder copied in).
fn apply_presets(cli: &mut GrepArgs) -> Result<()> {
    if let Some(reference) = cli.preset.clone() {
        let preset = load_preset(&reference)
            .with_context(|| format!("failed to load preset '{reference}'"))?;
        apply_preset(cli, &preset);
    }
    if cli.fast {
        match load_preset("_fast") {
            Ok(preset) => apply_preset(cli, &preset),
            Err(_) => {
                cli.filter
                    .not_path
                    .extend(FAST_EXCLUDE_GLOBS.iter().map(|s| s.to_string()));
                cli.filter.exclude_media = true;
            }
        }
    }
    Ok(())
}

/// The compiled search regexes. Owns what [`Query`] borrows, so it must outlive
/// the query handed to the engine.
struct BuiltQuery {
    plain: Regex,
    base64: Option<Regex>,
    base64_enabled: bool,
}

impl BuiltQuery {
    /// Compile the plain pattern and, when `--base64` is set, the alternation of
    /// its base64 fragments.
    fn build(cli: &GrepArgs) -> Result<Self> {
        // -l means "match this exact text", so escape any regex metacharacters.
        let pattern = if cli.literal_string {
            regex::escape(&cli.pattern)
        } else {
            cli.pattern.clone()
        };
        let plain = RegexBuilder::new(&pattern)
            .case_insensitive(cli.ignore_case)
            .build()
            .context("invalid regular expression")?;

        // --base64 also searches for the pattern's base64 encoding. Only a literal
        // can be encoded (a regex has no byte form), and a path is not base64, so the
        // mode requires -l and is incompatible with --match-path.
        let base64_enabled = cli.base64 || cli.base64_urlsafe;
        let base64 = if base64_enabled {
            if !cli.literal_string {
                anyhow::bail!(
                    "--base64 requires -l/--literal-string (a regex cannot be base64-encoded)"
                );
            }
            if cli.match_path {
                anyhow::bail!(
                    "--base64 cannot be combined with --match-path (a path is not base64)"
                );
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

        Ok(Self {
            plain,
            base64,
            base64_enabled,
        })
    }

    /// The engine-facing view borrowing the compiled regexes.
    fn query<'a>(&'a self, cli: &'a GrepArgs) -> Query<'a> {
        Query {
            plain: &self.plain,
            base64: self.base64.as_ref(),
            decoded: self.base64_enabled.then_some(cli.pattern.as_str()),
        }
    }
}

/// Whether to inject ANSI colour: only meaningful for txt sent to a terminal —
/// never into a file or a machine-readable format.
fn should_colourise(cli: &GrepArgs) -> bool {
    cli.output.is_none()
        && cli.format == OutputFormat::Txt
        && match cli.colour {
            ColourWhen::Always => true,
            ColourWhen::Never => false,
            ColourWhen::Auto => std::io::stdout().is_terminal(),
        }
}

/// Cross-validate flags that clap cannot relate on its own.
fn validate_flags(cli: &GrepArgs) -> Result<()> {
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
    Ok(())
}

/// Run metadata: the query and every filter in effect, recorded so JSON output
/// and the export report are self-describing.
fn build_run_info(cli: &GrepArgs, sources: &[ResolvedSource], base64_enabled: bool) -> RunInfo {
    RunInfo {
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
        exclude_media: cli.filter.exclude_media,
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
    }
}

/// Everything one per-source search pass needs, bundled so the `--count` and
/// records branches share a single signature.
struct SearchCtx<'a> {
    cli: &'a GrepArgs,
    query: &'a Query<'a>,
    filter: &'a EntryFilter,
    decrypt_ctx: Option<&'a mf_scan::decrypt::DecryptionContext>,
    /// Whether matches are inspected (`--inspect`); counting never inspects.
    deep: bool,
    stats: &'a mut ScanStats,
    decryptions: &'a mut Vec<DecryptionRecord>,
}

/// Open one source, search it, and hand the findings to `handle`; then fold the
/// source's stats/decryptions into the run totals and emit the `--verify`
/// attestation. The shared skeleton of the `--count` and records branches —
/// only their handling of the findings differs.
fn with_searched_source(
    src: &ResolvedSource,
    ctx: SearchCtx<'_>,
    handle: impl FnOnce(&mut mf_scan::engine::Findings, &dyn Source) -> Result<()>,
) -> Result<()> {
    with_source(src, ctx.cli.archive_depth, |source, raw| {
        let verify_before = (ctx.cli.verify).then(|| raw.map(sha256_hex)).flatten();
        let mut findings = search_with_reporter(
            source,
            ctx.query,
            ctx.deep,
            ctx.cli.match_path,
            ctx.filter,
            ctx.decrypt_ctx,
        )?;
        handle(&mut findings, source)?;
        ctx.decryptions.append(&mut findings.decryptions);
        ctx.stats.merge(findings.stats);
        report_verify_for(ctx.cli.verify, verify_before, raw);
        Ok(())
    })
}

/// Adapt a pre-resolved [`ResolvedSource`] onto the shared [`with_operand_source`]
/// open/dispatch point. Grep drives off the [`ResolvedKind`] decided by
/// `resolve_sources`; the folder case keeps `--archive-depth` so nested `.zip`
/// files expand. The raw archive bytes flow straight through (used by `--verify`).
fn with_source<R>(
    resolved: &ResolvedSource,
    archive_depth: u32,
    f: impl FnOnce(&dyn Source, Option<&[u8]>) -> Result<R>,
) -> Result<R> {
    let operand = match resolved.kind {
        ResolvedKind::Archive => Operand::Archive(&resolved.path),
        ResolvedKind::Folder => Operand::Folder {
            path: &resolved.path,
            archive_depth,
        },
    };
    with_operand_source(operand, f)
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
