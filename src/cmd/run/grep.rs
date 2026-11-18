//! The `grep` subcommand orchestration.
//!
//! Defines: [`run_grep`] (the orchestration) and its phase helpers — preset
//! application (`apply_presets`), query building (`BuiltQuery`), flag
//! cross-validation (`validate_flags`), run metadata (`build_run_info`), and the
//! shared per-source search skeleton (`with_searched_source`).
//! Used by: `run` (dispatched from `main`).
//! Uses: the `mf_scan` library plus the `crate::cmd::support::{sources, presets,
//! decryption, progress, reporting, exporting}` modules — each owning one concern.

use std::cell::RefCell;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{Context, Result};
use regex::bytes::{Regex, RegexBuilder};

use mf_scan::core::filter::EntryFilter;
use mf_scan::core::models::{Encoding, RunInfo};
use mf_scan::core::source::Source;
use mf_scan::core::stats::ScanStats;
use mf_scan::decrypt::DecryptionRecord;
use mf_scan::formats::inspect::{is_known_type, type_names};
use mf_scan::ops::apps::expand_app_globs;
use mf_scan::ops::search::{MatchOn, Query, encodings};
use mf_scan::platform::ios::containers::AppContainerMap;
use mf_scan::preset::fast::FAST_EXCLUDE_GLOBS;
use mf_scan::report::output::{
    ListedFile, OutputFormat, TxtStyle, write_counts, write_file_list, write_results,
};

use crate::cmd::cli::{ColourWhen, EncodingArg, GrepArgs};
use crate::cmd::support::decryption::{
    build_decryption_context, context_for_source, report_decryptions,
};
use crate::cmd::support::exporting::export_if_requested;
use crate::cmd::support::presets::{apply_preset, load_preset};
use crate::cmd::support::progress::search_with_reporter;
use crate::cmd::support::reporting::{
    emit, log_skip_rules, print_coverage_gaps, print_stats_summary, report_verify, sha256_hex,
    write_scan_report_if_enabled,
};
use crate::cmd::support::sources::{
    BackupFacts, BackupOptions, BackupProvenance, IoMode, ResolvedKind, ResolvedSource,
    ResolvedSources, STDIN_OPERAND, resolve_sources, with_operand_source,
};

/// Exit status: at least one match, and everything selected was searched.
const EXIT_MATCH: u8 = 0;
/// Exit status: everything selected was searched, and nothing matched.
const EXIT_NO_MATCH: u8 = 1;
/// Exit status: the run failed, or could not search everything it selected.
pub(crate) const EXIT_ERROR: u8 = 2;

/// The exit status for a finished search, following grep's 0 / 1 / 2 convention.
///
/// WHY an unreadable or undecryptable file outranks a match: grep reports an error
/// whenever it could not read a file, even if it matched elsewhere, and this also
/// keeps exit 1 meaning something a script can trust — "searched and absent", never
/// "absent from the part that could be read".
///
/// `-q` follows grep too: a match found is all it asks, so it exits 0 regardless.
fn exit_status(stats: &ScanStats, damaged: bool, quiet: bool) -> u8 {
    if quiet && stats.total_matches > 0 {
        EXIT_MATCH
    } else if stats.unreadable.count > 0 || stats.decrypt_failed.count > 0 || damaged {
        EXIT_ERROR
    } else if stats.total_matches > 0 {
        EXIT_MATCH
    } else {
        EXIT_NO_MATCH
    }
}

/// Run the `grep` subcommand, returning its exit status (see [`exit_status`]).
pub(crate) fn run_grep(mut cli: GrepArgs) -> Result<u8> {
    // -E is a no-op: our regex flavour is already extended. Consume the field
    // so it counts as read while documenting that acceptance is deliberate.
    let _ = cli.extended_regexp;

    normalise_operands(&mut cli)?;
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
    let ResolvedSources {
        sources,
        loose_skipped,
    } = resolve_sources(&cli.archives, cli.dir_mode, cli.recursive)?;
    if sources.is_empty() {
        anyhow::bail!(
            "-r found no archive (.zip, .tar, .tar.gz, .tgz) to search; {loose_skipped} loose \
             file(s) were not searched — use --dir-mode to search them"
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

    let run = RunInfo {
        loose_files_skipped: loose_skipped,
        ..build_run_info(&cli, &sources, built.wanted)
    };

    // Announce the active skip rules before any result, so the analyst knows what
    // --fast/presets will exclude up front rather than discovering it afterwards.
    if !cli.quiet {
        log_skip_rules(&run);
    }

    // Build the decryption context once: keys from --keyfile and/or a keyfile
    // dump found next to each archive. The engine consults it per entry.
    // Standard input has no folder to look beside.
    let archive_paths: Vec<&Path> = sources
        .iter()
        .filter(|s| s.kind != ResolvedKind::Stdin)
        .map(|s| s.path.as_path())
        .collect();
    let decrypt_ctx = build_decryption_context(&cli.decrypt.keys, &archive_paths)?;

    // The backup password (flag or env), and a sink the open path fills in when a
    // source turns out to be an encrypted backup that gets unlocked.
    let backup_opts = BackupOptions::resolve(cli.decrypt.backup_password.as_deref());
    let backup_prov = BackupProvenance::new();

    // Coverage statistics aggregated across every searched archive, the decryption
    // audit trail, and the wall clock around the search for throughput.
    let mut stats = ScanStats::default();
    let mut decryptions: Vec<DecryptionRecord> = Vec::new();
    let started = Instant::now();

    if cli.count || cli.files_with_matches {
        // One line per file, aggregated across sources (path tagged when multi).
        // Neither form shows a match's location inside its file, so `deep` is false.
        let mut counts: Vec<(ListedFile, usize)> = Vec::new();
        for src in &sources {
            let ctx = SearchCtx {
                cli: &cli,
                query: &query,
                filter: &filter,
                decrypt_ctx: decrypt_ctx.as_ref(),
                deep: false,
                stats: &mut stats,
                decryptions: &mut decryptions,
                backup_opts: &backup_opts,
                backup_record: backup_prov.sink(),
            };
            with_searched_source(src, ctx, |findings, source, _containers, source_ctx| {
                for f in &findings.files {
                    let path = if multi {
                        format!("{}/{}", src.label, f.entry.name)
                    } else {
                        f.entry.name.clone()
                    };
                    let listed = ListedFile {
                        path,
                        size: f.entry.uncompressed_size,
                        mtime: f.entry.mtime,
                        encodings: f.encodings.clone(),
                    };
                    counts.push((listed, f.offsets.len()));
                }
                if !multi {
                    // --manifest/--export only apply to a single source (guarded
                    // above), and --count rejects them, so this is -l's export path.
                    export_if_requested(&cli.sink, source, findings, &run, source_ctx)?;
                }
                Ok(())
            })?;
        }
        emit(cli.output.as_deref(), |w| {
            if cli.files_with_matches {
                let files: Vec<ListedFile> = counts.drain(..).map(|(f, _)| f).collect();
                write_file_list(&files, cli.long, cli.format, w)
            } else {
                write_counts(&counts, cli.long, cli.format, w)
            }
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
                backup_opts: &backup_opts,
                backup_record: backup_prov.sink(),
            };
            with_searched_source(src, ctx, |findings, source, container_map, source_ctx| {
                // Every record carries its source's full path (for JSON); multi-source
                // runs also get the short display label (for txt/csv).
                let full = src.path.display().to_string();
                for r in &mut findings.records {
                    r.archive_path = Some(full.clone());
                    if multi {
                        r.archive = Some(src.label.clone());
                    }
                }

                // iOS container annotation: set bundle_id on every record whose
                // path falls inside a known container directory. The map was built
                // before the search (it also widens the path filter), so this is a
                // cheap sequential pass.
                // WHY post-search, not in the hot parallel path: the parallel engine
                // must remain oblivious to iOS-specific enrichment.
                if !container_map.is_empty() {
                    for r in &mut findings.records {
                        r.bundle_id = container_map.resolve(&r.path).map(str::to_string);
                    }
                }

                if !multi {
                    // --manifest/--export only apply to a single source (guarded above).
                    export_if_requested(&cli.sink, source, findings, &run, source_ctx)?;
                }
                records.append(&mut findings.records);
                Ok(())
            })?;
        }
        let style = if cli.match_path {
            TxtStyle::PathOnly
        } else if cli.only_matching {
            TxtStyle::OnlyMatching
        } else {
            TxtStyle::Line
        };
        if !cli.quiet {
            emit(cli.output.as_deref(), |w| {
                write_results(&records, cli.format, colourise, style, &run, &stats, w)
            })?;
        }
    }

    // The merged stats carry per-source elapsed sums; replace that with the true
    // wall-clock of the whole run (sources are searched sequentially here).
    stats.elapsed = started.elapsed();
    if cli.no_stats || cli.quiet {
        print_coverage_gaps(&stats);
    } else {
        print_stats_summary(&stats, cli.match_path);
    }
    report_decryptions(&decryptions);

    // Surface the backup-decryption provenance: a loud stderr line at run time
    // (so the use of a DEFAULT password is impossible to miss) and the record in
    // the scan report. WHY here, once: a single backup is unlocked per run; the
    // open path filled the provenance sink during the search.
    let damaged = backup_prov.damaged();
    let backup_record = backup_prov.report();
    // -q asks a yes/no question, so it leaves no file behind unless one is named.
    if !cli.quiet || cli.report.is_some() {
        write_scan_report_if_enabled(&cli, &run, &stats, &decryptions, backup_record.as_ref())?;
    }

    Ok(exit_status(&stats, damaged, cli.quiet))
}

/// Settle which arguments are patterns and which are sources.
///
/// With `-e`, the first positional is a source, not a pattern: clap cannot express that,
/// so it is moved here. All patterns then live in `cli.regexps`. With no source at all
/// the search reads standard input, as grep does, unless that is a terminal, where it
/// would only appear to hang.
fn normalise_operands(cli: &mut GrepArgs) -> Result<()> {
    match cli.pattern.take() {
        Some(first) if cli.regexps.is_empty() => cli.regexps.push(first),
        Some(source) => cli.archives.insert(0, PathBuf::from(source)),
        None => {}
    }
    if cli.archives.is_empty() {
        if std::io::stdin().is_terminal() {
            anyhow::bail!(
                "no source given: name an archive, file or folder, or pipe data in (try -h)"
            );
        }
        if !cli.quiet {
            eprintln!("note: no source given; reading standard input");
        }
        cli.archives.push(PathBuf::from(STDIN_OPERAND));
    }
    if cli
        .archives
        .iter()
        .filter(|a| a.as_os_str() == STDIN_OPERAND)
        .count()
        > 1
    {
        anyhow::bail!("standard input can only be named once");
    }
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
    /// The literal's other encodings, each tagged (empty for a plain search).
    encoded: Vec<(Encoding, Regex)>,
    /// The literal a base64 hit decodes to; `None` without base64.
    decoded: Option<String>,
    /// The encodings searched besides plain, for the run record.
    wanted: encodings::EncodingSet,
}

/// The encodings the flags ask for, besides plain UTF-8.
fn encoding_set(cli: &GrepArgs) -> encodings::EncodingSet {
    let asked = |e: EncodingArg| cli.encodings.contains(&e);
    if cli.all_encodings || asked(EncodingArg::All) {
        return encodings::EncodingSet::all();
    }
    let utf16 = cli.utf16 || asked(EncodingArg::Utf16);
    encodings::EncodingSet {
        normal_forms: asked(EncodingArg::Nfd),
        utf16le: utf16 || asked(EncodingArg::Utf16le),
        utf16be: utf16 || asked(EncodingArg::Utf16be),
        cesu8: asked(EncodingArg::Cesu8),
        json: asked(EncodingArg::Json),
        url: asked(EncodingArg::Url),
        base64: asked(EncodingArg::Base64),
        base64url: asked(EncodingArg::Base64url),
        base64_named: asked(EncodingArg::Base64) || asked(EncodingArg::Base64url),
    }
}

impl BuiltQuery {
    /// Compile the plain pattern and, when other encodings are asked for, the
    /// literal's form in each.
    fn build(cli: &GrepArgs) -> Result<Self> {
        // -F means "match this exact text", so escape any regex metacharacters.
        let parts: Vec<String> = cli
            .regexps
            .iter()
            .map(|p| {
                if cli.literal_string {
                    regex::escape(p)
                } else {
                    p.clone()
                }
            })
            .collect();
        // Each -e is grouped, so one pattern's inline flags or alternation stay its own.
        let pattern = match parts.as_slice() {
            [only] => only.clone(),
            many => many
                .iter()
                .map(|p| format!("(?:{p})"))
                .collect::<Vec<_>>()
                .join("|"),
        };
        // WHY half boundaries rather than `\\b`: `\\b` needs a word character on the
        // pattern's side, so `-w '+33'` could never match. These test only the character
        // outside the match, which is what grep -w means.
        let pattern = if cli.word_regexp {
            format!(r"\b{{start-half}}(?:{pattern})\b{{end-half}}")
        } else {
            pattern
        };
        // WHY multi_line and crlf: the regex crate's default anchors `^`/`$` to the
        // whole file, so a grep-style `^bye` finds nothing in a multi-line file and
        // reads as a clean negative — missed evidence. `crlf` extends the line rule
        // to Windows line endings, where `world$` would otherwise miss too; its cost
        // is that `.` no longer matches a carriage return. `\A` and `\z` still anchor
        // to the whole file.
        let plain = RegexBuilder::new(&pattern)
            .case_insensitive(cli.ignore_case)
            .multi_line(true)
            .crlf(true)
            .build()
            .context("invalid regular expression")?;

        let wanted = encoding_set(cli);
        if !wanted.any() {
            return Ok(Self {
                plain,
                encoded: Vec::new(),
                decoded: None,
                wanted,
            });
        }
        // Only a literal has an encoded form (a regex has no byte form); a path is not
        // encoded; and a word boundary means nothing inside an encoded run.
        if !cli.literal_string {
            anyhow::bail!("other encodings require -F/--fixed-strings (a regex cannot be encoded)");
        }
        if cli.match_path {
            anyhow::bail!(
                "other encodings cannot be combined with --match-path (a path is not encoded)"
            );
        }
        if cli.word_regexp {
            anyhow::bail!("other encodings cannot be combined with -w");
        }
        let built = encodings::build(&cli.regexps, cli.ignore_case, wanted)?;
        for note in &built.notes {
            eprintln!("{note}");
        }
        Ok(Self {
            plain,
            encoded: built.patterns,
            decoded: built.decoded,
            wanted: built.searched,
        })
    }

    /// The engine-facing view borrowing the compiled regexes.
    fn query<'a>(&'a self, cli: &'a GrepArgs) -> Query<'a> {
        Query {
            plain: &self.plain,
            encoded: &self.encoded,
            decoded: self.decoded.as_deref(),
            line_numbers: cli.line_number,
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
    // --long describes files, so it needs an output that lists files.
    if cli.long && !cli.files_with_matches && !cli.count {
        anyhow::bail!("--long lists files: use it with -l or -c");
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
        if cli.only_matching {
            anyhow::bail!("--match-path cannot be combined with -o (it prints only paths)");
        }
        if cli.line_number {
            anyhow::bail!("--match-path cannot be combined with -n (no content is read)");
        }
    }
    // json/csv already carry the fields a consumer would pick from, so -o only shapes
    // the txt line; accepting it there would silently do nothing.
    if cli.only_matching && cli.format != OutputFormat::Txt {
        anyhow::bail!("-o/--only-matching applies to --format txt only");
    }
    // clap rejects these on the command line; a preset can still set `count: true`.
    if cli.count && (cli.files_with_matches || cli.only_matching) {
        anyhow::bail!("--count cannot be combined with -l or -o");
    }
    Ok(())
}

/// Run metadata: the query and every filter in effect, recorded so JSON output
/// and the export report are self-describing.
fn build_run_info(
    cli: &GrepArgs,
    sources: &[ResolvedSource],
    wanted: encodings::EncodingSet,
) -> RunInfo {
    // Search runs are not app-selected; the `app export` path fills the app fields.
    RunInfo {
        pattern: cli.regexps.join(" | "),
        patterns: if cli.regexps.len() > 1 {
            cli.regexps.clone()
        } else {
            Vec::new()
        },
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
        encodings: wanted.names(),
        keyfiles: cli
            .decrypt
            .keys
            .sources
            .keyfile
            .iter()
            .map(|p| p.display().to_string())
            .collect(),
        platform: cli
            .decrypt
            .keys
            .sources
            .platform
            .map(|p| p.to_platform().as_str().to_string()),
        ..RunInfo::default()
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
    /// The resolved backup password (flag/env), and the sink the open path fills
    /// when a source is an encrypted backup it unlocks.
    backup_opts: &'a BackupOptions,
    backup_record: &'a RefCell<BackupFacts>,
}

/// What the pattern is matched against, from `--match-path` / `--and-paths`.
fn match_on(cli: &GrepArgs) -> MatchOn {
    if cli.match_path {
        MatchOn::Path
    } else if cli.and_paths {
        MatchOn::Both
    } else {
        MatchOn::Content
    }
}

/// Open one source, search it, and hand the findings to `handle`; then fold the
/// source's stats/decryptions into the run totals and emit the `--verify`
/// attestation. The shared skeleton of the `--count` and records branches —
/// only their handling of the findings differs.
fn with_searched_source(
    src: &ResolvedSource,
    ctx: SearchCtx<'_>,
    handle: impl FnOnce(
        &mut mf_scan::ops::search::Findings,
        &dyn Source,
        &AppContainerMap,
        Option<&mf_scan::decrypt::DecryptionContext>,
    ) -> Result<()>,
) -> Result<()> {
    with_source(
        src,
        ctx.cli.archive_depth,
        ctx.cli.io_mode.to_io_mode(),
        ctx.backup_opts,
        ctx.backup_record,
        |source, raw| {
            let verify_before = (ctx.cli.verify).then(|| raw.map(sha256_hex)).flatten();

            // Build the container map BEFORE the search: it both widens the path
            // filter (an app-identity `--path` glob names a GUID-named container)
            // and annotates the records afterwards, so it is built once and used
            // twice rather than rebuilt.
            let container_map = AppContainerMap::build(source);
            let widened = widen_filter_for_apps(ctx.filter, &container_map, ctx.cli);
            let filter = widened.as_ref().unwrap_or(ctx.filter);

            // Keys a dump inside the source carries join those found beside it.
            let source_ctx = context_for_source(ctx.decrypt_ctx, source);
            let mut findings = search_with_reporter(
                source,
                ctx.query,
                ctx.deep,
                match_on(ctx.cli),
                filter,
                source_ctx.as_deref(),
                !ctx.cli.quiet,
            )?;
            handle(&mut findings, source, &container_map, source_ctx.as_deref())?;
            ctx.decryptions.append(&mut findings.decryptions);
            ctx.stats.merge(findings.stats);
            report_verify_for(ctx.cli.verify, verify_before, raw);
            Ok(())
        },
    )
}

/// Widen the path filter with the containers an app-identity `--path`/`--not-path`
/// glob names, or `None` when nothing resolved.
///
/// On a full-filesystem acquisition an app's container is named by a GUID, so
/// `--path '*com.burbn.instagram*'` matches nothing even though the identifier is
/// recorded in the container's metadata plist. Resolving it here — once, before the
/// search — keeps the engine and the filter app-agnostic.
///
/// What was added is reported, because a filter that quietly matches more than it
/// was asked to is worse than one that matches less.
fn widen_filter_for_apps(
    filter: &EntryFilter,
    map: &AppContainerMap,
    cli: &GrepArgs,
) -> Option<EntryFilter> {
    if map.is_empty() || (cli.filter.path.is_empty() && cli.filter.not_path.is_empty()) {
        return None;
    }
    let include = expand_app_globs(map, &cli.filter.path);
    let exclude = expand_app_globs(map, &cli.filter.not_path);
    if include.is_empty() && exclude.is_empty() {
        return None;
    }
    for (resolved, flag) in [(&include, "--path"), (&exclude, "--not-path")] {
        for g in resolved {
            eprintln!(
                "{flag} {:?} resolved to app {} -> {}",
                g.pattern, g.bundle_id, g.glob
            );
        }
    }
    let include: Vec<String> = include.into_iter().map(|g| g.glob).collect();
    let exclude: Vec<String> = exclude.into_iter().map(|g| g.glob).collect();
    Some(filter.with_extra_globs(&include, &exclude))
}

/// Adapt a pre-resolved [`ResolvedSource`] onto the shared [`with_operand_source`]
/// open/dispatch point via [`ResolvedSource::operand`]; the folder case keeps
/// `--archive-depth` so nested `.zip` files expand. The raw archive bytes flow
/// straight through (used by `--verify`).
fn with_source<R>(
    resolved: &ResolvedSource,
    archive_depth: u32,
    io_mode: IoMode,
    backup_opts: &BackupOptions,
    backup_record: &RefCell<BackupFacts>,
    f: impl FnOnce(&dyn Source, Option<&[u8]>) -> Result<R>,
) -> Result<R> {
    let operand = resolved.operand(archive_depth);
    with_operand_source(operand, backup_opts, io_mode, backup_record, f)
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
        _ => eprintln!("verify: skipped (this source has no single archive file to hash)"),
    }
}
