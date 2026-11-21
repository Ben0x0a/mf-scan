//! The `find` subcommand: list a source's files by name, size, date and type.
//!
//! Defines: [`run_find`], which builds the query, runs it over each source, renders the
//! results, and optionally exports what it found.
//! Used by: `main` (the `Find` dispatch arm).
//! Uses: `mf_scan::ops::find` (the listing), and `cmd::support::{sources, exporting,
//! reporting, scoping}` (`scoping`: `--app`).
//!
//! Unlike `grep` there is no coverage summary and no scan report: a listing reads no
//! content (bar a header for `--type`), and a `find` user expects only paths. An export
//! still writes its own integrity report.

use std::io::Write;
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use serde::Serialize;

use mf_scan::core::models::RunInfo;
use mf_scan::core::util::{UtcTime, parse_utc};
use mf_scan::ops::find::{FindQuery, Found, SizeTest, find};
use mf_scan::ops::search::MatchedFile;
use mf_scan::report::output::OutputFormat;

use crate::cmd::cli::FindArgs;
use crate::cmd::run::EXIT_ERROR;
use crate::cmd::support::decryption::{build_decryption_context, context_for_source};
use crate::cmd::support::exporting::run_export_sink;
use crate::cmd::support::reporting::emit;
use crate::cmd::support::scoping::{app_scope, scoped_run};
use crate::cmd::support::sources::{
    BackupOptions, BackupProvenance, resolve_sources, with_operand_source,
};
use crate::cmd::support::{Caveat, caveat};

/// One listed path, as rendered in every format.
#[derive(Serialize)]
struct Row {
    /// `f` or `d`.
    #[serde(rename = "type")]
    kind: &'static str,
    size: u64,
    /// UTC; empty when the source records no time.
    modified_utc: String,
    /// The detected format, when `--type` asked for one.
    format: &'static str,
    path: String,
}

impl Row {
    fn new(found: &Found<'_>, label: Option<&str>) -> Self {
        Row {
            kind: if found.is_dir { "d" } else { "f" },
            size: found.size,
            modified_utc: found
                .mtime
                .map(|m| UtcTime::from_unix(m).iso())
                .unwrap_or_default(),
            format: found.format.unwrap_or(""),
            path: match label {
                Some(label) => format!("{label}/{}", found.path),
                None => found.path.clone(),
            },
        }
    }
}

/// Run the `find` subcommand. Exits 0 with or without results, as `find` does, and
/// 2 when something could not be checked.
pub(crate) fn run_find(args: FindArgs) -> Result<ExitCode> {
    let date = |flag: &str, text: &Option<String>| -> Result<Option<u64>> {
        text.as_deref()
            .map(|t| {
                parse_utc(t).with_context(|| {
                    format!("invalid {flag} '{t}' (expected e.g. 2026-01-31 or 2026-01-31T12:00)")
                })
            })
            .transpose()
    };
    let mut regexes = Vec::new();
    for pattern in &args.regex {
        regexes.push(FindQuery::compile_regex(pattern, false)?);
    }
    for pattern in &args.iregex {
        regexes.push(FindQuery::compile_regex(pattern, true)?);
    }
    let base_query = FindQuery {
        names: args.name.clone(),
        inames: args.iname.clone(),
        paths: args.path.clone(),
        ipaths: args.ipath.clone(),
        not_names: args.not_name.clone(),
        not_paths: args.not_path.clone(),
        regexes,
        types: args.file_type.clone(),
        sizes: args
            .size
            .iter()
            .map(|s| SizeTest::parse(s))
            .collect::<Result<_>>()?,
        newer: date("--newer", &args.newer)?,
        older: date("--older", &args.older)?,
        max_depth: args.maxdepth,
        scope: None,
    };
    for kind in &args.file_type {
        if kind != "f" && kind != "d" && !mf_scan::formats::inspect::is_known_type(kind) {
            bail!(
                "unknown --type '{kind}'; use f, d, or one of: {}",
                mf_scan::formats::inspect::type_names().join(", ")
            );
        }
    }

    // A folder needs no flag here: walking a directory is what `find` does.
    let sources = resolve_sources(&args.sources, true, false)?.sources;
    let multi = sources.len() > 1;
    let wants_export = args.sink.manifest.is_some() || args.sink.export.is_some();
    if multi && wants_export {
        bail!("--export/--manifest require a single source");
    }

    let backup_opts = BackupOptions::resolve(
        args.decrypt.backup_password.as_deref(),
        args.decrypt.archive_password.as_deref(),
    );
    // Only an export uses keys: a listing reads no file content.
    let decrypt_ctx = if wants_export {
        let paths: Vec<&std::path::Path> = sources.iter().map(|s| s.path.as_path()).collect();
        build_decryption_context(&args.decrypt.keys, &paths)?
    } else {
        None
    };
    let prov = BackupProvenance::new();
    let run = RunInfo {
        pattern: format!("find {}", query_summary(&args)),
        archives: sources
            .iter()
            .map(|s| s.path.display().to_string())
            .collect(),
        path_globs: args.path.clone(),
        not_path_globs: args.not_path.clone(),
        app: (!args.app.is_empty()).then(|| args.app.join(", ")),
        types: args.file_type.clone(),
        ..RunInfo::default()
    };

    let mut rows = Vec::new();
    let mut incomplete = false;
    let mut query = base_query;
    for src in &sources {
        with_operand_source(
            src.operand(args.archive_depth),
            &backup_opts,
            args.io_mode.to_io_mode(),
            prov.sink(),
            |source, _raw| {
                // `--app`: only the apps' containers, resolved from this source.
                query.scope = app_scope(source, &args.app, &src.label, None);
                let outcome = find(source, &query)?;

                if outcome.undated > 0 {
                    eprintln!(
                        "note: {} entr(y/ies) have no timestamp, so --newer/--older excluded them",
                        outcome.undated
                    );
                }
                if !outcome.unreadable.is_empty() {
                    incomplete = true;
                    eprintln!(
                        "⚠ {} file(s) could not be read to test --type:",
                        outcome.unreadable.len()
                    );
                    for path in &outcome.unreadable {
                        eprintln!("    {path}");
                    }
                }
                let label = multi.then_some(src.label.as_str());
                rows.extend(outcome.found.iter().map(|f| Row::new(f, label)));

                if wants_export {
                    let files: Vec<MatchedFile> = outcome
                        .found
                        .iter()
                        .filter_map(|f| f.entry)
                        .map(|entry| MatchedFile::new(entry.clone(), Vec::new()))
                        .collect();
                    let source_ctx = context_for_source(decrypt_ctx.as_ref(), source);
                    let run = scoped_run(&run, query.scope.as_deref());
                    run_export_sink(
                        &args.sink,
                        source,
                        &files,
                        &run,
                        "found",
                        "find",
                        source_ctx.as_deref(),
                    )?;
                }
                Ok(())
            },
        )?;
    }
    prov.report();

    emit(args.output.as_deref(), |w| {
        write_rows(&rows, args.format, args.long, w)
    })?;
    // A listing stays quiet in a script, as `find`'s does; a person at a terminal is
    // told what it may miss.
    if std::io::IsTerminal::is_terminal(&std::io::stderr()) {
        caveat(Caveat::Files);
    }
    Ok(if incomplete {
        ExitCode::from(EXIT_ERROR)
    } else {
        ExitCode::SUCCESS
    })
}

/// The tests as given, for the run record.
fn query_summary(args: &FindArgs) -> String {
    let mut parts = Vec::new();
    let mut add = |flag: &str, values: &[String]| {
        parts.extend(values.iter().map(|v| format!("{flag} {v}")));
    };
    add("--name", &args.name);
    add("--iname", &args.iname);
    add("--path", &args.path);
    add("--ipath", &args.ipath);
    add("--regex", &args.regex);
    add("--iregex", &args.iregex);
    add("--not-name", &args.not_name);
    add("--not-path", &args.not_path);
    add("--type", &args.file_type);
    add("--size", &args.size);
    if let Some(date) = &args.newer {
        parts.push(format!("--newer {date}"));
    }
    if let Some(date) = &args.older {
        parts.push(format!("--older {date}"));
    }
    if let Some(depth) = args.maxdepth {
        parts.push(format!("--maxdepth {depth}"));
    }
    parts.join(" ")
}

fn write_rows(rows: &[Row], format: OutputFormat, long: bool, w: &mut dyn Write) -> Result<()> {
    match format {
        OutputFormat::Txt => {
            for row in rows {
                if long {
                    let modified = if row.modified_utc.is_empty() {
                        "-"
                    } else {
                        &row.modified_utc
                    };
                    writeln!(w, "{}\t{}\t{modified}\t{}", row.kind, row.size, row.path)
                } else {
                    writeln!(w, "{}", row.path)
                }
                .context("failed writing results")?;
            }
            Ok(())
        }
        OutputFormat::Json => {
            serde_json::to_writer_pretty(&mut *w, rows).context("failed writing results")?;
            writeln!(w).context("failed writing results")
        }
        OutputFormat::Csv => {
            let mut wtr = csv::Writer::from_writer(w);
            for row in rows {
                wtr.serialize(row).context("failed writing results")?;
            }
            wtr.flush().context("failed writing results")
        }
    }
}
