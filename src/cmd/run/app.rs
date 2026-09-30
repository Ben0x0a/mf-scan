//! The `app` subcommand: locate and export an application's data.
//!
//! Defines: [`run_app`] (dispatches the three verbs) and a private helper per verb
//! — `app grep` (inventory), `app paths` (per-app data locations), `app export`
//! (copy one app's data out, kind-labelled).
//! Used by: `run` (dispatched from `main`).
//! Uses: `mf_scan::ops::apps` (the platform-agnostic catalogue and selection),
//! `mf_scan::report::export` (the shared export engine, reused via `plan_tree`),
//! and the `crate::cmd::support` modules (`sources`, `reporting`, `exporting`).

use std::io::Write;

use anyhow::{Result, anyhow, bail};

use mf_scan::core::models::RunInfo;
use mf_scan::core::source::Source;
use mf_scan::ops::apps::{AppCatalog, AppContainer, ContainerKind, Platform, SigningRecord};
use mf_scan::ops::search::MatchedFile;
use mf_scan::report::export::{self, ExportOutcome};
use mf_scan::report::output::OutputFormat;

use crate::cmd::cli::{
    AppArgs, AppCommand, AppExportArgs, AppGrepArgs, AppPathsArgs, AppSourceArgs,
};
use crate::cmd::support::exporting::{
    report_integrity, report_portability_warnings, report_skipped_too_long,
    write_export_report_file,
};
use crate::cmd::support::reporting::{emit, report_verify, sha256_hex};
use crate::cmd::support::sources::{
    BackupOptions, BackupProvenance, resolve_sources, with_operand_source,
};

/// Run the `app` subcommand.
pub(crate) fn run_app(args: AppArgs) -> Result<()> {
    match args.command {
        AppCommand::Grep(a) => run_grep(a),
        AppCommand::Paths(a) => run_paths(a),
        AppCommand::Export(a) => run_export(a),
    }
}

/// `app grep`: list the installed-app inventory, optionally filtered by PATTERN.
fn run_grep(args: AppGrepArgs) -> Result<()> {
    open_app_source(&args.source, |source, _raw, _path| {
        let catalog = AppCatalog::build(source);
        warn_if_unknown(catalog.platform);
        note_mcm_wal(&catalog);
        let apps = catalog.inventory(source, args.pattern.as_deref());
        emit(args.output.as_deref(), |w| {
            write_inventory(&apps, args.format, w)
        })
    })
}

/// `app paths`: list every data location of one app (its own data, extensions/
/// widgets, and — unless `--no-groups` — its App Groups).
fn run_paths(args: AppPathsArgs) -> Result<()> {
    open_app_source(&args.source, |source, _raw, _path| {
        let catalog = AppCatalog::build(source);
        warn_if_unknown(catalog.platform);
        note_mcm_wal(&catalog);
        let containers = catalog.containers_for(&args.bundle_id, !args.no_groups);
        if containers.is_empty() {
            eprintln!(
                "no containers found for '{}' in this source",
                args.bundle_id
            );
        }
        let signing = catalog.signing_record(&args.bundle_id);
        emit(args.output.as_deref(), |w| {
            write_paths(&args.bundle_id, signing, &containers, args.format, w)
        })
    })
}

/// `app export`: copy all of an app's data out, one subfolder per container, with
/// the on-device tree preserved and a per-file integrity report.
fn run_export(args: AppExportArgs) -> Result<()> {
    open_app_source(&args.source, |source, raw, path| {
        let verify_before = args.verify.then(|| raw.map(sha256_hex)).flatten();

        let catalog = AppCatalog::build(source);
        warn_if_unknown(catalog.platform);
        note_mcm_wal(&catalog);
        let platform = catalog.platform;

        // The app's own data + extensions/widgets + (default) its App Groups, minus
        // the Bundle container — the `.app` is the installed binary/resources, not
        // user data, so it is excluded from a data export.
        let mut containers = catalog.containers_for(&args.bundle_id, !args.no_groups);
        containers.retain(|c| c.kind != ContainerKind::Bundle);
        if containers.is_empty() {
            bail!(
                "no data containers found for '{}' in this source",
                args.bundle_id
            );
        }

        // One (prefix, output-label) root per container drives the tree-preserving
        // plan; gather every file under those prefixes as the export set.
        let prefixes: Vec<String> = containers.iter().map(|c| c.prefix.clone()).collect();
        let roots: Vec<(String, String)> = containers
            .iter()
            .map(|c| (c.prefix.clone(), c.export_label(&args.bundle_id, platform)))
            .collect();
        let files: Vec<MatchedFile> = mf_scan::ops::apps::entries_under(source, &prefixes)
            .into_iter()
            .map(|e| MatchedFile {
                entry: e.clone(),
                offsets: Vec::new(),
            })
            .collect();

        let plan = export::plan_tree(&files, &roots);
        if !plan.renamed.is_empty() {
            // Two files whose paths differ only in case collide on a
            // case-insensitive file system; the later one is suffixed rather than
            // overwriting the earlier. Never do that silently.
            eprintln!(
                "⚠ {} file(s) renamed to avoid overwriting another file:",
                plan.renamed.len()
            );
            for r in &plan.renamed {
                eprintln!("    {} -> {}", r.wanted, r.used);
            }
        }
        let run = app_run_info(&args.bundle_id, &containers, platform, path);

        match export::export_files(
            &plan,
            source,
            &files,
            &args.to,
            Some(args.max_size),
            args.max_path_len,
        )? {
            ExportOutcome::Exported {
                files: n,
                bytes,
                report,
                skipped_too_long,
                portability_warnings,
                ..
            } => {
                write_export_report_file(
                    &args.to,
                    &run,
                    &report,
                    &skipped_too_long,
                    &portability_warnings,
                )?;
                eprintln!(
                    "exported {n} file(s) ({bytes} bytes) for {} from {} container(s) to {}",
                    args.bundle_id,
                    containers.len(),
                    args.to.display()
                );
                report_group_attribution(&containers);
                report_integrity(&report);
                report_skipped_too_long(&skipped_too_long);
                report_portability_warnings(&portability_warnings);
            }
            ExportOutcome::Refused { total_size, cap } => {
                eprintln!(
                    "refusing to export: {total_size} bytes exceeds --max-size {cap}; nothing written"
                );
            }
        }

        if let Some(before) = verify_before
            && let Some(bytes) = raw
        {
            report_verify(&before, &sha256_hex(bytes));
        }
        Ok(())
    })
}

/// Open the single source described by `src` (handling an encrypted backup), run
/// `f` with the live [`Source`], the raw archive bytes (for `--verify`, `None` for
/// a folder/ranged source), and the source's display path; then surface any
/// backup-unlock provenance on stderr.
fn open_app_source<R>(
    src: &AppSourceArgs,
    f: impl FnOnce(&dyn Source, Option<&[u8]>, &str) -> Result<R>,
) -> Result<R> {
    // `recursive = false`: an app command reads exactly one acquisition.
    let resolved = resolve_sources(std::slice::from_ref(&src.source), src.dir_mode, false)?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("no source to read"))?;

    let backup_opts = BackupOptions::resolve(src.backup_password.as_deref());
    let prov = BackupProvenance::new();
    let path_str = resolved.path.display().to_string();
    let operand = resolved.operand(src.archive_depth);

    let out = with_operand_source(
        operand,
        &backup_opts,
        src.io_mode.to_io_mode(),
        prov.sink(),
        |source, raw| f(source, raw, &path_str),
    )?;

    prov.report();
    Ok(out)
}

/// Warn (once) when no app-data layout was recognised, so an empty result is not
/// mistaken for "no apps".
fn warn_if_unknown(platform: Platform) {
    if platform == Platform::Unknown {
        eprintln!(
            "warning: no iOS (FFS/backup) or Android app-data layout detected in this source; \
             results will be empty"
        );
    }
}

/// Note that MobileContainerManager's write-ahead log was folded in.
///
/// WHY say it out loud: the replayed image differs from the bytes on disk, and an
/// analyst reconciling this output against a third-party tool that reads the main
/// file alone needs to know which state was read.
fn note_mcm_wal(catalog: &AppCatalog) {
    if catalog.mcm_wal_replayed() {
        eprintln!(
            "note: MobileContainerManager references.sqlite3-wal was replayed; \
             app entitlements reflect the committed write-ahead log"
        );
    }
}

/// Announce how each included App Group was attributed (authoritative record vs
/// heuristic), so the analyst can audit the group inclusions in an export.
fn report_group_attribution(containers: &[AppContainer]) {
    for c in containers {
        if let Some(link) = c.group_link {
            eprintln!("group: {} included ({})", c.id, link.as_str());
        }
    }
}

/// Build the run metadata recorded at the head of the export report.
fn app_run_info(
    id: &str,
    containers: &[AppContainer],
    platform: Platform,
    source_path: &str,
) -> RunInfo {
    RunInfo {
        pattern: format!("app export {id} ({})", platform_label(platform)),
        archives: vec![source_path.to_string()],
        platform: Some(platform_label(platform).to_string()),
        app: Some(id.to_string()),
        app_containers: containers.iter().map(|c| c.prefix.clone()).collect(),
        app_group_links: containers
            .iter()
            .filter_map(|c| c.group_link.map(|l| format!("{} -> {}", c.id, l.as_str())))
            .collect(),
        ..RunInfo::default()
    }
}

/// Human label for a detected platform.
fn platform_label(platform: Platform) -> &'static str {
    match platform {
        Platform::IosFfs => "ios-ffs",
        Platform::IosBackup => "ios-backup",
        Platform::Android => "android",
        Platform::Unknown => "unknown",
    }
}

/// Write the `app grep` inventory in the chosen format.
fn write_inventory(
    apps: &[mf_scan::ops::apps::AppSummary],
    format: OutputFormat,
    w: &mut dyn Write,
) -> Result<()> {
    match format {
        OutputFormat::Txt => {
            for s in apps {
                writeln!(
                    w,
                    "{}\t{}\t{} container(s)\t{} bytes\t{}",
                    s.id,
                    s.name.as_deref().unwrap_or("-"),
                    s.container_count,
                    s.total_size,
                    s.signing
                        .as_ref()
                        .and_then(|r| r.team_identifier.as_deref())
                        .unwrap_or("-"),
                )?;
            }
            Ok(())
        }
        OutputFormat::Json => {
            serde_json::to_writer_pretty(&mut *w, apps)?;
            writeln!(w)?;
            Ok(())
        }
        OutputFormat::Csv => bail!("app grep supports --format txt or json"),
    }
}

/// Write the `app paths` result in the chosen format: the app's signing record
/// (when the source has one) plus every container it can write.
///
/// WHY the JSON is an object rather than the bare container array it used to be:
/// the signing record describes the APP, not any one container, so hanging it off
/// each container would repeat it and imply it varies between them.
fn write_paths(
    id: &str,
    signing: Option<&SigningRecord>,
    containers: &[AppContainer],
    format: OutputFormat,
    w: &mut dyn Write,
) -> Result<()> {
    match format {
        OutputFormat::Txt => {
            if let Some(record) = signing {
                writeln!(
                    w,
                    "# {id}\tteam={}\tsigner={}",
                    record.team_identifier.as_deref().unwrap_or("-"),
                    record.signer_identity.as_deref().unwrap_or("-"),
                )?;
            }
            for c in containers {
                let link = c
                    .group_link
                    .map(|l| format!(" [{}]", l.as_str()))
                    .unwrap_or_default();
                writeln!(
                    w,
                    "{}\t{}\t{} file(s)\t{} bytes\t{}{}",
                    c.kind.as_str(),
                    c.id,
                    c.file_count,
                    c.total_size,
                    c.prefix,
                    link
                )?;
            }
            Ok(())
        }
        OutputFormat::Json => {
            let doc = serde_json::json!({
                "app": { "id": id, "signing": signing },
                "containers": containers,
            });
            serde_json::to_writer_pretty(&mut *w, &doc)?;
            writeln!(w)?;
            Ok(())
        }
        OutputFormat::Csv => bail!("app paths supports --format txt or json"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mf_scan::ops::apps::{AppSummary, GroupLink};

    fn to_json(f: impl FnOnce(&mut Vec<u8>) -> Result<()>) -> serde_json::Value {
        let mut buf = Vec::new();
        f(&mut buf).unwrap();
        serde_json::from_slice(&buf).unwrap()
    }

    /// Locks the `app paths` JSON shape: the document is an object carrying the
    /// app-level signing record beside the container array; `guid` stays internal
    /// (absent) and `kind`/`group_link` render as their short labels — so a struct
    /// or serde change that alters the output fails here rather than silently.
    #[test]
    fn app_paths_json_shape() {
        let containers = vec![
            AppContainer {
                id: "com.x.App".into(),
                kind: ContainerKind::AppData,
                prefix: "/p/App".into(),
                guid: Some("DEADBEEF".into()),
                parent_id: None,
                file_count: 3,
                total_size: 42,
                group_link: None,
            },
            AppContainer {
                id: "group.x".into(),
                kind: ContainerKind::AndroidExternal,
                prefix: "/p/ext".into(),
                guid: None,
                parent_id: None,
                file_count: 1,
                total_size: 7,
                group_link: Some(GroupLink::ContainerManager),
            },
        ];
        let signing = SigningRecord {
            team_identifier: Some("TEAMID1234".into()),
            application_groups: vec!["group.x".into()],
            ..SigningRecord::default()
        };
        let v = to_json(|w| {
            write_paths(
                "com.x.App",
                Some(&signing),
                &containers,
                OutputFormat::Json,
                w,
            )
        });

        assert_eq!(v["app"]["id"], "com.x.App");
        assert_eq!(v["app"]["signing"]["team_identifier"], "TEAMID1234");
        // Absent signing fields are omitted rather than serialised as null.
        assert!(v["app"]["signing"].get("signer_identity").is_none());

        let arr = v["containers"].as_array().unwrap();
        let obj = arr[0].as_object().unwrap();
        assert!(!obj.contains_key("guid"), "guid must stay internal");
        assert!(
            !obj.contains_key("parent_id"),
            "an absent parent must be omitted, not null"
        );
        for key in [
            "id",
            "kind",
            "prefix",
            "file_count",
            "total_size",
            "group_link",
        ] {
            assert!(obj.contains_key(key), "missing key {key}");
        }
        assert_eq!(obj.len(), 6);
        assert_eq!(arr[0]["kind"], "AppData");
        assert!(arr[0]["group_link"].is_null());
        assert_eq!(arr[1]["kind"], "external_data"); // Android kind uses its as_str label
        assert_eq!(arr[1]["group_link"], "ContainerManager");
    }

    /// An app with no MCM record still produces a well-formed document.
    #[test]
    fn app_paths_json_without_a_signing_record() {
        let v = to_json(|w| write_paths("com.x.App", None, &[], OutputFormat::Json, w));
        assert_eq!(v["app"]["id"], "com.x.App");
        assert!(v["app"]["signing"].is_null());
        assert!(v["containers"].as_array().unwrap().is_empty());
    }

    /// Locks the `app grep` JSON shape.
    #[test]
    fn app_grep_json_shape() {
        let apps = vec![AppSummary {
            id: "com.x.App".into(),
            name: Some("App".into()),
            container_count: 2,
            total_size: 10,
            signing: Some(SigningRecord {
                team_identifier: Some("TEAMID1234".into()),
                ..SigningRecord::default()
            }),
        }];
        let v = to_json(|w| write_inventory(&apps, OutputFormat::Json, w));
        let obj = v.as_array().unwrap()[0].as_object().unwrap();
        for key in ["id", "name", "container_count", "total_size", "signing"] {
            assert!(obj.contains_key(key), "missing key {key}");
        }
        assert_eq!(obj.len(), 5);
        assert_eq!(obj["signing"]["team_identifier"], "TEAMID1234");
    }

    /// An app with no MCM record omits `signing` entirely (Android, backups).
    #[test]
    fn app_grep_json_omits_absent_signing() {
        let apps = vec![AppSummary {
            id: "com.whatsapp".into(),
            name: None,
            container_count: 1,
            total_size: 10,
            signing: None,
        }];
        let v = to_json(|w| write_inventory(&apps, OutputFormat::Json, w));
        let obj = v.as_array().unwrap()[0].as_object().unwrap();
        assert!(!obj.contains_key("signing"));
        assert_eq!(obj.len(), 4);
    }
}
