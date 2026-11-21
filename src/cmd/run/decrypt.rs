//! The `decrypt` subcommand: decrypt an acquisition's app databases, and optionally
//! write the acquisition with each decrypted copy beside its original.
//!
//! Defines: [`run_decrypt`].
//! Used by: `main` (dispatch).
//! Uses: `cmd::support::{sources, decryption}`, `mf_scan::ops::decrypting` (the
//! per-entry decryptor) and `mf_scan::report::decrypted_zip` (the archive).
//!
//! The output archive extends the source ZIP verbatim when the source is a plain ZIP
//! (its members, read as they are). A ZIP holding an iOS backup is read through the
//! backup layer, whose files are not the ZIP's members, so it is re-packed instead, as
//! are folders, tars and Android backups.

use mf_scan::core::source::expand::Nesting;
use std::process::ExitCode;

use anyhow::{Result, anyhow, bail};

use mf_scan::core::models::RunInfo;
use mf_scan::core::source::Source;
use mf_scan::ops::decrypting::{DerivedCopy, SourceDecryptor};
use mf_scan::report::decrypted_zip::{self, DecryptedZipRequest};

use crate::cmd::cli::decrypt::DecryptCmdArgs;
use crate::cmd::support::decryption::{build_from_sources, context_for_source};
use crate::cmd::support::sources::{
    BackupOptions, BackupProvenance, ResolvedKind, resolve_sources, with_operand_source,
};

/// Exit status when a targeted database did not decrypt (the run itself completed).
const EXIT_SOME_FAILED: u8 = 1;

/// Run `decrypt`.
pub(crate) fn run_decrypt(args: DecryptCmdArgs) -> Result<ExitCode> {
    let resolved = resolve_sources(std::slice::from_ref(&args.source), args.dir_mode, false)?
        .sources
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("no source to read"))?;

    let Some(base) = build_from_sources(&args.keys, &[resolved.path.as_path()])? else {
        bail!("no decryption profiles are installed (profiles/ beside the binary)");
    };

    let run = RunInfo {
        pattern: "decrypt".to_string(),
        archives: vec![resolved.path.display().to_string()],
        keyfiles: args
            .keys
            .keyfile
            .iter()
            .map(|p| p.display().to_string())
            .collect(),
        platform: args
            .keys
            .platform
            .map(|p| p.to_platform().as_str().to_string()),
        ..RunInfo::default()
    };

    let backup_opts = BackupOptions::resolve(args.backup_password, args.archive_password)?;
    let prov = BackupProvenance::new();
    let failed = with_operand_source(
        resolved.operand(),
        &backup_opts,
        args.io_mode.to_io_mode(),
        Nesting::default(),
        prov.sink(),
        |source, _raw| {
            // Keys a dump inside the source carries (a Cellebrite report) join the rest.
            let ctx = context_for_source(Some(&base), source).expect("a base context was given");
            if !ctx.has_secrets() {
                bail!(
                    "no keys to decrypt with: no keychain/keystore dump beside or inside the \
                     source; pass --keyfile"
                );
            }
            let decryptor = SourceDecryptor::new(&ctx, source);
            match &args.to {
                None => Ok(report_only(source, &decryptor)),
                Some(output) => {
                    // A backup's files are its logical view, not the zip's members.
                    let plain_zip = resolved.kind == ResolvedKind::Archive && prov.kind().is_none();
                    let outcome = decrypted_zip::write(DecryptedZipRequest {
                        source,
                        original_zip: plain_zip.then_some(resolved.path.as_path()),
                        derive: &decryptor,
                        output,
                        force: args.force,
                        run: &run,
                    })?;
                    for d in &outcome.decrypted {
                        eprintln!("  decrypted  {}", d.member);
                    }
                    for f in &outcome.failed {
                        eprintln!("  FAILED     {}: {}", f.original, f.reason);
                    }
                    eprintln!(
                        "wrote {} ({} original member(s) {}, {} decrypted cop(y/ies) added)",
                        output.display(),
                        outcome.original_members,
                        if plain_zip {
                            "copied verbatim"
                        } else {
                            "re-packed"
                        },
                        outcome.decrypted.len()
                    );
                    eprintln!(
                        "sha256 {} -> {}",
                        outcome.archive_sha256,
                        outcome.sidecar.display()
                    );
                    Ok(outcome.failed.len())
                }
            }
        },
    )?;
    prov.report();
    Ok(if failed > 0 {
        ExitCode::from(EXIT_SOME_FAILED)
    } else {
        ExitCode::SUCCESS
    })
}

/// Without `--to`: decrypt each targeted database in memory and list the outcome.
/// Returns how many failed.
fn report_only(source: &dyn Source, decryptor: &SourceDecryptor<'_>) -> usize {
    let (mut ok, mut failed) = (0, 0);
    for entry in source.entries() {
        if entry.is_dir() || !decryptor.wants(entry) {
            continue;
        }
        let Ok(content) = source.content(entry) else {
            eprintln!("  FAILED     {}: cannot be read", entry.name);
            failed += 1;
            continue;
        };
        match decryptor.derive(entry, &content) {
            None => {}
            Some(Ok(copy)) => {
                ok += 1;
                println!("{}\t{}", entry.name, copy.note);
            }
            Some(Err(reason)) => {
                failed += 1;
                eprintln!("  FAILED     {}: {reason}", entry.name);
            }
        }
    }
    eprintln!("{ok} database(s) decrypt, {failed} failed; pass --to FILE.zip to write them");
    failed
}
