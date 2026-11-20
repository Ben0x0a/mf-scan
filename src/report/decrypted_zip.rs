//! Write an acquisition as one ZIP with each decrypted database beside its original.
//!
//! Defines: [`DecryptedZipRequest`], [`write()`] (the archive and its `.sha256` sidecar),
//! and [`RECORD_MEMBER`].
//! Used by: the binary's `decrypt` orchestrator (`cmd::run::decrypt`).
//! Uses: `report::zip_writer` (the format, including extending an archive verbatim),
//! `report::export` (the derived-copy hook, the naming rule, the per-file records), and
//! `report::publish` (the fail-closed temporary file, read-back check and sidecar).
//!
//! ── Two ways to build it ─────────────────────────────────────────────────────
//!   • The source is a ZIP on disk (the usual full-filesystem acquisition): the output
//!     starts as a verbatim copy of it. Every original member keeps its bytes, offset,
//!     compression and timestamps, and the decrypted copies are appended. Nothing is
//!     decompressed or recompressed, so a 40 GB acquisition costs one sequential copy.
//!   • Any other source (a folder, a tar, a backup): every file is written STORED with
//!     its own timestamp, then the decrypted copies, as `backup rebuild` writes.
//!
//! A decrypted copy is named `name.decrypted.ext` in its original's directory, carries
//! its original's timestamp, and is listed in [`RECORD_MEMBER`] with the hashes of
//! both files and how it was decrypted. A database whose key did not verify is listed
//! there too, with the reason, and gets no copy.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Serialize;

use crate::core::models::RunInfo;
use crate::core::source::Source;
use crate::core::util::now_unix;
use crate::core::util::{UtcTime, sha256_hex};
use crate::ops::decrypting::DerivedCopy;
use crate::report::export::{decrypted_name_numbered, fold_case};
use crate::report::publish::{check_and_hash, member_count, prepare, publish_replacing};
use crate::report::zip_writer::ZipWriter;

/// The record of what was decrypted, inside the archive. No device path starts with
/// `_mf-scan/`, but an archive an earlier `decrypt` wrote already holds one, so the
/// record is numbered when the name is taken (`_mf-scan/decryption.json-2`).
pub const RECORD_MEMBER: &str = "_mf-scan/decryption.json";

/// What the archive needs.
pub struct DecryptedZipRequest<'a> {
    pub source: &'a dyn Source,
    /// The source's ZIP on disk, to extend verbatim; `None` re-packs every file.
    pub original_zip: Option<&'a Path>,
    pub derive: &'a dyn DerivedCopy,
    pub output: &'a Path,
    /// Replace an archive already at `output`.
    pub force: bool,
    pub run: &'a RunInfo,
}

/// One decrypted copy added to the archive.
#[derive(Debug, Clone, Serialize)]
pub struct DecryptedMember {
    /// The original (encrypted) member.
    pub original: String,
    /// The decrypted copy's member name.
    pub member: String,
    pub size: u64,
    /// SHA-256 of the original's bytes as read from the source.
    pub original_sha256: String,
    /// SHA-256 of the decrypted copy, read back from the archive.
    pub sha256: String,
    /// How it was decrypted.
    pub note: String,
}

/// A database that should have decrypted but did not.
#[derive(Debug, Clone, Serialize)]
pub struct UndecryptedMember {
    pub original: String,
    pub reason: String,
}

/// What a finished archive holds.
pub struct DecryptedZipOutcome {
    pub decrypted: Vec<DecryptedMember>,
    pub failed: Vec<UndecryptedMember>,
    /// Members copied or written from the source.
    pub original_members: usize,
    pub archive_sha256: String,
    pub sidecar: PathBuf,
}

/// The record written into the archive.
#[derive(Serialize)]
struct Record<'a> {
    run: &'a RunInfo,
    created_utc: String,
    /// `extended` (the source ZIP copied verbatim) or `repacked`.
    layout: &'a str,
    original_members: usize,
    decrypted: &'a [DecryptedMember],
    #[serde(skip_serializing_if = "<[UndecryptedMember]>::is_empty")]
    failed: &'a [UndecryptedMember],
}

/// Write the archive described by `request`.
pub fn write(request: DecryptedZipRequest<'_>) -> Result<DecryptedZipOutcome> {
    let DecryptedZipRequest {
        source,
        original_zip,
        derive,
        output,
        force,
        run,
    } = request;

    if let Some(original) = original_zip
        && same_file(original, output)
    {
        bail!("--to must not be the source archive itself");
    }
    let partial = prepare(output, Some(force))?;

    // Start with the original members: copied verbatim, or written one by one.
    let (mut zip, original_members, layout) = match original_zip {
        Some(original) => {
            let zip = ZipWriter::extend(original, &partial.0)?;
            (zip, member_count(original)?, "extended")
        }
        None => {
            let mut zip = ZipWriter::create(&partial.0)?;
            let n = repack(&mut zip, source)?;
            (zip, n, "repacked")
        }
    };

    // Then each decrypted database, beside its original.
    let taken: HashSet<String> = source
        .entries()
        .iter()
        .map(|e| fold_case(&e.name))
        .collect();
    let mut names: Vec<String> = Vec::new();
    let mut decrypted = Vec::new();
    let mut failed = Vec::new();
    for entry in source.entries() {
        if entry.is_dir() || !derive.wants(entry) {
            continue;
        }
        let content = source
            .content(entry)
            .with_context(|| format!("cannot read {}", entry.name))?;
        match derive.derive(entry, &content) {
            None => {}
            Some(Err(reason)) => failed.push(UndecryptedMember {
                original: entry.name.clone(),
                reason,
            }),
            Some(Ok(copy)) => {
                let member = free_name(&entry.name, &taken, &names);
                let written = zip.add_file(&member, entry.mtime, &copy.bytes)?;
                decrypted.push(DecryptedMember {
                    original: entry.name.clone(),
                    member: member.clone(),
                    size: copy.bytes.len() as u64,
                    original_sha256: sha256_hex(&content),
                    sha256: zip.sha256_of(written)?,
                    note: copy.note,
                });
                names.push(member);
            }
        }
    }
    let record_member = numbered_free(RECORD_MEMBER.to_string(), &taken, &names);

    let now = now_unix();
    let record = Record {
        run,
        created_utc: UtcTime::from_unix(now).iso(),
        layout,
        original_members,
        decrypted: &decrypted,
        failed: &failed,
    };
    let bytes = serde_json::to_vec_pretty(&record).context("cannot encode the record")?;
    zip.add_file(&record_member, Some(now), &bytes)?;
    zip.finish()?;

    let expected = original_members + decrypted.len() + 1;
    let archive_sha256 = check_and_hash(&partial.0, expected)?;
    let sidecar = publish_replacing(&partial.0, output, &archive_sha256)?;

    Ok(DecryptedZipOutcome {
        decrypted,
        failed,
        original_members,
        archive_sha256,
        sidecar,
    })
}

/// Write every file and directory of `source` STORED, each with its own timestamp.
fn repack(zip: &mut ZipWriter, source: &dyn Source) -> Result<usize> {
    let mut n = 0;
    for entry in source.entries() {
        if entry.is_dir() {
            zip.add_directory(&entry.name, entry.mtime)?;
        } else {
            let content = source
                .content(entry)
                .with_context(|| format!("cannot read {}", entry.name))?;
            zip.add_file(&entry.name, entry.mtime, &content)?;
        }
        n += 1;
    }
    Ok(n)
}

/// The decrypted copy's member name: `name.decrypted.ext` in the original's directory,
/// then `name.decrypted-2.ext`, … when a member has that name, as an export names it.
fn free_name(original: &str, taken: &HashSet<String>, added: &[String]) -> String {
    let (dir, base) = match original.rsplit_once('/') {
        Some((dir, base)) => (format!("{dir}/"), base),
        None => (String::new(), original),
    };
    (1..)
        .map(|n| format!("{dir}{}", decrypted_name_numbered(base, n)))
        .find(|name| is_free(name, taken, added))
        .expect("an unbounded range always yields a free name")
}

/// `first`, or `first-2`, `first-3`… : the first name no member has.
fn numbered_free(first: String, taken: &HashSet<String>, added: &[String]) -> String {
    if is_free(&first, taken, added) {
        return first;
    }
    (2..)
        .map(|n| format!("{first}-{n}"))
        .find(|name| is_free(name, taken, added))
        .expect("an unbounded range always yields a free name")
}

/// Whether no member has `name`, compared as [`fold_case`] does: two names differing
/// only in case or accent form would be one file once extracted on Windows or macOS.
fn is_free(name: &str, taken: &HashSet<String>, added: &[String]) -> bool {
    let folded = fold_case(name);
    !taken.contains(&folded) && !added.iter().any(|a| fold_case(a) == folded)
}

/// Whether two paths name the same file (both must exist for a `true`).
fn same_file(a: &Path, b: &Path) -> bool {
    match (fs::canonicalize(a), fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::models::Entry;
    use crate::core::source::zip::ZipSource;
    use crate::ops::decrypting::Derived;
    use crate::report::publish::sidecar_path;

    /// "Decrypts" any member named `*.enc` by upper-casing it; fails on `bad.enc`.
    struct Upper;

    impl DerivedCopy for Upper {
        fn wants(&self, entry: &Entry) -> bool {
            entry.name.ends_with(".enc")
        }
        fn derive(&self, entry: &Entry, content: &[u8]) -> Option<Result<Derived, String>> {
            if entry.name.ends_with("bad.enc") {
                return Some(Err("no key".into()));
            }
            Some(Ok(Derived {
                bytes: content.to_ascii_uppercase(),
                note: "upper".into(),
            }))
        }
    }

    fn original(path: &Path) {
        let mut zip = ZipWriter::create(path).unwrap();
        zip.add_directory("app", Some(1_700_000_000)).unwrap();
        zip.add_file("app/db.enc", Some(1_700_000_001), b"secret")
            .unwrap();
        zip.add_file("app/bad.enc", Some(1_700_000_002), b"x")
            .unwrap();
        zip.add_file("app/plain.txt", Some(1_700_000_003), b"hello")
            .unwrap();
        zip.finish().unwrap();
    }

    #[test]
    fn extends_the_original_verbatim_and_adds_decrypted_copies() {
        let dir = tempfile::tempdir().unwrap();
        let src_path = dir.path().join("case.zip");
        original(&src_path);
        let src_bytes = fs::read(&src_path).unwrap();
        let source = ZipSource::open(&src_bytes).unwrap();
        let out = dir.path().join("case.decrypted.zip");

        let outcome = write(DecryptedZipRequest {
            source: &source,
            original_zip: Some(&src_path),
            derive: &Upper,
            output: &out,
            force: false,
            run: &RunInfo::default(),
        })
        .unwrap();
        assert_eq!(outcome.original_members, 4);
        assert_eq!(outcome.decrypted.len(), 1);
        assert_eq!(outcome.failed.len(), 1);
        assert_eq!(outcome.decrypted[0].member, "app/db.decrypted.enc");

        let out_bytes = fs::read(&out).unwrap();
        // The original members are the first bytes of the output, unchanged.
        let cd = crate::core::source::zip::find_cd_location(&src_bytes, 0).unwrap();
        let prefix = cd.cd_offset as usize;
        assert_eq!(&out_bytes[..prefix], &src_bytes[..prefix]);

        let read = ZipSource::open(&out_bytes).unwrap();
        let names: Vec<&str> = read.entries().iter().map(|e| e.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "app/",
                "app/db.enc",
                "app/bad.enc",
                "app/plain.txt",
                "app/db.decrypted.enc",
                RECORD_MEMBER
            ]
        );
        let copy = &read.entries()[4];
        assert_eq!(&*read.content(copy).unwrap(), b"SECRET");
        assert_eq!(
            copy.mtime,
            Some(1_700_000_001),
            "the copy keeps its original's time"
        );
        assert!(sidecar_path(&out).exists());
    }

    #[test]
    fn refuses_to_overwrite_the_source() {
        let dir = tempfile::tempdir().unwrap();
        let src_path = dir.path().join("case.zip");
        original(&src_path);
        let src_bytes = fs::read(&src_path).unwrap();
        let source = ZipSource::open(&src_bytes).unwrap();
        let err = write(DecryptedZipRequest {
            source: &source,
            original_zip: Some(&src_path),
            derive: &Upper,
            output: &src_path,
            force: true,
            run: &RunInfo::default(),
        })
        .err()
        .unwrap();
        assert!(err.to_string().contains("source archive"), "{err}");
    }

    #[test]
    fn a_taken_name_gets_a_number() {
        let taken: HashSet<String> = [fold_case("a/X.Decrypted.db")].into_iter().collect();
        assert_eq!(free_name("a/x.db", &taken, &[]), "a/x.decrypted-2.db");
        assert_eq!(free_name("y", &HashSet::new(), &[]), "y.decrypted");
    }
}
