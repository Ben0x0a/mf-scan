//! Input resolution: turn the operand paths into the sources to scan.
//!
//! Defines: [`ResolvedSource`] (a resolved operand plus its display label and
//! [`ResolvedKind`]), [`resolve_sources`] (apply `--dir-mode` to the operands),
//! [`resolve_file`] (decide what one file is), [`open_archive`] (memory-map an archive
//! read-only), and [`with_operand_source`] (the single open/dispatch point that
//! opens an [`Operand`] as a live [`Source`] for a closure).
//! Used by: every `run` orchestrator.
//! Uses: `memmap2` (read-only mmap), `mf_scan::core::source` (the `Source` trait and the
//! `ZipSource`/`FolderSource` openers), `anyhow`, the std library.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use std::cell::RefCell;

use anyhow::{Context, Result};
use memmap2::Mmap;

use mf_scan::core::source::bytes::BytesSource;
use mf_scan::core::source::folder::FolderSource;
use mf_scan::core::source::ranged::RangedZipSource;
use mf_scan::core::source::sevenz::{SevenZSource, Unlock};
use mf_scan::core::source::tar::TarSource;
use mf_scan::core::source::zip::ZipSource;
use mf_scan::core::source::{Container, Source, is_tar_name, sniff_container};
use mf_scan::ops::rebuild::BackupKind;
use mf_scan::platform::android::backup::AndroidBackupSource;
use mf_scan::platform::ios::backup::common::BackupStructure;
use mf_scan::platform::ios::backup::password::BackupRecord;
use mf_scan::platform::ios::backup::profile;
use mf_scan::platform::ios::backup::source::BackupSource;

/// How an archive's bytes are read: memory-mapped, positioned reads, or chosen
/// automatically from whether the source is on a network mount.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum IoMode {
    /// Positioned reads for a remote (SMB/NFS) source, memory-map otherwise.
    Auto,
    /// Always memory-map (fast for local files).
    Mmap,
    /// Always use positioned reads (no whole-file map) — for network shares.
    Ranged,
}

impl IoMode {
    /// Whether to open `path` with the positioned-read [`RangedZipSource`] rather
    /// than a memory map. `Auto` consults [`is_remote_path`].
    fn use_ranged(self, path: &Path) -> bool {
        match self {
            IoMode::Mmap => false,
            IoMode::Ranged => true,
            IoMode::Auto => is_remote_path(path),
        }
    }
}

/// The passwords resolved from the CLI flags or their environment variables,
/// threaded through the open path: the backup's (`MFSCAN_BACKUP_PASSWORD`; `None` ⇒
/// try the acquisition defaults) and an encrypted 7z's (`MFSCAN_ARCHIVE_PASSWORD`).
///
/// WHY two: a 7z can hold an encrypted iOS backup, and the two passwords are set by
/// different people (the examiner packing the case, the phone's owner).
#[derive(Clone, Default)]
pub(crate) struct BackupOptions {
    pub(crate) password: Option<String>,
    pub(crate) archive_password: Option<String>,
}

impl BackupOptions {
    /// Resolve the option from the flag value, falling back to the env var when
    /// the flag is absent. WHY env fallback: keeping the password out of the
    /// shell command line avoids it landing in shell history or `ps` output —
    /// forensic hygiene.
    pub(crate) fn resolve(flag: Option<&str>, archive_flag: Option<&str>) -> Self {
        let from = |flag: Option<&str>, var: &str| {
            flag.map(str::to_string)
                .or_else(|| std::env::var(var).ok().filter(|s| !s.is_empty()))
        };
        Self {
            password: from(flag, "MFSCAN_BACKUP_PASSWORD"),
            archive_password: from(archive_flag, "MFSCAN_ARCHIVE_PASSWORD"),
        }
    }
}

/// The operand naming standard input, as in `grep`.
pub(crate) const STDIN_OPERAND: &str = "-";
/// How standard input is named in results.
const STDIN_LABEL: &str = "(standard input)";

/// How a resolved operand is opened by `run`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResolvedKind {
    /// A ZIP archive — opened as a `ZipSource` over its mmap.
    Archive,
    /// A tar archive (plain or compressed) — opened as a `TarSource`.
    Tar,
    /// A 7z archive — decoded and opened as a `SevenZSource`.
    SevenZ,
    /// An Android `adb backup` — decoded and opened as an `AndroidBackupSource`.
    AndroidBackup,
    /// An ordinary file — one loose file, searched as itself.
    LooseFile,
    /// A directory scanned as a folder of loose files — opened as a `FolderSource`.
    Folder,
    /// Standard input, read into memory.
    Stdin,
}

/// Resolve one file operand, deciding what it is from its content.
pub(crate) fn resolve_file(path: &Path) -> Result<ResolvedSource> {
    let kind = match sniff_container(path)? {
        Container::Zip => ResolvedKind::Archive,
        Container::Tar => ResolvedKind::Tar,
        Container::SevenZ => ResolvedKind::SevenZ,
        Container::AndroidBackup => ResolvedKind::AndroidBackup,
        Container::Other => ResolvedKind::LooseFile,
    };
    Ok(ResolvedSource {
        path: path.to_path_buf(),
        label: path.to_string_lossy().into_owned(),
        kind,
    })
}

/// A resolved operand: what to open, the label shown for it, and how to open it.
pub(crate) struct ResolvedSource {
    pub(crate) path: PathBuf,
    pub(crate) label: String,
    pub(crate) kind: ResolvedKind,
}

impl ResolvedSource {
    /// The [`Operand`] to hand to [`with_operand_source`], derived from the resolved
    /// [`ResolvedKind`]. `archive_depth` is only consulted for a folder (nested
    /// `.zip` expansion). Shared so `grep` and `app` map the kind identically.
    pub(crate) fn operand(&self, archive_depth: u32) -> Operand<'_> {
        match self.kind {
            ResolvedKind::Archive => Operand::Archive(&self.path),
            ResolvedKind::Tar => Operand::Tar(&self.path),
            ResolvedKind::SevenZ => Operand::SevenZ(&self.path),
            ResolvedKind::AndroidBackup => Operand::AndroidBackup(&self.path),
            ResolvedKind::LooseFile => Operand::LooseFile(&self.path),
            ResolvedKind::Stdin => Operand::Stdin,
            ResolvedKind::Folder => Operand::Folder {
                path: &self.path,
                archive_depth,
            },
        }
    }
}

/// The outcome of [`resolve_sources`]: what to open, plus what was left out.
pub(crate) struct ResolvedSources {
    pub(crate) sources: Vec<ResolvedSource>,
    /// Non-archive files `-r` walked past. WHY it is counted: `-r` searches archives
    /// only, while a `grep` user expects every file under the directory to be read,
    /// so an uncounted skip would read as a clean negative.
    pub(crate) loose_skipped: usize,
}

/// Collects the backup-unlock provenance the open path may record, and emits the
/// loud stderr line once on the way out.
///
/// WHY a wrapper: both `grep` and `app` open sources through
/// [`with_operand_source`] and then surface the unlock provenance the same way — a
/// stderr line so a DEFAULT-password unlock is impossible to miss. Owning the
/// `RefCell` here keeps that reporting rule in one place. (`diff` deliberately
/// discards provenance, documented there, so it does not use this.)
pub(crate) struct BackupProvenance {
    facts: RefCell<BackupFacts>,
}

/// What the open path learned while recognising a backup source.
///
/// WHY the directory records ride along here rather than through
/// [`crate::core::source::Source`]: they are not files and must not appear in
/// `entries()` (see [`BackupStructure`]), but a caller that rebuilds the tree
/// needs them. This sink already exists to carry backup-specific facts out of the
/// closure, so it carries these too rather than widening the `Source` trait with
/// something only one acquisition type has.
#[derive(Default)]
pub(crate) struct BackupFacts {
    /// Unlock provenance, when the source was a backup.
    pub(crate) record: Option<BackupRecord>,
    /// The backup's directory and symlink records, when the source was a backup.
    pub(crate) structure: Option<BackupStructure>,
    /// Which kind of backup it was.
    pub(crate) kind: Option<BackupKind>,
    /// Whether its payload was truncated or corrupt, so part of it could not be read.
    pub(crate) damaged: bool,
}

impl BackupProvenance {
    pub(crate) fn new() -> Self {
        Self {
            facts: RefCell::new(BackupFacts::default()),
        }
    }

    /// The sink the open path fills when a source is a backup it recognises.
    pub(crate) fn sink(&self) -> &RefCell<BackupFacts> {
        &self.facts
    }

    /// The backup's directory/symlink records, if the source was a backup.
    ///
    /// Readable from inside the `with_operand_source` closure: the sink is filled
    /// when the `BackupSource` is built, which happens before the closure runs.
    pub(crate) fn structure(&self) -> Option<BackupStructure> {
        self.facts.borrow().structure.clone()
    }

    /// Which kind of backup the source was, if it was one.
    pub(crate) fn kind(&self) -> Option<BackupKind> {
        self.facts.borrow().kind
    }

    /// The backup's audit record, if the source was a backup.
    pub(crate) fn record(&self) -> Option<BackupRecord> {
        self.facts.borrow().record.clone()
    }

    /// Whether a backup was damaged, so part of it could not be read.
    pub(crate) fn damaged(&self) -> bool {
        self.facts.borrow().damaged
    }

    /// Emit the stderr provenance line (if any) and return the record so the caller
    /// can also embed it in the scan report.
    pub(crate) fn report(self) -> Option<BackupRecord> {
        let rec = self.facts.into_inner().record;
        if let Some(r) = &rec {
            eprintln!("{}", r.stderr_line());
        }
        rec
    }
}

/// Memory-map an archive read-only.
///
/// SAFETY: the archive is treated as read-only forensic evidence; we do not
/// mutate it and assume it is not concurrently truncated during the scan.
pub(crate) fn open_archive(path: &Path) -> Result<Mmap> {
    let file =
        File::open(path).with_context(|| format!("cannot open archive {}", path.display()))?;
    unsafe { Mmap::map(&file) }.with_context(|| format!("cannot mmap archive {}", path.display()))
}

/// Resolve the operand paths into the sources to scan.
///
/// A file operand resolves by its content: an archive, an Android backup, or else one
/// loose file. `-` is standard input. A directory operand needs one of:
/// - `dir_mode` (`--dir-mode`): scan the directory's files as one folder source;
/// - `recursive` (`-r`): walk the tree and yield each archive (ZIP or tar) as its own
///   source (labelled relative to the directory, so output reads like
///   `sub/case.zip/file`), counting the loose files it does not search.
///
/// The two are mutually exclusive (enforced by the CLI). A directory with neither is
/// rejected, so the operator always states intent — there is no silent default.
pub(crate) fn resolve_sources(
    paths: &[PathBuf],
    dir_mode: bool,
    recursive: bool,
) -> Result<ResolvedSources> {
    let mut sources = Vec::new();
    let mut loose_skipped = 0;
    for arg in paths {
        if arg.as_os_str() == STDIN_OPERAND {
            sources.push(ResolvedSource {
                path: arg.clone(),
                label: STDIN_LABEL.to_string(),
                kind: ResolvedKind::Stdin,
            });
        } else if !arg.is_dir() {
            sources.push(resolve_file(arg)?);
        } else if dir_mode {
            sources.push(ResolvedSource {
                path: arg.clone(),
                label: arg.to_string_lossy().into_owned(),
                kind: ResolvedKind::Folder,
            });
        } else if recursive {
            let mut archives = Vec::new();
            collect_archives(arg, &mut archives, &mut loose_skipped)
                .with_context(|| format!("cannot read directory {}", arg.display()))?;
            archives.sort();
            for archive in archives {
                let label = archive
                    .strip_prefix(arg)
                    .unwrap_or(&archive)
                    .to_string_lossy()
                    .into_owned();
                // Classify each harvested file the same way a directly-named one is, so
                // `-r` and naming the archive give identical treatment.
                let mut resolved = resolve_file(&archive)?;
                resolved.label = label;
                sources.push(resolved);
            }
        } else {
            anyhow::bail!(
                "{} is a directory; pass --dir-mode to scan its files, or -r to search \
                 the archives under it",
                arg.display()
            );
        }
    }
    Ok(ResolvedSources {
        sources,
        loose_skipped,
    })
}

/// One operand to open as a live [`Source`], independent of how it was resolved.
///
/// WHY this small enum exists: the two subcommands describe an operand
/// differently — `grep` drives off a pre-resolved [`ResolvedKind`], `diff` off a
/// raw path plus a `--dir-mode` flag — yet the actual open/dispatch (mmap an
/// archive into a `ZipSource`, or open a directory as a `FolderSource`) is one
/// piece of logic. Funnelling both through this enum means a *third* source kind
/// (a future encrypted iOS backup) is added in ONE match arm here, not in each
/// subcommand's wrapper.
pub(crate) enum Operand<'a> {
    /// A single ZIP archive file — opened as a `ZipSource` over its mmap.
    Archive(&'a Path),
    /// A single tar archive (plain or compressed) — opened as a `TarSource`.
    Tar(&'a Path),
    /// A single 7z archive, decoded and opened as a `SevenZSource`.
    SevenZ(&'a Path),
    /// An Android `adb backup` file.
    AndroidBackup(&'a Path),
    /// One ordinary file, searched as itself.
    LooseFile(&'a Path),
    /// Standard input, read into memory.
    Stdin,
    /// A directory scanned as a folder of loose files, expanding nested `.zip`
    /// files up to `archive_depth` levels.
    Folder { path: &'a Path, archive_depth: u32 },
}

/// Open `operand` as a live [`Source`] and run `f` with it, plus the raw archive
/// bytes for an archive operand (so a caller's `--verify` can hash them); a folder
/// has no single backing buffer, so it passes `None`.
///
/// WHY this is closure-passing rather than returning a `Source`: a `ZipSource`
/// borrows the mmap it reads from, so the mmap must outlive it. Keeping both in
/// this one scope ties their lifetimes together correctly and lets callers nest
/// two of these (diff's two sides) with both backing buffers alive across the
/// inner body. This is the single open/dispatch point both subcommands share.
///
/// Backup decryption is transparent here: if the opened inner source is an
/// ENCRYPTED iOS backup, it is wrapped in a [`BackupSource`] (unlocked with
/// `backup.password` or the acquisition defaults) and that decrypted view is
/// passed to `f`. The unlock provenance is written into `record` for the caller
/// to emit to stderr and the scan report. A non-encrypted backup or non-backup is
/// passed through unchanged.
pub(crate) fn with_operand_source<R>(
    operand: Operand<'_>,
    backup: &BackupOptions,
    io_mode: IoMode,
    record: &RefCell<BackupFacts>,
    f: impl FnOnce(&dyn Source, Option<&[u8]>) -> Result<R>,
) -> Result<R> {
    match operand {
        // A remote (or `--io-mode ranged`) archive is read with positioned reads,
        // never mapped: a multi-GB archive on a network share would otherwise fault
        // page-by-page over the network. The ranged source has no single backing
        // buffer, so `--verify` (which needs the raw bytes) is passed `None`.
        Operand::Archive(path) if io_mode.use_ranged(path) => {
            let source = RangedZipSource::open(path)?;
            with_maybe_backup(&source, backup, record, |s| f(s, None))
        }
        Operand::Archive(path) => {
            let mmap = open_archive(path)?;
            let source = ZipSource::open(&mmap)?;
            with_maybe_backup(&source, backup, record, |s| f(s, Some(&mmap)))
        }
        // Tar keeps its on-disk mapping alive alongside any inflated stream, so
        // `--verify` attests the archive FILE — the `.tar.gz` as stored, not the
        // bytes it inflates to (which would be identical after a re-compression at
        // a different level, and so a weaker attestation).
        Operand::Tar(path) => {
            let source = TarSource::open(path)?;
            with_maybe_backup(&source, backup, record, |s| f(s, Some(source.raw_bytes())))
        }
        // Like tar: `--verify` attests the `.7z` as stored. The decoded files may be an
        // iOS backup, which is then opened as one.
        Operand::SevenZ(path) => {
            let source = SevenZSource::open(path, backup.archive_password.as_deref())?;
            let what = match source.unlock() {
                Unlock::NotEncrypted => None,
                Unlock::Data => Some("encrypted"),
                Unlock::HeaderAndData => Some("encrypted, its list of files too"),
            };
            if let Some(what) = what {
                eprintln!(
                    "7z: {} is {what}; decrypted with the supplied password",
                    path.display()
                );
            }
            with_maybe_backup(&source, backup, record, |s| f(s, Some(source.raw_bytes())))
        }
        Operand::AndroidBackup(path) => {
            let source = AndroidBackupSource::open(path, backup.password.as_deref())?;
            let facts = source.facts().clone();
            if let Some(reason) = &facts.stream_error {
                eprintln!(
                    "⚠ backup: {} is damaged ({reason}); files after that point could not be read",
                    path.display()
                );
            }
            {
                let mut sink = record.borrow_mut();
                sink.damaged = facts.stream_error.is_some();
                sink.kind = Some(BackupKind::Android);
                sink.structure = Some(source.structure());
                let files = source.entries().iter().filter(|e| !e.is_dir()).count();
                sink.record = Some(BackupRecord::new_android(source.provenance(), files, facts));
            }
            f(&source, Some(source.raw_bytes()))
        }
        Operand::LooseFile(path) => {
            let source = FolderSource::open_file(path)?;
            f(&source, None)
        }
        Operand::Stdin => {
            let mut data = Vec::new();
            std::io::stdin()
                .lock()
                .read_to_end(&mut data)
                .context("cannot read standard input")?;
            let source = BytesSource::new(STDIN_LABEL, data);
            f(&source, None)
        }
        Operand::Folder {
            path,
            archive_depth,
        } => {
            let source = FolderSource::open(path, archive_depth)?;
            with_maybe_backup(&source, backup, record, |s| f(s, None))
        }
    }
}

/// Whether `path` lives on a remote (network) filesystem — SMB/NFS/WebDAV — where
/// memory-mapping a large file faults page-by-page over the network.
///
/// Best-effort: uses `statfs` on Unix (the macOS `MNT_LOCAL` flag, or the Linux
/// filesystem-type magic numbers) and returns `false` on any other platform or on
/// error — so an undetected remote source simply uses the default mmap path (the
/// operator can still force `--io-mode ranged`).
#[cfg(target_os = "macos")]
pub(crate) fn is_remote_path(path: &Path) -> bool {
    statfs(path)
        .map(|s| s.f_flags & (libc::MNT_LOCAL as u32) == 0)
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
pub(crate) fn is_remote_path(path: &Path) -> bool {
    // Filesystem-type magics for the network filesystems we care about.
    const NFS: i64 = 0x6969;
    const SMB: i64 = 0x517B;
    const CIFS: i64 = 0xFF53_4D42;
    const SMB2: i64 = 0xFE53_4D42;
    // `f_type` is `i64` on the glibc x86_64 target CI builds (where this cast is a
    // no-op clippy flags), but its width varies by libc/arch (e.g. 32-bit, musl) —
    // the cast normalises it so the `matches!` against the `i64` magics compiles
    // everywhere. Keep it and silence the target-specific lint rather than break
    // the other Linux targets.
    #[allow(clippy::unnecessary_cast)]
    statfs(path)
        .map(|s| matches!(s.f_type as i64, NFS | SMB | CIFS | SMB2))
        .unwrap_or(false)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub(crate) fn is_remote_path(_path: &Path) -> bool {
    false
}

/// Thin `statfs(2)` wrapper used by [`is_remote_path`].
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn statfs(path: &Path) -> Option<libc::statfs> {
    use std::os::unix::ffi::OsStrExt;
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: `c_path` is a valid NUL-terminated C string and `buf` is a fresh,
    // correctly-sized `statfs` the call fully initialises on success.
    unsafe {
        let mut buf = std::mem::zeroed::<libc::statfs>();
        if libc::statfs(c_path.as_ptr(), &mut buf) == 0 {
            Some(buf)
        } else {
            None
        }
    }
}

/// Detect whether `inner` is an iOS backup; if so, wrap it in a [`BackupSource`]
/// (encrypted or plain, chosen by the profile) and pass the logical view to `f`,
/// recording provenance — otherwise pass `inner` unchanged.
///
/// The `BackupSource` borrows `inner`, so both live in this one scope (the same
/// outlives-the-mmap discipline as the caller). An encrypted backup that no
/// candidate password unlocks fails loudly here, naming `--backup-password`.
fn with_maybe_backup<R>(
    inner: &dyn Source,
    backup: &BackupOptions,
    record: &RefCell<BackupFacts>,
    f: impl FnOnce(&dyn Source) -> Result<R>,
) -> Result<R> {
    match profile::detect(inner) {
        Some(p) => {
            // One constructor picks the encrypted vs plain variant from the
            // profile; both present files by logical domain/relativePath, so
            // output and export use the real names and each file is attested
            // against its Manifest.db digest.
            let bs = BackupSource::build(inner, &p, backup.password.as_deref())?;
            {
                let mut facts = record.borrow_mut();
                facts.record = Some(bs.record(&p));
                facts.structure = Some(bs.structure().clone());
                facts.kind = Some(BackupKind::Ios);
            }
            f(&bs)
        }
        // Not a backup at all: search the raw files unchanged.
        None => f(inner),
    }
}

/// Extensions `-r` harvests as archives, besides tars. A Cellebrite `.ufdr` report is
/// a zip; `.ab` is an Android backup.
const ARCHIVE_EXTENSIONS: &[&str] = &["zip", "ufdr", "ab", "7z"];

/// Whether a file's name marks it as an archive for `-r` to harvest.
fn is_archive_name(path: &Path) -> bool {
    is_tar_name(path)
        || path
            .extension()
            .is_some_and(|e| ARCHIVE_EXTENSIONS.iter().any(|x| e.eq_ignore_ascii_case(x)))
}

/// Recursively collect the archives `-r` should scan under `dir` into `out`, counting
/// every other file in `loose`.
///
/// ZIP, tar (plain or compressed), 7z and `.ab` are harvested. WHY tar belongs
/// here: it is a first-class acquisition container everywhere else in the tool, so
/// collecting only `*.zip` made `-r` silently skip every tar acquisition in a case
/// folder — a scope loss the operator had no way to notice.
///
/// What each harvested file then is, is decided by [`resolve_file`], exactly as for a
/// directly-named one.
fn collect_archives(dir: &Path, out: &mut Vec<PathBuf>, loose: &mut usize) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            collect_archives(&path, out, loose)?;
        } else if is_archive_name(&path) {
            out.push(path);
        } else {
            *loose += 1;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// `-r` must harvest tar acquisitions, not just ZIPs.
    ///
    /// Collecting only `*.zip` made `mf-scan grep -r ./cases` silently skip every
    /// `.tar`/`.tar.gz` in a case folder — a scope loss with no visible symptom,
    /// which is the worst kind for a forensic tool.
    #[test]
    fn recursive_harvest_collects_zip_and_tar() {
        let dir = tempdir().expect("tempdir");
        let root = dir.path();
        std::fs::create_dir(root.join("sub")).expect("subdir");
        for rel in [
            "a.zip",
            "sub/b.tar",
            "sub/c.tar.gz",
            "sub/d.tgz",
            "e.ZIP",
            "f.ab",
            "g.7z",
            "notes.txt",
            "image.jpg",
        ] {
            std::fs::write(root.join(rel), b"x").expect("write");
        }

        let mut found = Vec::new();
        let mut loose = 0;
        collect_archives(root, &mut found, &mut loose).expect("walks");
        assert_eq!(loose, 2, "notes.txt and image.jpg are counted as skipped");
        let mut names: Vec<String> = found
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        names.sort();

        assert_eq!(
            names,
            vec![
                "a.zip", "b.tar", "c.tar.gz", "d.tgz", "e.ZIP", "f.ab", "g.7z"
            ],
            "every archive form must be harvested, and nothing else"
        );
    }

    /// A harvested archive must be classified exactly as a directly-named one, or
    /// `-r` would hand a tar to the ZIP reader.
    #[test]
    fn recursive_harvest_classifies_tar_as_tar() {
        let dir = tempdir().expect("tempdir");
        let root = dir.path();
        std::fs::write(root.join("a.zip"), b"x").expect("write");
        std::fs::write(root.join("b.tar.gz"), b"x").expect("write");

        let resolved = resolve_sources(&[root.to_path_buf()], false, true).expect("resolves");
        let kinds: Vec<(String, bool)> = resolved
            .sources
            .iter()
            .map(|r| {
                (
                    r.path.file_name().unwrap().to_string_lossy().into_owned(),
                    matches!(r.kind, ResolvedKind::Tar),
                )
            })
            .collect();

        assert!(kinds.contains(&("a.zip".to_string(), false)), "{kinds:?}");
        assert!(kinds.contains(&("b.tar.gz".to_string(), true)), "{kinds:?}");
    }
}
