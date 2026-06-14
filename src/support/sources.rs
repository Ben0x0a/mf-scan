//! Input resolution: turn the operand paths into the sources to scan.
//!
//! Defines: [`ResolvedSource`] (a resolved operand: an archive file or a folder,
//! plus its display label and [`ResolvedKind`]), [`resolve_sources`] (apply
//! `--dir-mode` to the operands), [`open_archive`] (memory-map an archive
//! read-only), and [`with_operand_source`] (the single open/dispatch point that
//! opens an [`Operand`] as a live [`Source`] for a closure).
//! Used by: `run::grep`, `run::diff` and `run::export` (which open the resolved
//! sources).
//! Uses: `memmap2` (read-only mmap), `mf_scan::source` (the `Source` trait and the
//! `ZipSource`/`FolderSource` openers), `anyhow`, the std library.

use std::fs::File;
use std::path::{Path, PathBuf};

use std::cell::RefCell;

use anyhow::{Context, Result};
use memmap2::Mmap;

use mf_scan::ios::backup::password::BackupRecord;
use mf_scan::ios::backup::profile;
use mf_scan::ios::backup::source::BackupSource;
use mf_scan::source::Source;
use mf_scan::source::folder::FolderSource;
use mf_scan::source::ranged::RangedZipSource;
use mf_scan::source::zip::ZipSource;

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

/// The backup password resolved from the CLI flag or the `MFSCAN_BACKUP_PASSWORD`
/// environment variable, threaded through the open path so an encrypted backup
/// can be unlocked. `None` ⇒ try the acquisition defaults.
#[derive(Clone, Default)]
pub(crate) struct BackupOptions {
    pub(crate) password: Option<String>,
}

impl BackupOptions {
    /// Resolve the option from the flag value, falling back to the env var when
    /// the flag is absent. WHY env fallback: keeping the password out of the
    /// shell command line avoids it landing in shell history or `ps` output —
    /// forensic hygiene.
    pub(crate) fn resolve(flag: Option<&str>) -> Self {
        let password = flag.map(str::to_string).or_else(|| {
            std::env::var("MFSCAN_BACKUP_PASSWORD")
                .ok()
                .filter(|s| !s.is_empty())
        });
        Self { password }
    }
}

/// How a resolved operand is opened by `run`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResolvedKind {
    /// A single archive file — opened as a `ZipSource` over its mmap.
    Archive,
    /// A directory scanned as a folder of loose files — opened as a `FolderSource`.
    Folder,
}

/// A resolved operand: what to open, the label shown for it, and how to open it.
pub(crate) struct ResolvedSource {
    pub(crate) path: PathBuf,
    pub(crate) label: String,
    pub(crate) kind: ResolvedKind,
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
/// A file operand always resolves to an archive (a directly named `.zip` is always
/// expanded). A directory operand needs one of:
/// - `dir_mode` (`--dir-mode`): scan the directory's files as one folder source;
/// - `recursive` (`-r`): walk the tree and yield each `*.zip` as its own archive source
///   (labelled relative to the directory, so output reads like `sub/case.zip/file`).
///
/// The two are mutually exclusive (enforced by the CLI). A directory with neither is
/// rejected, so the operator always states intent — there is no silent default.
pub(crate) fn resolve_sources(
    paths: &[PathBuf],
    dir_mode: bool,
    recursive: bool,
) -> Result<Vec<ResolvedSource>> {
    let mut sources = Vec::new();
    for arg in paths {
        if !arg.is_dir() {
            sources.push(ResolvedSource {
                path: arg.clone(),
                label: arg.to_string_lossy().into_owned(),
                kind: ResolvedKind::Archive,
            });
        } else if dir_mode {
            sources.push(ResolvedSource {
                path: arg.clone(),
                label: arg.to_string_lossy().into_owned(),
                kind: ResolvedKind::Folder,
            });
        } else if recursive {
            let mut zips = Vec::new();
            collect_zips(arg, &mut zips)
                .with_context(|| format!("cannot read directory {}", arg.display()))?;
            zips.sort();
            for zip in zips {
                let label = zip
                    .strip_prefix(arg)
                    .unwrap_or(&zip)
                    .to_string_lossy()
                    .into_owned();
                sources.push(ResolvedSource {
                    path: zip,
                    label,
                    kind: ResolvedKind::Archive,
                });
            }
        } else {
            anyhow::bail!(
                "{} is a directory; pass --dir-mode to scan its files, or -r to search \
                 the *.zip files under it",
                arg.display()
            );
        }
    }
    Ok(sources)
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
    /// A single archive file — opened as a `ZipSource` over its mmap.
    Archive(&'a Path),
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
    record: &RefCell<Option<BackupRecord>>,
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
    record: &RefCell<Option<BackupRecord>>,
    f: impl FnOnce(&dyn Source) -> Result<R>,
) -> Result<R> {
    match profile::detect(inner) {
        Some(p) => {
            // One constructor picks the encrypted vs plain variant from the
            // profile; both present files by logical domain/relativePath, so
            // output and export use the real names and each file is attested
            // against its Manifest.db digest.
            let bs = BackupSource::build(inner, &p, backup.password.as_deref())?;
            *record.borrow_mut() = Some(bs.record(&p));
            f(&bs)
        }
        // Not a backup at all: search the raw files unchanged.
        None => f(inner),
    }
}

/// Recursively collect `*.zip` files under `dir` into `out`.
fn collect_zips(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            collect_zips(&path, out)?;
        } else if path
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("zip"))
        {
            out.push(path);
        }
    }
    Ok(())
}
