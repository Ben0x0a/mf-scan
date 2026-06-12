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

use anyhow::{Context, Result};
use memmap2::Mmap;

use mf_scan::source::Source;
use mf_scan::source::folder::FolderSource;
use mf_scan::source::zip::ZipSource;

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
pub(crate) fn with_operand_source<R>(
    operand: Operand<'_>,
    f: impl FnOnce(&dyn Source, Option<&[u8]>) -> Result<R>,
) -> Result<R> {
    match operand {
        Operand::Archive(path) => {
            let mmap = open_archive(path)?;
            let source = ZipSource::open(&mmap)?;
            f(&source, Some(&mmap))
        }
        Operand::Folder {
            path,
            archive_depth,
        } => {
            let source = FolderSource::open(path, archive_depth)?;
            f(&source, None)
        }
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
