//! Input resolution: turn the operand paths into the sources to scan.
//!
//! Defines: [`ResolvedSource`] (a resolved operand: an archive file or a folder,
//! plus its display label and [`ResolvedKind`]), [`resolve_sources`] (apply
//! `--dir-mode` to the operands), and [`open_archive`] (memory-map an archive
//! read-only).
//! Used by: `run::grep` and `run::export` (which open the resolved sources).
//! Uses: `memmap2` (read-only mmap), `crate::cli::DirMode`, `anyhow`, the std library.

use std::fs::File;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use memmap2::Mmap;

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
