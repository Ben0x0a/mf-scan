//! Folder source: scan a directory's files as a flat list of located entries.
//!
//! Defines: [`FolderSource`], a [`Source`] over a directory on disk. Every regular
//! file under the root (recursively) becomes an [`Entry`]: a loose file read lazily
//! from its own path. Archives inside it are opened by `expand` (`--archive-depth`),
//! as for any other source.
//! Used by: the binary's `support::sources` (builds it for a `--dir-mode folder`
//! operand, or one loose file) and, through the [`Source`] trait, the
//! search/diff/export engines.
//! Uses: `crate::core::models::{Entry, Location}`, `std::fs`, `memmap2`.
//!
//! Symlinks are not followed (a loop cannot hang the scan, a link cannot escape the
//! tree). Files are never loaded until read.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::core::models::{Entry, Location};
use crate::core::source::{Content, Source};

/// Loose files at or above this size are memory-mapped instead of read onto the
/// heap. Mirrors the top-level ZIP path (which is always an mmap): without it a
/// 4 GB video in a folder scan would be fully materialised just to be searched.
/// Small files stay on the simple read path — a map costs syscalls and page
/// faults that only pay off once the copy is expensive.
const MMAP_THRESHOLD: u64 = 16 * 1024 * 1024;

/// A [`Source`] over a directory on disk.
///
/// The subtree is enumerated up front (names + sizes), then file bytes are served
/// lazily, read from disk on demand.
pub struct FolderSource {
    entries: Vec<Entry>,
}

impl FolderSource {
    /// Walk `root` recursively and build the source. Entry names are each file's path
    /// relative to `root` (using `/` separators).
    pub fn open(root: &Path) -> Result<Self> {
        let mut entries = Vec::new();
        collect(root, root, &mut entries)
            .with_context(|| format!("cannot scan folder {}", root.display()))?;
        // Deterministic order (the OS does not guarantee read_dir ordering), so
        // results and the coverage report are stable across runs and platforms.
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(Self { entries })
    }

    /// A source holding the one loose file at `path`, named by its file name.
    pub fn open_file(path: &Path) -> Result<Self> {
        let meta = fs::metadata(path).with_context(|| format!("cannot read {}", path.display()))?;
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.display().to_string());
        Ok(Self {
            entries: vec![Entry {
                name,
                uncompressed_size: meta.len(),
                mtime: unix_mtime(&meta),
                location: Location::Loose {
                    path: path.to_path_buf(),
                },
            }],
        })
    }
}

/// A file's last-modified time as Unix epoch seconds, best-effort (used by `diff`).
fn unix_mtime(meta: &fs::Metadata) -> Option<u64> {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
}

impl Source for FolderSource {
    fn entries(&self) -> &[Entry] {
        &self.entries
    }

    fn content(&self, entry: &Entry) -> Result<Content<'_>> {
        match &entry.location {
            Location::Loose { path } => {
                use std::io::Read;
                let mut file = fs::File::open(path)
                    .with_context(|| format!("cannot read {}", path.display()))?;
                let len = file
                    .metadata()
                    .with_context(|| format!("cannot stat {}", path.display()))?
                    .len();
                if len >= MMAP_THRESHOLD {
                    // SAFETY: the map is read-only. A file mutated while mapped
                    // could yield torn reads — the same hazard the top-level
                    // archive mmap already accepts for evidence opened read-only.
                    let map = unsafe { memmap2::Mmap::map(&file) }
                        .with_context(|| format!("cannot map {}", path.display()))?;
                    return Ok(Content::Mapped(map));
                }
                // Read from the handle already opened above rather than re-opening
                // the path with `fs::read` — one `open()` syscall per small file, not
                // two, which adds up over a backup of hundreds of thousands of files.
                // The size hint is exact (we just stat'd it), so the buffer is sized
                // once with no growth reallocations.
                let mut bytes = Vec::with_capacity(len as usize);
                file.read_to_end(&mut bytes)
                    .with_context(|| format!("cannot read {}", path.display()))?;
                Ok(Content::Owned(bytes))
            }
            Location::Zip { .. }
            | Location::RangedZip { .. }
            | Location::Nested { .. }
            | Location::Tar { .. }
            | Location::SevenZ { .. } => bail!(
                "FolderSource::content called on an archive entry: {}",
                entry.name
            ),
        }
    }

    /// A loose file large enough to matter is mapped, not read (see
    /// `MMAP_THRESHOLD`); a smaller one is read, and is small.
    fn reads_in_place(&self, _entry: &Entry) -> bool {
        true
    }

    /// The first `max` bytes of a loose file, read alone: what `expand` looks at to
    /// tell an archive, without reading every file of the folder twice.
    fn content_head(&self, entry: &Entry, max: usize) -> Result<Content<'_>> {
        use std::io::Read;
        let Location::Loose { path } = &entry.location else {
            return self.content(entry);
        };
        let file =
            fs::File::open(path).with_context(|| format!("cannot read {}", path.display()))?;
        let mut head = Vec::with_capacity(max);
        file.take(max as u64)
            .read_to_end(&mut head)
            .with_context(|| format!("cannot read {}", path.display()))?;
        Ok(Content::Owned(head))
    }
}

/// Recursively collect files under `dir` into `entries`: each regular file a loose
/// entry. Directories are descended; symlinks are skipped.
fn collect(root: &Path, dir: &Path, entries: &mut Vec<Entry>) -> Result<()> {
    let mut children: Vec<fs::DirEntry> =
        fs::read_dir(dir)?.collect::<std::io::Result<Vec<_>>>()?;
    children.sort_by_key(|e| e.path());
    for child in children {
        let file_type = child.file_type()?;
        if file_type.is_symlink() {
            continue;
        }
        let path = child.path();
        if file_type.is_dir() {
            collect(root, &path, entries)?;
            continue;
        }
        if !file_type.is_file() {
            continue;
        }
        let name = relative_name(root, &path);

        let meta = child.metadata().ok();
        let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
        let mtime = meta.as_ref().and_then(unix_mtime);
        entries.push(Entry {
            name,
            uncompressed_size: size,
            mtime,
            location: Location::Loose { path },
        });
    }
    Ok(())
}

/// The path of `file` relative to `root`, with `/` separators.
fn relative_name(root: &Path, file: &Path) -> String {
    file.strip_prefix(root)
        .unwrap_or(file)
        .to_string_lossy()
        .replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn enumerates_files_recursively_with_relative_names() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join("sub/deep")).unwrap();
        fs::write(dir.path().join("a.txt"), b"alpha").unwrap();
        fs::write(dir.path().join("sub/b.txt"), b"bravo").unwrap();
        fs::write(dir.path().join("sub/deep/c.txt"), b"charlie!").unwrap();

        let src = FolderSource::open(dir.path()).unwrap();
        let names: Vec<&str> = src.entries().iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["a.txt", "sub/b.txt", "sub/deep/c.txt"]);

        // Sizes are read from the filesystem; content is read lazily.
        let c = &src.entries()[2];
        assert_eq!(c.uncompressed_size, 8);
        assert_eq!(&*src.content(c).unwrap(), b"charlie!");

        // The reported size is also the byte_size sum for the coverage report.
        assert_eq!(src.byte_size(), 5 + 5 + 8);
    }
}
