//! Folder source: scan a directory's files as a flat list of located entries.
//!
//! Defines: [`FolderSource`], a [`Source`] over a directory on disk. Every regular
//! file under the root (recursively) becomes a [`Entry`]: a loose file read lazily
//! from its own path, or — when `--archive-depth >= 1` — the expanded contents of a
//! nested `.zip` (read into an in-memory arena; see [`crate::source::nested`]).
//! Used by: the binary's `support::sources` (builds it for a `--dir-mode folder`
//! operand) and, through the [`Source`] trait, the search/diff/export engines.
//! Uses: `crate::models::{Entry, Location}`, `crate::source::{nested, zip}`, `std::fs`.
//!
//! Symlinks are not followed (a loop cannot hang the scan, a link cannot escape the
//! tree). Loose files are never loaded until read; only opened nested archives are
//! held in memory.

use std::borrow::Cow;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::models::{Entry, Location};
use crate::source::Source;
use crate::source::{nested, zip};

/// A [`Source`] over a directory on disk.
///
/// The subtree is enumerated up front (names + sizes; nested archives are opened
/// into `blobs`), then file bytes are served lazily: a loose file is read from disk
/// on demand, a nested-archive entry is read from its arena blob.
pub struct FolderSource {
    entries: Vec<Entry>,
    /// Opened nested-archive contents, indexed by [`Location::Nested::archive`].
    blobs: Vec<Vec<u8>>,
}

impl FolderSource {
    /// Walk `root` recursively and build the source. Entry names are each file's path
    /// relative to `root` (using `/` separators). `archive_depth` is how many levels
    /// of nested `.zip` to open and descend into (0 = treat them as opaque files).
    pub fn open(root: &Path, archive_depth: u32) -> Result<Self> {
        let mut entries = Vec::new();
        let mut blobs = Vec::new();
        collect(root, root, archive_depth, &mut entries, &mut blobs)
            .with_context(|| format!("cannot scan folder {}", root.display()))?;
        // Deterministic order (the OS does not guarantee read_dir ordering), so
        // results and the coverage report are stable across runs and platforms.
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(Self { entries, blobs })
    }
}

impl Source for FolderSource {
    fn entries(&self) -> &[Entry] {
        &self.entries
    }

    fn content(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        match &entry.location {
            Location::Loose { path } => {
                let bytes =
                    fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
                Ok(Cow::Owned(bytes))
            }
            // A file inside an opened nested archive: read its range from the blob.
            Location::Nested {
                archive,
                method,
                data_offset,
                data_len,
            } => {
                let blob = self.blobs.get(*archive).with_context(|| {
                    format!(
                        "nested archive index {archive} out of range for {}",
                        entry.name
                    )
                })?;
                zip::read_range(
                    blob,
                    *method,
                    *data_offset,
                    *data_len,
                    entry.uncompressed_size,
                    &entry.name,
                )
            }
            Location::Zip { .. } => bail!(
                "FolderSource::content called on a top-level ZIP entry: {}",
                entry.name
            ),
        }
    }
}

/// Recursively collect files under `dir` into `entries`. A regular file becomes a
/// loose entry; a `.zip` is expanded into nested entries when `depth >= 1` (falling
/// back to an opaque loose file if it cannot be read or parsed). Directories are
/// descended; symlinks are skipped.
fn collect(
    root: &Path,
    dir: &Path,
    depth: u32,
    entries: &mut Vec<Entry>,
    blobs: &mut Vec<Vec<u8>>,
) -> Result<()> {
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
            collect(root, &path, depth, entries, blobs)?;
            continue;
        }
        if !file_type.is_file() {
            continue;
        }
        let name = relative_name(root, &path);

        // A nested `.zip`, with depth budget: read and expand it. On any failure
        // (unreadable, unparseable) fall back to treating it as an opaque loose file.
        if depth >= 1
            && has_zip_extension(&path)
            && let Ok(bytes) = fs::read(&path)
            && nested::expand(bytes, &format!("{name}/"), depth - 1, entries, blobs).is_ok()
        {
            continue;
        }

        let meta = child.metadata().ok();
        let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
        // Last-modified as Unix epoch seconds, best-effort (used by `diff`).
        let mtime = meta
            .as_ref()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs());
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

/// True when `path` has a `.zip` extension (case-insensitive).
fn has_zip_extension(path: &Path) -> bool {
    path.extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("zip"))
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

        let src = FolderSource::open(dir.path(), 0).unwrap();
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
