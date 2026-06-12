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

use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::models::{Entry, Location};
use crate::source::{Content, Source};
use crate::source::{nested, zip};

/// Loose files at or above this size are memory-mapped instead of read onto the
/// heap. Mirrors the top-level ZIP path (which is always an mmap): without it a
/// 4 GB video in a folder scan would be fully materialised just to be searched.
/// Small files stay on the simple read path — a map costs syscalls and page
/// faults that only pay off once the copy is expensive.
const MMAP_THRESHOLD: u64 = 16 * 1024 * 1024;

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
        Self::open_with_arena_budget(root, archive_depth, nested::NESTED_ARENA_BUDGET)
    }

    /// Like [`FolderSource::open`], but with an explicit cap on the bytes the
    /// nested-archive arena may hold. Opening more nested archives than the
    /// budget allows fails loudly (crafted archives-of-archives could otherwise
    /// exhaust memory at depth 1). Exposed for tests and callers that need a
    /// tighter bound; `open` uses the built-in default.
    pub fn open_with_arena_budget(root: &Path, archive_depth: u32, budget: u64) -> Result<Self> {
        let mut entries = Vec::new();
        let mut blobs = Vec::new();
        let mut budget = budget;
        collect(
            root,
            root,
            archive_depth,
            &mut entries,
            &mut blobs,
            &mut budget,
        )
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

    fn content(&self, entry: &Entry) -> Result<Content<'_>> {
        match &entry.location {
            Location::Loose { path } => {
                let file = fs::File::open(path)
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
                let bytes =
                    fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
                Ok(Content::Owned(bytes))
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
    budget: &mut u64,
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
            collect(root, &path, depth, entries, blobs, budget)?;
            continue;
        }
        if !file_type.is_file() {
            continue;
        }
        let name = relative_name(root, &path);

        // A nested `.zip`, with depth budget: read and expand it. An unreadable or
        // unparseable one falls back to an opaque loose file; an exhausted arena
        // budget aborts the scan loudly (it is a resource limit, not a bad file).
        if depth >= 1 && has_zip_extension(&path) {
            // WHY pre-read budget check: fs::read materialises the entire file on
            // the heap. A 20 GB inner zip would be fully loaded *before* expand()
            // checked it against the remaining budget. Checking the on-disk size
            // first means we never allocate what we would immediately refuse —
            // important because the budget exists precisely to prevent exhaustion.
            // Note: we keep the in-expand check too (defense in depth; it also
            // guards the recursive in-memory pending path).
            let file_size = child.metadata().ok().map(|m| m.len()).unwrap_or(0);
            if file_size > *budget {
                return Err(anyhow::Error::new(nested::ArenaBudgetExceeded {
                    budget: nested::NESTED_ARENA_BUDGET,
                }));
            }
            if let Ok(bytes) = fs::read(&path) {
                match nested::expand(
                    bytes,
                    &format!("{name}/"),
                    depth - 1,
                    entries,
                    blobs,
                    budget,
                ) {
                    Ok(()) => continue,
                    Err(e) if e.is::<nested::ArenaBudgetExceeded>() => return Err(e),
                    Err(_) => {} // fall through to the opaque loose-file entry
                }
            }
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

    /// A nested `.zip` larger than the arena budget must be rejected BEFORE being
    /// read into memory — not after.
    ///
    /// WHY: `fs::read` materialises the entire file on the heap. A 20 GB inner zip
    /// would be fully allocated before `nested::expand` could reject it. The
    /// pre-read stat check ensures we never allocate what the budget disallows.
    /// Setting a tiny budget (1 byte) means even a small file triggers the guard.
    #[test]
    fn nested_zip_larger_than_budget_rejected_before_read() {
        let dir = tempdir().unwrap();
        // Write a file with a `.zip` extension that is larger than the tiny budget
        // we will set.  Its contents do not need to be a valid ZIP — the budget
        // check fires before fs::read, so the file is never loaded or parsed.
        let zip_path = dir.path().join("large.zip");
        fs::write(&zip_path, b"not a real zip but definitely > 1 byte").unwrap();

        // Budget of 1 byte: any file bigger than that must be refused immediately.
        let result = FolderSource::open_with_arena_budget(dir.path(), 1, 1);
        let err = match result {
            Ok(_) => panic!("expected ArenaBudgetExceeded but got Ok"),
            Err(e) => e,
        };
        assert!(
            err.is::<nested::ArenaBudgetExceeded>(),
            "expected ArenaBudgetExceeded, got: {err}"
        );
    }
}
