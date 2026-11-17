//! An editable copy of a finished export, for analysis that needs to write.
//!
//! Defines: [`work_copy`] and its result [`WorkCopy`].
//! Used by: the binary's `--work-copy` flag (`grep`/`find`/`diff --export`,
//! `app export`, `export`).
//! Uses: `core::util::sha256_hex` (each copy is checked against its original).
//!
//! WHY: an export's files are read-only, because they are evidence. Tools that open a
//! SQLite database read-write (to replay its `-wal`, or by default) then fail, so the
//! examiner gets a second tree, identical but writable, beside the first. The export
//! itself is never touched.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::core::util::sha256_hex;

/// The suffix of a work copy's folder: `out/` gets `out.work/` beside it.
const WORK_SUFFIX: &str = ".work";

/// A finished work copy.
pub struct WorkCopy {
    /// The copy's root folder.
    pub path: PathBuf,
    /// How many files it holds, each checked identical to its original.
    pub files: usize,
}

/// Copy the export at `dir` to `<dir>.work/`, every file writable and byte-for-byte
/// checked against its original. Refuses when `<dir>.work` already exists, so an
/// earlier copy (perhaps already edited) is never overwritten.
pub fn work_copy(dir: &Path) -> Result<WorkCopy> {
    let mut name = dir
        .file_name()
        .context("the export folder has no name")?
        .to_os_string();
    name.push(WORK_SUFFIX);
    let path = dir.with_file_name(name);
    if path.exists() {
        bail!(
            "{} already exists; move it away to make a new work copy",
            path.display()
        );
    }
    let files = copy_tree(dir, &path)?;
    Ok(WorkCopy { path, files })
}

/// Copy the tree at `from` to `to`, returning how many files were copied.
fn copy_tree(from: &Path, to: &Path) -> Result<usize> {
    fs::create_dir_all(to).with_context(|| format!("cannot create {}", to.display()))?;
    let mut files = 0;
    for entry in fs::read_dir(from).with_context(|| format!("cannot read {}", from.display()))? {
        let entry = entry?;
        let source = entry.path();
        let target = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            files += copy_tree(&source, &target)?;
        } else {
            copy_file(&source, &target)?;
            files += 1;
        }
    }
    Ok(files)
}

/// Copy one file, make the copy writable, and check it matches the original.
fn copy_file(source: &Path, target: &Path) -> Result<()> {
    fs::copy(source, target)
        .with_context(|| format!("cannot copy {} to {}", source.display(), target.display()))?;
    make_writable(target)?;
    let original = fs::read(source).with_context(|| format!("cannot read {}", source.display()))?;
    let copy = fs::read(target).with_context(|| format!("cannot read {}", target.display()))?;
    if sha256_hex(&original) != sha256_hex(&copy) {
        bail!("the copy of {} differs from the original", source.display());
    }
    Ok(())
}

/// Give the owner write access back (Unix), or clear the read-only flag (Windows).
pub(crate) fn make_writable(path: &Path) -> Result<()> {
    let mut permissions = fs::metadata(path)
        .with_context(|| format!("cannot read {}", path.display()))?
        .permissions();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Owner write only: `set_readonly(false)` would make the file world-writable.
        permissions.set_mode(permissions.mode() | 0o200);
    }
    #[cfg(not(unix))]
    {
        // On Windows the read-only attribute is the whole permission model here.
        #[allow(clippy::permissions_set_readonly_false)]
        permissions.set_readonly(false);
    }
    fs::set_permissions(path, permissions)
        .with_context(|| format!("cannot make {} writable", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::export::write_read_only;

    #[test]
    fn copies_a_read_only_export_into_a_writable_twin() {
        let root = tempfile::tempdir().unwrap();
        let export = root.path().join("out");
        fs::create_dir_all(export.join("db_1234")).unwrap();
        write_read_only(&export.join("db_1234/a.db"), b"evidence").unwrap();
        write_read_only(&export.join("export-report.json"), b"{}").unwrap();
        assert!(
            fs::metadata(export.join("db_1234/a.db"))
                .unwrap()
                .permissions()
                .readonly()
        );

        let copy = work_copy(&export).unwrap();
        assert_eq!(copy.path, root.path().join("out.work"));
        assert_eq!(copy.files, 2);
        let twin = copy.path.join("db_1234/a.db");
        assert_eq!(fs::read(&twin).unwrap(), b"evidence");
        assert!(!fs::metadata(&twin).unwrap().permissions().readonly());
        fs::write(&twin, b"edited").unwrap();
        assert_eq!(fs::read(export.join("db_1234/a.db")).unwrap(), b"evidence");

        // A second work copy never overwrites the first.
        assert!(work_copy(&export).is_err());
    }
}
