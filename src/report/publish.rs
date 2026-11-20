//! Publishing a written archive, failing closed: getting its destination ready, the
//! partial file it is written to, the read-back check, the move into place with its
//! `.sha256` sidecar, and the read-only flag on both.
//!
//! Defines: [`prepare`], [`PartialFile`], [`Reservation`] and [`reserve`] (an export's
//! name, claimed before it is written), [`check_and_hash`] and [`member_count`] (the
//! read-back), [`publish_new`] (never replaces), [`publish_replacing`] (for
//! `--force`), [`sidecar_path`].
//! Used by: `report::export::write` (every export), `report::rebuild_zip` (`backup
//! rebuild`) and `report::decrypted_zip` (`decrypt --to`).
//! Uses: `core::source::zip::ZipSource` (the read-back), `core::util::sha256_hex`.
//!
//! WHY one module: the three archive writers share these steps, and each writer
//! depending on another's module for them tied them together. An export never
//! replaces anything: it goes through [`reserve`] and [`publish_new`] only; the
//! replacing publish is for the two writers whose `--force` asks for it.

use std::fs;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::core::source::Source;
use crate::core::source::zip::ZipSource;
use crate::core::util::sha256_hex;

/// Get `output` ready to be written, and return the partial file beside it: refuse a
/// folder, refuse an archive already there (unless `force`, for a writer that offers
/// `--force`; `None` for an export, which never replaces one), create its folder.
pub(crate) fn prepare(output: &Path, force: Option<bool>) -> Result<PartialFile> {
    if output.is_dir() {
        bail!(
            "{} is a directory; the archive must be a file",
            output.display()
        );
    }
    match force {
        _ if !output.exists() => {}
        None => bail!(
            "{} already exists; an export never replaces one",
            output.display()
        ),
        Some(false) => bail!(
            "{} already exists; pass --force to replace it",
            output.display()
        ),
        Some(true) => {}
    }
    if let Some(parent) = output.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)
            .with_context(|| format!("cannot create {}", parent.display()))?;
    }
    Ok(PartialFile::beside(output))
}

/// The temporary file an archive is written to beside its destination; removed on
/// drop unless it was moved into place, so a failed run leaves nothing behind.
pub(crate) struct PartialFile(pub(crate) PathBuf);

impl PartialFile {
    /// The partial file for `output`: `<name>.partial-<process id>` beside it.
    pub(crate) fn beside(output: &Path) -> Self {
        let mut name = output.file_name().unwrap_or_default().to_os_string();
        name.push(format!(".partial-{}", std::process::id()));
        Self(output.with_file_name(name))
    }
}

impl Drop for PartialFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

/// An export's name, claimed before anything is written: its `.sha256` sidecar,
/// created empty with `create_new`. Removed on drop unless published.
pub(crate) struct Reservation {
    sidecar: PathBuf,
    file: Option<fs::File>,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if self.file.take().is_some() {
            let _ = fs::remove_file(&self.sidecar);
        }
    }
}

/// Claim `output` for an export: its sidecar is created (`create_new` claims the
/// name or fails), and an archive already at `output` is refused.
///
/// WHY before writing: a name checked first and claimed only at the end leaves the
/// whole export for another run to take it, and the work is then refused.
pub(crate) fn reserve(output: &Path) -> Result<Reservation> {
    let sidecar = sidecar_path(output);
    let file = match fs::File::options()
        .write(true)
        .create_new(true)
        .open(&sidecar)
    {
        Ok(file) => file,
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {
            bail!("{} already exists; nothing replaced", sidecar.display())
        }
        Err(e) => return Err(e).with_context(|| format!("cannot create {}", sidecar.display())),
    };
    let reservation = Reservation {
        sidecar,
        file: Some(file),
    };
    if output.exists() {
        bail!("{} already exists; nothing replaced", output.display());
    }
    Ok(reservation)
}

/// Map the archive at `path` and open it with the tool's own reader. Scoped by its
/// callers so the map is gone before the file is moved: Windows refuses to rename a
/// mapped file.
fn read_back<R>(path: &Path, f: impl FnOnce(&[u8], usize) -> R) -> Result<R> {
    let file = fs::File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
    // SAFETY: a read-only map of a finished archive, dropped before this returns.
    let map = unsafe { memmap2::Mmap::map(&file) }
        .with_context(|| format!("cannot map {}", path.display()))?;
    let source = ZipSource::open(&map).context("the archive does not read back")?;
    let members = source.entries().len();
    Ok(f(&map, members))
}

/// How many members the archive at `path` holds.
pub(crate) fn member_count(path: &Path) -> Result<usize> {
    read_back(path, |_, members| members)
}

/// Read the finished archive back with the tool's own reader, confirm it holds what
/// was written, and hash it.
pub(crate) fn check_and_hash(path: &Path, expected_members: usize) -> Result<String> {
    let (members, sha256) = read_back(path, |map, members| (members, sha256_hex(map)))?;
    if members != expected_members {
        bail!("the written archive holds {members} members, expected {expected_members}");
    }
    Ok(sha256)
}

/// Move a finished archive from `partial` to the `output` reserved for it and write
/// its `.sha256` into the reserved sidecar, both read-only. Returns the sidecar's
/// path.
///
/// HOW nothing is replaced, even by a run racing this one: the sidecar's name was
/// claimed by [`reserve`]; the archive is hard-linked to `output`, which fails if
/// the name exists, and the partial name then goes on drop. A file system without
/// hard links (FAT, exFAT, often on evidence drives) falls back to checking the name,
/// then renaming, which leaves only that instant unguarded.
pub(crate) fn publish_new(
    partial: &Path,
    output: &Path,
    archive_sha256: &str,
    mut reservation: Reservation,
) -> Result<PathBuf> {
    let taken = || anyhow::anyhow!("{} already exists; nothing replaced", output.display());
    match fs::hard_link(partial, output) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::AlreadyExists => return Err(taken()),
        Err(_) if output.exists() => return Err(taken()),
        Err(_) => fs::rename(partial, output)
            .with_context(|| format!("cannot move the archive to {}", output.display()))?,
    }
    set_read_only(output)?;
    let mut file = reservation
        .file
        .take()
        .expect("a reservation holds its sidecar until published");
    let sidecar = reservation.sidecar.clone();
    file.write_all(sidecar_line(output, archive_sha256).as_bytes())
        .and_then(|()| file.sync_all())
        .with_context(|| format!("cannot write {}", sidecar.display()))?;
    drop(file);
    set_read_only(&sidecar)?;
    Ok(sidecar)
}

/// Move a finished archive from `partial` to `output`, write its `.sha256` sidecar,
/// and make both read-only. Returns the sidecar's path.
///
/// An archive already at `output` (callers allow it only with `--force`) and its
/// sidecar are removed first: they are read-only, and Windows refuses to replace a
/// read-only file. For `backup rebuild` and `decrypt --to`; an export uses
/// [`publish_new`].
pub(crate) fn publish_replacing(
    partial: &Path,
    output: &Path,
    archive_sha256: &str,
) -> Result<PathBuf> {
    let sidecar = sidecar_path(output);
    remove_read_only(output)?;
    remove_read_only(&sidecar)?;
    fs::rename(partial, output)
        .with_context(|| format!("cannot move the archive to {}", output.display()))?;
    set_read_only(output)?;
    fs::write(&sidecar, sidecar_line(output, archive_sha256))
        .with_context(|| format!("cannot write {}", sidecar.display()))?;
    set_read_only(&sidecar)?;
    Ok(sidecar)
}

/// The sidecar's one line, in `sha256sum` format: verifiable with `sha256sum -c` or
/// `shasum -a 256 -c`.
fn sidecar_line(output: &Path, archive_sha256: &str) -> String {
    let file_name = output.file_name().unwrap_or_default().to_string_lossy();
    format!("{archive_sha256}  {file_name}\n")
}

/// Remove `path` if it exists, read-only or not.
fn remove_read_only(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    make_writable(path)?;
    fs::remove_file(path).with_context(|| format!("cannot replace {}", path.display()))
}

/// Where the sidecar for `output` goes: `<name>.zip.sha256`.
pub(crate) fn sidecar_path(output: &Path) -> PathBuf {
    let mut name = output.file_name().unwrap_or_default().to_os_string();
    name.push(".sha256");
    output.with_file_name(name)
}

/// Make `path` read-only for everyone.
fn set_read_only(path: &Path) -> Result<()> {
    let mut permissions = fs::metadata(path)
        .with_context(|| format!("cannot read {}", path.display()))?
        .permissions();
    permissions.set_readonly(true);
    fs::set_permissions(path, permissions)
        .with_context(|| format!("cannot make {} read-only", path.display()))
}

/// Give the owner write access back (Unix), or clear the read-only flag (Windows).
fn make_writable(path: &Path) -> Result<()> {
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

    #[test]
    fn publishing_never_replaces_an_archive_or_a_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("a.zip");

        // A stale sidecar alone blocks the name, and survives.
        fs::write(sidecar_path(&output), b"stale").unwrap();
        assert!(reserve(&output).is_err());
        assert_eq!(fs::read(sidecar_path(&output)).unwrap(), b"stale");
        fs::remove_file(sidecar_path(&output)).unwrap();

        // An archive alone blocks it too, and no sidecar is left behind.
        fs::write(&output, b"earlier").unwrap();
        assert!(reserve(&output).is_err());
        assert_eq!(fs::read(&output).unwrap(), b"earlier");
        assert!(!sidecar_path(&output).exists());
        fs::remove_file(&output).unwrap();

        // An archive appearing after the reservation is not replaced, and the
        // reservation goes with the failed publish.
        let partial = PartialFile::beside(&output);
        fs::write(&partial.0, b"new").unwrap();
        let reservation = reserve(&output).unwrap();
        fs::write(&output, b"racing").unwrap();
        assert!(publish_new(&partial.0, &output, "00", reservation).is_err());
        assert_eq!(fs::read(&output).unwrap(), b"racing");
        assert!(!sidecar_path(&output).exists());
        fs::remove_file(&output).unwrap();

        // A free name: published, read-only, the partial name gone on drop.
        let reservation = reserve(&output).unwrap();
        let sidecar = publish_new(&partial.0, &output, "ab", reservation).unwrap();
        drop(partial);
        assert_eq!(fs::read(&output).unwrap(), b"new");
        assert_eq!(fs::read_to_string(&sidecar).unwrap(), "ab  a.zip\n");
        assert!(fs::metadata(&output).unwrap().permissions().readonly());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
    }
}
