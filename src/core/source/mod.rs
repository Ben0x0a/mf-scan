//! Sources: the container abstraction the search and diff engines read through.
//!
//! Defines: the [`Source`] trait — enumerate a container's files ([`Source::entries`])
//! and read any file's logical bytes ([`Source::content`]) — plus [`Content`]
//! (the borrowed/owned/mapped byte carrier) and the concrete containers. A
//! `Source` is whatever yields located files with bytes: a ZIP archive
//! ([`zip::ZipSource`]), a tar archive ([`tar::TarSource`], plain or compressed), a
//! 7z archive ([`sevenz::SevenZSource`]), a directory of loose files or one such file ([`folder::FolderSource`]), or bytes held
//! in memory ([`bytes::BytesSource`], standard input). [`sniff_container`] is the single
//! decision on which of these a file is.
//! Used by: `engine` (search), `report::export` and `diff`. Built by the
//! binary's `support::sources`.
//! Uses: `crate::core::models::Entry`, `anyhow`, `memmap2` (large loose files).
//!
//! Why a trait rather than passing `&[u8]` around: the engine used to assume every
//! source was a memory-mapped ZIP addressed by byte offsets. Reading bytes through
//! one method lets a folder of loose files (no offsets, read from disk) flow through
//! the exact same search/inspect/export pipeline, with the offset model
//! (`MatchRecord::archive_offset`) becoming `None` where there is no archive.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::ops::Deref;
use std::path::Path;

use anyhow::{Context, Result};

use crate::core::models::Entry;

pub mod bytes;
pub(crate) mod compressed;
pub mod folder;
mod nested;
pub mod ranged;
pub mod sevenz;
pub(crate) mod spool;
pub mod tar;
pub mod zip;
mod zip_crypto;

/// What kind of container a file is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Container {
    Zip,
    Tar,
    SevenZ,
    AndroidBackup,
    /// Not a container: an ordinary file, to be searched as itself.
    Other,
}

/// The first line of an Android `adb backup` (`.ab`) file.
pub const ANDROID_BACKUP_MAGIC: &[u8] = b"ANDROID BACKUP\n";

/// Whether `head`, the first bytes of a file, are an `.ab` header. Decided by content,
/// never by file name. Here rather than in `platform::android`, which re-exports it,
/// because deciding what a container is belongs to this layer and `core` must not
/// depend on `platform`.
pub fn is_android_backup(head: &[u8]) -> bool {
    head.starts_with(ANDROID_BACKUP_MAGIC)
}

/// The names of a tar archive, plain or compressed (gzip, bzip2, xz, zstd).
const TAR_SUFFIXES: [&str; 12] = [
    ".tar",
    ".tar.gz",
    ".tgz",
    ".tar.bz2",
    ".tbz2",
    ".tbz",
    ".tar.xz",
    ".txz",
    ".tar.zst",
    ".tar.zstd",
    ".tzst",
    ".tar.md5",
];

/// Whether `path` is named like a tar archive, plain or compressed.
pub fn is_tar_name(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    TAR_SUFFIXES.iter().any(|s| name.ends_with(s))
}

fn is_zip_name(path: &Path) -> bool {
    path.extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("zip"))
}

/// Whether `path` is named like a 7z archive.
pub fn is_seven_z_name(path: &Path) -> bool {
    path.extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("7z"))
}

/// Decide what kind of container the file at `path` is.
///
/// HOW: from its content first (the `.ab` magic, a ZIP header or end-of-central-directory
/// record, the 7z signature, the `ustar` tar magic, a compressed tar), because forensic file names are often wrong or
/// absent. The name is the fallback, and it decides in one case the content cannot: a
/// damaged `.zip`, `.tar` or `.7z` must fail loudly as an archive rather than be quietly
/// searched as one opaque file.
pub fn sniff_container(path: &Path) -> Result<Container> {
    /// Where the `ustar` magic sits in a tar header.
    const USTAR_OFFSET: usize = 257;
    /// An end-of-central-directory record, plus the longest possible comment.
    const ZIP_TAIL: u64 = 22 + u16::MAX as u64;

    let mut file = File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
    let mut head = Vec::with_capacity(512);
    file.by_ref()
        .take(512)
        .read_to_end(&mut head)
        .with_context(|| format!("cannot read {}", path.display()))?;

    if is_android_backup(&head) {
        return Ok(Container::AndroidBackup);
    }
    if head.starts_with(b"PK\x03\x04") || head.starts_with(b"PK\x05\x06") {
        return Ok(Container::Zip);
    }
    if sevenz::is_seven_z(&head) {
        return Ok(Container::SevenZ);
    }
    if head.get(USTAR_OFFSET..USTAR_OFFSET + 5) == Some(b"ustar") {
        return Ok(Container::Tar);
    }
    // A compressed file is a tar when what it decodes to starts like one. A damaged
    // stream decides nothing here: the name below still can.
    if let Some(compression) = compressed::Compression::of(&head) {
        file.seek(SeekFrom::Start(0))
            .with_context(|| format!("cannot read {}", path.display()))?;
        let inner = compression.head(&mut file, 512).unwrap_or_default();
        if inner.get(USTAR_OFFSET..USTAR_OFFSET + 5) == Some(b"ustar") {
            return Ok(Container::Tar);
        }
    }
    if is_tar_name(path) {
        return Ok(Container::Tar);
    }
    if is_zip_name(path) {
        return Ok(Container::Zip);
    }
    if is_seven_z_name(path) {
        return Ok(Container::SevenZ);
    }

    // A ZIP can start with anything (a self-extractor's stub), so look for its tail.
    let len = file
        .metadata()
        .with_context(|| format!("cannot read {}", path.display()))?
        .len();
    let tail_base = len.saturating_sub(ZIP_TAIL);
    file.seek(SeekFrom::Start(tail_base))
        .with_context(|| format!("cannot read {}", path.display()))?;
    let mut tail = Vec::new();
    file.read_to_end(&mut tail)
        .with_context(|| format!("cannot read {}", path.display()))?;
    Ok(if zip::has_end_record(&tail, tail_base) {
        Container::Zip
    } else {
        Container::Other
    })
}

/// One entry's logical bytes, however the source backs them.
///
/// Like `Cow<'a, [u8]>` with a third, self-owning variant: a memory map. The
/// map is what lets [`folder::FolderSource`] serve a multi-GB loose file
/// without materialising it on the heap — a `Cow` could only *borrow* a map
/// owned by `&self`, but the map is created per call — mirroring the zero-copy
/// path the top-level ZIP mmap already has.
pub enum Content<'a> {
    /// Borrowed from the source's backing store (a STORED ZIP entry over the mmap).
    Borrowed(&'a [u8]),
    /// Owned heap bytes (DEFLATE inflate, decrypted plaintext, small loose file).
    Owned(Vec<u8>),
    /// A read-only memory map of a large loose file.
    Mapped(memmap2::Mmap),
}

impl Deref for Content<'_> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        match self {
            Content::Borrowed(b) => b,
            Content::Owned(v) => v,
            Content::Mapped(m) => m,
        }
    }
}

impl AsRef<[u8]> for Content<'_> {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

impl Content<'_> {
    /// The bytes as an owned `Vec`, copying only when not already owned.
    pub fn into_owned(self) -> Vec<u8> {
        match self {
            Content::Borrowed(b) => b.to_vec(),
            Content::Owned(v) => v,
            Content::Mapped(m) => m.to_vec(),
        }
    }
}

/// Outcome of checking an entry's *stored* bytes against a digest the source
/// itself records — independent provenance metadata, not a hash this tool
/// computed. The only source that carries one today is an encrypted iOS backup,
/// whose `Manifest.db` records the SHA-1 of each file's encrypted on-disk blob.
///
/// Used by the export path to attest that the original evidence (the stored
/// ciphertext) was read intact, *before* any decryption — a stronger guarantee
/// than hashing only the bytes we wrote out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntegrityCheck {
    /// The source records a digest for this entry and the stored bytes matched.
    Verified { algorithm: &'static str },
    /// The source records a digest and the stored bytes did NOT match it —
    /// the original evidence is corrupt or was read wrong. Surfaced loudly.
    Mismatch {
        algorithm: &'static str,
        expected: String,
        actual: String,
    },
    /// The source records no digest for this entry (the common case).
    Unrecorded,
}

/// A container of located files: enumerate them, and read any one's bytes.
///
/// `Sync` because the engine searches entries in parallel (rayon) and calls
/// [`Source::content`] from worker threads. Implementors return each entry's
/// *logical* content — uncompressed, but still encrypted: decryption is the
/// engine's concern, applied after the bytes are read.
pub trait Source: Sync {
    /// The files this source exposes, in a stable order (directory placeholders
    /// included, so callers can report and skip them uniformly).
    fn entries(&self) -> &[Entry];

    /// The logical bytes of `entry`: borrowed from the backing store when possible
    /// (a STORED ZIP entry over the mmap), owned otherwise (DEFLATE inflate, a
    /// small loose file), or a fresh memory map (a large loose file).
    fn content(&self, entry: &Entry) -> Result<Content<'_>>;

    /// The absolute archive byte where `entry`'s data begins, if this source can
    /// resolve it — so a match can report the exact offset of its bytes in the
    /// underlying image (the carve coordinate an examiner needs).
    ///
    /// The default delegates to [`Entry::archive_data_start`], correct for a
    /// memory-mapped [`zip::ZipSource`] (whose [`crate::core::models::Location::Zip`]
    /// already carries the resolved data offset) and for sources with no enclosing
    /// archive (folders, nested), which return `None`. The positioned-read
    /// [`ranged::RangedZipSource`] overrides it to resolve the Local File Header
    /// lazily — so a ranged scan reports the *same* exact offsets as the mmap path
    /// without resolving every header at open. Resolved once per matched file (not
    /// per match), and only for files that actually matched, so the cost is
    /// negligible next to the search itself.
    fn archive_data_start(&self, entry: &Entry) -> Option<u64> {
        entry.archive_data_start()
    }

    /// The source's physical size in bytes — the archive file size for a ZIP, the
    /// summed file sizes for a folder. Used only for the coverage report; the
    /// default sums the entries' logical sizes, which a backing store can override
    /// with its true on-disk size.
    fn byte_size(&self) -> u64 {
        self.entries().iter().map(|e| e.uncompressed_size).sum()
    }

    /// Check `entry`'s stored bytes against a digest the source records about
    /// them, if any. The default — for sources with no independent integrity
    /// metadata (folders, plain ZIPs) — is [`IntegrityCheck::Unrecorded`]. The
    /// encrypted-backup source overrides this to verify each file's encrypted
    /// blob against the SHA-1 in `Manifest.db`.
    fn integrity_check(&self, _entry: &Entry) -> IntegrityCheck {
        IntegrityCheck::Unrecorded
    }

    /// Whether classifying an entry's type from a cheap header *prefix* (rather
    /// than its full content) is worth it for this source.
    ///
    /// `false` by default: for an mmap or folder source [`Source::content`] is
    /// already lazy (the OS faults only the pages actually touched), so reading a
    /// prefix first would be pure overhead. The positioned-read
    /// [`ranged::RangedZipSource`] overrides it to `true` — over a network mount,
    /// fetching a whole media file only to skip it by `--type`/`--exclude-media`
    /// is exactly the cost to avoid, so the engine classifies from a small header
    /// read first (see [`Source::content_prefix`]).
    fn prefers_prefix_classification(&self) -> bool {
        false
    }

    /// Read up to `max` bytes of `entry`'s logical content, for type
    /// classification before committing to the full read.
    ///
    /// The default returns the whole content (correct everywhere — the caller
    /// only looks at the header); the ranged source overrides it to fetch just a
    /// small header range over the network. Only consulted when
    /// [`Source::prefers_prefix_classification`] is `true`.
    fn content_prefix(&self, entry: &Entry, _max: usize) -> Result<Content<'_>> {
        self.content(entry)
    }

    /// Read at least the last `max` bytes of `entry`'s logical content, for a
    /// format whose signature is at the end of the file. The caller uses only the
    /// last `max` bytes of what it gets.
    ///
    /// The default returns the whole content, like [`Source::content_prefix`]; the
    /// ranged source overrides it to fetch just the end of a STORED entry.
    fn content_suffix(&self, entry: &Entry, _max: usize) -> Result<Content<'_>> {
        self.content(entry)
    }

    /// Whether [`Source::content_suffix`] costs about as little as the bytes it
    /// returns, so the end of `entry` is worth reading before deciding to fetch the
    /// whole of it. `false` by default (the default suffix is the whole content).
    fn cheap_suffix(&self, _entry: &Entry) -> bool {
        false
    }
}
