//! Nested containers: open the archives and compressed files found inside a source.
//!
//! Defines: [`ExpandedSource`] (any [`Source`] with the containers inside it opened,
//! up to a depth), [`Nesting`] (that depth and the cap on what opening them adds),
//! and [`DEFAULT_NESTED_LIMIT`].
//! Used by: the binary's `support::sources` (wraps every operand when
//! `--archive-depth` is 1 or more), and, through the [`Source`] trait, the engines.
//! Uses: `mod::head_kind` (the one table of container signatures), `zip`, `tar`,
//! `sevenz`, `compressed` (the readers), `spool` (where decoded containers are kept,
//! capped), `crate::core::models::{Entry, Location}`.
//!
//! HOW: every entry of the inner source is listed, in order. An entry whose first
//! bytes are a ZIP, a tar, a 7z or a compressed stream (gzip, bzip2, xz, zstd) is
//! opened, and its members are listed right after it, named `<entry>/<member>`, as
//! [`Location::Nested`] ranges of the container's bytes. A ZIP or a tar is read in
//! place when its bytes already are (a slice of a mapped file, or of a container
//! opened before); a 7z, a compressed stream, or a container the inner source can
//! only hand over in memory goes to the spool. A compressed stream is a tar when what
//! it decodes to starts like one, else a single file, named after the entry without
//! its compression suffix. Members are looked at the same way, one level less deep
//! each time.
//!
//! WHY by content, in every source: forensic file names are often wrong, and an
//! archive is as likely inside a ZIP acquisition or a tar as in a folder.
//! WHY the archive itself stays listed but is not searched again: `find`, `diff` and
//! export still see the file the evidence holds, while its bytes are searched once,
//! through its members (a STORED ZIP searched as itself would give every hit twice).
//! A container that cannot be opened (damaged, or encrypted: nested containers are
//! not decrypted) is searched as one file; one only partly listed (a tar cut short)
//! is searched as one file too, besides the members listed. Both say why on stderr
//! and are listed by [`Source::nested_gaps`], so the run reports the gap in its exit
//! status, as it does for a file it could not read.
//!
//! What opening adds to memory or temporary files (decoded containers, containers
//! read into memory) is capped for the whole source ([`Nesting::limit`]); a
//! container is checked against what is left before it is read. Passing the cap
//! fails the run: cutting the expansion short would leave files unsearched without a
//! trace, and a decompression bomb must not fill the memory or the disk.

use std::collections::{HashMap, HashSet};

use anyhow::{Result, bail};

use crate::core::models::{Encryption, Entry, Location, Method};
use crate::core::source::compressed::Compression;
use crate::core::source::spool::{Spool, SpoolCapExceeded};
use crate::core::source::zip::{self, Coding};
use crate::core::source::zip_crypto::ZipPassword;
use crate::core::source::{
    Content, HeadKind, IntegrityCheck, Source, head_kind, is_ustar, sevenz, tar,
};

/// The default cap on what opening nested containers may add, in all (16 GiB).
pub const DEFAULT_NESTED_LIMIT: u64 = 16 * 1024 * 1024 * 1024;
/// The bytes looked at to tell a container (a tar header's magic is at 257).
const HEAD: usize = 512;
/// The suffixes a single compressed file's name drops when it is opened.
const COMPRESSED_SUFFIXES: [&str; 6] = [".gz", ".bz2", ".xz", ".zst", ".zstd", ".z"];

/// How deep to open nested containers, and how much opening them may add in all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Nesting {
    /// Levels of nesting to open: 0 opens nothing, 1 the containers in the source,
    /// 2 the containers in those, and so on.
    pub depth: u32,
    /// The most bytes opening may add to memory or temporary files.
    pub limit: u64,
}

impl Default for Nesting {
    fn default() -> Self {
        Self {
            depth: 0,
            limit: DEFAULT_NESTED_LIMIT,
        }
    }
}

/// A container's kind, among those opened.
#[derive(Debug, Clone, Copy)]
enum Kind {
    Zip,
    Tar,
    SevenZ,
    Compressed(Compression),
}

/// The kind of container `head` starts like, if it is one this module opens. An
/// Android backup is not opened nested (decided with the owner: rare inside an
/// acquisition, and often encrypted).
fn kind_of(head: &[u8]) -> Option<Kind> {
    match head_kind(&head[..head.len().min(HEAD)])? {
        HeadKind::Zip => Some(Kind::Zip),
        HeadKind::Tar => Some(Kind::Tar),
        HeadKind::SevenZ => Some(Kind::SevenZ),
        HeadKind::Compressed(c) => Some(Kind::Compressed(c)),
        HeadKind::AndroidBackup => None,
    }
}

/// The bytes of an opened container: its own, or a range of another one's.
enum Blob<'a> {
    Bytes(Content<'a>),
    /// A STORED, unencrypted member of blob `parent`: read where it is.
    View {
        parent: usize,
        start: usize,
        len: usize,
    },
}

/// A container's members, located in its bytes or in a decoded copy of them.
struct Listed {
    /// The decoded copy (7z, compressed stream), or `None`: the members are
    /// located in the container's own bytes (ZIP, tar).
    decoded: Option<Content<'static>>,
    /// Members as their reader located them (ZIP, tar or 7z locations).
    members: Vec<Entry>,
    /// The CRC-32 a ZIP records for each member, by its data offset.
    crcs: HashMap<u64, u32>,
    /// What the reader noticed, for stderr (a damaged tar, unreadable members).
    notes: Vec<String>,
    /// Whether the members listed are only part of the container (a tar cut short).
    partial: bool,
}

/// List the container `bytes` (an entry named `name`) of `kind`, decoding into at
/// most `budget` bytes when it has to be decoded.
fn list(kind: Kind, bytes: &[u8], name: &str, budget: u64) -> Result<Listed> {
    let spool = || Spool::capped("a nested container", budget);
    let mut listed = Listed {
        decoded: None,
        members: Vec::new(),
        crcs: HashMap::new(),
        notes: Vec::new(),
        partial: false,
    };
    match kind {
        Kind::Zip => {
            for (member, crc) in zip::parse_entries_with_crc(bytes)? {
                if let Location::Zip { data_offset, .. } = member.location {
                    listed.crcs.insert(data_offset, crc);
                }
                listed.members.push(member);
            }
        }
        Kind::Tar => tar_members(bytes, &mut listed),
        Kind::SevenZ => {
            let (decoded, members) = sevenz::decode_bytes(bytes, spool())?;
            listed.decoded = Some(decoded);
            listed.members = members;
        }
        Kind::Compressed(compression) => {
            let decoded = compression.decode_into(bytes, spool())?;
            if is_ustar(&decoded) {
                tar_members(&decoded, &mut listed);
            } else {
                listed.members = vec![single_file(name, decoded.len() as u64)];
            }
            listed.decoded = Some(decoded);
        }
    }
    let unread = listed
        .members
        .iter()
        .filter(|m| {
            m.is_encrypted()
                || matches!(
                    m.location,
                    Location::Zip {
                        method: Method::Other(_),
                        ..
                    }
                )
        })
        .count();
    if unread > 0 {
        listed.notes.push(format!(
            "{unread} file(s) NOT searched: encrypted (nested archives are not decrypted), \
             or a compression method mf-scan does not read"
        ));
    }
    Ok(listed)
}

/// A tar stream's members; one cut short is marked partial, with a note.
fn tar_members(stream: &[u8], listed: &mut Listed) {
    let parsed = tar::parse(stream);
    if let Some(damage) = parsed.damage {
        listed.notes.push(format!(
            "damaged ({damage}): the files after it could not be listed; searched as one \
             file too"
        ));
        listed.partial = true;
    }
    listed.members = parsed.entries;
}

/// The one member of a single compressed file: the whole decoded stream, named after
/// the file without its compression suffix (`app.log.gz` holds `app.log`), or with
/// `.decompressed` added when it has none.
fn single_file(name: &str, len: u64) -> Entry {
    let base = name.rsplit('/').next().unwrap_or(name);
    let lower = base.to_ascii_lowercase();
    let inner = COMPRESSED_SUFFIXES
        .iter()
        .find(|s| lower.len() > s.len() && lower.ends_with(*s))
        .map(|s| base[..base.len() - s.len()].to_string())
        .unwrap_or_else(|| format!("{base}.decompressed"));
    Entry {
        name: inner,
        uncompressed_size: len,
        mtime: None,
        location: Location::Tar {
            data_offset: 0,
            data_len: len,
        },
    }
}

/// `member` of the container named `parent`, as an entry of the expanded source: its
/// name under the parent's, its location a range of blob `archive`.
fn nested_entry(member: Entry, parent: &str, archive: usize) -> Entry {
    let (method, encryption, data_offset, data_len) = match member.location {
        Location::Zip {
            method,
            encryption,
            data_offset,
            data_len,
        } => (method, encryption, data_offset, data_len),
        Location::Tar {
            data_offset,
            data_len,
        }
        | Location::SevenZ {
            data_offset,
            data_len,
        } => (Method::Stored, Encryption::None, data_offset, data_len),
        // The readers above locate members only these three ways.
        Location::RangedZip { .. } | Location::Loose { .. } | Location::Nested { .. } => {
            unreachable!("a container member located in its own bytes or decoded copy")
        }
    };
    Entry {
        name: format!("{parent}/{}", member.name),
        uncompressed_size: member.uncompressed_size,
        mtime: member.mtime,
        location: Location::Nested {
            archive,
            method,
            encryption,
            data_offset,
            data_len,
        },
    }
}

/// Whether `e` is the error of a spool reaching its cap, however deep.
fn is_cap(e: &anyhow::Error) -> bool {
    e.chain().any(|c| c.is::<SpoolCapExceeded>())
}

/// `inner` with the containers inside it opened (see the module documentation).
pub struct ExpandedSource<'a> {
    inner: &'a dyn Source,
    entries: Vec<Entry>,
    /// Opened containers' bytes; indexed by [`Location::Nested`]'s `archive`.
    blobs: Vec<Blob<'a>>,
    /// The entries opened, whose members are searched in their place. By entry, not
    /// name: an archive may hold two entries of one name.
    expanded: HashSet<Entry>,
    /// The CRC-32 recorded for each nested ZIP member, by (blob, data offset).
    crcs: HashMap<(usize, u64), u32>,
    /// Containers not opened, and what the opened ones could not list, for stderr.
    notes: Vec<String>,
    /// The names of the containers not opened, or only partly read.
    gaps: Vec<String>,
    /// Bytes opening may still add to memory or temporary files.
    budget: u64,
    limit: u64,
}

impl<'a> ExpandedSource<'a> {
    /// List `inner`'s entries, opening the containers among them up to
    /// `nesting.depth` levels. Fails only when opening would pass `nesting.limit`;
    /// a container that cannot be opened is noted and kept as one file.
    pub fn open(inner: &'a dyn Source, nesting: Nesting) -> Result<Self> {
        let mut this = Self {
            inner,
            entries: Vec::with_capacity(inner.entries().len()),
            blobs: Vec::new(),
            expanded: HashSet::new(),
            crcs: HashMap::new(),
            notes: Vec::new(),
            gaps: Vec::new(),
            budget: nesting.limit,
            limit: nesting.limit,
        };
        if nesting.depth == 0 {
            this.entries.extend(inner.entries().iter().cloned());
            return Ok(this);
        }
        for entry in inner.entries() {
            this.entries.push(entry.clone());
            if entry.is_dir() {
                continue;
            }
            // A read failure here is not reported: the search reads the entry
            // again and counts it as unreadable.
            let Some(kind) = inner
                .content_head(entry, HEAD)
                .ok()
                .and_then(|h| kind_of(&h))
            else {
                continue;
            };
            let in_place = inner.reads_in_place(entry);
            this.check_size(entry, in_place)?;
            let Ok(content) = inner.content(entry) else {
                continue;
            };
            let blob = this.keep(content, in_place)?;
            this.open_blob(kind, blob, entry, nesting.depth - 1)?;
        }
        Ok(this)
    }

    /// What could not be opened or listed, one line per container, for stderr.
    pub fn notes(&self) -> &[String] {
        &self.notes
    }

    /// Before an entry that is not read in place is read into memory: whether its
    /// declared size fits what is left of the cap.
    fn check_size(&self, entry: &Entry, in_place: bool) -> Result<()> {
        if !in_place && entry.uncompressed_size > self.budget {
            bail!(self.limit_error(&entry.name));
        }
        Ok(())
    }

    fn limit_error(&self, name: &str) -> String {
        format!(
            "nested containers would take more than {} bytes (--nested-limit) to open {name}: \
             raise the limit, or lower --archive-depth",
            self.limit
        )
    }

    /// A container's bytes as a blob: kept where they are when read in place, else
    /// moved to the spool (out of memory past its threshold) and charged.
    fn keep(&mut self, content: Content<'a>, in_place: bool) -> Result<Blob<'a>> {
        if in_place {
            return Ok(Blob::Bytes(content));
        }
        let mut spool = Spool::capped("a nested container", self.budget);
        let kept = spool.write(&content).and_then(|()| spool.finish());
        drop(content);
        match kept {
            Ok(kept) => {
                self.budget = self.budget.saturating_sub(kept.len() as u64);
                Ok(Blob::Bytes(kept))
            }
            Err(e) if is_cap(&e) => bail!(self.limit_error("a container")),
            Err(e) => Err(e),
        }
    }

    /// The bytes of blob `index`.
    fn blob_bytes(&self, index: usize) -> &[u8] {
        match &self.blobs[index] {
            Blob::Bytes(content) => content,
            Blob::View { parent, start, len } => &self.blob_bytes(*parent)[*start..start + len],
        }
    }

    /// Open the container `entry` (of `kind`, held in `blob`): list its members,
    /// then, with `remaining` levels left, open the containers among them.
    fn open_blob(
        &mut self,
        kind: Kind,
        blob: Blob<'a>,
        entry: &Entry,
        remaining: u32,
    ) -> Result<()> {
        let index = self.blobs.len();
        self.blobs.push(blob);
        let name = &entry.name;
        let listed = match list(kind, self.blob_bytes(index), name, self.budget) {
            Ok(listed) => listed,
            Err(e) if is_cap(&e) => bail!(self.limit_error(name)),
            Err(e) => {
                self.notes.push(format!(
                    "{name}: not opened ({e:#}); searched as one file, its contents NOT searched"
                ));
                self.gaps.push(name.clone());
                return Ok(());
            }
        };
        // Members of a decoded copy live in that copy, a blob of its own.
        let archive = match listed.decoded {
            Some(decoded) => {
                self.budget = self.budget.saturating_sub(decoded.len() as u64);
                self.blobs.push(Blob::Bytes(decoded));
                self.blobs.len() - 1
            }
            None => index,
        };
        for note in listed.notes {
            self.notes.push(format!("{name}: {note}"));
        }
        if listed.partial {
            // Searched as one file as well: its bytes past the damage hold files
            // the listing could not reach.
            self.gaps.push(name.clone());
        } else {
            self.expanded.insert(entry.clone());
        }
        for (offset, crc) in listed.crcs {
            self.crcs.insert((archive, offset), crc);
        }
        for member in listed.members {
            let nested = nested_entry(member, name, archive);
            self.entries.push(nested.clone());
            if remaining > 0 && !nested.is_dir() {
                self.open_member(&nested, remaining)?;
            }
        }
        Ok(())
    }

    /// Open `member` of an opened container, if it is a container itself.
    fn open_member(&mut self, member: &Entry, remaining: u32) -> Result<()> {
        let Some(kind) = self
            .content_head(member, HEAD)
            .ok()
            .and_then(|h| kind_of(&h))
        else {
            return Ok(());
        };
        let Location::Nested {
            archive,
            method,
            encryption,
            data_offset,
            data_len,
        } = member.location
        else {
            return Ok(());
        };
        let blob = if method == Method::Stored && encryption == Encryption::None {
            let (Ok(start), Ok(len)) = (usize::try_from(data_offset), usize::try_from(data_len))
            else {
                return Ok(());
            };
            Blob::View {
                parent: archive,
                start,
                len,
            }
        } else {
            // Inflated (or failing, saying why when the search reads it again),
            // then kept in the spool: it does not borrow the parent's bytes.
            self.check_size(member, false)?;
            let content = match self.content(member) {
                Ok(content) => content.into_owned(),
                Err(_) => return Ok(()),
            };
            self.keep(Content::Owned(content), false)?
        };
        self.open_blob(kind, blob, member, remaining - 1)
    }

    /// The raw range of a nested entry, and how it is coded, if it is one.
    fn nested(&self, entry: &Entry) -> Option<Result<(&[u8], Coding<'static>)>> {
        let Location::Nested {
            archive,
            method,
            encryption,
            data_offset,
            data_len,
        } = entry.location
        else {
            return None;
        };
        let coding = Coding {
            method,
            encryption,
            password: ZipPassword::Nested,
        };
        let range = (archive < self.blobs.len())
            .then(|| self.blob_bytes(archive))
            .and_then(|blob| {
                let start = usize::try_from(data_offset).ok()?;
                let end = start.checked_add(usize::try_from(data_len).ok()?)?;
                blob.get(start..end)
            });
        Some(match range {
            Some(raw) => Ok((raw, coding)),
            None => Err(anyhow::anyhow!(
                "nested entry {} is out of its container's bounds",
                entry.name
            )),
        })
    }
}

impl Source for ExpandedSource<'_> {
    fn entries(&self) -> &[Entry] {
        &self.entries
    }

    fn content(&self, entry: &Entry) -> Result<Content<'_>> {
        match self.nested(entry) {
            Some(found) => {
                let (raw, coding) = found?;
                zip::decode(raw, coding, entry.uncompressed_size, &entry.name)
            }
            None => self.inner.content(entry),
        }
    }

    fn archive_data_start(&self, entry: &Entry) -> Option<u64> {
        match entry.location {
            Location::Nested { .. } => None,
            _ => self.inner.archive_data_start(entry),
        }
    }

    fn byte_size(&self) -> u64 {
        self.inner.byte_size()
    }

    /// A nested ZIP member is checked against the CRC-32 its archive records, as a
    /// top-level one is; tar and 7z members record none here.
    fn integrity_check(&self, entry: &Entry) -> IntegrityCheck {
        let Location::Nested {
            archive,
            data_offset,
            ..
        } = entry.location
        else {
            return self.inner.integrity_check(entry);
        };
        let Some(&expected) = self.crcs.get(&(archive, data_offset)) else {
            return IntegrityCheck::Unrecorded;
        };
        if expected == 0 {
            return IntegrityCheck::Unrecorded;
        }
        let Ok(content) = self.content(entry) else {
            return IntegrityCheck::Unrecorded;
        };
        let actual = crc32fast::hash(&content);
        if actual == expected {
            IntegrityCheck::Verified { algorithm: "crc32" }
        } else {
            IntegrityCheck::Mismatch {
                algorithm: "crc32",
                expected: format!("{expected:08x}"),
                actual: format!("{actual:08x}"),
            }
        }
    }

    fn prefers_prefix_classification(&self) -> bool {
        self.inner.prefers_prefix_classification()
    }

    fn content_prefix(&self, entry: &Entry, max: usize) -> Result<Content<'_>> {
        match entry.location {
            Location::Nested { .. } => self.content(entry),
            _ => self.inner.content_prefix(entry, max),
        }
    }

    fn content_suffix(&self, entry: &Entry, max: usize) -> Result<Content<'_>> {
        match entry.location {
            Location::Nested { .. } => self.content(entry),
            _ => self.inner.content_suffix(entry, max),
        }
    }

    fn cheap_suffix(&self, entry: &Entry) -> bool {
        match entry.location {
            Location::Nested { .. } => false,
            _ => self.inner.cheap_suffix(entry),
        }
    }

    fn content_head(&self, entry: &Entry, max: usize) -> Result<Content<'_>> {
        match self.nested(entry) {
            // A plain DEFLATE member: only its start is inflated.
            Some(Ok((
                raw,
                Coding {
                    method: Method::Deflate,
                    encryption: Encryption::None,
                    ..
                },
            ))) => zip::inflate_head(raw, max).map(Content::Owned),
            Some(_) => self.content(entry),
            None => self.inner.content_head(entry, max),
        }
    }

    fn reads_in_place(&self, entry: &Entry) -> bool {
        match entry.location {
            Location::Nested {
                method, encryption, ..
            } => method == Method::Stored && encryption == Encryption::None,
            _ => self.inner.reads_in_place(entry),
        }
    }

    fn is_expanded(&self, entry: &Entry) -> bool {
        self.expanded.contains(entry)
    }

    fn nested_gaps(&self) -> &[String] {
        &self.gaps
    }
}
