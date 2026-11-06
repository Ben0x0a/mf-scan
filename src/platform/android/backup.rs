//! Read an Android `adb backup` (`.ab`) file as a [`Source`].
//!
//! Defines: [`is_android_backup`], [`AndroidBackupSource`] (the decoded archive plus
//! what the header and unlock established) and [`AndroidFacts`] (the audit record).
//! Used by: the binary's `support::sources`; through the `Source` trait, every
//! operation (`grep`, `find`, `diff`, `export`, `app`, `backup`).
//! Uses: `core::source::tar` (the payload is a tar), `aes`/`cbc`/`pbkdf2`/`sha1`
//! (encryption), `flate2` (compression), `tempfile` (the spill file), and the
//! acquisition-default password list in `platform::ios::backup::password`.
//!
//! ── The format, as written by AOSP ─────────────────────────────────────────────
//! `PerformAdbBackupTask.java` writes it and `PerformAdbRestoreTask.java` reads it
//! (frameworks/base, `services/backup/`). Text header lines, each ending in `\n`:
//!
//! ```text
//! 1  ANDROID BACKUP             magic
//! 2  <version>                  1..5
//! 3  1 | 0                      zlib-compressed or not
//! 4  none | AES-256             encryption
//! -- only when AES-256 --
//! 5  user password salt  [hex]
//! 6  key checksum salt   [hex]
//! 7  PBKDF2 rounds       [decimal]
//! 8  user key IV         [hex]
//! 9  key blob            [hex], AES-256-CBC under the user key, holding
//!                        [len][IV] [len][key] [len][key checksum]
//! ```
//!
//! Then the payload: a tar stream, zlib-deflated when line 3 is 1, then
//! AES-256-CBC/PKCS7 encrypted under the blob's key and IV when line 4 is AES-256.
//!
//! The user key is PBKDF2-HMAC-SHA1(password, user salt, rounds, 256 bits). The
//! checksum is the same PBKDF2 over the payload key's bytes, each widened to a Java
//! `char` exactly as `PasswordUtils.makeKeyChecksum` does. Version 1 archives were
//! written with the "8bit" PBKDF2 variant, so, like AOSP, both are tried there.
//!
//! ── Reading a damaged backup ───────────────────────────────────────────────────
//! A truncated or corrupt payload does not fail the open: what could be read is
//! evidence, so it is presented, and [`AndroidFacts::stream_error`] says what happened.
//! The binary reports it loudly, `grep` exits 2, and `backup rebuild` refuses to write
//! an archive unless told to keep the partial result.
//!
//! ── Memory ─────────────────────────────────────────────────────────────────────
//! A compressed or encrypted payload must be decoded before it can be read at random.
//! Up to [`SPOOL_LIMIT`] it stays in memory; beyond that it spills to an unnamed
//! temporary file, which the operating system deletes when the process ends, because
//! a backup can run to many gigabytes. That file holds decrypted evidence while the
//! tool runs. Point `TMPDIR` (`TMP` on Windows) at an approved location if that matters.

use std::fs::File;
use std::io::Write;
use std::path::Path;

use aes::Aes256;
use anyhow::{Context, Result, bail};
use cbc::Decryptor;
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::generic_array::GenericArray;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use flate2::{Decompress, FlushDecompress, Status};
use pbkdf2::pbkdf2_hmac;
use serde::Serialize;
use sha1::Sha1;

use crate::core::models::Entry;
use crate::core::source::tar::TarSource;
use crate::core::source::{Content, IntegrityCheck, Source};
use crate::platform::ios::backup::common::{BackupStructure, DirectoryRecord};
use crate::platform::ios::backup::password::{UnlockProvenance, candidates};

const MAGIC: &[u8] = crate::core::source::ANDROID_BACKUP_MAGIC;
/// The highest archive version AOSP writes (`BACKUP_FILE_VERSION`). A newer one is
/// refused, as AOSP refuses it: an unknown format change would be misread silently.
const MAX_VERSION: u32 = 5;
const ENCRYPTION_NONE: &str = "none";
const ENCRYPTION_AES: &str = "AES-256";
/// Bound on a header line, so a file that merely starts with the magic cannot make
/// the parser walk gigabytes looking for a newline.
const MAX_HEADER_LINE: usize = 4096;
/// PBKDF2 output length AOSP uses (`PBKDF2_KEY_SIZE`, 256 bits).
const KEY_BYTES: usize = 32;
const AES_BLOCK: usize = 16;

/// Decoded payload above this spills from memory to a temporary file.
const SPOOL_LIMIT: usize = 64 * 1024 * 1024;
/// How much of the payload is decoded at a time. A multiple of the AES block size,
/// so only the very last chunk can be a partial block.
const DECODE_CHUNK: usize = 1024 * 1024;
const INFLATE_BUFFER: usize = 1024 * 1024;

pub use crate::core::source::is_android_backup;

/// The parsed text header.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Header {
    version: u32,
    compressed: bool,
    encryption: String,
    /// Byte offset of the payload, just after the last header line.
    data_offset: usize,
    user_salt: Vec<u8>,
    checksum_salt: Vec<u8>,
    rounds: u32,
    user_iv: Vec<u8>,
    key_blob: Vec<u8>,
}

impl Header {
    fn encrypted(&self) -> bool {
        self.encryption != ENCRYPTION_NONE
    }
}

/// Read one `\n`-terminated header line from `data` at `pos`.
fn read_line<'a>(data: &'a [u8], pos: &mut usize) -> Result<&'a str> {
    let rest = data.get(*pos..).unwrap_or_default();
    let window = &rest[..rest.len().min(MAX_HEADER_LINE)];
    let Some(end) = window.iter().position(|&b| b == b'\n') else {
        bail!("truncated or malformed Android backup header");
    };
    *pos += end + 1;
    std::str::from_utf8(&window[..end]).context("malformed Android backup header")
}

fn parse_hex(text: &str) -> Result<Vec<u8>> {
    if !text.len().is_multiple_of(2) || !text.is_ascii() {
        bail!("malformed encryption header in Android backup");
    }
    (0..text.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&text[i..i + 2], 16)
                .context("malformed encryption header in Android backup")
        })
        .collect()
}

fn parse_header(data: &[u8]) -> Result<Header> {
    if !is_android_backup(data) {
        bail!("not an Android backup: the file does not start with 'ANDROID BACKUP'");
    }
    let mut pos = MAGIC.len();
    let version: u32 = read_line(data, &mut pos)?
        .parse()
        .context("malformed Android backup header")?;
    if !(1..=MAX_VERSION).contains(&version) {
        bail!("unsupported Android backup version {version} (supported: 1-{MAX_VERSION})");
    }
    let compressed = read_line(data, &mut pos)?
        .parse::<u32>()
        .context("malformed Android backup header")?
        != 0;
    let encryption = read_line(data, &mut pos)?.to_string();
    let mut header = Header {
        version,
        compressed,
        encryption,
        data_offset: 0,
        user_salt: Vec::new(),
        checksum_salt: Vec::new(),
        rounds: 0,
        user_iv: Vec::new(),
        key_blob: Vec::new(),
    };
    match header.encryption.as_str() {
        ENCRYPTION_NONE => {}
        ENCRYPTION_AES => {
            header.user_salt = parse_hex(read_line(data, &mut pos)?)?;
            header.checksum_salt = parse_hex(read_line(data, &mut pos)?)?;
            header.rounds = read_line(data, &mut pos)?
                .parse()
                .context("malformed encryption header in Android backup")?;
            header.user_iv = parse_hex(read_line(data, &mut pos)?)?;
            header.key_blob = parse_hex(read_line(data, &mut pos)?)?;
        }
        other => bail!("unsupported Android backup encryption: {other:?}"),
    }
    header.data_offset = pos;
    Ok(header)
}

/// How a password's characters become PBKDF2 input, named as in AOSP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyDerivation {
    /// `PBKDF2WithHmacSHA1`: the characters as UTF-8.
    Utf8,
    /// `PBKDF2WithHmacSHA1And8bit`: the low 8 bits of each character.
    EightBit,
}

impl KeyDerivation {
    fn as_str(self) -> &'static str {
        match self {
            KeyDerivation::Utf8 => "PBKDF2WithHmacSHA1",
            KeyDerivation::EightBit => "PBKDF2WithHmacSHA1And8bit",
        }
    }

    fn secret(self, text: &str) -> Vec<u8> {
        match self {
            KeyDerivation::Utf8 => text.as_bytes().to_vec(),
            KeyDerivation::EightBit => text.chars().map(|c| c as u32 as u8).collect(),
        }
    }
}

/// Widen each key byte to a Java `char`, as `makeKeyChecksum` does.
///
/// HOW: `(char) b` on a signed Java byte sign-extends, so 0x00-0x7F stay as they are
/// and 0x80-0xFF become U+FF80-U+FFFF.
/// WHY reproduce it: the stored checksum was computed over those characters, so a
/// plain-bytes PBKDF2 would never match and every correct password would look wrong.
fn key_as_java_chars(key: &[u8]) -> String {
    key.iter()
        .map(|&b| {
            let code = if b < 0x80 {
                b as u32
            } else {
                0xFF00 | b as u32
            };
            char::from_u32(code).expect("U+0000-U+007F and U+FF80-U+FFFF are valid characters")
        })
        .collect()
}

fn pbkdf2(secret: &[u8], salt: &[u8], rounds: u32) -> [u8; KEY_BYTES] {
    let mut out = [0u8; KEY_BYTES];
    pbkdf2_hmac::<Sha1>(secret, salt, rounds, &mut out);
    out
}

/// Split the decrypted key blob, `[len][IV][len][key][len][checksum]`.
fn split_key_blob(blob: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
    let mut rest = blob;
    let mut take = || {
        let (&len, tail) = rest.split_first()?;
        let (part, tail) = tail.split_at_checked(len as usize)?;
        rest = tail;
        Some(part)
    };
    Some((take()?, take()?, take()?))
}

/// The payload's key and IV, if `password` unlocks the header.
///
/// HOW: derive the user key, decrypt the key blob, and accept it only if the checksum
/// recomputed over the recovered key matches the stored one: the same check AOSP makes
/// before it trusts a password.
fn try_password(header: &Header, password: &str) -> Option<(Vec<u8>, Vec<u8>, KeyDerivation)> {
    let regimes: &[KeyDerivation] = if header.version == 1 {
        &[KeyDerivation::Utf8, KeyDerivation::EightBit]
    } else {
        &[KeyDerivation::Utf8]
    };
    for &regime in regimes {
        let user_key = pbkdf2(&regime.secret(password), &header.user_salt, header.rounds);
        let Ok(decryptor) = Decryptor::<Aes256>::new_from_slices(&user_key, &header.user_iv) else {
            continue;
        };
        let mut buffer = header.key_blob.clone();
        let Ok(blob) = decryptor.decrypt_padded_mut::<Pkcs7>(&mut buffer) else {
            continue;
        };
        let Some((iv, key, checksum)) = split_key_blob(blob) else {
            continue;
        };
        let computed = pbkdf2(
            &regime.secret(&key_as_java_chars(key)),
            &header.checksum_salt,
            header.rounds,
        );
        if computed.as_slice() == checksum {
            return Some((key.to_vec(), iv.to_vec(), regime));
        }
    }
    None
}

/// Collects decoded bytes, in memory up to [`SPOOL_LIMIT`], then in a temporary file.
struct Spool {
    memory: Vec<u8>,
    file: Option<File>,
}

impl Spool {
    fn new() -> Self {
        Self {
            memory: Vec::new(),
            file: None,
        }
    }

    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        if self.file.is_none() && self.memory.len() + bytes.len() > SPOOL_LIMIT {
            let mut file = tempfile::tempfile()
                .context("cannot create a temporary file to decode the Android backup")?;
            file.write_all(&self.memory)
                .context("cannot write the decoded Android backup to a temporary file")?;
            self.memory = Vec::new();
            self.file = Some(file);
        }
        match &mut self.file {
            Some(file) => file
                .write_all(bytes)
                .context("cannot write the decoded Android backup to a temporary file"),
            None => {
                self.memory.extend_from_slice(bytes);
                Ok(())
            }
        }
    }

    fn finish(self) -> Result<Content<'static>> {
        match self.file {
            None => Ok(Content::Owned(self.memory)),
            Some(file) => {
                // SAFETY: an unnamed temporary file this process alone holds, mapped
                // read-only once it is complete.
                let map = unsafe { memmap2::Mmap::map(&file) }
                    .context("cannot map the decoded Android backup")?;
                Ok(Content::Mapped(map))
            }
        }
    }
}

/// Inflates a zlib stream chunk by chunk.
///
/// WHY `Decompress` directly rather than the `flate2` reader: the reader reports a
/// stream that stops early as an ordinary end of file, and tar tolerates a missing
/// end-of-archive marker, so a truncated backup would otherwise decode "cleanly". Only
/// `Status::StreamEnd` proves the stream was complete.
struct Inflater {
    inner: Decompress,
    buffer: Vec<u8>,
    ended: bool,
}

impl Inflater {
    fn new() -> Self {
        Self {
            inner: Decompress::new(true),
            buffer: vec![0u8; INFLATE_BUFFER],
            ended: false,
        }
    }

    fn feed(&mut self, mut input: &[u8], out: &mut Spool) -> Result<(), DecodeStop> {
        while !self.ended && !input.is_empty() {
            let (before_in, before_out) = (self.inner.total_in(), self.inner.total_out());
            let status = self
                .inner
                .decompress(input, &mut self.buffer, FlushDecompress::None)
                .map_err(|e| DecodeStop::Damaged(format!("corrupt compressed stream: {e}")))?;
            let consumed = (self.inner.total_in() - before_in) as usize;
            let produced = (self.inner.total_out() - before_out) as usize;
            input = &input[consumed..];
            out.write(&self.buffer[..produced])
                .map_err(DecodeStop::Io)?;
            match status {
                Status::StreamEnd => self.ended = true,
                Status::BufError if consumed == 0 && produced == 0 => {
                    return Err(DecodeStop::Damaged("corrupt compressed stream".to_string()));
                }
                Status::Ok | Status::BufError => {}
            }
        }
        Ok(())
    }

    /// Flush output still held inside the inflater once all the input has been fed.
    fn drain(&mut self, out: &mut Spool) -> Result<(), DecodeStop> {
        while !self.ended {
            let before_out = self.inner.total_out();
            let status = self
                .inner
                .decompress(&[], &mut self.buffer, FlushDecompress::None)
                .map_err(|e| DecodeStop::Damaged(format!("corrupt compressed stream: {e}")))?;
            let produced = (self.inner.total_out() - before_out) as usize;
            out.write(&self.buffer[..produced])
                .map_err(DecodeStop::Io)?;
            match status {
                Status::StreamEnd => self.ended = true,
                _ if produced == 0 => break,
                _ => {}
            }
        }
        Ok(())
    }
}

/// Why decoding stopped early: damage is reported and what was read is kept, while a
/// local I/O failure (a full disk) is not evidence of anything and fails the open.
enum DecodeStop {
    Damaged(String),
    Io(anyhow::Error),
}

/// Decode the payload, returning the tar stream and a description of any damage.
fn decode_payload(
    payload: &[u8],
    keys: Option<(&[u8], &[u8])>,
    compressed: bool,
) -> Result<(Content<'static>, Option<String>)> {
    let mut out = Spool::new();
    let stop = run_decode(payload, keys, compressed, &mut out);
    let damage = match stop {
        Ok(()) => None,
        Err(DecodeStop::Damaged(reason)) => Some(reason),
        Err(DecodeStop::Io(err)) => return Err(err),
    };
    Ok((out.finish()?, damage))
}

fn run_decode(
    payload: &[u8],
    keys: Option<(&[u8], &[u8])>,
    compressed: bool,
    out: &mut Spool,
) -> Result<(), DecodeStop> {
    let mut decryptor = match keys {
        Some((key, iv)) => Some(Decryptor::<Aes256>::new_from_slices(key, iv).map_err(|_| {
            DecodeStop::Damaged("the key blob holds an unusable key or IV".to_string())
        })?),
        None => None,
    };
    let mut inflater = compressed.then(Inflater::new);
    let mut buffer = Vec::with_capacity(DECODE_CHUNK);

    let mut chunks = payload.chunks(DECODE_CHUNK).peekable();
    let mut damage = None;
    while let Some(chunk) = chunks.next() {
        let is_last = chunks.peek().is_none();
        let plain: &[u8] = if let Some(decryptor) = &mut decryptor {
            buffer.clear();
            buffer.extend_from_slice(chunk);
            // Only whole blocks can be decrypted; a partial one means truncation.
            let whole = buffer.len() - buffer.len() % AES_BLOCK;
            if whole != buffer.len() {
                damage = Some("the payload is truncated (a partial AES block)".to_string());
            }
            buffer.truncate(whole);
            for block in buffer.as_chunks_mut::<AES_BLOCK>().0 {
                decryptor.decrypt_block_mut(GenericArray::from_mut_slice(block));
            }
            if is_last && damage.is_none() {
                match pkcs7_plain_len(&buffer) {
                    Some(len) => buffer.truncate(len),
                    None => {
                        damage = Some(
                            "the payload is truncated or corrupt (bad AES padding)".to_string(),
                        );
                    }
                }
            }
            &buffer
        } else {
            chunk
        };
        match &mut inflater {
            Some(inflater) => inflater.feed(plain, out)?,
            None => out.write(plain).map_err(DecodeStop::Io)?,
        }
    }
    if let Some(inflater) = &mut inflater {
        inflater.drain(out)?;
        if !inflater.ended {
            damage.get_or_insert_with(|| {
                "the payload is truncated (the compressed stream does not end)".to_string()
            });
        }
    }
    match damage {
        Some(reason) => Err(DecodeStop::Damaged(reason)),
        None => Ok(()),
    }
}

/// The plaintext length of `data` once its PKCS7 padding is removed, if it is valid.
fn pkcs7_plain_len(data: &[u8]) -> Option<usize> {
    let &pad = data.last()?;
    let pad = pad as usize;
    if pad == 0 || pad > AES_BLOCK || pad > data.len() {
        return None;
    }
    data[data.len() - pad..]
        .iter()
        .all(|&b| b as usize == pad)
        .then_some(data.len() - pad)
}

/// What the header and unlock established, for the audit record.
#[derive(Debug, Clone, Serialize)]
pub struct AndroidFacts {
    pub format_version: u32,
    pub compressed: bool,
    pub encryption: String,
    /// The PBKDF2 variant that unlocked it, when encrypted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_derivation: Option<&'static str>,
    /// Package names found in the archive, sorted.
    pub packages: Vec<String>,
    /// What cut the payload short, when it is truncated or corrupt. Files after that
    /// point could not be read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream_error: Option<String>,
}

/// An `.ab` file, decoded and presented as a [`Source`] of its tar members.
///
/// Entries keep the archive's own names (`apps/<package>/db/x.db`), as an iOS backup
/// keeps `domain/relativePath`: that is what the evidence records. `backup rebuild`
/// maps them to device paths.
pub struct AndroidBackupSource {
    tar: TarSource,
    facts: AndroidFacts,
    provenance: Option<UnlockProvenance>,
}

impl AndroidBackupSource {
    /// Open and decode the `.ab` at `path`.
    ///
    /// A supplied password is the only one tried. With none, the acquisition defaults
    /// are tried and the one that worked is recorded, as for an iOS backup.
    pub fn open(path: &Path, password: Option<&str>) -> Result<Self> {
        let file = File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
        // SAFETY: read-only map of evidence opened read-only, as for every archive.
        let raw = unsafe { memmap2::Mmap::map(&file) }
            .with_context(|| format!("cannot map {}", path.display()))?;
        let header = parse_header(&raw)?;

        let mut keys = None;
        let mut key_derivation = None;
        let mut provenance = None;
        if header.encrypted() {
            let unlocked = candidates(password).into_iter().find_map(|candidate| {
                try_password(&header, &candidate).map(|found| (candidate, found))
            });
            let Some((candidate, (key, iv, regime))) = unlocked else {
                if password.is_some() {
                    bail!("the supplied --backup-password did not unlock this Android backup");
                }
                bail!(
                    "this Android backup is encrypted and no default password unlocked it — pass \
                     the password with --backup-password (or MFSCAN_BACKUP_PASSWORD)"
                );
            };
            keys = Some((key, iv));
            key_derivation = Some(regime.as_str());
            provenance = Some(if password.is_some() {
                UnlockProvenance::Supplied
            } else {
                UnlockProvenance::Default(candidate)
            });
        }

        let (stream, mut stream_error) = decode_payload(
            &raw[header.data_offset..],
            keys.as_ref().map(|(k, iv)| (k.as_slice(), iv.as_slice())),
            header.compressed,
        )?;
        let tar = TarSource::from_decoded(raw, stream);
        // Decoding can succeed while the tar inside is cut short (an uncompressed,
        // unencrypted payload has nothing else to detect truncation with).
        if stream_error.is_none() {
            stream_error = tar.damage().map(str::to_string);
        }

        let facts = AndroidFacts {
            format_version: header.version,
            compressed: header.compressed,
            encryption: header.encryption.clone(),
            key_derivation,
            packages: packages(tar.entries()),
            stream_error,
        };
        Ok(Self {
            tar,
            facts,
            provenance,
        })
    }

    pub fn facts(&self) -> &AndroidFacts {
        &self.facts
    }

    /// How an encrypted backup was unlocked; `None` when it is not encrypted.
    pub fn provenance(&self) -> Option<&UnlockProvenance> {
        self.provenance.as_ref()
    }

    /// Names of link and device members, which have no content to present.
    pub fn links(&self) -> &[String] {
        self.tar.links()
    }

    /// The directories and links the archive records, in the form a rebuild takes.
    pub fn structure(&self) -> BackupStructure {
        let mut structure = BackupStructure {
            directories: self
                .entries()
                .iter()
                .filter(|e| e.is_dir())
                .map(|e| DirectoryRecord {
                    name: e.name.trim_end_matches('/').to_string(),
                    mtime: e.mtime,
                })
                .collect(),
            symlinks: self.links().to_vec(),
            manifest: None,
        };
        structure.directories.sort();
        structure.symlinks.sort();
        structure
    }

    /// The `.ab` file exactly as stored, for `--verify`.
    pub fn raw_bytes(&self) -> &[u8] {
        self.tar.raw_bytes()
    }
}

/// The distinct package names in `entries`, sorted.
fn packages(entries: &[Entry]) -> Vec<String> {
    let mut names: Vec<String> = entries
        .iter()
        .filter_map(|e| {
            let mut parts = e.name.split('/');
            (parts.next() == Some("apps"))
                .then(|| parts.next())
                .flatten()
                .filter(|p| !p.is_empty())
                .map(str::to_string)
        })
        .collect();
    names.sort();
    names.dedup();
    names
}

impl Source for AndroidBackupSource {
    fn entries(&self) -> &[Entry] {
        self.tar.entries()
    }

    fn content(&self, entry: &Entry) -> Result<Content<'_>> {
        self.tar.content(entry)
    }

    fn byte_size(&self) -> u64 {
        self.raw_bytes().len() as u64
    }

    /// An `.ab` member has no single byte in the file on disk: its offset indexes the
    /// decoded stream.
    fn archive_data_start(&self, _entry: &Entry) -> Option<u64> {
        None
    }

    fn integrity_check(&self, _entry: &Entry) -> IntegrityCheck {
        IntegrityCheck::Unrecorded
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cbc::Encryptor;
    use cbc::cipher::BlockEncryptMut;

    const ROUNDS: u32 = 1000;

    fn tar_member(name: &str, data: &[u8], mtime: u64) -> Vec<u8> {
        let mut header = [0u8; 512];
        header[..name.len()].copy_from_slice(name.as_bytes());
        header[100..107].copy_from_slice(b"0000644");
        header[124..135].copy_from_slice(format!("{:011o}", data.len()).as_bytes());
        header[136..147].copy_from_slice(format!("{mtime:011o}").as_bytes());
        header[156] = if name.ends_with('/') { b'5' } else { b'0' };
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        header[148..156].fill(b' ');
        let sum: u32 = header.iter().map(|&b| b as u32).sum();
        header[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
        let mut out = header.to_vec();
        out.extend_from_slice(data);
        out.resize(out.len().next_multiple_of(512), 0);
        out
    }

    fn sample_tar() -> Vec<u8> {
        let mut tar = tar_member("apps/com.x/_manifest", b"manifest", 1_700_000_000);
        tar.extend(tar_member("apps/com.x/db/", b"", 1_700_000_100));
        tar.extend(tar_member("apps/com.x/db/m.db", b"needle", 1_700_000_200));
        tar.extend(vec![0u8; 1024]);
        tar
    }

    fn deflate(data: &[u8]) -> Vec<u8> {
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    fn encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {
        let mut buffer = data.to_vec();
        buffer.resize(data.len() + AES_BLOCK, 0);
        let written = Encryptor::<Aes256>::new_from_slices(key, iv)
            .unwrap()
            .encrypt_padded_mut::<Pkcs7>(&mut buffer, data.len())
            .unwrap()
            .len();
        buffer.truncate(written);
        buffer
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02X}")).collect()
    }

    /// Follows AOSP's `emitAesBackupHeader`: the write side, implemented separately so
    /// the reader under test has to agree with something it did not produce.
    fn build_ab(tar: &[u8], compressed: bool, password: Option<&str>) -> Vec<u8> {
        let payload = if compressed {
            deflate(tar)
        } else {
            tar.to_vec()
        };
        let mut out = format!("ANDROID BACKUP\n5\n{}\n", u8::from(compressed)).into_bytes();
        let Some(password) = password else {
            out.extend_from_slice(b"none\n");
            out.extend_from_slice(&payload);
            return out;
        };
        let (user_salt, checksum_salt) = ([7u8; 64], [9u8; 64]);
        let (user_iv, iv, key) = ([1u8; 16], [2u8; 16], [0xC3u8; 32]);
        let user_key = pbkdf2(password.as_bytes(), &user_salt, ROUNDS);
        let checksum = pbkdf2(key_as_java_chars(&key).as_bytes(), &checksum_salt, ROUNDS);
        let mut blob = Vec::new();
        for part in [&iv[..], &key[..], &checksum[..]] {
            blob.push(part.len() as u8);
            blob.extend_from_slice(part);
        }
        out.extend_from_slice(
            format!(
                "AES-256\n{}\n{}\n{ROUNDS}\n{}\n{}\n",
                hex(&user_salt),
                hex(&checksum_salt),
                hex(&user_iv),
                hex(&encrypt(&user_key, &user_iv, &blob)),
            )
            .as_bytes(),
        );
        out.extend_from_slice(&encrypt(&key, &iv, &payload));
        out
    }

    fn open(bytes: &[u8], password: Option<&str>) -> Result<AndroidBackupSource> {
        let dir = tempfile::tempdir().unwrap();
        // Named without `.ab`: detection is by content.
        let path = dir.path().join("backup.bin");
        std::fs::write(&path, bytes).unwrap();
        AndroidBackupSource::open(&path, password)
    }

    fn assert_sample(source: &AndroidBackupSource) {
        let names: Vec<&str> = source.entries().iter().map(|e| e.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "apps/com.x/_manifest",
                "apps/com.x/db/",
                "apps/com.x/db/m.db"
            ]
        );
        assert_eq!(&*source.content(&source.entries()[2]).unwrap(), b"needle");
        assert_eq!(source.entries()[2].mtime, Some(1_700_000_200));
        assert_eq!(source.facts().packages, ["com.x"]);
        assert_eq!(source.facts().stream_error, None);
    }

    #[test]
    fn reads_plain_and_compressed() {
        assert_sample(&open(&build_ab(&sample_tar(), false, None), None).unwrap());
        assert_sample(&open(&build_ab(&sample_tar(), true, None), None).unwrap());
    }

    #[test]
    fn reads_encrypted_with_the_right_password() {
        let source = open(
            &build_ab(&sample_tar(), true, Some("s3cret")),
            Some("s3cret"),
        )
        .unwrap();
        assert_sample(&source);
        assert_eq!(source.provenance(), Some(&UnlockProvenance::Supplied));
        assert_eq!(source.facts().key_derivation, Some("PBKDF2WithHmacSHA1"));
    }

    #[test]
    fn a_default_password_is_recorded() {
        let source = open(&build_ab(&sample_tar(), true, Some("1234")), None).unwrap();
        assert_eq!(
            source.provenance(),
            Some(&UnlockProvenance::Default("1234".to_string()))
        );
    }

    #[test]
    fn a_wrong_password_is_refused() {
        let ab = build_ab(&sample_tar(), true, Some("s3cret"));
        let err = open(&ab, Some("wrong")).err().expect("must be refused");
        assert!(err.to_string().contains("did not unlock"), "{err}");
        let err = open(&ab, None).err().expect("must be refused");
        assert!(err.to_string().contains("--backup-password"), "{err}");
    }

    #[test]
    fn a_newer_version_is_refused() {
        let ab = b"ANDROID BACKUP\n6\n0\nnone\n";
        let err = open(ab, None).err().expect("must be refused");
        assert!(err.to_string().contains("version 6"), "{err}");
    }

    /// A truncated backup must never look complete, whichever layer notices first.
    #[test]
    fn truncation_is_reported_and_earlier_members_are_kept() {
        let big: Vec<u8> = (0..200_000u32).flat_map(|i| i.to_le_bytes()).collect();
        let mut tar = tar_member("apps/com.x/f/first", b"needle", 1);
        tar.extend(tar_member("apps/com.x/f/big", &big, 2));
        tar.extend(vec![0u8; 1024]);

        for (compressed, password) in [(false, None), (true, None), (true, Some("pw"))] {
            let ab = build_ab(&tar, compressed, password);
            let cut = &ab[..ab.len() - ab.len() / 4];
            let source = open(cut, password).unwrap();
            assert!(
                source.facts().stream_error.is_some(),
                "compressed={compressed} password={password:?}"
            );
            let first = &source.entries()[0];
            assert_eq!(first.name, "apps/com.x/f/first");
            assert_eq!(&*source.content(first).unwrap(), b"needle");
        }
    }

    #[test]
    fn a_payload_past_the_spool_limit_spills_and_still_reads() {
        let mut spool = Spool::new();
        let chunk = vec![0xABu8; SPOOL_LIMIT / 2 + 1];
        spool.write(&chunk).unwrap();
        assert!(spool.file.is_none());
        spool.write(&chunk).unwrap();
        assert!(spool.file.is_some());
        let content = spool.finish().unwrap();
        assert_eq!(content.len(), chunk.len() * 2);
        assert!(content.iter().all(|&b| b == 0xAB));
    }

    #[test]
    fn java_char_widening_matches_aosp() {
        assert_eq!(key_as_java_chars(&[0x41]), "A");
        assert_eq!(key_as_java_chars(&[0x80]), "\u{FF80}");
        assert_eq!(key_as_java_chars(&[0xFF]), "\u{FFFF}");
    }
}
