//! The spool: where a container decoded before it can be read at random is kept.
//!
//! Defines: `Spool` (collect decoded bytes) and `spool_reader` (drain a decoder into
//! one).
//! Used by: `tar` (compressed tar streams), `platform::android::backup` (the decoded
//! `.ab` payload).
//! Uses: `tempfile` (the spill file), `memmap2`, `Content`.
//!
//! HOW: bytes stay in memory up to `SPOOL_LIMIT`; past it, everything so far and all
//! that follows goes to an unnamed temporary file, mapped read-only once complete.
//!
//! WHY: a compressed stream (a `.tar.gz`, a `.tar.xz`, a 7z member, an `.ab`) has no
//! random access, so it is decoded once, whole; an acquisition can decode to many
//! gigabytes, more than memory. The file is unnamed, so the operating system deletes
//! it when the process ends, but it holds decoded evidence while the tool runs:
//! `TMPDIR` (`TMP` on Windows) chooses where. A stream larger than the free space
//! there fails loudly when a write fails, it is never cut short silently.

use std::fs::File;
use std::io::{Read, Write};

use anyhow::{Context, Result};

use crate::core::source::Content;

/// Decoded bytes above this spill from memory to a temporary file.
pub(crate) const SPOOL_LIMIT: usize = 64 * 1024 * 1024;
/// How much is read from a decoder at a time.
const CHUNK: usize = 1024 * 1024;

/// Collects decoded bytes, in memory up to [`SPOOL_LIMIT`], then in a temporary file.
pub(crate) struct Spool {
    memory: Vec<u8>,
    file: Option<File>,
    /// What is being decoded, for error messages ("the Android backup").
    what: &'static str,
}

impl Spool {
    pub(crate) fn new(what: &'static str) -> Self {
        Self {
            memory: Vec::new(),
            file: None,
            what,
        }
    }

    pub(crate) fn write(&mut self, bytes: &[u8]) -> Result<()> {
        let what = self.what;
        if self.file.is_none() && self.memory.len() + bytes.len() > SPOOL_LIMIT {
            let mut file = tempfile::tempfile()
                .with_context(|| format!("cannot create a temporary file to decode {what}"))?;
            file.write_all(&self.memory)
                .with_context(|| format!("cannot write decoded {what} to a temporary file"))?;
            self.memory = Vec::new();
            self.file = Some(file);
        }
        match &mut self.file {
            Some(file) => file
                .write_all(bytes)
                .with_context(|| format!("cannot write decoded {what} to a temporary file")),
            None => {
                self.memory.extend_from_slice(bytes);
                Ok(())
            }
        }
    }

    /// Whether the bytes went to a temporary file.
    #[cfg(test)]
    pub(crate) fn spilled(&self) -> bool {
        self.file.is_some()
    }

    pub(crate) fn finish(self) -> Result<Content<'static>> {
        match self.file {
            None => Ok(Content::Owned(self.memory)),
            Some(file) => {
                // SAFETY: an unnamed temporary file this process alone holds, mapped
                // read-only once it is complete.
                let map = unsafe { memmap2::Mmap::map(&file) }
                    .with_context(|| format!("cannot map decoded {}", self.what))?;
                Ok(Content::Mapped(map))
            }
        }
    }
}

/// Everything `reader` yields, spooled. A read error (a corrupt or truncated stream)
/// is returned, not taken for the end: a decoder that stops early would otherwise
/// read as a complete, shorter stream.
pub(crate) fn spool_reader(mut reader: impl Read, what: &'static str) -> Result<Content<'static>> {
    let mut spool = Spool::new(what);
    let mut buffer = vec![0u8; CHUNK];
    loop {
        let n = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e).with_context(|| format!("cannot decode {what}")),
        };
        spool.write(&buffer[..n])?;
    }
    spool.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn past_the_limit_it_spills_and_still_reads() {
        let mut spool = Spool::new("test data");
        let chunk = vec![0xABu8; SPOOL_LIMIT / 2 + 1];
        spool.write(&chunk).unwrap();
        assert!(!spool.spilled());
        spool.write(&chunk).unwrap();
        assert!(spool.spilled());
        let content = spool.finish().unwrap();
        assert_eq!(content.len(), chunk.len() * 2);
        assert!(content.iter().all(|&b| b == 0xAB));
    }

    #[test]
    fn a_reader_is_spooled_and_its_error_returned() {
        let content = spool_reader(&b"abc"[..], "test data").unwrap();
        assert_eq!(&*content, b"abc");
        struct Broken;
        impl Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("corrupt"))
            }
        }
        let Err(error) = spool_reader(Broken, "test data") else {
            panic!("a read error must be returned");
        };
        assert!(format!("{error:#}").contains("corrupt"), "{error:#}");
    }
}
