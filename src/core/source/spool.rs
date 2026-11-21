//! The spool: where a container decoded before it can be read at random is kept.
//!
//! Defines: `Spool` (collect decoded bytes).
//! Used by: `compressed` (a compressed stream), `platform::android::backup` (the
//! decoded `.ab` payload).
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
use std::io::Write;

use anyhow::{Context, Result};

use crate::core::source::Content;

/// Decoded bytes above this spill from memory to a temporary file.
pub(crate) const SPOOL_LIMIT: usize = 64 * 1024 * 1024;

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
}
