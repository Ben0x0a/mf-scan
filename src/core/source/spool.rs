//! The spool: where a container decoded before it can be read at random is kept.
//!
//! Defines: `Spool` (collect decoded bytes, optionally up to a cap) and
//! [`SpoolCapExceeded`] (the error when the cap is reached).
//! Used by: `compressed` (a compressed stream), `sevenz` (a 7z's decoded blocks),
//! `expand` (nested containers, under the run's `--nested-limit`),
//! `platform::android::backup` (the decoded `.ab` payload).
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

use std::fmt;
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
    /// Bytes written so far, in memory or in the file.
    len: u64,
    /// The most bytes this spool may hold, if capped.
    cap: Option<u64>,
    /// What is being decoded, for error messages ("the Android backup").
    what: &'static str,
}

impl Spool {
    pub(crate) fn new(what: &'static str) -> Self {
        Self {
            memory: Vec::new(),
            file: None,
            len: 0,
            cap: None,
            what,
        }
    }

    /// A spool that refuses to hold more than `cap` bytes: the write that would pass
    /// it fails with [`SpoolCapExceeded`], before anything more is stored.
    pub(crate) fn capped(what: &'static str, cap: u64) -> Self {
        Self {
            cap: Some(cap),
            ..Self::new(what)
        }
    }

    pub(crate) fn write(&mut self, bytes: &[u8]) -> Result<()> {
        let what = self.what;
        if let Some(cap) = self.cap
            && self.len + bytes.len() as u64 > cap
        {
            return Err(anyhow::Error::new(SpoolCapExceeded { cap }));
        }
        self.len += bytes.len() as u64;
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

    /// What is being decoded, as errors name it.
    pub(crate) fn what(&self) -> &'static str {
        self.what
    }

    /// How many bytes have been written so far: where the next write starts.
    pub(crate) fn len(&self) -> u64 {
        self.len
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

/// A capped spool's write would have passed its cap.
///
/// A marker, so the caller can tell a resource limit (to report and stop) from a
/// damaged stream (to note and carry on), however deep in a decoder it happened.
#[derive(Debug)]
pub(crate) struct SpoolCapExceeded {
    pub(crate) cap: u64,
}

impl fmt::Display for SpoolCapExceeded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the decoded data would pass the {} bytes allowed",
            self.cap
        )
    }
}

impl std::error::Error for SpoolCapExceeded {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_capped_spool_refuses_the_write_past_its_cap() {
        let mut spool = Spool::capped("test data", 10);
        spool.write(&[1; 10]).unwrap();
        let e = spool.write(&[1]).unwrap_err();
        assert!(e.is::<SpoolCapExceeded>(), "{e}");
        assert_eq!(spool.len(), 10);
    }

    #[test]
    fn past_the_limit_it_spills_and_still_reads() {
        let mut spool = Spool::new("test data");
        let chunk = vec![0xABu8; SPOOL_LIMIT / 2 + 1];
        spool.write(&chunk).unwrap();
        assert!(!spool.spilled());
        spool.write(&chunk).unwrap();
        assert!(spool.spilled());
        assert_eq!(spool.len(), chunk.len() as u64 * 2);
        let content = spool.finish().unwrap();
        assert_eq!(content.len(), chunk.len() * 2);
        assert!(content.iter().all(|&b| b == 0xAB));
    }
}
