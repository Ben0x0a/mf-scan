//! A source over bytes held in memory: one file, such as standard input.
//!
//! Defines: [`BytesSource`].
//! Used by: the binary's `support::sources` (reads standard input into one).
//! Uses: `crate::core::models::{Entry, Location}`.

use std::path::PathBuf;

use anyhow::Result;

use crate::core::models::{Entry, Location};
use crate::core::source::{Content, Source};

/// One in-memory file, presented under `name`. It has no location on disk or in an
/// archive, so `Location::Loose` only gives the entry an identity.
pub struct BytesSource {
    entries: Vec<Entry>,
    data: Vec<u8>,
}

impl BytesSource {
    pub fn new(name: &str, data: Vec<u8>) -> Self {
        Self {
            entries: vec![Entry {
                name: name.to_string(),
                uncompressed_size: data.len() as u64,
                mtime: None,
                location: Location::Loose {
                    path: PathBuf::from(name),
                },
            }],
            data,
        }
    }
}

impl Source for BytesSource {
    fn entries(&self) -> &[Entry] {
        &self.entries
    }

    fn content(&self, _entry: &Entry) -> Result<Content<'_>> {
        Ok(Content::Borrowed(&self.data))
    }

    fn reads_in_place(&self, _entry: &Entry) -> bool {
        true
    }

    fn byte_size(&self) -> u64 {
        self.data.len() as u64
    }
}
