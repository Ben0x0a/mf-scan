//! JSON inspector: map a byte offset to a JSON key path (e.g. `$.users[3].id`).
//!
//! Defines: `inspect`, returning the path to the value (or key) that contains a
//! match offset.
//! Used by: `inspect::inspect` (dispatch).
//! Uses: `crate::models::Inspection`, `serde_json` (structured detail).
//!
//! Why a hand-rolled scanner rather than `serde_json`: serde gives a parsed
//! tree but not byte spans, and we need to know which value's bytes contain a
//! given offset. This single-pass scanner tracks the path stack as it walks the
//! document and records the path of the first value/key whose span covers the
//! target offset. It is tolerant of minor malformation (it locates, it does not
//! validate).

use serde_json::{Value, json};

use crate::inspect::value_diff::diff_values;
use crate::models::{ContentDiff, Inspection};

/// One step in a JSON path: an object key or an array index.
enum Seg {
    Key(String),
    Index(usize),
}

/// JSON inspector — detected by `.json` extension (JSON has no header magic).
pub struct Json;

impl super::Inspector for Json {
    fn name(&self) -> &'static str {
        "json"
    }
    fn category(&self) -> &'static str {
        "structured"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["json"]
    }
    fn detect(&self, _content: &[u8]) -> bool {
        false // no signature
    }
    fn inspect(&self, content: &[u8], offset: usize) -> Option<Inspection> {
        resolve(content, offset)
    }
    fn diff(&self, old: &[u8], new: &[u8]) -> Option<ContentDiff> {
        // For the diff we want the parsed tree, not byte spans, so serde_json is the
        // right tool here (the hand-rolled scanner above exists only for offsets).
        let old: Value = serde_json::from_slice(old).ok()?;
        let new: Value = serde_json::from_slice(new).ok()?;
        Some(diff_values("json", &old, &new))
    }
}

/// Locate the JSON path of the value/key at `offset`.
fn resolve(content: &[u8], offset: usize) -> Option<Inspection> {
    if offset >= content.len() {
        return None;
    }
    let mut scanner = Scanner {
        bytes: content,
        pos: 0,
    };
    let mut path = Vec::new();
    let mut found = None;
    scanner.value(offset, &mut path, &mut found, 0);

    let path = found?;
    let line = super::line_at(content, offset);
    Some(Inspection {
        format: "json".into(),
        summary: format!("key: {path}  line: {line}"),
        detail: json!({ "path": path, "line": line }),
    })
}

/// Render a path stack as `$`-rooted JSONPath-ish text.
fn render(path: &[Seg]) -> String {
    let mut s = String::from("$");
    for seg in path {
        match seg {
            Seg::Key(k) => {
                s.push('.');
                s.push_str(k);
            }
            Seg::Index(i) => {
                s.push('[');
                s.push_str(&i.to_string());
                s.push(']');
            }
        }
    }
    s
}

/// Maximum container nesting the scanner descends into — the same limit
/// serde_json enforces. The methods below recurse per nesting level, so a
/// crafted file of 100 000 `[` bytes would otherwise overflow the stack and
/// crash the whole process; past the cap the scanner abandons the subtree and
/// inspection degrades to the offset-only fallback.
const MAX_DEPTH: usize = 128;

struct Scanner<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Scanner<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn bump(&mut self) {
        self.pos += 1;
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.bump();
        }
    }

    /// Record `path` as the hit if `[start, end)` covers `target` and nothing
    /// has been found yet.
    fn maybe_hit(
        &self,
        start: usize,
        end: usize,
        target: usize,
        path: &[Seg],
        found: &mut Option<String>,
    ) {
        if found.is_none() && target >= start && target < end {
            *found = Some(render(path));
        }
    }

    /// Parse a value at the cursor, descending into containers (to `MAX_DEPTH`).
    fn value(
        &mut self,
        target: usize,
        path: &mut Vec<Seg>,
        found: &mut Option<String>,
        depth: usize,
    ) {
        if depth > MAX_DEPTH {
            return;
        }
        self.skip_ws();
        let start = self.pos;
        match self.peek() {
            Some(b'{') => self.object(target, path, found, depth),
            Some(b'[') => self.array(target, path, found, depth),
            Some(b'"') => {
                self.scan_string();
                self.maybe_hit(start, self.pos, target, path, found);
            }
            Some(_) => {
                // number / true / false / null: read up to the next delimiter.
                while let Some(c) = self.peek() {
                    if matches!(c, b',' | b'}' | b']' | b' ' | b'\t' | b'\n' | b'\r') {
                        break;
                    }
                    self.bump();
                }
                self.maybe_hit(start, self.pos, target, path, found);
            }
            None => {}
        }
    }

    /// Consume a string token (cursor must be on the opening quote), leaving the
    /// cursor just past the closing quote.
    fn scan_string(&mut self) {
        self.bump(); // opening quote
        while let Some(c) = self.peek() {
            self.bump();
            match c {
                b'\\' => {
                    self.bump(); // skip the escaped character
                }
                b'"' => break,
                _ => {}
            }
        }
    }

    /// Read an object key string, returning its byte span and decoded text.
    fn read_key(&mut self) -> (usize, usize, String) {
        let start = self.pos;
        self.bump(); // opening quote
        let mut key = String::new();
        while let Some(c) = self.peek() {
            self.bump();
            match c {
                b'\\' => {
                    if let Some(e) = self.peek() {
                        self.bump();
                        key.push(decode_escape(e));
                    }
                }
                b'"' => break,
                _ => key.push(c as char),
            }
        }
        (start, self.pos, key)
    }

    fn object(
        &mut self,
        target: usize,
        path: &mut Vec<Seg>,
        found: &mut Option<String>,
        depth: usize,
    ) {
        self.bump(); // {
        loop {
            self.skip_ws();
            match self.peek() {
                Some(b'}') => {
                    self.bump();
                    return;
                }
                None => return,
                Some(b'"') => {}
                _ => {
                    // Tolerate stray bytes without looping forever.
                    self.bump();
                    continue;
                }
            }

            let (key_start, key_end, key) = self.read_key();
            // A match inside the key name points at the value that key selects.
            if found.is_none() && target >= key_start && target < key_end {
                path.push(Seg::Key(key.clone()));
                *found = Some(render(path));
                path.pop();
            }

            self.skip_ws();
            if self.peek() == Some(b':') {
                self.bump();
            }

            path.push(Seg::Key(key));
            self.value(target, path, found, depth + 1);
            path.pop();

            self.skip_ws();
            match self.peek() {
                Some(b',') => self.bump(),
                Some(b'}') => {
                    self.bump();
                    return;
                }
                _ => return,
            }
        }
    }

    fn array(
        &mut self,
        target: usize,
        path: &mut Vec<Seg>,
        found: &mut Option<String>,
        depth: usize,
    ) {
        self.bump(); // [
        let mut index = 0;
        loop {
            self.skip_ws();
            match self.peek() {
                Some(b']') => {
                    self.bump();
                    return;
                }
                None => return,
                _ => {}
            }

            path.push(Seg::Index(index));
            self.value(target, path, found, depth + 1);
            path.pop();
            index += 1;

            self.skip_ws();
            match self.peek() {
                Some(b',') => self.bump(),
                Some(b']') => {
                    self.bump();
                    return;
                }
                _ => return,
            }
        }
    }
}

/// Decode the common JSON string escapes for display in a path.
fn decode_escape(e: u8) -> char {
    match e {
        b'n' => '\n',
        b't' => '\t',
        b'r' => '\r',
        b'"' => '"',
        b'\\' => '\\',
        b'/' => '/',
        other => other as char,
    }
}
