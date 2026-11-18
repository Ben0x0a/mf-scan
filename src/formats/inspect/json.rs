//! JSON inspector: map a byte offset to a JSON key path (e.g. `$.users[3].id`).
//!
//! Defines: the JSON inspector, returning the path to the value (or key) that
//! contains each match offset.
//! Used by: `inspect::inspect` (dispatch, including the structure fallback); its
//! `unescape` by `ops::search::encodings::json` (a JSON-escaped search match).
//! Uses: `crate::core::models::Inspection`, `serde_json` (structured detail).
//!
//! Why a hand-rolled scanner rather than `serde_json`: serde gives a parsed
//! tree but not byte spans, and we need to know which value's bytes contain a
//! given offset. This single-pass scanner tracks the path stack as it walks the
//! document and records, for every match offset, the path of the first value/key
//! whose span covers it. It is tolerant of minor malformation (it locates, it does
//! not validate).
//!
//! WHY all offsets in one walk: spans are met in byte order, so with the offsets
//! sorted, each span settles the pending offsets inside it and the walk stops once
//! all are settled. Resolving offsets one by one would rescan the file per match.

use serde_json::{Value, json};

use crate::core::models::{ContentDiff, Inspection};
use crate::formats::inspect::value_diff::diff_values;

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
        resolve_many(content, &[offset]).pop().flatten()
    }
    fn inspect_many(&self, content: &[u8], offsets: &[usize]) -> Vec<Option<Inspection>> {
        resolve_many(content, offsets)
    }
    fn diff(&self, old: &[u8], new: &[u8]) -> Option<ContentDiff> {
        // For the diff we want the parsed tree, not byte spans, so serde_json is the
        // right tool here (the hand-rolled scanner above exists only for offsets).
        let old: Value = serde_json::from_slice(old).ok()?;
        let new: Value = serde_json::from_slice(new).ok()?;
        Some(diff_values("json", &old, &new))
    }
}

/// Locate the JSON path of the value/key at each of `offsets`, in one walk of the
/// document. Results are in the order of `offsets`; `None` for an offset outside
/// every key and value (between tokens) or past the end.
fn resolve_many(content: &[u8], offsets: &[usize]) -> Vec<Option<Inspection>> {
    let mut targets = Targets::new(content.len(), offsets);
    let mut scanner = Scanner {
        bytes: content,
        pos: 0,
    };
    scanner.value(&mut Vec::new(), &mut targets, 0);

    // Line numbers in the same order, counting newlines once, forwards.
    let mut out: Vec<Option<Inspection>> = offsets.iter().map(|_| None).collect();
    let (mut at, mut line) = (0usize, 1usize);
    for &(offset, index) in &targets.sorted {
        let Some(path) = targets.paths[index].take() else {
            continue;
        };
        line += content[at..offset].iter().filter(|&&b| b == b'\n').count();
        at = offset;
        out[index] = Some(Inspection {
            format: "json".into(),
            summary: format!("key: {path}  line: {line}"),
            detail: json!({ "path": path, "line": line }),
        });
    }
    out
}

/// The match offsets still to place, sorted, with the path found for each.
struct Targets {
    /// `(offset, index into the caller's offsets)`, by offset.
    sorted: Vec<(usize, usize)>,
    /// The first entry of `sorted` not settled yet.
    next: usize,
    /// The path found for each caller offset.
    paths: Vec<Option<String>>,
}

impl Targets {
    fn new(len: usize, offsets: &[usize]) -> Self {
        let mut sorted: Vec<(usize, usize)> = offsets
            .iter()
            .enumerate()
            .filter(|&(_, &o)| o < len)
            .map(|(i, &o)| (o, i))
            .collect();
        sorted.sort_unstable();
        Self {
            sorted,
            next: 0,
            paths: offsets.iter().map(|_| None).collect(),
        }
    }

    fn done(&self) -> bool {
        self.next >= self.sorted.len()
    }

    /// The span `[start, end)` belongs to `path`: settle the offsets inside it. The
    /// offsets before it fell between tokens, and are settled with no path.
    fn hit(&mut self, start: usize, end: usize, path: &[Seg]) {
        while self.sorted.get(self.next).is_some_and(|&(o, _)| o < start) {
            self.next += 1;
        }
        let mut rendered: Option<String> = None;
        while let Some(&(o, index)) = self.sorted.get(self.next)
            && o < end
        {
            let p = rendered.get_or_insert_with(|| render(path));
            self.paths[index] = Some(p.clone());
            self.next += 1;
        }
    }
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

    /// Parse a value at the cursor, descending into containers (to `MAX_DEPTH`).
    fn value(&mut self, path: &mut Vec<Seg>, targets: &mut Targets, depth: usize) {
        if depth > MAX_DEPTH || targets.done() {
            return;
        }
        self.skip_ws();
        let start = self.pos;
        match self.peek() {
            Some(b'{') => self.object(path, targets, depth),
            Some(b'[') => self.array(path, targets, depth),
            Some(b'"') => {
                self.scan_string();
                targets.hit(start, self.pos, path);
            }
            Some(_) => {
                // number / true / false / null: read up to the next delimiter.
                while let Some(c) = self.peek() {
                    if matches!(c, b',' | b'}' | b']' | b' ' | b'\t' | b'\n' | b'\r') {
                        break;
                    }
                    self.bump();
                }
                targets.hit(start, self.pos, path);
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
    ///
    /// The key's bytes are gathered and decoded at the end, escapes included: pushing
    /// each byte as a char would turn a non-ASCII key (`prénom`) into `prÃ©nom`, and
    /// `pr\u00e9nom` (as Python writes it) must read `prénom` too.
    fn read_key(&mut self) -> (usize, usize, String) {
        let start = self.pos;
        self.bump(); // opening quote
        let mut key = Vec::new();
        while let Some(c) = self.peek() {
            self.bump();
            match c {
                // An escape is kept as written (so `\"` does not end the key) and
                // resolved with the whole key below.
                b'\\' => {
                    key.push(c);
                    if let Some(e) = self.peek() {
                        self.bump();
                        key.push(e);
                    }
                }
                b'"' => break,
                _ => key.push(c),
            }
        }
        (start, self.pos, unescape(&key))
    }

    fn object(&mut self, path: &mut Vec<Seg>, targets: &mut Targets, depth: usize) {
        self.bump(); // {
        loop {
            if targets.done() {
                return;
            }
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
            path.push(Seg::Key(key));
            targets.hit(key_start, key_end, path);

            self.skip_ws();
            if self.peek() == Some(b':') {
                self.bump();
            }

            self.value(path, targets, depth + 1);
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

    fn array(&mut self, path: &mut Vec<Seg>, targets: &mut Targets, depth: usize) {
        self.bump(); // [
        let mut index = 0;
        loop {
            if targets.done() {
                return;
            }
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
            self.value(path, targets, depth + 1);
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

/// JSON string text with its escapes resolved: `\uXXXX` (a surrogate pair as one
/// character, an unpaired one as U+FFFD), `\n` and the other short escapes. Used
/// for object keys here, and for a JSON-escaped search match (`--encoding json`).
pub(crate) fn unescape(span: &[u8]) -> String {
    let text = String::from_utf8_lossy(span);
    let mut units: Vec<u16> = Vec::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            let mut buf = [0u16; 2];
            units.extend_from_slice(c.encode_utf16(&mut buf));
            continue;
        }
        match chars.next() {
            Some('u') => {
                let hex: String = chars.by_ref().take(4).collect();
                units.push(u16::from_str_radix(&hex, 16).unwrap_or(0xFFFD));
            }
            Some('n') => units.push(u16::from(b'\n')),
            Some('t') => units.push(u16::from(b'\t')),
            Some('r') => units.push(u16::from(b'\r')),
            Some('b') => units.push(0x08),
            Some('f') => units.push(0x0C),
            Some(other) => {
                let mut buf = [0u16; 2];
                units.extend_from_slice(other.encode_utf16(&mut buf));
            }
            None => units.push(u16::from(b'\\')),
        }
    }
    String::from_utf16_lossy(&units)
}

#[cfg(test)]
mod tests {
    use super::resolve_many;

    const DOC: &[u8] = br#"{
  "users": [
    {"id": 7, "name": "Ana", "tags": ["a", "b"]},
    {"id": 8, "name": "Bo\"b", "deep": {"x": [1, {"y": null}]}}
  ],
  "count": 2
}"#;

    fn path_line(found: &Option<crate::core::models::Inspection>) -> Option<(String, u64)> {
        found.as_ref().map(|f| {
            (
                f.detail["path"].as_str().unwrap().to_string(),
                f.detail["line"].as_u64().unwrap(),
            )
        })
    }

    #[test]
    fn all_offsets_in_one_walk_match_each_offset_alone() {
        // Every offset, reversed (unsorted), resolved together and one by one.
        let offsets: Vec<usize> = (0..DOC.len() + 2).rev().collect();
        let together = resolve_many(DOC, &offsets);
        for (&offset, found) in offsets.iter().zip(&together) {
            let alone = resolve_many(DOC, &[offset]).pop().flatten();
            assert_eq!(path_line(found), path_line(&alone), "offset {offset}");
        }
        let at = |needle: &[u8]| DOC.windows(needle.len()).position(|w| w == needle).unwrap();
        let get = |o: usize| path_line(&resolve_many(DOC, &[o])[0]).unwrap();
        assert_eq!(get(at(b"Ana")), ("$.users[0].name".into(), 3));
        assert_eq!(get(at(b"null")), ("$.users[1].deep.x[1].y".into(), 4));
        assert_eq!(get(at(b"count")), ("$.count".into(), 6));
        // A non-ASCII key keeps its letters, written raw or escaped (as Python does).
        for doc in ["{\"pr\u{e9}nom\": \"Zoe\"}", r#"{"pr\u00e9nom": "Zoe"}"#] {
            let zoe = doc.find("Zoe").unwrap();
            let found = path_line(&resolve_many(doc.as_bytes(), &[zoe])[0]).unwrap();
            assert_eq!(found.0, "$.pr\u{e9}nom", "{doc}");
        }
        // Between tokens: no path.
        assert!(resolve_many(DOC, &[at(b"[\n")])[0].is_none());
    }
}
