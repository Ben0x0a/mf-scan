//! ABX inspector: map a byte offset in an Android Binary XML file (Android 12+
//! `packages.xml`, `settings_*.xml`, …) to its element path, attribute and value.
//!
//! Defines: [`Abx`] (the inspector).
//! Used by: `inspect::mod` (registered in `INSPECTORS`).
//! Uses: `crate::core::models::Inspection`, `base64`, `serde_json`.
//!
//! ── Format ───────────────────────────────────────────────────────────────────
//! As written by Android's `BinaryXmlSerializer` (and read by CCL Forensics' reader
//! that ALEAPP vendors, MIT): "ABX" and version 0, then one token per XML event. A
//! token byte's low nibble is the event (0 start document, 1 end document, 2 start
//! tag, 3 end tag, 4-10 text-like: text, CDATA, entity, whitespace, processing
//! instruction, comment, doctype; 15 attribute), its high nibble the data type (1
//! null, 2 string, 3 interned string, 4 hex bytes, 5 base64 bytes, 6 int, 7 hex int,
//! 8 long, 9 hex long, 10 float, 11 double, 12 true, 13 false). Numbers are
//! big-endian. A string is a u16 length and its UTF-8 bytes; an interned string is a
//! u16 index into the strings seen so far, or 0xFFFF followed by a new string that
//! joins them. Tag names and attribute names are interned.
//!
//! Checked on every ABX file of the test file systems (1,234, three Android
//! devices): each parses token by token to its end, its tags balanced.

use std::collections::HashMap;
use std::ops::Range;

use base64::Engine;
use serde_json::json;

use super::{SHOWN_CHARS, quoted};
use crate::core::models::Inspection;

const MAGIC: &[u8; 4] = b"ABX\0";

/// ABX inspector — recognised by its `ABX\0` magic.
pub struct Abx;

impl super::Inspector for Abx {
    fn name(&self) -> &'static str {
        "abx"
    }
    fn category(&self) -> &'static str {
        "structured"
    }
    /// None: ABX files keep their `.xml` names, which would claim text XML too.
    fn extensions(&self) -> &'static [&'static str] {
        &[]
    }
    fn detect(&self, content: &[u8]) -> bool {
        content.starts_with(MAGIC)
    }
    fn inspect(&self, content: &[u8], offset: usize) -> Option<Inspection> {
        self.inspect_many(content, &[offset]).pop().flatten()
    }
    /// The token stream is read once; each match is then a lookup.
    fn inspect_many(&self, content: &[u8], offsets: &[usize]) -> Vec<Option<Inspection>> {
        let tokens = read(content);
        offsets
            .iter()
            .map(|&o| locate(content, &tokens, o))
            .collect()
    }
}

/// What a token is, with what the result shows for it.
#[derive(Debug)]
enum Part {
    /// A start or end tag (the element's own path).
    Tag,
    /// An attribute: its name and value as shown.
    Attribute { name: String, value: Value },
    /// Text-like content (`text()`, `comment()`, …) and its text, when not null.
    Text {
        node: &'static str,
        text: Option<String>,
    },
    /// Start or end of the document.
    Document,
}

/// An attribute value, typed as stored.
#[derive(Debug)]
struct Value {
    kind: &'static str,
    shown: String,
}

/// One token: its bytes, the path of the element it belongs to, and what it is.
#[derive(Debug)]
struct Token {
    range: Range<usize>,
    path: String,
    part: Part,
}

/// Bytes read from `content` at a cursor; `None` past the end.
struct Cursor<'c> {
    c: &'c [u8],
    pos: usize,
}

impl Cursor<'_> {
    fn take(&mut self, n: usize) -> Option<&[u8]> {
        let bytes = self.c.get(self.pos..self.pos.checked_add(n)?)?;
        self.pos += n;
        Some(bytes)
    }
    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_be_bytes(self.take(2)?.try_into().ok()?))
    }
    fn utf(&mut self) -> Option<String> {
        let n = usize::from(self.u16()?);
        Some(String::from_utf8_lossy(self.take(n)?).into_owned())
    }
    fn interned(&mut self, table: &mut Vec<String>) -> Option<String> {
        match self.u16()? {
            0xFFFF => {
                let s = self.utf()?;
                table.push(s.clone());
                Some(s)
            }
            i => table.get(usize::from(i)).cloned(),
        }
    }
}

/// One open element: its path, and how many children of each name it has so far.
struct Frame {
    path: String,
    children: HashMap<String, usize>,
}

/// Read the token stream. Reading stops at the end of the document or at the first
/// token that does not fit the format; the tokens before it are kept.
fn read(c: &[u8]) -> Vec<Token> {
    let mut tokens = Vec::new();
    if !c.starts_with(MAGIC) {
        return tokens;
    }
    let mut cur = Cursor {
        c,
        pos: MAGIC.len(),
    };
    let mut interned = Vec::new();
    let mut stack: Vec<Frame> = Vec::new();
    // The top level's children, counted like an element's.
    let mut top: HashMap<String, usize> = HashMap::new();
    while cur.pos < c.len() {
        let start = cur.pos;
        let Some(token) = read_token(&mut cur, &mut interned, &mut stack, &mut top) else {
            break;
        };
        let (path, part, end_of_document) = token;
        tokens.push(Token {
            range: start..cur.pos,
            path,
            part,
        });
        if end_of_document {
            break;
        }
    }
    tokens
}

/// One token at the cursor: the element path it belongs to, what it is, and whether
/// it ends the document.
fn read_token(
    cur: &mut Cursor<'_>,
    interned: &mut Vec<String>,
    stack: &mut Vec<Frame>,
    top: &mut HashMap<String, usize>,
) -> Option<(String, Part, bool)> {
    let byte = *cur.take(1)?.first()?;
    let (event, ty) = (byte & 0x0F, byte >> 4);
    let here = |stack: &[Frame]| {
        stack
            .last()
            .map_or_else(|| "/".to_string(), |f| f.path.clone())
    };
    match event {
        0 | 1 if ty == 1 => Some((here(stack), Part::Document, event == 1)),
        2 if ty == 3 => {
            let name = cur.interned(interned)?;
            let siblings = stack.last_mut().map_or(&mut *top, |f| &mut f.children);
            let n = siblings.entry(name.clone()).or_insert(0);
            *n += 1;
            let n = *n;
            let parent = stack.last().map_or("", |f| f.path.as_str());
            let path = format!("{parent}/{name}[{n}]");
            stack.push(Frame {
                path: path.clone(),
                children: HashMap::new(),
            });
            Some((path, Part::Tag, false))
        }
        3 if ty == 3 => {
            let name = cur.interned(interned)?;
            let frame = stack.pop()?;
            // The closing name must be the open element's (its last segment).
            let open = frame.path.rsplit('/').next()?;
            (open.split('[').next()? == name).then_some((frame.path, Part::Tag, false))
        }
        4..=10 => {
            let node = match event {
                5 => "cdata()",
                9 => "comment()",
                8 => "processing-instruction()",
                10 => "doctype()",
                _ => "text()",
            };
            let text = match ty {
                2 => Some(cur.utf()?),
                1 => None,
                _ => return None,
            };
            Some((here(stack), Part::Text { node, text }, false))
        }
        15 => {
            let name = cur.interned(interned)?;
            let value = attribute_value(cur, interned, ty)?;
            Some((here(stack), Part::Attribute { name, value }, false))
        }
        _ => None,
    }
}

/// An attribute's value, read by its data type.
fn attribute_value(cur: &mut Cursor<'_>, interned: &mut Vec<String>, ty: u8) -> Option<Value> {
    let int = |b: &[u8]| i32::from_be_bytes(b.try_into().unwrap_or_default());
    let long = |b: &[u8]| i64::from_be_bytes(b.try_into().unwrap_or_default());
    let (kind, shown) = match ty {
        1 => ("null", "null".to_string()),
        2 => ("string", quoted(&cur.utf()?)),
        3 => ("string", quoted(&cur.interned(interned)?)),
        4 => {
            let n = usize::from(cur.u16()?);
            ("bytes (hex)", hex(cur.take(n)?))
        }
        5 => {
            let n = usize::from(cur.u16()?);
            let b64 = base64::engine::general_purpose::STANDARD.encode(cur.take(n)?);
            ("bytes (base64)", b64)
        }
        6 => ("int", int(cur.take(4)?).to_string()),
        7 => ("int (hex)", format!("{:x}", int(cur.take(4)?))),
        8 => ("long", long(cur.take(8)?).to_string()),
        9 => ("long (hex)", format!("{:x}", long(cur.take(8)?))),
        10 => (
            "float",
            f32::from_be_bytes(cur.take(4)?.try_into().ok()?).to_string(),
        ),
        11 => (
            "double",
            f64::from_be_bytes(cur.take(8)?.try_into().ok()?).to_string(),
        ),
        12 => ("boolean", "true".to_string()),
        13 => ("boolean", "false".to_string()),
        _ => return None,
    };
    Some(Value { kind, shown })
}

/// Bytes as hex, capped like a quoted value.
fn hex(bytes: &[u8]) -> String {
    let mut s: String = bytes
        .iter()
        .take(SHOWN_CHARS / 2)
        .map(|b| format!("{b:02x}"))
        .collect();
    if bytes.len() > SHOWN_CHARS / 2 {
        s.push('…');
    }
    s
}

fn locate(c: &[u8], tokens: &[Token], offset: usize) -> Option<Inspection> {
    if offset >= c.len() {
        return None;
    }
    let found = |summary: String, detail: serde_json::Value| Inspection {
        format: "abx".into(),
        summary,
        detail,
    };
    if offset < MAGIC.len() {
        return Some(found("ABX header".into(), json!({ "part": "header" })));
    }
    let i = tokens.partition_point(|t| t.range.start <= offset);
    let token = tokens
        .get(i.checked_sub(1)?)
        .filter(|t| t.range.contains(&offset))?;
    let path = &token.path;
    Some(match &token.part {
        Part::Tag => found(format!("path: {path}"), json!({ "path": path })),
        Part::Attribute { name, value } => found(
            format!("path: {path}/@{name}  value: {}", value.shown),
            json!({ "path": path, "attribute": name, "type": value.kind, "value": value.shown }),
        ),
        Part::Text { node, text } => {
            let shown = text.as_deref().map_or_else(|| "null".to_string(), quoted);
            found(
                format!("path: {path}/{node}  value: {shown}"),
                json!({ "path": path, "node": node, "value": text }),
            )
        }
        Part::Document => found(
            "ABX document start or end".into(),
            json!({ "part": "document" }),
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::super::Inspector;
    use super::*;

    /// Builds an ABX stream token by token.
    struct AbxBuilder(Vec<u8>, Vec<String>);

    impl AbxBuilder {
        fn new() -> Self {
            let mut v = MAGIC.to_vec();
            v.push(0x10); // start document
            Self(v, Vec::new())
        }
        fn interned(&mut self, s: &str) {
            if let Some(i) = self.1.iter().position(|x| x == s) {
                self.0.extend_from_slice(&(i as u16).to_be_bytes());
            } else {
                self.0.extend_from_slice(&[0xFF, 0xFF]);
                self.utf(s);
                self.1.push(s.into());
            }
        }
        fn utf(&mut self, s: &str) {
            self.0.extend_from_slice(&(s.len() as u16).to_be_bytes());
            self.0.extend_from_slice(s.as_bytes());
        }
        fn start(&mut self, name: &str) -> &mut Self {
            self.0.push(0x32);
            self.interned(name);
            self
        }
        fn end(&mut self, name: &str) -> &mut Self {
            self.0.push(0x33);
            self.interned(name);
            self
        }
        fn attr_str(&mut self, name: &str, value: &str) -> &mut Self {
            self.0.push(0x2F);
            self.interned(name);
            self.utf(value);
            self
        }
        fn attr_int(&mut self, name: &str, value: i32) -> &mut Self {
            self.0.push(0x6F);
            self.interned(name);
            self.0.extend_from_slice(&value.to_be_bytes());
            self
        }
        fn attr_true(&mut self, name: &str) -> &mut Self {
            self.0.push(0xCF);
            self.interned(name);
            self
        }
        fn text(&mut self, s: &str) -> &mut Self {
            self.0.push(0x24);
            self.utf(s);
            self
        }
        fn done(&mut self) -> Vec<u8> {
            self.0.push(0x11); // end document
            self.0.clone()
        }
    }

    fn sample() -> Vec<u8> {
        AbxBuilder::new()
            .start("packages")
            .start("package")
            .attr_str("name", "com.example.first")
            .attr_int("userId", 10123)
            .end("package")
            .start("package")
            .attr_str("name", "com.example.second")
            .attr_true("isOrphaned")
            .start("sigs")
            .text("abc signature")
            .end("sigs")
            .end("package")
            .end("packages")
            .done()
    }

    fn at(f: &[u8], needle: &[u8]) -> usize {
        f.windows(needle.len()).position(|w| w == needle).unwrap()
    }

    #[test]
    fn attributes_text_and_tags_resolve_to_paths() {
        let f = sample();
        assert!(Abx.detect(&f));
        let get = |needle: &[u8]| Abx.inspect(&f, at(&f, needle)).unwrap();

        let second = get(b"example.second");
        assert_eq!(
            second.summary,
            "path: /packages[1]/package[2]/@name  value: \"com.example.second\""
        );
        assert_eq!(second.detail["type"], "string");
        let sig = get(b"signature");
        assert_eq!(
            sig.summary,
            "path: /packages[1]/package[2]/sigs[1]/text()  value: \"abc signature\""
        );
        // An interned name, written once: its bytes are in the first token using it.
        let user = get(b"userId");
        assert_eq!(
            user.summary,
            "path: /packages[1]/package[1]/@userId  value: 10123"
        );
        let orphan = get(b"isOrphaned");
        assert_eq!(orphan.detail["value"], "true");
        assert_eq!(Abx.inspect(&f, 1).unwrap().summary, "ABX header");
    }

    #[test]
    fn a_broken_stream_keeps_what_came_before() {
        let mut f = sample();
        let cut = at(&f, b"abc signature");
        f.truncate(cut + 3);
        // The string is cut: that token is unread, the first package still resolves.
        assert!(Abx.inspect(&f, cut).is_none());
        assert!(Abx.inspect(&f, at(&f, b"example.first")).is_some());
    }

    #[test]
    fn corrupt_bytes_never_panic() {
        let f = sample();
        for i in 0..f.len() {
            for b in [0x00, 0x33, 0xFF] {
                let mut g = f.clone();
                g[i] = b;
                let _ = Abx.inspect_many(&g, &[0, i, g.len() - 1]);
            }
        }
    }
}
