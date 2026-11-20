//! XML inspector: map a byte offset to its node, as the ABX inspector does for binary
//! XML: the element path with sibling indices (`/manifest[1]/application[1]`), and
//! the attribute (`/@android:name  value: …`) or the text node (`text()`, `cdata()`,
//! `comment()`, …) holding it.
//!
//! Defines: [`Xml`] (the inspector).
//! Used by: `inspect::mod` (registered in `INSPECTORS`).
//! Uses: `quick_xml` (an event reader over the file's own bytes), `serde_json`,
//! `crate::core::models::Inspection`, `inspect::{line_at, quoted}`.
//!
//! HOW: one pass over the file, the matches taken in offset order. quick-xml reports
//! the position after each event, so an event spans `[previous position, position)`;
//! it reads the file's bytes in place, so an attribute's name and value are slices of
//! the file and their offsets are exact. Only the open elements are kept (their paths
//! and sibling counts); a node's attributes or text are read only when a match is in
//! it, once for all its matches; reading stops after the last match.
//!
//! WHY sibling indices: `/packages/package` names every package; `package[37]` names
//! the one, the same path `abx` gives for the binary form of the same files.
//! WHY adjacent text and entity references are one node: quick-xml reports `a &amp; b`
//! as three events, and a match in any of them is in that one text.
//! WHY a pass, not a table of nodes: a match near the top of a 200 MB file then costs
//! the bytes before it, not a copy of the whole file's text and paths.

use std::collections::HashMap;
use std::ops::Range;

use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};
use serde_json::json;

use crate::core::models::Inspection;
use crate::formats::inspect::{detail_text, quoted};

/// XML inspector — generic XML (an Apple plist is handled by the plist
/// inspector, which is checked first).
pub struct Xml;

impl super::Inspector for Xml {
    fn name(&self) -> &'static str {
        "xml"
    }
    fn category(&self) -> &'static str {
        "structured"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["xml"]
    }
    fn detect(&self, content: &[u8]) -> bool {
        super::looks_like_xml(content)
    }
    fn inspect(&self, content: &[u8], offset: usize) -> Option<Inspection> {
        self.inspect_many(content, &[offset]).pop().flatten()
    }
    /// One pass over the file for all the matches.
    fn inspect_many(&self, content: &[u8], offsets: &[usize]) -> Vec<Option<Inspection>> {
        let mut order: Vec<usize> = (0..offsets.len()).collect();
        order.sort_by_key(|&i| offsets[i]);
        let mut walk = Walk {
            content,
            offsets,
            order,
            next: 0,
            out: offsets.iter().map(|_| None).collect(),
            counted: (0, 1),
        };
        walk.run();
        walk.out
    }
}

/// An attribute of a tag: its range (name to closing quote), name and value.
struct Attribute {
    range: Range<usize>,
    name: String,
    value: String,
}

/// An open element: its path and how many of each name its children have had.
struct Frame {
    path: String,
    children: HashMap<String, usize>,
}

/// The pass: the matches in offset order, the next one to place, the results.
struct Walk<'c> {
    content: &'c [u8],
    offsets: &'c [usize],
    /// Indices into `offsets`, by offset.
    order: Vec<usize>,
    next: usize,
    out: Vec<Option<Inspection>>,
    /// Newlines counted so far: up to this offset, this line.
    counted: (usize, usize),
}

/// Where `part`, a slice of `content`, starts in it.
fn offset_in(content: &[u8], part: &[u8]) -> Option<usize> {
    let base = content.as_ptr() as usize;
    let at = (part.as_ptr() as usize).checked_sub(base)?;
    (at + part.len() <= content.len()).then_some(at)
}

impl Walk<'_> {
    /// Read the file to its end, the first malformation quick-xml cannot pass, or the
    /// last match.
    fn run(&mut self) {
        let content = self.content;
        let mut reader = Reader::from_reader(content);
        // Locate, don't validate: tolerate mismatched or unclosed tags in evidence.
        reader.config_mut().check_end_names = false;
        let mut stack: Vec<Frame> = Vec::new();
        let mut top: HashMap<String, usize> = HashMap::new();
        let mut last = 0usize;
        // The text node being read: text events and entity references, adjacent.
        let mut text: Option<Range<usize>> = None;
        while self.next < self.order.len() {
            let Ok(event) = reader.read_event() else {
                break;
            };
            let pos = usize::try_from(reader.buffer_position()).unwrap_or(usize::MAX);
            let range = last..pos.min(content.len());
            last = pos;
            if matches!(event, Event::Text(_) | Event::GeneralRef(_)) {
                text = Some(text.map_or(range.clone(), |t| t.start..range.end));
                continue;
            }
            if let Some(t) = text.take() {
                self.text_node(&t, here(&stack));
            }
            match event {
                Event::Eof => break,
                Event::Start(ref e) | Event::Empty(ref e) => {
                    let name = String::from_utf8_lossy(e.name().as_ref()).into_owned();
                    let siblings = stack.last_mut().map_or(&mut top, |f| &mut f.children);
                    let n = siblings.entry(name.clone()).or_insert(0);
                    *n += 1;
                    let n = *n;
                    let parent = stack.last().map_or("", |f| f.path.as_str());
                    let path = format!("{parent}/{name}[{n}]");
                    let hits = self.take(&range);
                    if !hits.is_empty() {
                        let attributes = attributes(content, e, range.end);
                        for (i, offset) in hits {
                            self.tag(i, offset, &path, &attributes);
                        }
                    }
                    if matches!(event, Event::Start(_)) {
                        stack.push(Frame {
                            path,
                            children: HashMap::new(),
                        });
                    }
                }
                Event::End(_) => {
                    let path = stack.pop().map_or_else(|| "/".to_string(), |f| f.path);
                    for (i, offset) in self.take(&range) {
                        self.tag(i, offset, &path, &[]);
                    }
                }
                Event::Decl(_) => {
                    for (i, offset) in self.take(&range) {
                        let line = self.line(offset);
                        self.out[i] = Some(found(
                            "path: /  (the XML declaration)".into(),
                            line,
                            json!({ "path": "/", "node": "declaration", "line": line }),
                        ));
                    }
                }
                ref other => {
                    let (node, inner): (&str, &[u8]) = match other {
                        Event::CData(e) => ("cdata()", e.as_ref()),
                        Event::Comment(e) => ("comment()", e.as_ref()),
                        Event::PI(e) => ("processing-instruction()", e.as_ref()),
                        Event::DocType(e) => ("doctype()", e.as_ref()),
                        _ => ("node()", &[]),
                    };
                    let hits = self.take(&range);
                    if !hits.is_empty() {
                        let value = String::from_utf8_lossy(inner);
                        self.node(&hits, here(&stack), node, &value);
                    }
                }
            }
        }
        if let Some(t) = text {
            self.text_node(&t, here(&stack));
        }
    }

    /// The matches in `range`, taken from the queue; those before it (in no node) are
    /// passed over, left `None`.
    fn take(&mut self, range: &Range<usize>) -> Vec<(usize, usize)> {
        let mut hits = Vec::new();
        while let Some(&i) = self.order.get(self.next) {
            let offset = self.offsets[i];
            if offset >= range.end {
                break;
            }
            if offset >= range.start {
                hits.push((i, offset));
            }
            self.next += 1;
        }
        hits
    }

    /// The line of `offset`, counting on from the last one asked (offsets come in order).
    fn line(&mut self, offset: usize) -> usize {
        let (from, line) = self.counted;
        let to = offset.min(self.content.len()).max(from);
        let line = line
            + self.content[from..to]
                .iter()
                .filter(|&&b| b == b'\n')
                .count();
        self.counted = (to, line);
        line
    }

    /// A match in a tag: in one of its attributes, or the tag itself.
    fn tag(&mut self, i: usize, offset: usize, path: &str, attributes: &[Attribute]) {
        let line = self.line(offset);
        self.out[i] = Some(
            match attributes.iter().find(|a| a.range.contains(&offset)) {
                Some(a) => found(
                    format!("path: {path}/@{}  value: {}", a.name, quoted(&a.value)),
                    line,
                    json!({
                        "path": path,
                        "attribute": a.name,
                        "value": detail_text(&a.value),
                        "line": line,
                    }),
                ),
                None => found(
                    format!("path: {path}"),
                    line,
                    json!({ "path": path, "line": line }),
                ),
            },
        );
    }

    /// The matches in a text node: its text, entities resolved where they can be.
    fn text_node(&mut self, range: &Range<usize>, path: String) {
        let hits = self.take(range);
        if hits.is_empty() {
            return;
        }
        let raw = String::from_utf8_lossy(&self.content[range.clone()]);
        let text = quick_xml::escape::unescape(&raw).unwrap_or_else(|_| raw.clone());
        self.node(&hits, path, "text()", &text);
    }

    /// The matches `hits` in a text-like node of the element `path`.
    fn node(&mut self, hits: &[(usize, usize)], path: String, node: &str, value: &str) {
        let at = if path == "/" { "" } else { path.as_str() };
        let summary = format!("path: {at}/{node}  value: {}", quoted(value));
        let value = detail_text(value);
        for &(i, offset) in hits {
            let line = self.line(offset);
            self.out[i] = Some(found(
                summary.clone(),
                line,
                json!({ "path": path, "node": node, "value": value, "line": line }),
            ));
        }
    }
}

/// The path of the element being read: `/` outside any.
fn here(stack: &[Frame]) -> String {
    stack
        .last()
        .map_or_else(|| "/".to_string(), |f| f.path.clone())
}

/// The attributes of the tag `e`, which ends before `end`, with their ranges.
fn attributes(content: &[u8], e: &BytesStart, end: usize) -> Vec<Attribute> {
    let mut out = Vec::new();
    for attribute in e.attributes().with_checks(false) {
        let Ok(attribute) = attribute else {
            break;
        };
        let key = attribute.key.as_ref();
        let Some(start) = offset_in(content, key) else {
            continue;
        };
        // To the closing quote, when the value is a slice of the file.
        let stop = offset_in(content, &attribute.value)
            .filter(|&v| v >= start)
            .map_or(start + key.len(), |v| {
                (v + attribute.value.len() + 1).min(end)
            });
        let raw = String::from_utf8_lossy(&attribute.value);
        out.push(Attribute {
            range: start..stop,
            name: String::from_utf8_lossy(key).into_owned(),
            value: quick_xml::escape::unescape(&raw)
                .map_or_else(|_| raw.to_string(), |v| v.into_owned()),
        });
    }
    out
}

fn found(summary: String, line: usize, detail: serde_json::Value) -> Inspection {
    Inspection {
        format: "xml".into(),
        summary: format!("{summary}  line: {line}"),
        detail,
    }
}

#[cfg(test)]
mod tests {
    use super::super::Inspector;
    use super::*;

    fn at(f: &[u8], needle: &str) -> usize {
        f.windows(needle.len())
            .position(|w| w == needle.as_bytes())
            .unwrap()
    }

    const PACKAGES: &[u8] = br#"<?xml version='1.0' encoding='utf-8'?>
<packages>
  <package name="com.a" codePath="/data/app/a" />
  <package name="com.b" codePath="/data/app/b">
    <sigs count="1"><cert key="abc &amp; def" /></sigs>
    <note>first &amp; second</note>
    <!-- a comment -->
    <![CDATA[raw <data>]]>
  </package>
</packages>
"#;

    #[test]
    fn attributes_resolve_with_sibling_indices() {
        let b = Xml.inspect(PACKAGES, at(PACKAGES, "com.b")).unwrap();
        assert_eq!(
            b.summary,
            "path: /packages[1]/package[2]/@name  value: \"com.b\"  line: 4"
        );
        assert_eq!(b.detail["attribute"], "name");
        // The attribute's name counts too, and an entity is resolved in the value.
        let path = Xml
            .inspect(PACKAGES, at(PACKAGES, "codePath=\"/data/app/a"))
            .unwrap();
        assert_eq!(path.detail["path"], "/packages[1]/package[1]");
        assert_eq!(path.detail["attribute"], "codePath");
        let key = Xml.inspect(PACKAGES, at(PACKAGES, "def")).unwrap();
        assert_eq!(key.detail["value"], "abc & def");
        assert_eq!(
            key.detail["path"],
            "/packages[1]/package[2]/sigs[1]/cert[1]"
        );
        // Between attributes: the tag.
        let tag = Xml
            .inspect(PACKAGES, at(PACKAGES, "<package name=\"com.a"))
            .unwrap();
        assert!(tag.detail.get("attribute").is_none());
    }

    #[test]
    fn text_comment_and_cdata_resolve() {
        let second = Xml.inspect(PACKAGES, at(PACKAGES, "second")).unwrap();
        assert_eq!(
            second.summary,
            "path: /packages[1]/package[2]/note[1]/text()  value: \"first & second\"  line: 6"
        );
        let first = Xml.inspect(PACKAGES, at(PACKAGES, "first")).unwrap();
        assert_eq!(first.detail["value"], "first & second");
        let comment = Xml.inspect(PACKAGES, at(PACKAGES, "a comment")).unwrap();
        assert_eq!(comment.detail["node"], "comment()");
        let cdata = Xml.inspect(PACKAGES, at(PACKAGES, "raw <data>")).unwrap();
        assert_eq!(cdata.detail["node"], "cdata()");
        assert_eq!(cdata.detail["value"], "raw <data>");
        let decl = Xml.inspect(PACKAGES, 3).unwrap();
        assert_eq!(decl.detail["node"], "declaration");
        let end = Xml.inspect(PACKAGES, at(PACKAGES, "</packages>")).unwrap();
        assert_eq!(end.detail["path"], "/packages[1]");
    }

    #[test]
    fn many_matches_in_any_order_resolve_in_one_pass() {
        let offsets = [
            at(PACKAGES, "second"),
            at(PACKAGES, "com.b"),
            PACKAGES.len() + 5,
            at(PACKAGES, "com.b"),
            3,
        ];
        let found = Xml.inspect_many(PACKAGES, &offsets);
        let line = |n: usize| found[n].as_ref().unwrap().detail["line"].clone();
        assert_eq!(line(0), 6);
        assert_eq!(line(1), 4);
        assert!(found[2].is_none());
        assert_eq!(found[1], found[3]);
        assert_eq!(line(4), 1);
    }

    #[test]
    fn a_long_value_is_cut_in_the_detail() {
        let long = "x".repeat(DETAIL_CHARS_PLUS);
        let f = format!("<?xml version='1.0'?>\n<a k=\"{long}\">{long}</a>\n");
        let f = f.as_bytes();
        for offset in [at(f, "k=\"x") + 10, f.len() - 20] {
            let found = Xml.inspect(f, offset).unwrap();
            assert_eq!(found.detail["value"]["truncated"], true, "{offset}");
            assert_eq!(
                found.detail["value"]["text"].as_str().unwrap().len(),
                crate::formats::inspect::DETAIL_CHARS
            );
        }
    }

    const DETAIL_CHARS_PLUS: usize = crate::formats::inspect::DETAIL_CHARS + 10;

    #[test]
    fn malformed_xml_never_panics() {
        for i in 0..PACKAGES.len() {
            for b in [b'<', b'>', b'"', b'&', 0] {
                let mut g = PACKAGES.to_vec();
                g[i] = b;
                let offsets: Vec<usize> = (0..g.len()).collect();
                let _ = Xml.inspect_many(&g, &offsets);
            }
        }
    }
}
