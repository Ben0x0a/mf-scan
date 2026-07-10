//! XML inspector: map a byte offset to an element path (e.g. `/plist/dict/key`).
//!
//! Defines: `inspect`, returning the path of the element whose span (start tag,
//! content, or end tag) contains a match offset.
//! Used by: `inspect::inspect` (dispatch).
//! Uses: `quick_xml` (event reader with byte positions), `serde_json`
//! (structured detail), `crate::core::models::Inspection`.
//!
//! HOW: quick-xml reports the byte position after each event, so each event
//! spans `[last_position, current_position)`. We keep a stack of open element
//! names and, when an event's span covers the target offset, record the path.
//! Attribute-level resolution is left for a later refinement; for now a match
//! inside a start tag reports that element.

use quick_xml::Reader;
use quick_xml::events::Event;
use serde_json::json;

use crate::core::models::Inspection;

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
        resolve(content, offset)
    }
}

/// Locate the element path of the content at `offset`.
fn resolve(content: &[u8], offset: usize) -> Option<Inspection> {
    let mut reader = Reader::from_reader(content);
    // Locate, don't validate: tolerate mismatched/!unclosed tags in evidence.
    reader.config_mut().check_end_names = false;

    let mut buf = Vec::new();
    let mut stack: Vec<String> = Vec::new();
    let mut last = 0usize;
    let mut hit: Option<String> = None;

    // `while let Ok(..)` stops at the first malformation we cannot pass.
    while let Ok(event) = reader.read_event_into(&mut buf) {
        let pos = reader.buffer_position() as usize;
        let covers = offset >= last && offset < pos;

        match event {
            Event::Eof => break,
            Event::Start(e) => {
                let name = name_of(e.name().as_ref());
                if covers && hit.is_none() {
                    hit = Some(path_with(&stack, Some(&name)));
                }
                stack.push(name);
            }
            Event::End(_) => {
                if covers && hit.is_none() {
                    hit = Some(path_with(&stack, None));
                }
                stack.pop();
            }
            Event::Empty(e) => {
                let name = name_of(e.name().as_ref());
                if covers && hit.is_none() {
                    hit = Some(path_with(&stack, Some(&name)));
                }
            }
            // Text, CDATA, comments, declarations: attribute them to the
            // currently open element.
            _ => {
                if covers && hit.is_none() {
                    hit = Some(path_with(&stack, None));
                }
            }
        }

        buf.clear();
        last = pos;
        if hit.is_some() {
            break;
        }
    }

    let path = hit?;
    let line = super::line_at(content, offset);
    Some(Inspection {
        format: "xml".into(),
        summary: format!("path: {path}  line: {line}"),
        detail: json!({ "path": path, "line": line }),
    })
}

fn name_of(raw: &[u8]) -> String {
    String::from_utf8_lossy(raw).into_owned()
}

/// Build `/a/b/c`, optionally appending one more element (for start/empty tags
/// not yet pushed onto the stack).
fn path_with(stack: &[String], extra: Option<&str>) -> String {
    let mut s = String::new();
    for name in stack {
        s.push('/');
        s.push_str(name);
    }
    if let Some(name) = extra {
        s.push('/');
        s.push_str(name);
    }
    if s.is_empty() { "/".to_string() } else { s }
}
