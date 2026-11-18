//! typedstream inspector: map a byte offset in an Apple typedstream (the
//! `NSArchiver` format: iMessage `attributedBody`, older archives) to the object
//! holding it and the string there.
//!
//! Defines: [`Typedstream`] (the inspector).
//! Used by: `inspect::mod` (registered in `INSPECTORS`), and through it the SQLite
//! inspector for a BLOB holding one (`sms.db` `message.attributedBody`).
//! Uses: `crate::core::models::Inspection`, `serde_json`.
//!
//! ── Format ───────────────────────────────────────────────────────────────────
//! As documented by the NeXT/GNU typedstream sources and dgelessus'
//! `python-typedstream`: a header (streamer version 4, the shared string
//! "streamtyped", the system version), then typed groups: a type encoding (a shared
//! string such as `@`, `+`, `iI`) and one value per type in it. Head bytes: 0x81 an
//! int16 follows, 0x82 an int32, 0x83 a float/double, 0x84 something new (a shared
//! string, object or class), 0x85 nil, 0x86 end of an object; any other byte is a
//! literal, and as a reference, the index `value + 110` into the strings (for a
//! shared string) or the objects and classes (for an object or class) seen so far.
//! Integers are little-endian. An object is its class (name, version, then its
//! superclass, down to nil) and typed groups up to 0x86. `+` is a length and raw
//! bytes (an `NSString`'s UTF-8); `*`, `:` and `%` are shared strings.
//!
//! Only little-endian streams ("streamtyped") are read. A type or head byte this
//! reader does not know ends the reading: the strings found before it are kept, the
//! rest is left unresolved, never guessed.

use std::ops::Range;

use serde_json::json;

use crate::core::models::Inspection;

const SIGNATURE: &[u8; 13] = b"\x04\x0bstreamtyped";
const TAG_INT16: u8 = 0x81;
const TAG_INT32: u8 = 0x82;
const TAG_FLOAT: u8 = 0x83;
const TAG_NEW: u8 = 0x84;
const TAG_NIL: u8 = 0x85;
const TAG_END: u8 = 0x86;
/// The literal value of the first reference number (0x92 as a signed byte).
const FIRST_REFERENCE: i64 = -110;
const MAX_DEPTH: usize = 64;

/// typedstream inspector — recognised by its header.
pub struct Typedstream;

impl super::Inspector for Typedstream {
    fn name(&self) -> &'static str {
        "typedstream"
    }
    fn category(&self) -> &'static str {
        "structured"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &[]
    }
    fn detect(&self, content: &[u8]) -> bool {
        content.starts_with(SIGNATURE)
    }
    fn inspect(&self, content: &[u8], offset: usize) -> Option<Inspection> {
        self.inspect_many(content, &[offset]).pop().flatten()
    }
    /// The stream is read once; each match is then a lookup.
    fn inspect_many(&self, content: &[u8], offsets: &[usize]) -> Vec<Option<Inspection>> {
        let strings = read(content);
        offsets
            .iter()
            .map(|&o| locate(content, &strings, o))
            .collect()
    }
}

/// A string found in the stream: its bytes and the chain of objects holding it.
#[derive(Debug)]
struct Found {
    range: Range<usize>,
    /// Class names of the enclosing objects, outermost first.
    objects: Vec<String>,
    /// The type it was read as: `+` (raw bytes), `*` (C string), …
    kind: char,
}

struct Reader<'c> {
    c: &'c [u8],
    pos: usize,
    strings: Vec<String>,
    /// Objects and classes, in the order seen; a class entry holds its name.
    objects: Vec<Option<String>>,
    /// The classes of the objects being read, outermost first.
    stack: Vec<String>,
    found: Vec<Found>,
}

/// Read the stream; the strings found up to the first byte that does not fit.
fn read(c: &[u8]) -> Vec<Found> {
    if !c.starts_with(SIGNATURE) {
        return Vec::new();
    }
    let mut r = Reader {
        c,
        pos: SIGNATURE.len(),
        strings: Vec::new(),
        objects: Vec::new(),
        stack: Vec::new(),
        found: Vec::new(),
    };
    if r.int().is_some() {
        // The system version, then typed groups to the end.
        while r.pos < c.len() && r.group(0).is_some() {}
    }
    r.found.sort_by_key(|f| f.range.start);
    r.found
}

impl Reader<'_> {
    fn byte(&mut self) -> Option<u8> {
        let b = *self.c.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }
    fn peek(&self) -> Option<u8> {
        self.c.get(self.pos).copied()
    }
    fn take(&mut self, n: usize) -> Option<Range<usize>> {
        let range = self.pos..self.pos.checked_add(n)?;
        (range.end <= self.c.len()).then(|| {
            self.pos = range.end;
            range
        })
    }
    /// An integer: a literal signed byte, or a tagged int16 / int32.
    fn int_after(&mut self, head: u8) -> Option<i64> {
        match head {
            TAG_INT16 => {
                let r = self.take(2)?;
                Some(i64::from(i16::from_le_bytes(self.c[r].try_into().ok()?)))
            }
            TAG_INT32 => {
                let r = self.take(4)?;
                Some(i64::from(i32::from_le_bytes(self.c[r].try_into().ok()?)))
            }
            TAG_FLOAT | TAG_NEW | TAG_NIL | TAG_END => None,
            b => Some(i64::from(b as i8)),
        }
    }
    fn int(&mut self) -> Option<i64> {
        let head = self.byte()?;
        self.int_after(head)
    }
    /// A reference number after its head byte, as an index.
    fn reference(&mut self, head: u8) -> Option<usize> {
        usize::try_from(self.int_after(head)? - FIRST_REFERENCE).ok()
    }
    /// A shared string: new (recorded), nil, or a reference. Returns its text and,
    /// when new, where its bytes are.
    fn shared(&mut self) -> Option<(Option<String>, Option<Range<usize>>)> {
        match self.byte()? {
            TAG_NEW => {
                let n = usize::try_from(self.int()?).ok()?;
                let range = self.take(n)?;
                let text = String::from_utf8_lossy(&self.c[range.clone()]).into_owned();
                self.strings.push(text.clone());
                Some((Some(text), Some(range)))
            }
            TAG_NIL => Some((None, None)),
            head => {
                let i = self.reference(head)?;
                Some((Some(self.strings.get(i)?.clone()), None))
            }
        }
    }
    /// A class: new (name, version, superclass, recorded), nil, or a reference.
    /// Returns its name.
    fn class(&mut self, depth: usize) -> Option<Option<String>> {
        if depth > MAX_DEPTH {
            return None;
        }
        match self.byte()? {
            TAG_NEW => {
                let (name, range) = self.shared()?;
                let name = name?;
                if let Some(range) = range {
                    self.record(range, '#');
                }
                self.int()?; // version
                self.objects.push(Some(name.clone()));
                self.class(depth + 1)?; // superclass chain, down to nil
                Some(Some(name))
            }
            TAG_NIL => Some(None),
            head => {
                let i = self.reference(head)?;
                Some(Some(self.objects.get(i)?.clone()?))
            }
        }
    }
    /// An object: new (class, then typed groups up to the end tag), nil, or a
    /// reference.
    fn object(&mut self, depth: usize) -> Option<()> {
        if depth > MAX_DEPTH {
            return None;
        }
        match self.byte()? {
            TAG_NEW => {
                let slot = self.objects.len();
                self.objects.push(None); // the object itself comes before its class
                let class = self.class(depth + 1)?.unwrap_or_else(|| "?".into());
                self.objects[slot] = Some(class.clone());
                self.stack.push(class);
                while self.peek()? != TAG_END {
                    self.group(depth + 1)?;
                }
                self.pos += 1;
                self.stack.pop();
                Some(())
            }
            TAG_NIL => Some(()),
            head => self.reference(head).map(|_| ()),
        }
    }
    /// A typed group: the type encoding, then one value per type in it.
    fn group(&mut self, depth: usize) -> Option<()> {
        let (types, _) = self.shared()?;
        let types = types?;
        let mut chars = types.chars().peekable();
        while chars.peek().is_some() {
            self.value(&mut chars, depth)?;
        }
        Some(())
    }
    /// One value of the next type in `types`.
    fn value(
        &mut self,
        types: &mut std::iter::Peekable<std::str::Chars<'_>>,
        depth: usize,
    ) -> Option<()> {
        if depth > MAX_DEPTH {
            return None;
        }
        match types.next()? {
            'c' | 'C' | 's' | 'S' | 'i' | 'I' | 'l' | 'L' | 'q' | 'Q' | 'B' => {
                self.int()?;
            }
            t @ ('f' | 'd') => match self.byte()? {
                // A tagged float is 4 bytes, a tagged double 8.
                TAG_FLOAT => {
                    self.take(if t == 'f' { 4 } else { 8 })?;
                }
                head => {
                    self.int_after(head)?;
                }
            },
            '+' => {
                let n = usize::try_from(self.int()?).ok()?;
                let range = self.take(n)?;
                self.record(range, '+');
            }
            '*' | ':' | '%' => {
                if let (_, Some(range)) = self.shared()? {
                    self.record(range, '*');
                }
            }
            '@' => self.object(depth + 1)?,
            '#' => {
                self.class(depth + 1)?;
            }
            _ => return None, // arrays, structs, pointers: not read (see the module doc)
        }
        Some(())
    }
    fn record(&mut self, range: Range<usize>, kind: char) {
        if !range.is_empty() {
            self.found.push(Found {
                range,
                objects: self.stack.clone(),
                kind,
            });
        }
    }
}

fn locate(c: &[u8], found: &[Found], offset: usize) -> Option<Inspection> {
    if offset >= c.len() {
        return None;
    }
    if offset < SIGNATURE.len() {
        return Some(Inspection {
            format: "typedstream".into(),
            summary: "typedstream header".into(),
            detail: json!({ "part": "header" }),
        });
    }
    let i = found.partition_point(|f| f.range.start <= offset);
    let f = found
        .get(i.checked_sub(1)?)
        .filter(|f| f.range.contains(&offset))?;
    let text = String::from_utf8_lossy(&c[f.range.clone()]);
    let shown = super::one_line(&text);
    let objects = if f.objects.is_empty() {
        "(top level)".to_string()
    } else {
        f.objects.join(" / ")
    };
    let what = if f.kind == '#' {
        "class name"
    } else {
        "string"
    };
    Some(Inspection {
        format: "typedstream".into(),
        summary: format!("object: {objects}  {what}: \"{shown}\""),
        detail: json!({
            "objects": f.objects,
            "kind": what,
            "value": text,
            "offset_in_value": offset - f.range.start,
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::super::Inspector;
    use super::*;

    /// The start of a real iMessage `attributedBody` (sms.db, test data): an
    /// NSMutableAttributedString holding an NSMutableString with the text, then an
    /// `iI` group and an NSDictionary with an NSString key.
    fn sample() -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(SIGNATURE);
        b.extend_from_slice(&[0x81, 0xe8, 0x03]); // system version 1000
        b.extend_from_slice(&[0x84, 0x01, b'@']); // group "@"
        b.extend_from_slice(&[0x84, 0x84, 0x84, 25]);
        b.extend_from_slice(b"NSMutableAttributedString\x00");
        b.extend_from_slice(&[0x84, 0x84, 18]);
        b.extend_from_slice(b"NSAttributedString\x00");
        b.extend_from_slice(&[0x84, 0x84, 8]);
        b.extend_from_slice(b"NSObject\x00\x85");
        // Group "@" (string 0), NSMutableString : NSString : NSObject (object 3).
        b.extend_from_slice(&[0x92, 0x84, 0x84, 0x84, 15]);
        b.extend_from_slice(b"NSMutableString\x01");
        b.extend_from_slice(&[0x84, 0x84, 8]);
        b.extend_from_slice(b"NSString\x01\x95");
        b.extend_from_slice(&[0x84, 0x01, b'+', 11]);
        b.extend_from_slice(b"Hello there");
        b.push(0x86); // end NSMutableString
        b.extend_from_slice(&[0x84, 0x02, b'i', b'I', 0x01, 0x0b]); // group "iI"
        b.push(0x86); // end NSMutableAttributedString
        b
    }

    fn at(f: &[u8], needle: &[u8]) -> usize {
        f.windows(needle.len()).position(|w| w == needle).unwrap()
    }

    #[test]
    fn a_string_resolves_to_its_objects() {
        let f = sample();
        assert!(Typedstream.detect(&f));
        let hit = Typedstream.inspect(&f, at(&f, b"there")).unwrap();
        assert_eq!(
            hit.summary,
            "object: NSMutableAttributedString / NSMutableString  string: \"Hello there\""
        );
        assert_eq!(hit.detail["offset_in_value"], 6);
        let class = Typedstream.inspect(&f, at(&f, b"NSString")).unwrap();
        assert!(
            class.summary.contains("class name: \"NSString\""),
            "{}",
            class.summary
        );
        assert_eq!(
            Typedstream.inspect(&f, 3).unwrap().summary,
            "typedstream header"
        );
    }

    #[test]
    fn an_unknown_type_stops_reading_but_keeps_what_came_before() {
        let mut f = sample();
        let at_ii = at(&f, &[0x84, 0x02, b'i', b'I']);
        f[at_ii + 2] = b'['; // an array type, not read
        assert!(Typedstream.inspect(&f, at(&f, b"Hello")).is_some());
    }

    #[test]
    fn corrupt_bytes_never_panic() {
        let f = sample();
        for i in 0..f.len() {
            for b in [0x00, 0x84, 0x92, 0xFF] {
                let mut g = f.clone();
                g[i] = b;
                let _ = Typedstream.inspect_many(&g, &[0, i, g.len() - 1]);
            }
        }
    }
}
