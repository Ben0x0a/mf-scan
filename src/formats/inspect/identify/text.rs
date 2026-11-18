//! Identify-only text formats, named by their opening line: vCard, iCalendar, PEM.
//! Unlike the other identify-only formats, a match in them resolves to its line and
//! column, as in any text file, under the format's own name (category `text`).
//!
//! Defines: [`Vcard`], [`Icalendar`], [`Pem`], and the `text_format!` macro they use.
//! Used by: `identify` (re-export) → `inspect::mod` registry.
//! Uses: `identify::{has_at, starts_text}`, `inspect::txt::resolve_many`.

use super::{has_at, starts_text};

/// A text format named by its opening line: a match resolves to its line and
/// column, as in any text file, under the format's own name (category `text`).
macro_rules! text_format {
    ($ty:ident, $name:literal, $detect:expr) => {
        pub struct $ty;
        impl $crate::formats::inspect::Inspector for $ty {
            fn name(&self) -> &'static str {
                $name
            }
            fn category(&self) -> &'static str {
                "text"
            }
            fn extensions(&self) -> &'static [&'static str] {
                &[]
            }
            fn detect(&self, content: &[u8]) -> bool {
                ($detect)(content)
            }
            fn inspect(
                &self,
                content: &[u8],
                offset: usize,
            ) -> Option<$crate::core::models::Inspection> {
                self.inspect_many(content, &[offset]).pop().flatten()
            }
            fn inspect_many(
                &self,
                content: &[u8],
                offsets: &[usize],
            ) -> Vec<Option<$crate::core::models::Inspection>> {
                let mut found = super::super::txt::resolve_many(content, offsets);
                for f in found.iter_mut().flatten() {
                    f.format = $name.into();
                }
                found
            }
        }
    };
}

// vCard (RFC 6350) and iCalendar (RFC 5545): the opening line, case-insensitive.
// No iCalendar file was found in the test file systems.
text_format!(Vcard, "vcard", |c: &[u8]| starts_text(c, b"BEGIN:VCARD"));
text_format!(Icalendar, "icalendar", |c: &[u8]| starts_text(
    c,
    b"BEGIN:VCALENDAR"
));

// PEM (RFC 7468: certificates, keys): the encapsulation boundary "-----BEGIN ".
// OpenPGP armour (RFC 4880) uses the same boundary style but is not PEM: left out.
text_format!(Pem, "pem", |c: &[u8]| has_at(c, 0, b"-----BEGIN ")
    && !has_at(c, 0, b"-----BEGIN PGP "));
