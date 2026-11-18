//! Match scanning: run a byte regex and build a readable line preview per match.
//!
//! Defines: `search_bytes_capped`/`SearchHits` (one `SearchHit` per match, with
//! a per-file cap), the `search_bytes` convenience, plus the private
//! `preview`/`line_bounds` helpers and the preview/cap constants.
//! Used by: `search::search_entry`, `engine`.
//! Uses: `regex::bytes` (the engine), `crate::core::models::SearchHit`.
//!
//! Why `regex::bytes` rather than `regex` on `&str`: forensic data is arbitrary
//! bytes (mixed encodings, binary blobs), so matching must happen on `&[u8]` —
//! decoding to UTF-8 first would either fail or corrupt the data. Raw line bytes
//! are handed back so the caller can render (and colourise) them.

use std::ops::Range;

use regex::bytes::Regex;

use crate::core::models::SearchHit;

/// Maximum preview length (bytes) of the line shown for a match.
///
/// Binary files (the whole reason we search bytes) have almost no newlines, so a
/// "line" can span the entire file. Longer lines are truncated to a window
/// around the match so output stays readable and memory stays bounded. The
/// reported byte offsets are exact regardless — this caps only the preview text.
const MAX_PREVIEW: usize = 200;

/// Maximum hits collected per file. Each hit holds up to ~200 bytes of preview,
/// so a pathological pattern (a typo'd `.` with `-i` over a multi-GB binary)
/// could otherwise hold gigabytes of previews until output. Hitting the cap is
/// reported via [`SearchHits::truncated`] and the scan statistics — never
/// silently, since "what did you not see" must stay exact for a forensic run.
pub const MAX_HITS_PER_FILE: usize = 100_000;

/// Unicode horizontal ellipsis (U+2026) marking a truncated line edge.
pub(crate) const ELLIPSIS: &[u8] = "…".as_bytes();

/// The most of one match a preview holds. A preview always contains the whole match
/// up to this, so `-o` prints it entire, as grep does; a longer match (a `.*` over a
/// binary with no newlines) is cut here and ends right before the `…` marker.
/// WHY 4 KiB: every hit keeps its preview until output, up to [`MAX_HITS_PER_FILE`]
/// of them, so this bounds a file's previews near 400 MB in the worst case. Tokens,
/// keys and base64 blobs an examiner extracts with `-o` fit well within it.
const MAX_MATCH_SHOWN: usize = 4 * 1024;

/// The hits found in one haystack, plus whether the per-file cap cut them off.
pub struct SearchHits {
    pub hits: Vec<SearchHit>,
    /// True when matching stopped at [`MAX_HITS_PER_FILE`]: the file contains
    /// more matches than `hits` reports.
    pub truncated: bool,
}

/// Run the regex over a haystack, producing one hit per match, stopping at
/// [`MAX_HITS_PER_FILE`].
pub fn search_bytes_capped(haystack: &[u8], re: &Regex) -> SearchHits {
    capped(haystack, re, MAX_HITS_PER_FILE)
}

/// [`search_bytes_capped`] with an explicit cap — separate so the truncation
/// path is testable without generating 100 000 real matches.
fn capped(haystack: &[u8], re: &Regex, cap: usize) -> SearchHits {
    let mut hits = Vec::new();
    let mut truncated = false;
    for m in re.find_iter(haystack) {
        if hits.len() >= cap {
            truncated = true;
            break;
        }
        let (line_start, line_end) = line_bounds(haystack, m.start(), m.end());
        let (line, match_in_line) = preview(haystack, line_start, line_end, m.start(), m.end());
        hits.push(SearchHit {
            offset: m.start() as u64,
            len: m.len(),
            line,
            match_in_line,
        });
    }
    SearchHits { hits, truncated }
}

/// Plain-`Vec` convenience over [`search_bytes_capped`] for callers that do not
/// track truncation (tests, `search_entry`).
pub fn search_bytes(haystack: &[u8], re: &Regex) -> Vec<SearchHit> {
    search_bytes_capped(haystack, re).hits
}

/// Build the line shown for a match: the whole line when short, otherwise a
/// `MAX_PREVIEW`-byte window centred on the match with `…` edge markers.
///
/// Returns the preview bytes and the match's byte range within them.
fn preview(
    haystack: &[u8],
    line_start: usize,
    line_end: usize,
    match_start: usize,
    match_end: usize,
) -> (Vec<u8>, Range<usize>) {
    // Window bounds within the haystack.
    let (win_start, win_end) = if line_end - line_start <= MAX_PREVIEW {
        (line_start, line_end)
    } else {
        // Keep a little context before the match, then a fixed-width window that
        // always reaches past the match's end (or to the cap): so a match ending
        // right before a `…` marker is one the cap cut, and no other.
        let lead = (MAX_PREVIEW / 4).min(match_start - line_start);
        let start = match_start - lead;
        let shown_end = match_end.min(match_start + MAX_MATCH_SHOWN);
        let past_match = if shown_end < match_end {
            shown_end
        } else {
            shown_end + 1
        };
        (start, (start + MAX_PREVIEW).max(past_match).min(line_end))
    };

    let truncated_left = win_start > line_start;
    let truncated_right = win_end < line_end;

    let mut window = haystack[win_start..win_end].to_vec();
    let mut match_lo = match_start - win_start;
    let mut match_hi = (match_end - win_start).min(window.len());

    // Strip a trailing CR only when this is the real end of the line, so CRLF
    // files display cleanly without dropping a byte mid-window.
    if !truncated_right && window.last() == Some(&b'\r') {
        window.pop();
        match_lo = match_lo.min(window.len());
        match_hi = match_hi.min(window.len());
    }

    // Assemble with ellipsis markers, shifting the match range past any prefix.
    let mut line = Vec::with_capacity(window.len() + 2 * ELLIPSIS.len());
    if truncated_left {
        line.extend_from_slice(ELLIPSIS);
    }
    let shift = line.len();
    line.extend_from_slice(&window);
    if truncated_right {
        line.extend_from_slice(ELLIPSIS);
    }

    (line, (match_lo + shift)..(match_hi + shift))
}

/// Expand a match span outward to the enclosing line (newline-delimited).
///
/// HOW: walk left from the match start to the previous `\n` (exclusive) and
/// right from the match end to the next `\n`, clamping to the haystack bounds.
/// Returns `[line_start, line_end)`, mirroring grep's notion of "the line that
/// contains the match".
fn line_bounds(haystack: &[u8], match_start: usize, match_end: usize) -> (usize, usize) {
    let line_start = haystack[..match_start]
        .iter()
        .rposition(|&b| b == b'\n')
        .map_or(0, |i| i + 1);
    let line_end = haystack[match_end..]
        .iter()
        .position(|&b| b == b'\n')
        .map_or(haystack.len(), |i| match_end + i);
    (line_start, line_end)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A long match on a long line is kept whole, not cut at the preview width.
    #[test]
    fn a_long_match_is_kept_whole() {
        let mut hay = vec![b'#'; 1000];
        hay.extend(std::iter::repeat_n(b'A', 3000));
        hay.extend(vec![b'#'; 1000]);
        let hit = &search_bytes(&hay, &Regex::new("A+").unwrap())[0];
        let shown = &hit.line[hit.match_in_line.clone()];
        assert_eq!(shown.len(), 3000);
        assert_eq!(
            hit.line[hit.match_in_line.end], b'#',
            "the byte after the match is shown, so the match is not marked as cut"
        );
    }

    /// A match longer than the cap is cut there, right before the `…` marker.
    #[test]
    fn a_match_over_the_cap_ends_at_the_marker() {
        let mut hay = vec![b'A'; MAX_MATCH_SHOWN + 500];
        hay.extend(vec![b'#'; 10]);
        let hit = &search_bytes(&hay, &Regex::new("A+").unwrap())[0];
        assert_eq!(hit.match_in_line.len(), MAX_MATCH_SHOWN);
        assert_eq!(&hit.line[hit.match_in_line.end..], ELLIPSIS);
    }

    /// The per-file cap stops collection and reports truncation (review P2).
    #[test]
    fn hit_cap_truncates_and_reports_it() {
        let re = Regex::new("x").unwrap();
        let hay = b"xxxxx";

        let cut = capped(hay, &re, 3);
        assert_eq!(cut.hits.len(), 3);
        assert!(cut.truncated);

        let all = capped(hay, &re, 5);
        assert_eq!(all.hits.len(), 5);
        assert!(!all.truncated);
    }
}
