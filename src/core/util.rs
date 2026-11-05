//! Small crate-wide helpers with no domain logic.
//!
//! Defines: `sha256_hex` (the crate's single SHA-256-to-lowercase-hex helper) and the
//! crate's single UTC calendar conversion ([`UtcTime`], [`unix_from_civil`],
//! [`parse_utc`]).
//! Used by: `report::export` and `report::zip_writer` (hashes, member timestamps),
//! `decrypt::context` (audit records), `core::source::zip` (DOS timestamps),
//! `ops::find` (date tests), and the binary's `support::reporting`.
//! Uses: `sha2`.
//!
//! WHY a foundation module: these are needed below (`decrypt`, `core::source`) and
//! above (`report`) the engine, so they must live beside `models`/`filter` at the
//! bottom of the layering — one definition, no drift between the callers.
//!
//! WHY the calendar is by hand: the standard library has no date formatting or
//! parsing, and every date in this tool is UTC, so these two short, standard
//! conversions (Howard Hinnant's `days_from_civil` and `civil_from_days`) avoid a
//! date dependency.

use sha2::{Digest, Sha256};

/// SHA-256 of `bytes` as lowercase hex.
pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A calendar date and time in UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UtcTime {
    pub year: u64,
    pub month: u64,
    pub day: u64,
    pub hour: u64,
    pub minute: u64,
    pub second: u64,
}

impl UtcTime {
    /// The UTC calendar time of `secs` seconds after the Unix epoch.
    pub fn from_unix(secs: u64) -> Self {
        let (days, rem) = (secs / 86_400, secs % 86_400);
        let z = days + 719_468;
        let era = z / 146_097;
        let day_of_era = z % 146_097;
        let year_of_era =
            (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
        let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
        let shifted_month = (5 * day_of_year + 2) / 153;
        let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
        let month = if shifted_month < 10 {
            shifted_month + 3
        } else {
            shifted_month - 9
        };
        Self {
            year: year_of_era + era * 400 + u64::from(month <= 2),
            month,
            day,
            hour: rem / 3_600,
            minute: rem % 3_600 / 60,
            second: rem % 60,
        }
    }

    /// Compact form for file names: `20261105T181403Z`.
    pub fn compact(&self) -> String {
        format!(
            "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        )
    }

    /// ISO 8601 form for reports and listings: `2026-11-05T18:14:03Z`.
    pub fn iso(&self) -> String {
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        )
    }
}

/// Seconds since the Unix epoch for a UTC calendar time (negative before 1970).
pub fn unix_from_civil(
    year: i64,
    month: i64,
    day: i64,
    hour: i64,
    minute: i64,
    second: i64,
) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    let days = era * 146_097 + doe - 719_468;
    days * 86_400 + hour * 3_600 + minute * 60 + second
}

/// Parse `YYYY-MM-DD`, optionally followed by `T` or a space and `HH:MM[:SS]`, and an
/// optional trailing `Z`, as a UTC time in seconds since the Unix epoch.
///
/// `None` for anything else, including an impossible date such as `2026-02-31`.
pub fn parse_utc(text: &str) -> Option<u64> {
    let text = text.trim();
    let text = text.strip_suffix('Z').unwrap_or(text);
    let (date, time) = match text.split_once(['T', ' ']) {
        Some((date, time)) => (date, Some(time)),
        None => (text, None),
    };

    let number = |s: &str| {
        s.bytes()
            .all(|b| b.is_ascii_digit())
            .then(|| s.parse::<i64>().ok())?
    };
    let mut parts = date.split('-');
    let year = number(parts.next()?)?;
    let month = number(parts.next()?)?;
    let day = number(parts.next()?)?;
    if parts.next().is_some() {
        return None;
    }

    let (mut hour, mut minute, mut second) = (0, 0, 0);
    if let Some(time) = time {
        let mut parts = time.split(':');
        hour = number(parts.next()?)?;
        minute = number(parts.next()?)?;
        if let Some(s) = parts.next() {
            second = number(s)?;
        }
        if parts.next().is_some() {
            return None;
        }
    }
    if !(0..24).contains(&hour) || !(0..60).contains(&minute) || !(0..60).contains(&second) {
        return None;
    }

    let secs = u64::try_from(unix_from_civil(year, month, day, hour, minute, second)).ok()?;
    // Round-trip to reject an out-of-range month or day, which the arithmetic above
    // would otherwise silently carry into the next month.
    let back = UtcTime::from_unix(secs);
    (back.year as i64 == year && back.month as i64 == month && back.day as i64 == day)
        .then_some(secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_known_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    /// Expected values come from `date -u -r <secs>`, including a leap day.
    #[test]
    fn utc_time_matches_known_dates() {
        assert_eq!(UtcTime::from_unix(0).compact(), "19700101T000000Z");
        assert_eq!(
            UtcTime::from_unix(951_782_400).compact(),
            "20000229T000000Z"
        );
        assert_eq!(
            UtcTime::from_unix(1_793_000_000).iso(),
            "2026-10-26T07:33:20Z"
        );
    }

    #[test]
    fn parse_utc_accepts_dates_and_times_and_rejects_nonsense() {
        assert_eq!(parse_utc("2000-02-29"), Some(951_782_400));
        assert_eq!(parse_utc("2026-10-26T07:33:20Z"), Some(1_793_000_000));
        assert_eq!(parse_utc("2026-10-26 07:33:20"), Some(1_793_000_000));
        assert_eq!(parse_utc("2026-10-26T07:33"), Some(1_792_999_980));
        for bad in [
            "2026-02-31",
            "2026-13-01",
            "yesterday",
            "2026-1",
            "2026-01-01T25:00",
        ] {
            assert_eq!(parse_utc(bad), None, "{bad}");
        }
    }

    #[test]
    fn the_two_conversions_are_inverses() {
        for secs in [0, 86_399, 951_782_400, 1_793_000_000, 4_102_444_800] {
            let t = UtcTime::from_unix(secs);
            let back = unix_from_civil(
                t.year as i64,
                t.month as i64,
                t.day as i64,
                t.hour as i64,
                t.minute as i64,
                t.second as i64,
            );
            assert_eq!(back, secs as i64);
        }
    }
}
