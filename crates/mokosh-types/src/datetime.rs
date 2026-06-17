//! Canonical date-bucketing in the active user's timezone (PMS-360).
//!
//! Every UI surface and server aggregate that buckets a UTC instant by
//! calendar day must agree on which day that instant falls on. The single
//! source of truth is the user's `users.timezone` preference (PMS-253), not
//! the browser locale, not the server session (UTC), and not `chrono::Local`.
//! Two users in different zones therefore correctly see the same UTC instant
//! land on different days when it is a different day for each of them.
//!
//! These helpers live in the shared crate (PMS-129) so `mokosh-server` SQL
//! aggregates and the `mokosh-apps` WASM renders bucket identically: the
//! frontend calls [`user_local_date`] / [`user_today`] for every
//! date-bucketed render, and the server binds [`canonical_tz_name`] into its
//! `AT TIME ZONE` day-bucket queries.

use chrono::{DateTime, NaiveDate, Utc};
use chrono_tz::Tz;

/// Resolve a user timezone string to a [`Tz`], falling back to UTC when the
/// string is empty or not a valid IANA name.
///
/// Bucketing must never fail on a malformed preference; UTC is the safe,
/// predictable default. The preference is validated on write
/// (`mokosh_types::contacts` / the auth profile update), so a bad value here
/// is a defensive backstop, not the expected path.
pub fn resolve_tz(user_tz: &str) -> Tz {
    user_tz.parse::<Tz>().unwrap_or(chrono_tz::UTC)
}

/// Canonical IANA name for `user_tz`, falling back to `"UTC"`.
///
/// Bind this into a SQL `AT TIME ZONE $n` parameter so Postgres buckets a
/// `timestamptz` in the exact same zone the Rust helpers use. Going through
/// [`resolve_tz`] first means an invalid stored value degrades to `"UTC"`
/// rather than raising a Postgres `invalid value for parameter TimeZone`
/// error mid-query.
pub fn canonical_tz_name(user_tz: &str) -> &'static str {
    resolve_tz(user_tz).name()
}

/// The calendar date `dt` falls on **in the user's timezone**.
///
/// This is the one helper every in-memory date-bucket call site uses. A
/// 2026-06-15 23:30 `America/Los_Angeles` instant (2026-06-16 06:30 UTC)
/// buckets to 2026-06-15, not 2026-06-16.
pub fn user_local_date(dt: DateTime<Utc>, user_tz: &str) -> NaiveDate {
    dt.with_timezone(&resolve_tz(user_tz)).date_naive()
}

/// "Today" in the user's timezone for a given `now`.
///
/// Calendar / Dispatch "today" detection uses this instead of browser-local
/// `chrono::Local::today()`, so the highlighted day matches the day the
/// records bucket onto.
pub fn user_today(now: DateTime<Utc>, user_tz: &str) -> NaiveDate {
    user_local_date(now, user_tz)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn d(s: &str) -> NaiveDate {
        NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap()
    }

    /// AC: a 23:30 entry in America/Los_Angeles stays on its local day, not
    /// the UTC day that is already tomorrow.
    #[test]
    fn late_evening_pacific_stays_on_local_day() {
        // 2026-06-15 23:30 Pacific == 2026-06-16 06:30 UTC.
        let utc = Utc.with_ymd_and_hms(2026, 6, 16, 6, 30, 0).unwrap();
        assert_eq!(user_local_date(utc, "America/Los_Angeles"), d("2026-06-15"));
        // Same instant in UTC genuinely is the 16th.
        assert_eq!(user_local_date(utc, "UTC"), d("2026-06-16"));
    }

    /// AC: two users in different zones bucket the same UTC instant onto
    /// different days when it is a different day for each.
    #[test]
    fn different_zones_can_bucket_to_different_days() {
        let utc = Utc.with_ymd_and_hms(2026, 6, 16, 6, 30, 0).unwrap();
        let la = user_local_date(utc, "America/Los_Angeles");
        let london = user_local_date(utc, "Europe/London");
        assert_eq!(la, d("2026-06-15"));
        assert_eq!(london, d("2026-06-16"));
        assert_ne!(la, london);
    }

    #[test]
    fn invalid_or_empty_timezone_falls_back_to_utc() {
        let utc = Utc.with_ymd_and_hms(2026, 6, 16, 6, 30, 0).unwrap();
        assert_eq!(user_local_date(utc, "Not/AZone"), d("2026-06-16"));
        assert_eq!(user_local_date(utc, ""), d("2026-06-16"));
        assert_eq!(canonical_tz_name("Not/AZone"), "UTC");
        assert_eq!(canonical_tz_name(""), "UTC");
    }

    #[test]
    fn canonical_name_round_trips_valid_zone() {
        assert_eq!(
            canonical_tz_name("America/Los_Angeles"),
            "America/Los_Angeles"
        );
    }

    #[test]
    fn user_today_uses_user_zone() {
        // Just after midnight UTC on the 16th is still the 15th in Pacific.
        let now = Utc.with_ymd_and_hms(2026, 6, 16, 0, 30, 0).unwrap();
        assert_eq!(user_today(now, "America/Los_Angeles"), d("2026-06-15"));
        assert_eq!(user_today(now, "UTC"), d("2026-06-16"));
    }
}
