//! Small date helpers.

use chrono::{Datelike, Duration, NaiveDate, Weekday};

/// Add `n` business days (Monday-Friday) to `start`, skipping weekends.
///
/// `n == 0` returns `start` unchanged. Holidays are not considered (a future
/// enhancement); this is the "standard due date" offset used by the tenant
/// `scheduling/default_due_business_days` setting (PMS-345). The result is
/// always a weekday.
pub fn add_business_days(start: NaiveDate, n: u32) -> NaiveDate {
    let mut date = start;
    let mut remaining = n;
    while remaining > 0 {
        date += Duration::days(1);
        if !matches!(date.weekday(), Weekday::Sat | Weekday::Sun) {
            remaining -= 1;
        }
    }
    date
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(s: &str) -> NaiveDate {
        NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap()
    }

    #[test]
    fn adds_within_the_week() {
        // Mon 2026-06-15 + 3 business days = Thu 2026-06-18.
        assert_eq!(add_business_days(d("2026-06-15"), 3), d("2026-06-18"));
    }

    #[test]
    fn skips_weekends() {
        // Fri 2026-06-19 + 1 business day = Mon 2026-06-22.
        assert_eq!(add_business_days(d("2026-06-19"), 1), d("2026-06-22"));
        // Thu 2026-06-18 + 3 business days = Tue 2026-06-23.
        assert_eq!(add_business_days(d("2026-06-18"), 3), d("2026-06-23"));
    }

    #[test]
    fn zero_returns_start() {
        assert_eq!(add_business_days(d("2026-06-15"), 0), d("2026-06-15"));
    }

    #[test]
    fn result_is_never_a_weekend() {
        let start = d("2026-06-19"); // Friday
        for n in 1..=20 {
            let r = add_business_days(start, n);
            assert!(!matches!(r.weekday(), Weekday::Sat | Weekday::Sun));
        }
    }
}
