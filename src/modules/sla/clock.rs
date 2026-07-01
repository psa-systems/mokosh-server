//! Business-hours-aware SLA clock (PMS-106).
//!
//! A pure, DB-free engine that computes when an SLA target comes due
//! given a start instant, a budget in hours, a weekly business schedule,
//! a holiday set, and whether the target runs `24x7` (`Always`) or only
//! during business hours (`BusinessHours`). It is deliberately isolated
//! from `sqlx`, the DB, and HTTP so the arithmetic is unit-testable in
//! isolation and reusable from any caller (the service evaluate path, a
//! background breach scanner, etc.).
//!
//! ## Stored shapes this module parses
//!
//! `business_hours.schedule` (JSONB) is keyed by ISO-ish weekday number
//! as a *string*, where `"0"` is Sunday and `"6"` is Saturday (matching
//! `migrations/023_seed_data.sql`). Each value is either JSON `null`
//! (a non-working day) or a single window object
//! `{"start": "HH:MM", "end": "HH:MM"}`:
//!
//! ```json
//! {
//!   "0": null,
//!   "1": {"start": "08:00", "end": "17:00"},
//!   "2": {"start": "08:00", "end": "17:00"},
//!   "3": {"start": "08:00", "end": "17:00"},
//!   "4": {"start": "08:00", "end": "17:00"},
//!   "5": {"start": "08:00", "end": "17:00"},
//!   "6": null
//! }
//! ```
//!
//! To stay tolerant of hand-authored data the parser also accepts:
//! - lowercase three-letter weekday keys (`"mon"`..`"sun"`), the shape
//!   documented on [`super::models::UpsertBusinessHoursRequest`];
//! - a JSON *array* of windows per day (`[{"start","end"}, ...]`), so a
//!   future split-shift schedule (e.g. a lunch break) round-trips; a
//!   single object is treated as a one-element array.
//!
//! Unknown keys and malformed windows are skipped rather than erroring,
//! so one bad row never wedges evaluation for an otherwise valid policy.
//!
//! `holiday_calendars.holidays` (JSONB) and the engine's holiday set are
//! a list of `YYYY-MM-DD` dates. [`parse_holidays`] accepts either bare
//! date strings (`["2026-12-25", ...]`) or `{"date": "YYYY-MM-DD", ...}`
//! objects (the `{date, name}` shape documented on
//! [`super::models::UpsertHolidayCalendarRequest`]). Holiday dates are
//! interpreted in the schedule's timezone (a holiday is a calendar day
//! local to the business, not a UTC day).

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Datelike, Duration, NaiveDate, NaiveTime, TimeZone, Utc, Weekday};
use chrono_tz::Tz;

/// Whether an SLA target's clock runs continuously or only inside the
/// business schedule. Mirrors the `sla_targets.operational_hours`
/// CHECK domain (`'24x7'` / `'business_hours'`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationalHours {
    /// 24x7: wall-clock arithmetic, schedule and holidays ignored.
    Always,
    /// Consume only minutes that fall inside the business schedule,
    /// skipping closed hours, non-working weekdays, and holidays.
    BusinessHours,
}

impl OperationalHours {
    /// Map the stored `operational_hours` string onto the enum.
    /// Anything other than `"24x7"` (case-insensitive) is treated as
    /// `BusinessHours`, matching the column default.
    pub fn from_db(s: &str) -> Self {
        if s.eq_ignore_ascii_case("24x7") {
            OperationalHours::Always
        } else {
            OperationalHours::BusinessHours
        }
    }
}

/// A single contiguous working window within a day, in the schedule's
/// local wall-clock time. `start < end`; zero-length windows are dropped
/// at parse time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Window {
    start: NaiveTime,
    end: NaiveTime,
}

/// A parsed weekly business schedule plus its IANA timezone.
///
/// Windows for each weekday are sorted by start time and non-empty days
/// only are stored. A weekday absent from the map is a non-working day
/// (the engine skips it the same way it skips a holiday).
#[derive(Debug, Clone)]
pub struct BusinessSchedule {
    tz: Tz,
    /// Working windows per weekday. Empty / absent entries = closed.
    by_weekday: HashMap<Weekday, Vec<Window>>,
}

impl BusinessSchedule {
    /// The schedule's timezone.
    pub fn timezone(&self) -> Tz {
        self.tz
    }

    /// Whether any weekday has at least one working window. A schedule
    /// with no windows at all would loop forever in `due_at`, so callers
    /// (and the engine) treat an empty schedule as "fall back to 24x7".
    pub fn has_any_window(&self) -> bool {
        self.by_weekday.values().any(|w| !w.is_empty())
    }

    /// Windows for `weekday` (already sorted, possibly empty).
    fn windows(&self, weekday: Weekday) -> &[Window] {
        self.by_weekday
            .get(&weekday)
            .map_or(&[][..], |v| v.as_slice())
    }

    /// Build directly from parts. Mainly for tests; production code goes
    /// through [`BusinessSchedule::parse`]. Windows are normalized
    /// (sorted, zero-length dropped) so callers need not pre-sort.
    pub fn from_windows(
        tz: Tz,
        days: impl IntoIterator<Item = (Weekday, Vec<(NaiveTime, NaiveTime)>)>,
    ) -> Self {
        let mut by_weekday: HashMap<Weekday, Vec<Window>> = HashMap::new();
        for (wd, windows) in days {
            let mut ws: Vec<Window> = windows
                .into_iter()
                .filter(|(s, e)| e > s)
                .map(|(start, end)| Window { start, end })
                .collect();
            ws.sort_by_key(|w| w.start);
            if !ws.is_empty() {
                by_weekday.insert(wd, ws);
            }
        }
        Self { tz, by_weekday }
    }

    /// Parse a [`BusinessSchedule`] from the stored `timezone` string and
    /// `schedule` JSONB value.
    ///
    /// Tolerant of the shapes documented at module level. An unparseable
    /// timezone falls back to UTC (logged by the caller if desired); a
    /// malformed schedule yields an all-closed schedule, which the engine
    /// degrades to 24x7 via [`BusinessSchedule::has_any_window`].
    pub fn parse(timezone: &str, schedule: &serde_json::Value) -> Self {
        let tz: Tz = timezone.parse().unwrap_or(Tz::UTC);
        let mut by_weekday: HashMap<Weekday, Vec<Window>> = HashMap::new();

        if let Some(map) = schedule.as_object() {
            for (key, value) in map {
                let Some(weekday) = parse_weekday_key(key) else {
                    continue;
                };
                let mut windows = parse_windows(value);
                windows.sort_by_key(|w| w.start);
                if !windows.is_empty() {
                    by_weekday.entry(weekday).or_default().extend(windows);
                }
            }
        }

        Self { tz, by_weekday }
    }
}

/// Map a schedule key onto a [`Weekday`]. Accepts numeric-string keys
/// (`"0"`=Sunday .. `"6"`=Saturday, the seeded shape) and lowercase
/// three-letter names (`"mon"`..`"sun"`). Returns `None` for anything
/// else so unknown keys are skipped.
///
/// Exposed to the module (PMS-604) so the write-time schedule validator
/// accepts exactly the key set this parser understands, keeping the two in
/// lock-step rather than duplicating the mapping.
pub(crate) fn parse_weekday_key(key: &str) -> Option<Weekday> {
    match key.trim() {
        "0" | "sun" | "sunday" => Some(Weekday::Sun),
        "1" | "mon" | "monday" => Some(Weekday::Mon),
        "2" | "tue" | "tuesday" => Some(Weekday::Tue),
        "3" | "wed" | "wednesday" => Some(Weekday::Wed),
        "4" | "thu" | "thursday" => Some(Weekday::Thu),
        "5" | "fri" | "friday" => Some(Weekday::Fri),
        "6" | "sat" | "saturday" => Some(Weekday::Sat),
        _ => None,
    }
}

/// Parse the per-day value into zero or more [`Window`]s. Accepts a
/// single window object, an array of window objects, or JSON null
/// (closed). Malformed entries are skipped.
fn parse_windows(value: &serde_json::Value) -> Vec<Window> {
    match value {
        serde_json::Value::Null => Vec::new(),
        serde_json::Value::Array(items) => items.iter().filter_map(parse_window).collect(),
        serde_json::Value::Object(_) => parse_window(value).into_iter().collect(),
        _ => Vec::new(),
    }
}

/// Parse a single `{"start": "HH:MM", "end": "HH:MM"}` object. Returns
/// `None` if either field is missing, unparseable, or `end <= start`.
fn parse_window(value: &serde_json::Value) -> Option<Window> {
    let start = parse_hhmm(value.get("start")?.as_str()?)?;
    let end = parse_hhmm(value.get("end")?.as_str()?)?;
    if end > start {
        Some(Window { start, end })
    } else {
        None
    }
}

/// Parse `"HH:MM"` or `"HH:MM:SS"` into a [`NaiveTime`].
///
/// Exposed to the module (PMS-604) so the write-time schedule validator
/// accepts exactly the time formats this parser understands.
pub(crate) fn parse_hhmm(s: &str) -> Option<NaiveTime> {
    NaiveTime::parse_from_str(s, "%H:%M")
        .or_else(|_| NaiveTime::parse_from_str(s, "%H:%M:%S"))
        .ok()
}

/// Parse a holiday list (JSONB) into a set of [`NaiveDate`]s.
///
/// Accepts bare `"YYYY-MM-DD"` strings or `{"date": "YYYY-MM-DD", ...}`
/// objects (the `{date, name}` shape). Unparseable entries are skipped.
pub fn parse_holidays(holidays: &serde_json::Value) -> HashSet<NaiveDate> {
    let mut set = HashSet::new();
    if let Some(items) = holidays.as_array() {
        for item in items {
            let date_str = match item {
                serde_json::Value::String(s) => Some(s.as_str()),
                serde_json::Value::Object(_) => item.get("date").and_then(|v| v.as_str()),
                _ => None,
            };
            if let Some(d) = date_str.and_then(|s| NaiveDate::parse_from_str(s, "%Y-%m-%d").ok()) {
                set.insert(d);
            }
        }
    }
    set
}

/// Compute when an SLA target comes due.
///
/// * `start` - when the clock starts (e.g. ticket `created_at`), in UTC.
/// * `hours` - the budget in hours (fractional allowed, e.g. `1.5`).
/// * `schedule` - the weekly business schedule + timezone.
/// * `holidays` - dates (in the schedule's timezone) that are non-working.
/// * `operational` - `Always` (24x7) or `BusinessHours`.
///
/// For [`OperationalHours::Always`] this is plain wall-clock addition.
/// For [`OperationalHours::BusinessHours`] only minutes inside an open
/// window of a working, non-holiday weekday are consumed; closed hours,
/// weekends, and holidays are skipped. A non-positive budget returns
/// `start` unchanged. If the schedule has no working windows at all the
/// function degrades to 24x7 rather than looping forever.
pub fn due_at(
    start: DateTime<Utc>,
    hours: f64,
    schedule: &BusinessSchedule,
    holidays: &HashSet<NaiveDate>,
    operational: OperationalHours,
) -> DateTime<Utc> {
    if hours <= 0.0 {
        return start;
    }

    // Budget in whole seconds; sub-second precision is not meaningful for
    // SLA targets and keeps the arithmetic on integers.
    let budget = Duration::seconds((hours * 3600.0).round() as i64);

    match operational {
        OperationalHours::Always => start + budget,
        OperationalHours::BusinessHours => {
            if !schedule.has_any_window() {
                // Misconfigured / empty schedule: avoid an infinite walk.
                return start + budget;
            }
            due_at_business_hours(start, budget, schedule, holidays)
        }
    }
}

/// Walk the schedule day by day in local time, consuming `budget` only
/// from open windows, and return the resulting instant back in UTC.
fn due_at_business_hours(
    start: DateTime<Utc>,
    budget: Duration,
    schedule: &BusinessSchedule,
    holidays: &HashSet<NaiveDate>,
) -> DateTime<Utc> {
    let tz = schedule.timezone();
    // Cursor in the schedule's local time.
    let mut cursor = start.with_timezone(&tz);
    let mut remaining = budget;

    // Hard cap on iterations as a termination guard against pathological
    // data. Each pass either consumes from a window (advancing the
    // cursor) or skips a closed/holiday day (advancing one calendar day),
    // so the cap bounds the calendar span the walk can cover. ~30 years
    // of days is far beyond any realistic SLA budget yet guarantees
    // termination even on a near-empty schedule.
    for _ in 0..(366 * 30) {
        if remaining <= Duration::zero() {
            break;
        }
        let date = cursor.date_naive();

        // Holiday or non-working weekday: jump to local midnight of the
        // next day and retry.
        if holidays.contains(&date) {
            cursor = next_day_start(tz, date);
            continue;
        }
        let windows = schedule.windows(cursor.weekday());
        if windows.is_empty() {
            cursor = next_day_start(tz, date);
            continue;
        }

        let mut consumed_today = false;

        for w in windows {
            // Resolve this window's start/end as concrete local instants.
            let win_start = local_dt(tz, date, w.start);
            let win_end = local_dt(tz, date, w.end);

            // Already past this window today: try the next window.
            if cursor >= win_end {
                continue;
            }

            // Before the window opens: fast-forward to its open instant
            // (no budget consumed) and re-enter the loop so the same
            // window is evaluated as "inside".
            if cursor < win_start {
                cursor = win_start;
            }

            // We are now inside [win_start, win_end). Consume from here.
            let avail = win_end - cursor;
            if remaining <= avail {
                cursor += remaining;
                remaining = Duration::zero();
            } else {
                remaining -= avail;
                cursor = win_end;
            }
            consumed_today = true;
            break;
        }

        if remaining <= Duration::zero() {
            break;
        }
        if !consumed_today {
            // Cursor was at/after every window for today: advance to the
            // next day's local midnight.
            cursor = next_day_start(tz, date);
        }
    }

    cursor.with_timezone(&Utc)
}

/// Local datetime for `date` at `time` in `tz`, resolving DST folds by
/// preferring the earliest valid instant (and nudging forward across a
/// spring-forward gap so a window that starts in a non-existent local
/// hour still yields a usable instant).
///
/// `.earliest()` collapses both the unambiguous and the fall-back
/// (ambiguous) cases to a single instant; only the spring-forward gap
/// (no local instant) needs the minute-walk fallback.
fn local_dt(tz: Tz, date: NaiveDate, time: NaiveTime) -> DateTime<Tz> {
    let naive = date.and_time(time);
    if let Some(dt) = tz.from_local_datetime(&naive).earliest() {
        return dt;
    }
    // Spring-forward gap: walk forward minute by minute until the local
    // time exists. Bounded by the largest real DST jump.
    let mut t = naive;
    for _ in 0..180 {
        t += Duration::minutes(1);
        if let Some(dt) = tz.from_local_datetime(&t).earliest() {
            return dt;
        }
    }
    // Fall back to a UTC interpretation; should be unreachable.
    tz.from_utc_datetime(&naive)
}

/// Local-midnight instant of the day after `date` in `tz`.
fn next_day_start(tz: Tz, date: NaiveDate) -> DateTime<Tz> {
    let next = date.succ_opt().unwrap_or(date);
    local_dt(tz, next, NaiveTime::from_hms_opt(0, 0, 0).unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono_tz::America::New_York;

    /// Mon-Fri 09:00-17:00 in the given timezone (8h/day).
    fn weekday_9_5(tz: Tz) -> BusinessSchedule {
        let nine = NaiveTime::from_hms_opt(9, 0, 0).unwrap();
        let five = NaiveTime::from_hms_opt(17, 0, 0).unwrap();
        BusinessSchedule::from_windows(
            tz,
            [
                (Weekday::Mon, vec![(nine, five)]),
                (Weekday::Tue, vec![(nine, five)]),
                (Weekday::Wed, vec![(nine, five)]),
                (Weekday::Thu, vec![(nine, five)]),
                (Weekday::Fri, vec![(nine, five)]),
            ],
        )
    }

    fn no_holidays() -> HashSet<NaiveDate> {
        HashSet::new()
    }

    /// Build a UTC instant from Y-M-D H:M.
    fn utc(y: i32, m: u32, d: u32, h: u32, min: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, h, min, 0).unwrap()
    }

    #[test]
    fn always_is_wall_clock() {
        let sched = weekday_9_5(Tz::UTC);
        // Friday 16:00 UTC + 4h 24x7 => Friday 20:00 UTC, schedule ignored.
        let start = utc(2026, 6, 5, 16, 0);
        let got = due_at(start, 4.0, &sched, &no_holidays(), OperationalHours::Always);
        assert_eq!(got, utc(2026, 6, 5, 20, 0));
    }

    #[test]
    fn always_fractional_hours() {
        let sched = weekday_9_5(Tz::UTC);
        let start = utc(2026, 6, 5, 10, 0);
        let got = due_at(start, 1.5, &sched, &no_holidays(), OperationalHours::Always);
        assert_eq!(got, utc(2026, 6, 5, 11, 30));
    }

    #[test]
    fn zero_budget_returns_start() {
        let sched = weekday_9_5(Tz::UTC);
        let start = utc(2026, 6, 5, 10, 0);
        let got = due_at(
            start,
            0.0,
            &sched,
            &no_holidays(),
            OperationalHours::BusinessHours,
        );
        assert_eq!(got, start);
    }

    #[test]
    fn mid_window_start_utc() {
        // 2026-06-01 is a Monday. Start 10:00 UTC, +4h business hours,
        // window 09:00-17:00 => 14:00 same day.
        let sched = weekday_9_5(Tz::UTC);
        let start = utc(2026, 6, 1, 10, 0);
        let got = due_at(
            start,
            4.0,
            &sched,
            &no_holidays(),
            OperationalHours::BusinessHours,
        );
        assert_eq!(got, utc(2026, 6, 1, 14, 0));
    }

    #[test]
    fn start_before_open_anchors_to_open() {
        // Monday 06:00 UTC, +2h => clock starts at 09:00, due 11:00.
        let sched = weekday_9_5(Tz::UTC);
        let start = utc(2026, 6, 1, 6, 0);
        let got = due_at(
            start,
            2.0,
            &sched,
            &no_holidays(),
            OperationalHours::BusinessHours,
        );
        assert_eq!(got, utc(2026, 6, 1, 11, 0));
    }

    #[test]
    fn start_after_close_rolls_to_next_working_day() {
        // Monday 18:00 UTC (after close), +2h => Tuesday 09:00 + 2h = 11:00.
        let sched = weekday_9_5(Tz::UTC);
        let start = utc(2026, 6, 1, 18, 0);
        let got = due_at(
            start,
            2.0,
            &sched,
            &no_holidays(),
            OperationalHours::BusinessHours,
        );
        assert_eq!(got, utc(2026, 6, 2, 11, 0));
    }

    #[test]
    fn spills_across_multiple_days() {
        // Monday 15:00 UTC, +4h. 2h left Monday (15->17), 2h Tuesday
        // (09->11) => Tuesday 11:00.
        let sched = weekday_9_5(Tz::UTC);
        let start = utc(2026, 6, 1, 15, 0);
        let got = due_at(
            start,
            4.0,
            &sched,
            &no_holidays(),
            OperationalHours::BusinessHours,
        );
        assert_eq!(got, utc(2026, 6, 2, 11, 0));
    }

    #[test]
    fn friday_afternoon_skips_weekend_to_monday() {
        // 2026-06-05 is a Friday. 15:00 UTC + 4h: 2h Friday (15->17),
        // weekend skipped, 2h Monday 2026-06-08 (09->11) => Monday 11:00.
        let sched = weekday_9_5(Tz::UTC);
        let start = utc(2026, 6, 5, 15, 0);
        let got = due_at(
            start,
            4.0,
            &sched,
            &no_holidays(),
            OperationalHours::BusinessHours,
        );
        assert_eq!(got, utc(2026, 6, 8, 11, 0));
    }

    #[test]
    fn holiday_inside_span_is_skipped() {
        // Make Tuesday 2026-06-02 a holiday. Monday 15:00 UTC + 4h:
        // 2h Monday (15->17), Tuesday is a holiday (skipped), 2h
        // Wednesday 2026-06-03 (09->11) => Wednesday 11:00.
        let sched = weekday_9_5(Tz::UTC);
        let mut holidays = HashSet::new();
        holidays.insert(NaiveDate::from_ymd_opt(2026, 6, 2).unwrap());
        let start = utc(2026, 6, 1, 15, 0);
        let got = due_at(
            start,
            4.0,
            &sched,
            &holidays,
            OperationalHours::BusinessHours,
        );
        assert_eq!(got, utc(2026, 6, 3, 11, 0));
    }

    #[test]
    fn fractional_hours_business() {
        // Monday 10:00 UTC + 1.5h => 11:30 same day.
        let sched = weekday_9_5(Tz::UTC);
        let start = utc(2026, 6, 1, 10, 0);
        let got = due_at(
            start,
            1.5,
            &sched,
            &no_holidays(),
            OperationalHours::BusinessHours,
        );
        assert_eq!(got, utc(2026, 6, 1, 11, 30));
    }

    #[test]
    fn exactly_on_close_boundary_rolls_to_next_day() {
        // Monday 13:00 UTC + 4h lands exactly at 17:00 (close). The
        // remaining budget is zero at that instant, so the due time is
        // 17:00 Monday, NOT bumped to Tuesday. This pins the boundary
        // semantics: consuming the last second of a window is allowed.
        let sched = weekday_9_5(Tz::UTC);
        let start = utc(2026, 6, 1, 13, 0);
        let got = due_at(
            start,
            4.0,
            &sched,
            &no_holidays(),
            OperationalHours::BusinessHours,
        );
        assert_eq!(got, utc(2026, 6, 1, 17, 0));
    }

    #[test]
    fn budget_one_second_past_close_rolls_over() {
        // Monday 13:00 UTC + 4h0m1s (4.000277...h). 3h59m59s left after
        // filling to 16:59:59? No: fills Monday to 17:00 consuming 4h,
        // 1s remains, rolls to Tuesday 09:00:01.
        let sched = weekday_9_5(Tz::UTC);
        let start = utc(2026, 6, 1, 13, 0);
        let hours = 4.0 + 1.0 / 3600.0;
        let got = due_at(
            start,
            hours,
            &sched,
            &no_holidays(),
            OperationalHours::BusinessHours,
        );
        assert_eq!(got, Utc.with_ymd_and_hms(2026, 6, 2, 9, 0, 1).unwrap());
    }

    #[test]
    fn timezone_is_respected_new_york() {
        // Schedule is 09:00-17:00 America/New_York. 2026-06-01 is a
        // Monday; EDT (UTC-4) in June. Start 13:00 UTC == 09:00 EDT
        // (window open). +4h business => 13:00 EDT == 17:00 UTC.
        let sched = weekday_9_5(New_York);
        let start = utc(2026, 6, 1, 13, 0); // 09:00 EDT
        let got = due_at(
            start,
            4.0,
            &sched,
            &no_holidays(),
            OperationalHours::BusinessHours,
        );
        assert_eq!(got, utc(2026, 6, 1, 17, 0)); // 13:00 EDT
    }

    #[test]
    fn new_york_start_before_open_anchors_local() {
        // 2026-06-01 Monday. Start 11:00 UTC == 07:00 EDT (before 09:00
        // open). +2h => clock starts 09:00 EDT (13:00 UTC), due 11:00 EDT
        // == 15:00 UTC.
        let sched = weekday_9_5(New_York);
        let start = utc(2026, 6, 1, 11, 0); // 07:00 EDT
        let got = due_at(
            start,
            2.0,
            &sched,
            &no_holidays(),
            OperationalHours::BusinessHours,
        );
        assert_eq!(got, utc(2026, 6, 1, 15, 0)); // 11:00 EDT
    }

    #[test]
    fn empty_schedule_degrades_to_wall_clock() {
        // A schedule with no windows must not loop; it falls back to 24x7.
        let sched = BusinessSchedule::from_windows(Tz::UTC, std::iter::empty());
        assert!(!sched.has_any_window());
        let start = utc(2026, 6, 1, 10, 0);
        let got = due_at(
            start,
            5.0,
            &sched,
            &no_holidays(),
            OperationalHours::BusinessHours,
        );
        assert_eq!(got, utc(2026, 6, 1, 15, 0));
    }

    // ---- parser tests --------------------------------------------------

    #[test]
    fn parse_numeric_seeded_schedule() {
        // The exact seeded shape from migrations/023_seed_data.sql.
        let schedule = serde_json::json!({
            "0": null,
            "1": {"start": "08:00", "end": "17:00"},
            "2": {"start": "08:00", "end": "17:00"},
            "3": {"start": "08:00", "end": "17:00"},
            "4": {"start": "08:00", "end": "17:00"},
            "5": {"start": "08:00", "end": "17:00"},
            "6": null
        });
        let sched = BusinessSchedule::parse("America/New_York", &schedule);
        assert_eq!(sched.timezone(), New_York);
        assert!(sched.has_any_window());
        assert!(sched.windows(Weekday::Sun).is_empty());
        assert!(sched.windows(Weekday::Sat).is_empty());
        let mon = sched.windows(Weekday::Mon);
        assert_eq!(mon.len(), 1);
        assert_eq!(mon[0].start, NaiveTime::from_hms_opt(8, 0, 0).unwrap());
        assert_eq!(mon[0].end, NaiveTime::from_hms_opt(17, 0, 0).unwrap());
    }

    #[test]
    fn parse_lowercase_name_keys_and_array_windows() {
        let schedule = serde_json::json!({
            "mon": [{"start": "09:00", "end": "12:00"}, {"start": "13:00", "end": "17:00"}],
            "sat": null
        });
        let sched = BusinessSchedule::parse("UTC", &schedule);
        let mon = sched.windows(Weekday::Mon);
        assert_eq!(mon.len(), 2, "split shift should yield two windows");
        // A split shift consumes the lunch gap: Monday 11:00 + 3h => the
        // last hour before lunch (11->12) then 13->15 => 15:00.
        let start = utc(2026, 6, 1, 11, 0);
        let got = due_at(
            start,
            3.0,
            &sched,
            &no_holidays(),
            OperationalHours::BusinessHours,
        );
        assert_eq!(got, utc(2026, 6, 1, 15, 0));
    }

    #[test]
    fn parse_bad_timezone_falls_back_to_utc() {
        let sched = BusinessSchedule::parse("Not/AZone", &serde_json::json!({}));
        assert_eq!(sched.timezone(), Tz::UTC);
        assert!(!sched.has_any_window());
    }

    #[test]
    fn parse_holidays_accepts_strings_and_objects() {
        let bare = serde_json::json!(["2026-12-25", "2026-01-01"]);
        let objs = serde_json::json!([
            {"date": "2026-12-25", "name": "Christmas"},
            {"date": "2026-07-04", "name": "Independence Day"}
        ]);
        let from_bare = parse_holidays(&bare);
        let from_objs = parse_holidays(&objs);
        assert!(from_bare.contains(&NaiveDate::from_ymd_opt(2026, 12, 25).unwrap()));
        assert!(from_bare.contains(&NaiveDate::from_ymd_opt(2026, 1, 1).unwrap()));
        assert!(from_objs.contains(&NaiveDate::from_ymd_opt(2026, 12, 25).unwrap()));
        assert!(from_objs.contains(&NaiveDate::from_ymd_opt(2026, 7, 4).unwrap()));
    }

    #[test]
    fn operational_hours_from_db() {
        assert_eq!(OperationalHours::from_db("24x7"), OperationalHours::Always);
        assert_eq!(OperationalHours::from_db("24X7"), OperationalHours::Always);
        assert_eq!(
            OperationalHours::from_db("business_hours"),
            OperationalHours::BusinessHours
        );
        assert_eq!(
            OperationalHours::from_db("anything-else"),
            OperationalHours::BusinessHours
        );
    }
}
