//! Shared numeric-field validators for money/hours DTOs (PMS-383).
//!
//! Decimal money rates, hours, and mileage figures are bound straight to
//! `DECIMAL`/`NUMERIC` columns. Without a request-layer guard an out-of-range
//! value reaches Postgres and triggers a numeric-field-overflow that surfaces
//! as a raw 500 (`DATABASE_ERROR`) instead of a clean 422, and a value with
//! more decimal places than the column holds is silently rounded. These
//! validators reject both up front. They live here in `mokosh-types` so both
//! `mokosh-server` and the `mokosh-apps` WASM client share one definition,
//! mirroring `validate_money_amount` / `validate_budget_*` in the server crate.
//!
//! Each is applied per field with `#[validate(custom(function = ...))]`; on an
//! `Option<Decimal>` the validator runs on the inner value and skips `None`.

use rust_decimal::Decimal;
use validator::ValidationError;

/// Exclusive magnitude bound for a `DECIMAL(10, 2)` column (largest holdable
/// value `99_999_999.99`): `work_types.default_rate`, `time_entries`/
/// `projects.hourly_rate`, and `tasks.estimated_hours`.
const DECIMAL_10_2_MAX_EXCLUSIVE: i64 = 100_000_000;

/// Exclusive bound for the mileage `distance_miles` `NUMERIC(8, 2)` column
/// (largest holdable value `999_999.99`).
const DISTANCE_MILES_MAX_EXCLUSIVE: i64 = 1_000_000;

/// Exclusive bound for the mileage `rate_per_mile` `NUMERIC(8, 4)` column
/// (largest holdable value `9_999.9999`).
const RATE_PER_MILE_MAX_EXCLUSIVE: i64 = 10_000;

/// Shared non-negative numeric rule: reject negatives, more than `max_scale`
/// decimal places, and magnitudes that would overflow the backing column.
/// `noun` / `column` tailor the human-readable message.
fn validate_nonneg(
    value: &Decimal,
    max_exclusive: i64,
    max_scale: u32,
    noun: &str,
    column: &str,
) -> Result<(), ValidationError> {
    if value.is_sign_negative() {
        let mut error = ValidationError::new("value_negative");
        error.message = Some(format!("{noun} must not be negative").into());
        return Err(error);
    }
    if value.scale() > max_scale {
        let mut error = ValidationError::new("value_scale");
        error.message = Some(format!("{noun} must have at most {max_scale} decimal places").into());
        return Err(error);
    }
    if value.abs() >= Decimal::from(max_exclusive) {
        let mut error = ValidationError::new("value_out_of_range");
        error.message = Some(
            format!("{noun} must be less than {max_exclusive} (the {column} column limit)").into(),
        );
        return Err(error);
    }
    Ok(())
}

/// Validate a money rate stored in a `DECIMAL(10, 2)` column (`default_rate`,
/// `hourly_rate`): non-negative, at most 2 decimal places, magnitude `< 1e8`.
/// A zero rate is allowed (free / non-billable work).
/// A URL slug: lowercase alphanumerics in hyphen-separated groups, with no
/// leading, trailing or doubled hyphen. Grammar `^[a-z0-9]+(-[a-z0-9]+)*$`.
///
/// PMS-898: moved here with the forms DTOs, which validate a definition's slug
/// on the wire. Written by hand rather than with the `regex` the server's copy
/// used, because this crate is compiled into the SPA's WASM bundle and a regex
/// engine is a large thing to ship for one grammar this simple. The server's
/// `utils::validation::validate_slug` now delegates here, so there is one
/// definition rather than two that can disagree.
pub fn validate_slug(slug: &str) -> Result<(), ValidationError> {
    let ok = !slug.is_empty()
        && !slug.starts_with('-')
        && !slug.ends_with('-')
        && !slug.contains("--")
        && slug
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if ok {
        Ok(())
    } else {
        Err(ValidationError::new("invalid_slug"))
    }
}

pub fn validate_rate(value: &Decimal) -> Result<(), ValidationError> {
    validate_nonneg(
        value,
        DECIMAL_10_2_MAX_EXCLUSIVE,
        2,
        "rate",
        "DECIMAL(10, 2)",
    )
}

/// Validate an estimated-hours value stored in a `DECIMAL(10, 2)` column:
/// non-negative, at most 2 decimal places, magnitude `< 1e8`.
pub fn validate_hours(value: &Decimal) -> Result<(), ValidationError> {
    validate_nonneg(
        value,
        DECIMAL_10_2_MAX_EXCLUSIVE,
        2,
        "hours",
        "DECIMAL(10, 2)",
    )
}

/// Validate the mileage `rate_per_mile` `NUMERIC(8, 4)` column: non-negative,
/// at most 4 decimal places, magnitude `< 10_000`.
pub fn validate_rate_per_mile(value: &Decimal) -> Result<(), ValidationError> {
    validate_nonneg(
        value,
        RATE_PER_MILE_MAX_EXCLUSIVE,
        4,
        "rate per mile",
        "NUMERIC(8, 4)",
    )
}

/// Validate the mileage `distance_miles` `NUMERIC(8, 2)` column. Unlike the
/// rate/hours fields the distance must be strictly positive (a zero-mile trip
/// is not a trip; the column carries a `distance_miles > 0` CHECK), so it is
/// validated separately rather than via [`validate_rate`].
pub fn validate_distance_miles(value: &Decimal) -> Result<(), ValidationError> {
    if !value.is_sign_positive() || value.is_zero() {
        let mut error = ValidationError::new("distance_not_positive");
        error.message = Some("distance must be greater than 0".into());
        return Err(error);
    }
    if value.scale() > 2 {
        let mut error = ValidationError::new("distance_scale");
        error.message = Some("distance must have at most 2 decimal places".into());
        return Err(error);
    }
    if value.abs() >= Decimal::from(DISTANCE_MILES_MAX_EXCLUSIVE) {
        let mut error = ValidationError::new("distance_out_of_range");
        error.message = Some(
            format!(
                "distance must be less than {DISTANCE_MILES_MAX_EXCLUSIVE} \
                 (the NUMERIC(8, 2) column limit)"
            )
            .into(),
        );
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn dec(s: &str) -> Decimal {
        Decimal::from_str(s).unwrap()
    }

    #[test]
    fn rate_and_hours_bounds() {
        // Boundary value the DECIMAL(10, 2) column can hold.
        assert!(validate_rate(&dec("99999999.99")).is_ok());
        assert!(validate_rate(&dec("0")).is_ok());
        assert!(validate_hours(&dec("8.50")).is_ok());

        // Overflow magnitude -> would 500 at Postgres without this guard.
        assert!(validate_rate(&dec("100000000")).is_err());
        assert!(validate_rate(&dec("99999999999")).is_err());
        assert!(validate_hours(&dec("100000000")).is_err());

        // Negative and excess scale.
        assert!(validate_rate(&dec("-0.01")).is_err());
        assert!(validate_hours(&dec("1.234")).is_err());
    }

    #[test]
    fn rate_per_mile_bounds() {
        // 4 decimal places fit NUMERIC(8, 4).
        assert!(validate_rate_per_mile(&dec("0.6700")).is_ok());
        assert!(validate_rate_per_mile(&dec("9999.9999")).is_ok());
        assert!(validate_rate_per_mile(&dec("0")).is_ok());

        assert!(validate_rate_per_mile(&dec("10000")).is_err());
        assert!(validate_rate_per_mile(&dec("0.12345")).is_err());
        assert!(validate_rate_per_mile(&dec("-1")).is_err());
    }

    #[test]
    fn distance_miles_bounds() {
        assert!(validate_distance_miles(&dec("42.5")).is_ok());
        assert!(validate_distance_miles(&dec("999999.99")).is_ok());

        // Strictly positive: zero and negative are rejected.
        assert!(validate_distance_miles(&dec("0")).is_err());
        assert!(validate_distance_miles(&dec("-1")).is_err());

        assert!(validate_distance_miles(&dec("1000000")).is_err());
        assert!(validate_distance_miles(&dec("1.234")).is_err());
    }
}

#[cfg(test)]
mod pms898_slug_tests {
    use super::validate_slug;

    /// The grammar the regex this replaces enforced, case by case, so the
    /// hand-written form cannot drift from `^[a-z0-9]+(-[a-z0-9]+)*$`.
    #[test]
    fn slug_grammar_matches_the_regex_it_replaces() {
        for ok in ["a", "hello-world", "hello123", "a1-b2-c3", "9"] {
            assert!(validate_slug(ok).is_ok(), "`{ok}` should be valid");
        }
        for bad in [
            "",
            "-leading",
            "trailing-",
            "double--hyphen",
            "Upper",
            "has space",
            "under_score",
            "-",
        ] {
            assert!(validate_slug(bad).is_err(), "`{bad}` should be rejected");
        }
    }
}
