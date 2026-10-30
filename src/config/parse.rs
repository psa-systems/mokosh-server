//! The one shared rule for an optional numeric / boolean configuration value
//! (PMS-1577): unset or blank means the caller's documented default, and set
//! but unparseable (or, for [`parse_positive`], set but non-positive) is a
//! boot error naming the variable and the raw value it was set to.
//!
//! Before this module each of these sites parsed its own raw string and fell
//! back to its default with `.ok()` / `.unwrap_or(..)` on a parse failure, so
//! a typo in `PORT` or `MOKOSH_MAX_TENANTS` changed behaviour with nothing
//! logged. [`parse_optional`] and [`parse_positive`] are the ONE place that
//! rule lives now; every call site below passes the value it already has
//! (from [`crate::config::get`]) rather than re-reading it, which keeps the
//! rule testable without mutating process-global environment.

use crate::config::ConfigKey;

/// `raw` is `None` or blank: `Ok(None)`, the caller's default stands.
/// `raw` parses as `T`: `Ok(Some(value))`.
/// `raw` is set but does not parse as `T`: `Err`, naming `key` and the raw
/// value.
pub fn parse_optional<T>(key: &ConfigKey, raw: Option<String>) -> Result<Option<T>, String>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    match raw {
        Some(value) if !value.trim().is_empty() => {
            value.trim().parse::<T>().map(Some).map_err(|e| {
                format!(
                    "{} is set to {:?}, which is not a valid value: {e}",
                    key.name(),
                    value
                )
            })
        }
        _ => Ok(None),
    }
}

/// Same as [`parse_optional`], additionally rejecting a parsed value that is
/// not strictly positive (a cap of zero or less is nonsensical, and PMS-1577
/// refuses to read it as "uncapped" the way an unset value is read).
pub fn parse_positive<T>(key: &ConfigKey, raw: Option<String>) -> Result<Option<T>, String>
where
    T: std::str::FromStr + PartialOrd + Default + std::fmt::Display,
    T::Err: std::fmt::Display,
{
    match parse_optional::<T>(key, raw)? {
        None => Ok(None),
        Some(value) if value > T::default() => Ok(Some(value)),
        Some(value) => Err(format!(
            "{} must be a positive value, got {value}",
            key.name()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::registry;

    #[test]
    fn unset_or_blank_is_none() {
        assert_eq!(parse_optional::<u16>(&registry::PORT, None), Ok(None));
        assert_eq!(
            parse_optional::<u16>(&registry::PORT, Some("".into())),
            Ok(None)
        );
        assert_eq!(
            parse_optional::<u16>(&registry::PORT, Some("   ".into())),
            Ok(None)
        );
    }

    #[test]
    fn a_valid_value_parses() {
        assert_eq!(
            parse_optional::<u16>(&registry::PORT, Some("9090".into())),
            Ok(Some(9090))
        );
    }

    #[test]
    fn a_malformed_value_is_an_error_naming_the_key_and_value() {
        let err = parse_optional::<u16>(&registry::PORT, Some("not-a-port".into()))
            .expect_err("must fail");
        assert!(err.contains("PORT"), "{err}");
        assert!(err.contains("not-a-port"), "{err}");
    }

    #[test]
    fn positive_rejects_zero_and_negative() {
        assert!(parse_positive::<usize>(&registry::MOKOSH_MAX_TENANTS, Some("0".into())).is_err());
        assert!(parse_positive::<i64>(&registry::MOKOSH_MAX_TENANTS, Some("-1".into())).is_err());
    }

    #[test]
    fn positive_accepts_a_positive_value_and_unset() {
        assert_eq!(
            parse_positive::<usize>(&registry::MOKOSH_MAX_TENANTS, Some("5".into())),
            Ok(Some(5))
        );
        assert_eq!(
            parse_positive::<usize>(&registry::MOKOSH_MAX_TENANTS, None),
            Ok(None)
        );
    }
}
