//! Custom validation utilities

use regex::Regex;
use rust_decimal::Decimal;
use std::sync::LazyLock;
use validator::ValidationError;

// Regex patterns
static EMAIL_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap());

static PHONE_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\+?[1-9]\d{1,14}$").unwrap());

static SLUG_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z0-9]+(?:-[a-z0-9]+)*$").unwrap());

/// Validate an email address
pub fn validate_email(email: &str) -> Result<(), ValidationError> {
    if EMAIL_REGEX.is_match(email) {
        Ok(())
    } else {
        Err(ValidationError::new("invalid_email"))
    }
}

/// Validate a phone number (E.164 format)
pub fn validate_phone(phone: &str) -> Result<(), ValidationError> {
    if phone.is_empty() || PHONE_REGEX.is_match(phone) {
        Ok(())
    } else {
        Err(ValidationError::new("invalid_phone"))
    }
}

/// Validate a URL slug
pub fn validate_slug(slug: &str) -> Result<(), ValidationError> {
    if SLUG_REGEX.is_match(slug) {
        Ok(())
    } else {
        Err(ValidationError::new("invalid_slug"))
    }
}

/// Validate password strength
pub fn validate_password_strength(password: &str) -> Result<(), ValidationError> {
    let mut errors = Vec::new();

    if password.len() < 8 {
        errors.push("at least 8 characters");
    }
    if password.len() > 128 {
        errors.push("no more than 128 characters");
    }
    if !password.chars().any(|c| c.is_lowercase()) {
        errors.push("a lowercase letter");
    }
    if !password.chars().any(|c| c.is_uppercase()) {
        errors.push("an uppercase letter");
    }
    if !password.chars().any(|c| c.is_ascii_digit()) {
        errors.push("a number");
    }
    if !password.chars().any(|c| !c.is_alphanumeric()) {
        errors.push("a special character");
    }

    if errors.is_empty() {
        Ok(())
    } else {
        let mut error = ValidationError::new("weak_password");
        error.message = Some(format!("Password must contain: {}", errors.join(", ")).into());
        Err(error)
    }
}

/// Validate a CRON expression
pub fn validate_cron(expr: &str) -> Result<(), ValidationError> {
    match cron::Schedule::try_from(expr) {
        Ok(_) => Ok(()),
        Err(_) => Err(ValidationError::new("invalid_cron")),
    }
}

/// Contract types accepted by the `contracts.contract_type` CHECK
/// constraint (migration `009_contracts.sql`). Kept in sync with the DB
/// so a request carrying an out-of-set value is rejected with a 422 at
/// the request layer instead of hitting the constraint and surfacing as a
/// 500 DATABASE_ERROR (PMS-299).
pub const CONTRACT_TYPES: [&str; 5] = [
    "managed_services",
    "block_hours",
    "time_and_materials",
    "fixed_price",
    "warranty",
];

/// Validate a contract type against the set the DB CHECK constraint
/// allows. The `contract_type` field deserializes as a free `String`, so
/// values such as `recurring` or `retainer` pass deserialization but
/// violate the DB constraint; rejecting them here turns an unhandled 500
/// into a clear 422 (PMS-299).
pub fn validate_contract_type(value: &str) -> Result<(), ValidationError> {
    if CONTRACT_TYPES.contains(&value) {
        Ok(())
    } else {
        let mut error = ValidationError::new("invalid_contract_type");
        error.message = Some(
            format!(
                "contract_type must be one of: {}",
                CONTRACT_TYPES.join(", ")
            )
            .into(),
        );
        Err(error)
    }
}

/// Contract statuses accepted by the `contracts.status` CHECK constraint
/// (migration `009_contracts.sql`). Kept in sync with the DB so a request
/// carrying an out-of-set value is rejected with a 422 at the request layer
/// instead of hitting the constraint and surfacing as a 500 DATABASE_ERROR
/// (PMS-337).
pub const CONTRACT_STATUSES: [&str; 5] = ["draft", "active", "expired", "cancelled", "renewed"];

/// Validate a contract status against the set the DB CHECK constraint allows.
/// The `status` field deserializes as a free `String`, so an unknown value
/// passes deserialization but violates the DB constraint; rejecting it here
/// turns an unhandled 500 into a clear 422 (PMS-337).
pub fn validate_contract_status(value: &str) -> Result<(), ValidationError> {
    if CONTRACT_STATUSES.contains(&value) {
        Ok(())
    } else {
        let mut error = ValidationError::new("invalid_contract_status");
        error.message =
            Some(format!("status must be one of: {}", CONTRACT_STATUSES.join(", ")).into());
        Err(error)
    }
}

/// Billing cycles accepted by the `contracts.billing_cycle` CHECK constraint
/// (migration `009_contracts.sql`). Kept in sync with the DB so a request
/// carrying an out-of-set value is rejected with a 422 at the request layer
/// instead of hitting the constraint and surfacing as a 500 DATABASE_ERROR
/// (PMS-337).
pub const BILLING_CYCLES: [&str; 4] = ["monthly", "quarterly", "annually", "one_time"];

/// Validate a billing cycle against the set the DB CHECK constraint allows.
/// The `billing_cycle` field deserializes as a free `String`, so an unknown
/// value passes deserialization but violates the DB constraint; rejecting it
/// here turns an unhandled 500 into a clear 422 (PMS-337).
pub fn validate_billing_cycle(value: &str) -> Result<(), ValidationError> {
    if BILLING_CYCLES.contains(&value) {
        Ok(())
    } else {
        let mut error = ValidationError::new("invalid_billing_cycle");
        error.message = Some(
            format!(
                "billing_cycle must be one of: {}",
                BILLING_CYCLES.join(", ")
            )
            .into(),
        );
        Err(error)
    }
}

/// Exclusive upper bound on the magnitude of a money amount stored in a
/// `DECIMAL(12, 2)` column: 10 integer digits, so values must satisfy
/// `|amount| < 10_000_000_000`. The bound is exclusive because the largest
/// value the column can hold is `9_999_999_999.99`.
const MONEY_AMOUNT_MAX_EXCLUSIVE: i64 = 10_000_000_000;

/// Validate that a money amount fits the `DECIMAL(12, 2)` columns used for
/// invoice / payment money fields. Without this bound an oversized amount
/// (e.g. `1e15`) reaches Postgres and triggers a numeric field overflow that
/// surfaces as a 500 `DATABASE_ERROR` instead of a clear 422 (PMS-306, same
/// class as PMS-297). The check is on the absolute value so signed amounts
/// (refunds, credits) are bounded symmetrically; the sign itself is allowed
/// (see the field-level docs on `CreatePaymentRequest::amount`).
pub fn validate_money_amount(value: &Decimal) -> Result<(), ValidationError> {
    if value.abs() < Decimal::from(MONEY_AMOUNT_MAX_EXCLUSIVE) {
        Ok(())
    } else {
        let mut error = ValidationError::new("amount_out_of_range");
        error.message = Some(
            format!(
                "amount magnitude must be less than {MONEY_AMOUNT_MAX_EXCLUSIVE} \
                 (the DECIMAL(12, 2) column limit)"
            )
            .into(),
        );
        Err(error)
    }
}

/// Exclusive upper bound on the magnitude of a project budget *amount* stored
/// in a `DECIMAL(12, 2)` column (largest holdable value `9_999_999_999.99`).
const BUDGET_AMOUNT_MAX_EXCLUSIVE: i64 = 10_000_000_000;

/// Exclusive upper bound on the magnitude of a project budget *hours* value
/// stored in a `DECIMAL(10, 2)` column (largest holdable value `99_999_999.99`).
const BUDGET_HOURS_MAX_EXCLUSIVE: i64 = 100_000_000;

/// Shared budget rule (PMS-324): reject negatives, more than two decimal
/// places, and magnitudes that would overflow the backing `DECIMAL` column.
/// Without the range check an oversized value reaches Postgres and surfaces as
/// a 500 numeric-overflow rather than a clear 422 (same class as PMS-306);
/// without the scale check a value like `1.234` is silently rounded to `1.23`
/// by the column. `column` names the backing type in the message only.
fn validate_budget(
    value: &Decimal,
    max_exclusive: i64,
    column: &'static str,
) -> Result<(), ValidationError> {
    if value.is_sign_negative() {
        let mut error = ValidationError::new("budget_negative");
        error.message = Some("budget must not be negative".into());
        return Err(error);
    }
    if value.scale() > 2 {
        let mut error = ValidationError::new("budget_scale");
        error.message = Some("budget must have at most 2 decimal places".into());
        return Err(error);
    }
    if value.abs() >= Decimal::from(max_exclusive) {
        let mut error = ValidationError::new("budget_out_of_range");
        error.message = Some(
            format!("budget must be less than {max_exclusive} (the {column} column limit)").into(),
        );
        return Err(error);
    }
    Ok(())
}

/// Validate a project `budget_amount` against its `DECIMAL(12, 2)` column.
pub fn validate_budget_amount(value: &Decimal) -> Result<(), ValidationError> {
    validate_budget(value, BUDGET_AMOUNT_MAX_EXCLUSIVE, "DECIMAL(12, 2)")
}

/// Validate a project `budget_hours` against its `DECIMAL(10, 2)` column.
pub fn validate_budget_hours(value: &Decimal) -> Result<(), ValidationError> {
    validate_budget(value, BUDGET_HOURS_MAX_EXCLUSIVE, "DECIMAL(10, 2)")
}

/// Generate a slug from a string
pub fn slugify(s: &str) -> String {
    s.to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .split('-')
        .filter(|s| !s.is_empty())
        .collect::<Vec<&str>>()
        .join("-")
}

/// Sanitize HTML content to prevent XSS
pub fn sanitize_html(html: &str) -> String {
    // Basic HTML entity encoding for XSS prevention
    html.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

/// Truncate a string to a maximum length, adding ellipsis if needed.
///
/// `max_len` is a byte budget. Slicing at an arbitrary byte index panics when
/// it lands inside a multi-byte UTF-8 sequence, so the cut point is snapped
/// back to the nearest char boundary via `char_indices` before slicing.
pub fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        return s.to_string();
    }
    // Reserve 3 bytes for the "..." suffix, then find the last char boundary
    // at or before that byte budget so the slice never splits a code point.
    let budget = max_len.saturating_sub(3);
    let cut = s
        .char_indices()
        .map(|(i, _)| i)
        .take_while(|&i| i <= budget)
        .last()
        .unwrap_or(0);
    format!("{}...", &s[..cut])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_email() {
        assert!(validate_email("test@example.com").is_ok());
        assert!(validate_email("user.name+tag@domain.co.uk").is_ok());
        assert!(validate_email("invalid").is_err());
        assert!(validate_email("@example.com").is_err());
    }

    #[test]
    fn test_validate_phone() {
        assert!(validate_phone("+14155551234").is_ok());
        assert!(validate_phone("14155551234").is_ok());
        assert!(validate_phone("").is_ok()); // Empty is allowed
        assert!(validate_phone("abc123").is_err());
    }

    #[test]
    fn test_validate_slug() {
        assert!(validate_slug("hello-world").is_ok());
        assert!(validate_slug("hello123").is_ok());
        assert!(validate_slug("HELLO").is_err());
        assert!(validate_slug("hello_world").is_err());
    }

    #[test]
    fn test_validate_password_strength() {
        assert!(validate_password_strength("Str0ng@Pass!").is_ok());
        assert!(validate_password_strength("weak").is_err());
        assert!(validate_password_strength("NoNumber!").is_err());
    }

    #[test]
    fn test_validate_contract_type() {
        // PMS-299: only the DB CHECK set is accepted.
        assert!(validate_contract_type("managed_services").is_ok());
        assert!(validate_contract_type("block_hours").is_ok());
        assert!(validate_contract_type("time_and_materials").is_ok());
        assert!(validate_contract_type("fixed_price").is_ok());
        assert!(validate_contract_type("warranty").is_ok());
        // Values that passed deserialization but caused a 500 before.
        assert!(validate_contract_type("recurring").is_err());
        assert!(validate_contract_type("retainer").is_err());
        assert!(validate_contract_type("").is_err());
    }

    #[test]
    fn test_validate_contract_status() {
        // PMS-337: only the DB CHECK set is accepted.
        assert!(validate_contract_status("draft").is_ok());
        assert!(validate_contract_status("active").is_ok());
        assert!(validate_contract_status("expired").is_ok());
        assert!(validate_contract_status("cancelled").is_ok());
        assert!(validate_contract_status("renewed").is_ok());
        // Values that passed deserialization but caused a 500 before.
        assert!(validate_contract_status("pending").is_err());
        assert!(validate_contract_status("Active").is_err());
        assert!(validate_contract_status("").is_err());
    }

    #[test]
    fn test_validate_billing_cycle() {
        // PMS-337: only the DB CHECK set is accepted.
        assert!(validate_billing_cycle("monthly").is_ok());
        assert!(validate_billing_cycle("quarterly").is_ok());
        assert!(validate_billing_cycle("annually").is_ok());
        assert!(validate_billing_cycle("one_time").is_ok());
        // Values that passed deserialization but caused a 500 before.
        assert!(validate_billing_cycle("weekly").is_err());
        assert!(validate_billing_cycle("yearly").is_err());
        assert!(validate_billing_cycle("").is_err());
    }

    #[test]
    fn test_validate_money_amount() {
        use std::str::FromStr;
        // In-range values, including the column maximum and signed amounts.
        assert!(validate_money_amount(&Decimal::from_str("0").unwrap()).is_ok());
        assert!(validate_money_amount(&Decimal::from_str("9999999999.99").unwrap()).is_ok());
        assert!(validate_money_amount(&Decimal::from_str("-9999999999.99").unwrap()).is_ok());
        // PMS-306: oversized amount (e.g. 1e15) must be rejected here instead
        // of overflowing the column and surfacing as a 500.
        assert!(validate_money_amount(&Decimal::from_str("10000000000").unwrap()).is_err());
        assert!(validate_money_amount(&Decimal::from_str("1000000000000000").unwrap()).is_err());
        assert!(validate_money_amount(&Decimal::from_str("-1000000000000000").unwrap()).is_err());
    }

    #[test]
    fn test_validate_budget() {
        use std::str::FromStr;
        // Valid: zero, two decimal places, the column maxima.
        assert!(validate_budget_amount(&Decimal::from_str("0").unwrap()).is_ok());
        assert!(validate_budget_amount(&Decimal::from_str("9999999999.99").unwrap()).is_ok());
        assert!(validate_budget_hours(&Decimal::from_str("99999999.99").unwrap()).is_ok());
        assert!(validate_budget_hours(&Decimal::from_str("8.50").unwrap()).is_ok());
        // Negative rejected (PMS-324).
        assert!(validate_budget_amount(&Decimal::from_str("-1").unwrap()).is_err());
        assert!(validate_budget_hours(&Decimal::from_str("-0.01").unwrap()).is_err());
        // More than 2 decimal places rejected (would be silently rounded by the column).
        assert!(validate_budget_amount(&Decimal::from_str("1.234").unwrap()).is_err());
        assert!(validate_budget_hours(&Decimal::from_str("1.001").unwrap()).is_err());
        // Out of range for the respective column (would overflow -> 500).
        assert!(validate_budget_amount(&Decimal::from_str("10000000000").unwrap()).is_err());
        assert!(validate_budget_hours(&Decimal::from_str("100000000").unwrap()).is_err());
        // A value that fits hours' bigger sibling but overflows hours' DECIMAL(10, 2).
        assert!(validate_budget_amount(&Decimal::from_str("99999999.99").unwrap()).is_ok());
    }

    #[test]
    fn test_slugify() {
        assert_eq!(slugify("Hello World!"), "hello-world");
        assert_eq!(slugify("  Multiple   Spaces  "), "multiple-spaces");
        assert_eq!(slugify("Special@#Characters"), "special-characters");
    }

    #[test]
    fn test_sanitize_html() {
        assert_eq!(sanitize_html("<script>"), "&lt;script&gt;");
        assert_eq!(sanitize_html("\"test\""), "&quot;test&quot;");
    }

    #[test]
    fn test_truncate() {
        assert_eq!(truncate("Hello", 10), "Hello");
        assert_eq!(truncate("Hello World", 8), "Hello...");
    }

    #[test]
    fn test_truncate_multibyte_no_panic() {
        // PMS-196: 'ñ' is two bytes, so an odd byte budget lands inside a code
        // point. The old byte-slice (`&s[..n]`) panicked here.
        // "ñññññ" is 10 bytes / 5 chars; budget 5 snaps back to byte 4.
        let s = "ñññññ";
        assert_eq!(truncate(s, 8), "ññ...");
        // 4-byte code points (emoji) must also be safe.
        assert_eq!(truncate("😀😀😀", 8), "😀...");
    }
}
