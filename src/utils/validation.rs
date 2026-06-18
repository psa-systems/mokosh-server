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

/// Scheduling-template kinds accepted by the `scheduling_templates.kind`
/// CHECK constraint (migration `054_scheduling_templates.sql`). `dispatch`
/// templates model on-site work (with travel buffers); `calendar` templates
/// model client interactions / status updates. Kept in sync with the DB so a
/// request carrying an out-of-set value is rejected with a 422 at the request
/// layer instead of hitting the constraint and surfacing as a 500
/// DATABASE_ERROR (PMS-403).
pub const SCHEDULING_TEMPLATE_KINDS: [&str; 2] = ["dispatch", "calendar"];

/// Validate a scheduling-template kind against the set the DB CHECK constraint
/// allows. The `kind` field deserializes as a free `String`, so an unknown
/// value passes deserialization but violates the DB constraint; rejecting it
/// here turns an unhandled 500 into a clear 422 (PMS-403).
pub fn validate_scheduling_template_kind(value: &str) -> Result<(), ValidationError> {
    if SCHEDULING_TEMPLATE_KINDS.contains(&value) {
        Ok(())
    } else {
        let mut error = ValidationError::new("invalid_scheduling_template_kind");
        error.message = Some(
            format!(
                "kind must be one of: {}",
                SCHEDULING_TEMPLATE_KINDS.join(", ")
            )
            .into(),
        );
        Err(error)
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
pub const BILLING_CYCLES: [&str; 6] = [
    "monthly",
    "quarterly",
    "annually",
    "one_time",
    "weekly",
    "bi_weekly",
];

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

/// Validate a payment `amount` against its `DECIMAL(12, 2)` column (PMS-373).
///
/// A payment must be strictly positive: a zero or negative amount distorts
/// invoice balances, customer statements, and revenue reporting, so it is
/// rejected with a 422 field error before any row is created (refunds /
/// reversals are modelled separately, not as negative payments). More than two
/// decimal places would be silently rounded by the column, and an oversized
/// magnitude would overflow it and surface as a 500 (same class as PMS-306).
/// A `payments_amount_positive` CHECK constraint backstops this at the DB.
pub fn validate_payment_amount(value: &Decimal) -> Result<(), ValidationError> {
    if !value.is_sign_positive() || value.is_zero() {
        let mut error = ValidationError::new("payment_amount_not_positive");
        error.message = Some("payment amount must be greater than 0".into());
        return Err(error);
    }
    if value.scale() > 2 {
        let mut error = ValidationError::new("payment_amount_scale");
        error.message = Some("payment amount must have at most 2 decimal places".into());
        return Err(error);
    }
    if *value >= Decimal::from(MONEY_AMOUNT_MAX_EXCLUSIVE) {
        let mut error = ValidationError::new("payment_amount_out_of_range");
        error.message = Some(
            format!(
                "payment amount must be less than {MONEY_AMOUNT_MAX_EXCLUSIVE} \
                 (the DECIMAL(12, 2) column limit)"
            )
            .into(),
        );
        return Err(error);
    }
    Ok(())
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

/// Exclusive upper bound on the magnitude of an SLA target *hours* value stored
/// in a `DECIMAL(10, 2)` column (largest holdable value `99_999_999.99`).
const SLA_HOURS_MAX_EXCLUSIVE: i64 = 100_000_000;

/// Validate an SLA target hours value (`first_response_hours` /
/// `resolution_hours`) against its `DECIMAL(10, 2)` column (PMS-338).
///
/// SLA targets previously accepted negative, zero, and over-precise hours at
/// every layer. We require a strictly-positive value: a blank/`None` field
/// already means "no target", so a stored target of `0` (an instantaneous
/// deadline) is never the intent and is rejected. More than two decimal places
/// would be silently rounded by the column, and an oversized magnitude would
/// overflow it and surface as a 500 instead of a clear 422 (same class as
/// PMS-324). Applied per field via `#[validate(custom(...))]`; on an
/// `Option<Decimal>` the validator runs on the inner value and skips `None`.
pub fn validate_sla_target_hours(value: &Decimal) -> Result<(), ValidationError> {
    if !value.is_sign_positive() || value.is_zero() {
        let mut error = ValidationError::new("sla_hours_not_positive");
        error.message = Some("SLA target hours must be greater than 0".into());
        return Err(error);
    }
    if value.scale() > 2 {
        let mut error = ValidationError::new("sla_hours_scale");
        error.message = Some("SLA target hours must have at most 2 decimal places".into());
        return Err(error);
    }
    if *value >= Decimal::from(SLA_HOURS_MAX_EXCLUSIVE) {
        let mut error = ValidationError::new("sla_hours_out_of_range");
        error.message = Some(
            format!(
                "SLA target hours must be less than {SLA_HOURS_MAX_EXCLUSIVE} \
                 (the DECIMAL(10, 2) column limit)"
            )
            .into(),
        );
        return Err(error);
    }
    Ok(())
}

/// Inclusive upper bound on a tax rate, expressed as a percentage (PMS-339).
/// The stored value is the percentage as-typed (e.g. 8.25, not 0.0825), so a
/// single rate above 100% is almost certainly a data-entry error and is
/// rejected. The backing column is `DECIMAL(7, 4)` (max magnitude 999.9999),
/// widened from `DECIMAL(5, 4)` in migration 051 precisely so a percentage
/// >= 10% fits; this bound stays well inside it.
const TAX_RATE_MAX_INCLUSIVE: i64 = 100;

/// Validate a tax rate percentage against its `DECIMAL(7, 4)` column (PMS-339).
///
/// `UpsertTaxRateRequest.rate` deserializes as a free `Decimal`, so before this
/// check a rate >= 10 overflowed the old `DECIMAL(5, 4)` column and surfaced as
/// an opaque 500 `DATABASE_ERROR`, while a negative or absurd value reached the
/// DB unchecked. We require `0 <= rate <= 100` (a percentage, not a fraction)
/// and at most 4 decimal places, matching the column scale; more than 4 dp
/// would be silently rounded by the column. This turns the DB 500 into a clean
/// 422 with a field-level message (same class as PMS-306 / PMS-324).
pub fn validate_tax_rate(value: &Decimal) -> Result<(), ValidationError> {
    if value.is_sign_negative() {
        let mut error = ValidationError::new("tax_rate_negative");
        error.message = Some("tax rate must not be negative".into());
        return Err(error);
    }
    if value.scale() > 4 {
        let mut error = ValidationError::new("tax_rate_scale");
        error.message = Some("tax rate must have at most 4 decimal places".into());
        return Err(error);
    }
    if *value > Decimal::from(TAX_RATE_MAX_INCLUSIVE) {
        let mut error = ValidationError::new("tax_rate_out_of_range");
        error.message = Some(
            format!("tax rate must be a percentage between 0 and {TAX_RATE_MAX_INCLUSIVE}").into(),
        );
        return Err(error);
    }
    Ok(())
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

/// Param key used to carry the form field a schema-level (cross-field)
/// validation error should attach to. `From<ValidationErrors> for AppError`
/// reads this param to re-key the error off validator-crate's `__all__`
/// bucket and onto a real field (PMS-364).
pub const CROSS_FIELD_TARGET_PARAM: &str = "field";

/// Build a schema-level (cross-field) `ValidationError` that names the form
/// field its message should attach to.
///
/// validator-crate keys every `#[validate(schema(...))]` error under the
/// special `__all__` bucket, which the client cannot bind to a form field, so
/// the message degrades to a generic banner instead of an inline field error
/// (PMS-364). Recording the target field as a param lets the
/// `From<ValidationErrors> for AppError` conversion re-key the error onto that
/// field so the form renders it inline, the same as a single-field error.
pub fn cross_field_error(
    code: &'static str,
    field: &'static str,
    message: &'static str,
) -> ValidationError {
    let mut error = ValidationError::new(code);
    error.message = Some(message.into());
    error.add_param(std::borrow::Cow::Borrowed(CROSS_FIELD_TARGET_PARAM), &field);
    error
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
        // PMS-404: sub-month cycles are now accepted.
        assert!(validate_billing_cycle("weekly").is_ok());
        assert!(validate_billing_cycle("bi_weekly").is_ok());
        // Values that passed deserialization but caused a 500 before.
        assert!(validate_billing_cycle("yearly").is_err());
        assert!(validate_billing_cycle("biweekly").is_err());
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
    fn test_validate_payment_amount() {
        use std::str::FromStr;
        // Valid: strictly-positive, at most 2 dp, within the column range.
        assert!(validate_payment_amount(&Decimal::from_str("50.00").unwrap()).is_ok());
        assert!(validate_payment_amount(&Decimal::from_str("0.01").unwrap()).is_ok());
        assert!(validate_payment_amount(&Decimal::from_str("9999999999.99").unwrap()).is_ok());
        // PMS-373: zero and negative amounts are rejected (no longer "refunds").
        assert!(validate_payment_amount(&Decimal::from_str("0").unwrap()).is_err());
        assert!(validate_payment_amount(&Decimal::from_str("-50.00").unwrap()).is_err());
        // More than 2 decimal places rejected (would be silently rounded).
        assert!(validate_payment_amount(&Decimal::from_str("1.001").unwrap()).is_err());
        // Out of range for DECIMAL(12, 2) (would overflow -> 500).
        assert!(validate_payment_amount(&Decimal::from_str("10000000000").unwrap()).is_err());
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
    fn test_validate_sla_target_hours() {
        use std::str::FromStr;
        // Valid: strictly-positive, at most 2 dp, within the column range.
        assert!(validate_sla_target_hours(&Decimal::from_str("4").unwrap()).is_ok());
        assert!(validate_sla_target_hours(&Decimal::from_str("0.25").unwrap()).is_ok());
        assert!(validate_sla_target_hours(&Decimal::from_str("99999999.99").unwrap()).is_ok());
        // Zero rejected: blank/None already means "no target" (PMS-338).
        assert!(validate_sla_target_hours(&Decimal::from_str("0").unwrap()).is_err());
        // Negative rejected.
        assert!(validate_sla_target_hours(&Decimal::from_str("-1").unwrap()).is_err());
        // More than 2 decimal places rejected (would be silently rounded).
        assert!(validate_sla_target_hours(&Decimal::from_str("1.001").unwrap()).is_err());
        // Out of range for DECIMAL(10, 2) (would overflow -> 500).
        assert!(validate_sla_target_hours(&Decimal::from_str("100000000").unwrap()).is_err());
    }

    #[test]
    fn test_validate_tax_rate() {
        use std::str::FromStr;
        // Boundaries valid: 0 and 100 (PMS-339).
        assert!(validate_tax_rate(&Decimal::from_str("0").unwrap()).is_ok());
        assert!(validate_tax_rate(&Decimal::from_str("100").unwrap()).is_ok());
        // Real-world rates that overflowed the old DECIMAL(5, 4) column.
        assert!(validate_tax_rate(&Decimal::from_str("10").unwrap()).is_ok());
        assert!(validate_tax_rate(&Decimal::from_str("20").unwrap()).is_ok());
        // Non-integer percentages keep full precision (up to 4 dp).
        assert!(validate_tax_rate(&Decimal::from_str("8.25").unwrap()).is_ok());
        assert!(validate_tax_rate(&Decimal::from_str("7.375").unwrap()).is_ok());
        // Rejections: negative and just over the 100% cap.
        assert!(validate_tax_rate(&Decimal::from_str("-1").unwrap()).is_err());
        assert!(validate_tax_rate(&Decimal::from_str("100.01").unwrap()).is_err());
        // More than 4 decimal places would be silently rounded by the column.
        assert!(validate_tax_rate(&Decimal::from_str("1.23456").unwrap()).is_err());
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
