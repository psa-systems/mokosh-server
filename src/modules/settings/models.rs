//! Settings DTOs.

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

use crate::utils::error::{AppError, AppResult};

#[derive(Debug, Clone, Serialize)]
pub struct TenantSettingResponse {
    pub id: Uuid,
    pub category: String,
    pub key: String,
    pub value: serde_json::Value,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpsertTenantSettingRequest {
    #[validate(length(min = 1, max = 50))]
    pub category: String,
    #[validate(length(min = 1, max = 100))]
    pub key: String,
    pub value: serde_json::Value,
}

/// Module configuration response.
///
/// `id` is `None` when the row does not yet exist in `module_config`
/// (PMS-113 AC4: missing rows return a soft default rather than 404).
/// The persisted form always has an `id`; SPA consumers can treat
/// `id.is_none()` as "this is the implicit default for an unconfigured
/// module on this tenant".
#[derive(Debug, Clone, Serialize)]
pub struct ModuleConfigResponse {
    pub id: Option<Uuid>,
    pub module_name: String,
    pub is_enabled: bool,
    pub config: serde_json::Value,
}

impl ModuleConfigResponse {
    /// Soft default returned for a module that has no row yet. Both the
    /// settings-API and tenants-API surfaces use this so a tenant never
    /// sees a 404 for an unconfigured module - it sees a row-shaped
    /// response with `is_enabled = false` (PMS-113 AC4).
    pub fn default_for(module_name: &str) -> Self {
        Self {
            id: None,
            module_name: module_name.to_string(),
            is_enabled: false,
            config: serde_json::json!({}),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpsertModuleConfigRequest {
    pub is_enabled: bool,
    #[serde(default)]
    pub config: serde_json::Value,
}

/// Body shape for per-key tenant_settings writes. The category and key
/// come from the URL path (`/api/v1/settings/:category/:key`); only the
/// value JSON travels in the body, so the SPA never has to repeat the
/// path components in the payload.
#[derive(Debug, Clone, Deserialize)]
pub struct PutSettingValueRequest {
    pub value: serde_json::Value,
}

/// Validate a tenant_settings value against the known
/// (category, key) shape table (PMS-113 AC1).
///
/// Unknown `(category, key)` pairs are accepted so the SPA can ship a
/// new knob without a server-side change, but emit a `tracing::warn!`
/// so we notice when this table needs a new entry. Returns
/// `AppError::Validation` for malformed known shapes; that maps to
/// HTTP 422 via `utils::error`.
pub fn validate_setting_value(
    category: &str,
    key: &str,
    value: &serde_json::Value,
) -> AppResult<()> {
    use serde_json::Value;

    fn bad(field: &str, msg: &str) -> AppError {
        AppError::validation_field(field, msg)
    }

    match (category, key) {
        ("notifications", "channel_email_enabled")
        | ("notifications", "channel_in_app_enabled") => match value {
            Value::Bool(_) => Ok(()),
            _ => Err(bad("value", "expected a boolean")),
        },
        ("notifications", "default_locale") => match value.as_str() {
            Some(s) if !s.is_empty() && s.len() <= 10 => Ok(()),
            _ => Err(bad("value", "expected a non-empty locale string (max 10)")),
        },
        // PMS-776: one shape table for both writers of a branding value.
        // `PUT /api/v1/tenants/:id` merges the same keys into
        // `tenants.branding`, so the two endpoints share
        // `tenants::branding::validate_branding_value` rather than drifting.
        // An unknown branding key is refused here too: the fall-through below
        // exists for a category whose shapes are not settled, and this one's
        // are, key by key.
        ("branding", _) => crate::modules::tenants::branding::validate_branding_value(key, value)
            .map_err(|message| bad("value", &message)),
        ("billing_prefs", "currency") => match value.as_str() {
            Some(s) if s.len() == 3 && s.chars().all(|c| c.is_ascii_uppercase()) => Ok(()),
            _ => Err(bad(
                "value",
                "expected a 3-letter uppercase ISO 4217 currency code",
            )),
        },
        ("ticketing", "auto_close_resolved_after_days") => match value.as_u64() {
            Some(n) if (1..=90).contains(&n) => Ok(()),
            _ => Err(bad("value", "expected an integer in 1..=90")),
        },
        // PMS-345: standard due date offset in business days, applied to new
        // tasks (when no due date is given) and to tickets with no SLA-derived
        // due date. 0 disables it.
        ("scheduling", "default_due_business_days") => match value.as_u64() {
            Some(n) if n <= 365 => Ok(()),
            _ => Err(bad(
                "value",
                "expected an integer in 0..=365 (0 disables the default due date)",
            )),
        },
        // PMS-396: per-tenant cap on a user's total logged time for a single
        // calendar date, in whole hours. A day cannot exceed 24 real hours, so
        // the range is 1..=24; the cap defaults to 24 when unset.
        ("time_tracking", "max_hours_per_day") => match value.as_u64() {
            Some(n) if (1..=24).contains(&n) => Ok(()),
            _ => Err(bad("value", "expected an integer in 1..=24")),
        },
        // PMS-469: company-id used to land a contact auto-created when an
        // unknown-sender intake arrives. Unset (or NULL) preserves the
        // Phase 1 "unknown sender => 422" posture. The companies row
        // itself is validated by the email_intake service at use time;
        // here we only check the value shape.
        ("email_intake", "default_company_id") => match value.as_str() {
            Some(s) if Uuid::parse_str(s).is_ok() => Ok(()),
            _ => Err(bad(
                "value",
                "expected a UUID string referencing companies.id",
            )),
        },
        // PMS-475: per-tenant ceiling for the CI impact-graph
        // traversal. Hard server-side cap is 10; the validator
        // accepts the same range so a typo cannot blow the query
        // plan. Default is 5 when the row is absent.
        ("ci", "impact_max_depth") => match value.as_u64() {
            Some(n) if (1..=10).contains(&n) => Ok(()),
            _ => Err(bad("value", "expected an integer in 1..=10")),
        },
        // PMS-467: cycle cap for mutating workflow rules on transition
        // triggers. 1 disables nested rule firing entirely; the upper
        // bound is 10 so a typo cannot let a tenant DOS itself with a
        // status-flipping rule. Default is 3 when unset.
        ("workflows", "rule_max_depth") => match value.as_u64() {
            Some(n) if (1..=10).contains(&n) => Ok(()),
            _ => Err(bad("value", "expected an integer in 1..=10")),
        },
        // Unknown (category, key): accept with a warning so a future SPA
        // experiment doesn't require a server change before the
        // validator can be taught the shape.
        _ => {
            tracing::warn!(
                category,
                key,
                "tenant_setting value validation: unknown (category, key); accepting verbatim. Add a match arm to validate_setting_value when the shape is finalized."
            );
            Ok(())
        }
    }
}

/// The one hex-colour predicate in the tree (PMS-776). `pub(crate)` rather than
/// duplicated in `tenants::branding`, which validates the same two keys on the
/// other write path.
pub(crate) fn is_hex_color(s: &str) -> bool {
    s.len() == 7 && s.starts_with('#') && s[1..].chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::tenants::branding::validate_branding_value;
    use serde_json::json;

    /// PMS-776: the settings endpoint and the tenants endpoint write the same
    /// branding keys to different stores (PMS-703 F18). They must not disagree
    /// about which values are legal, so this asserts one verdict per case
    /// rather than two tables.
    #[test]
    fn the_two_branding_writers_agree_on_every_key() {
        let cases = [
            ("primary_color", json!("#0066cc")),
            ("primary_color", json!("red")),
            ("secondary_color", json!("#00AA55")),
            ("accent_color", json!("#0066cc")),
            ("support_email", json!("help@acme.example")),
            ("support_email", json!("call us")),
            ("support_phone", json!("555-0100")),
            ("support_phone", json!("call the service desk")),
            ("support_contact_name", json!("Dana")),
            ("support_contact_name", json!("  ")),
            ("logo_url", json!("/api/v1/public/tenants/x/logo")),
            ("logo_url", json!("https://evil.example/logo.png")),
            ("logo_mime", json!("image/png")),
            ("logo_mime", json!("image/svg+xml")),
            ("company_name", json!("Acme IT")),
            ("portal_domain", json!("portal.acme.example")),
            ("supprt_email", json!("help@acme.example")),
        ];
        for (key, value) in cases {
            assert_eq!(
                validate_setting_value("branding", key, &value).is_ok(),
                validate_branding_value(key, &value).is_ok(),
                "the two writers disagree about branding.{key} = {value}"
            );
        }
    }

    /// The fall-through stays for a category whose shapes are not settled;
    /// `branding` no longer reaches it.
    #[test]
    fn an_unknown_key_outside_branding_is_still_accepted_with_a_warning() {
        assert!(validate_setting_value("experiments", "new_knob", &json!(1)).is_ok());
        assert!(validate_setting_value("branding", "new_knob", &json!(1)).is_err());
    }
}
