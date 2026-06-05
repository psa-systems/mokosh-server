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
        ("branding", "primary_color") | ("branding", "accent_color") => match value.as_str() {
            Some(s) if is_hex_color(s) => Ok(()),
            _ => Err(bad("value", "expected a hex color like #0066cc")),
        },
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

fn is_hex_color(s: &str) -> bool {
    s.len() == 7 && s.starts_with('#') && s[1..].chars().all(|c| c.is_ascii_hexdigit())
}
