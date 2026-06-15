//! SLA DTOs.

use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Clone, Serialize)]
pub struct SlaPolicyResponse {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub business_hours_id: Option<Uuid>,
    pub is_default: bool,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpsertSlaPolicyRequest {
    #[validate(length(min = 1, max = 100))]
    pub name: String,
    pub description: Option<String>,
    pub business_hours_id: Option<Uuid>,
    #[serde(default)]
    pub is_default: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SlaTargetResponse {
    pub id: Uuid,
    pub sla_policy_id: Uuid,
    pub priority_id: Uuid,
    pub first_response_hours: Option<Decimal>,
    pub resolution_hours: Option<Decimal>,
    pub operational_hours: String,
}

#[derive(Debug, Clone, Deserialize, Validate)]
#[validate(schema(function = validate_sla_target_range))]
pub struct UpsertSlaTargetRequest {
    pub priority_id: Uuid,
    #[validate(custom(function = crate::utils::validation::validate_sla_target_hours))]
    pub first_response_hours: Option<Decimal>,
    #[validate(custom(function = crate::utils::validation::validate_sla_target_hours))]
    pub resolution_hours: Option<Decimal>,
    /// "business_hours" | "24x7"
    #[serde(default = "default_24x7")]
    pub operational_hours: String,
}

/// Cross-field check (PMS-338): when both hours are present, the first-response
/// target may not exceed the resolution target. A resolution deadline that
/// falls before the first-response deadline is incoherent and was previously
/// accepted at every layer; reject it with a 422. Either field being `None`
/// (no target) leaves the pair unconstrained.
fn validate_sla_target_range(
    req: &UpsertSlaTargetRequest,
) -> Result<(), validator::ValidationError> {
    if let (Some(first_response), Some(resolution)) =
        (req.first_response_hours, req.resolution_hours)
    {
        if first_response > resolution {
            let mut error = validator::ValidationError::new("invalid_sla_target_range");
            error.message =
                Some("first_response_hours must be less than or equal to resolution_hours".into());
            return Err(error);
        }
    }
    Ok(())
}

fn default_24x7() -> String {
    "24x7".into()
}

#[derive(Debug, Clone, Serialize)]
pub struct BusinessHoursResponse {
    pub id: Uuid,
    pub name: String,
    pub timezone: String,
    pub schedule: serde_json::Value,
    pub is_default: bool,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpsertBusinessHoursRequest {
    #[validate(length(min = 1, max = 100))]
    pub name: String,
    #[serde(default = "default_utc")]
    pub timezone: String,
    /// Per-day windows, e.g.
    /// `{"mon": [{"start": "09:00", "end": "17:00"}], ...}`.
    #[serde(default)]
    pub schedule: serde_json::Value,
    #[serde(default)]
    pub is_default: bool,
}

fn default_utc() -> String {
    "UTC".into()
}

#[derive(Debug, Clone, Serialize)]
pub struct HolidayCalendarResponse {
    pub id: Uuid,
    pub name: String,
    /// List of `{date, name}` entries.
    pub holidays: serde_json::Value,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpsertHolidayCalendarRequest {
    #[validate(length(min = 1, max = 100))]
    pub name: String,
    #[serde(default)]
    pub holidays: serde_json::Value,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn target(first_response: Option<&str>, resolution: Option<&str>) -> UpsertSlaTargetRequest {
        UpsertSlaTargetRequest {
            priority_id: Uuid::new_v4(),
            first_response_hours: first_response.map(|s| Decimal::from_str(s).unwrap()),
            resolution_hours: resolution.map(|s| Decimal::from_str(s).unwrap()),
            operational_hours: default_24x7(),
        }
    }

    #[test]
    fn accepts_valid_target_pair() {
        // PMS-338: positive, <=2dp, first_response <= resolution.
        assert!(target(Some("1"), Some("8")).validate().is_ok());
        // Equal deadlines are allowed.
        assert!(target(Some("4"), Some("4")).validate().is_ok());
        // None means "no target" and is always allowed.
        assert!(target(None, None).validate().is_ok());
        assert!(target(Some("2.5"), None).validate().is_ok());
    }

    #[test]
    fn rejects_non_positive_hours() {
        // PMS-338: zero and negative hours are rejected per field.
        assert!(target(Some("0"), Some("8")).validate().is_err());
        assert!(target(Some("-1"), Some("8")).validate().is_err());
        assert!(target(Some("1"), Some("0")).validate().is_err());
    }

    #[test]
    fn rejects_over_precise_hours() {
        // PMS-338: more than 2 decimal places would be silently rounded.
        assert!(target(Some("1.001"), Some("8")).validate().is_err());
    }

    #[test]
    fn rejects_first_response_after_resolution() {
        // PMS-338: first_response_hours must not exceed resolution_hours.
        assert!(target(Some("8"), Some("4")).validate().is_err());
    }
}
