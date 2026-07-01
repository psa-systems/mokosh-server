//! SLA DTOs.

use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::{Validate, ValidationError};

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
            // Re-key onto `first_response_hours` so the form shows the message
            // inline rather than as a generic banner (PMS-364).
            return Err(crate::utils::validation::cross_field_error(
                "invalid_sla_target_range",
                "first_response_hours",
                "first_response_hours must be less than or equal to resolution_hours",
            ));
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
    #[validate(custom(function = validate_business_schedule))]
    pub schedule: serde_json::Value,
    #[serde(default)]
    pub is_default: bool,
}

fn default_utc() -> String {
    "UTC".into()
}

/// Build a field-level `ValidationError` carrying a human message for a
/// malformed JSON payload (PMS-604). The validator crate keys the error onto
/// the field the `#[validate(custom(...))]` attribute sits on (`schedule` /
/// `holidays`), so the frontend binds the message inline.
fn json_shape_error(code: &'static str, message: String) -> ValidationError {
    let mut error = ValidationError::new(code);
    error.message = Some(message.into());
    error
}

/// Write-time validation of the `schedule` JSONB payload (PMS-604).
///
/// The SLA clock reader ([`super::clock::BusinessSchedule::parse`]) is
/// deliberately tolerant: it silently skips unknown weekday keys and malformed
/// windows so one bad row never wedges evaluation. That tolerance means a
/// typo'd payload is accepted at write time and then quietly ignored, which
/// distorts SLA due-time math (a day the admin believes is closed, or a window
/// that never takes effect). This is the strict counterpart run on
/// create/update: it accepts exactly the shapes the reader understands (reusing
/// the reader's own key/time parsers so the two cannot drift) and rejects
/// anything else with a 422 instead of storing it.
///
/// Accepted:
/// - JSON `null` or an empty object: no working windows (engine runs 24/7).
/// - An object keyed by weekday (`"0"`..`"6"`, 0=Sunday, or `"mon"`..`"sun"`),
///   each value either `null` (closed), a single `{"start","end"}` window, or
///   an array of such windows; `start`/`end` are `HH:MM`(`:SS`) and `end` must
///   be strictly after `start`.
fn validate_business_schedule(schedule: &serde_json::Value) -> Result<(), ValidationError> {
    // Absent / explicitly empty: no schedule, engine falls back to 24/7.
    if schedule.is_null() {
        return Ok(());
    }
    let Some(map) = schedule.as_object() else {
        return Err(json_shape_error(
            "invalid_schedule",
            "schedule must be a JSON object keyed by weekday, \
             e.g. {\"mon\": [{\"start\": \"09:00\", \"end\": \"17:00\"}]}"
                .to_string(),
        ));
    };
    for (key, value) in map {
        if super::clock::parse_weekday_key(key).is_none() {
            return Err(json_shape_error(
                "invalid_schedule",
                format!(
                    "unknown weekday key {key:?}; use \"0\"-\"6\" (0=Sunday) or \"mon\"-\"sun\""
                ),
            ));
        }
        validate_schedule_day(key, value)?;
    }
    Ok(())
}

/// Validate one weekday's value: `null` (closed), a single window object, or an
/// array of window objects.
fn validate_schedule_day(day: &str, value: &serde_json::Value) -> Result<(), ValidationError> {
    match value {
        serde_json::Value::Null => Ok(()),
        serde_json::Value::Object(_) => validate_schedule_window(day, value),
        serde_json::Value::Array(items) => {
            for item in items {
                validate_schedule_window(day, item)?;
            }
            Ok(())
        }
        _ => Err(json_shape_error(
            "invalid_schedule",
            format!("schedule for {day:?} must be null, a {{start, end}} window, or an array of windows"),
        )),
    }
}

/// Validate a single `{"start": "HH:MM", "end": "HH:MM"}` window object.
fn validate_schedule_window(day: &str, window: &serde_json::Value) -> Result<(), ValidationError> {
    let obj = window.as_object().ok_or_else(|| {
        json_shape_error(
            "invalid_schedule",
            format!("schedule window for {day:?} must be a {{start, end}} object"),
        )
    })?;
    let (Some(start), Some(end)) = (
        obj.get("start").and_then(|v| v.as_str()),
        obj.get("end").and_then(|v| v.as_str()),
    ) else {
        return Err(json_shape_error(
            "invalid_schedule",
            format!("schedule window for {day:?} needs string \"start\" and \"end\" times"),
        ));
    };
    let (Some(start_t), Some(end_t)) = (super::clock::parse_hhmm(start), super::clock::parse_hhmm(end))
    else {
        return Err(json_shape_error(
            "invalid_schedule",
            format!("schedule window for {day:?} has an unparseable time; use HH:MM (e.g. 09:00)"),
        ));
    };
    if end_t <= start_t {
        return Err(json_shape_error(
            "invalid_schedule",
            format!("schedule window for {day:?} must have end after start"),
        ));
    }
    Ok(())
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
