//! PMS-731: the runtime submission validator.
//!
//! This is the part that does NOT exist in eForm, whose entire validation
//! surface is one hardcoded "email is required", and the part the `validator`
//! crate cannot supply either: `#[derive(Validate)]` expands rules known at
//! COMPILE time, while these rules are rows a tenant authored at RUNTIME. So
//! the rule set is interpreted here.
//!
//! What IS reused is the error vocabulary. Failures are reported as
//! [`AppError::Validation`] carrying a `Vec<FieldError>`, which is the exact
//! wire shape the derive-based request validation already produces, so a
//! client renders a form-definition error and a DTO error the same way.
//! (`validator::ValidationErrors::add` takes `&'static str`, so it cannot
//! carry a runtime field name without leaking; `FieldError` takes owned
//! strings and is the right target.)
//!
//! Every error is collected before returning. A submission missing three
//! required fields reports all three, not the first.

use chrono::NaiveDate;
use serde_json::{Map, Value};

use super::models::{FieldType, FormFieldResponse, FormRule};
use crate::utils::error::{AppError, AppResult, FieldError};
use crate::utils::validation::validate_email;

const DATE_FORMAT: &str = "%Y-%m-%d";

/// Validate `payload` against a definition's `fields` and cross-field
/// `rules`, returning the normalised answers to store.
///
/// Normalisation is deliberately small: strings are trimmed, and a value that
/// is empty after trimming is treated as ABSENT. That way a required field
/// answered with whitespace reports "required" rather than passing a blank
/// through, and an optional field answered with whitespace is simply omitted
/// from the stored payload instead of persisting noise.
///
/// `today` is passed in rather than read from the clock so the
/// date-not-in-past rule is testable.
pub fn validate_submission(
    fields: &[FormFieldResponse],
    rules: &[FormRule],
    payload: &Value,
    today: NaiveDate,
) -> AppResult<Map<String, Value>> {
    let Some(object) = payload.as_object() else {
        return Err(AppError::validation_field(
            "payload",
            "Submission payload must be a JSON object",
        ));
    };

    let mut errors: Vec<FieldError> = Vec::new();
    let mut normalised = Map::new();

    // Unknown keys are rejected rather than ignored. A typo'd key would
    // otherwise be silently dropped and the request worked from incomplete
    // data, which is the exact round-trip cost PMS-730 exists to remove.
    for key in object.keys() {
        if !fields.iter().any(|f| &f.name == key) {
            errors.push(FieldError::new(
                key.clone(),
                format!("Unknown field `{key}` for this form"),
                "unknown_field",
            ));
        }
    }

    for field in fields {
        let raw = object.get(&field.name);
        let present = normalise_present(field, raw);
        let required = field.is_required || required_by_rule(field, rules, object);

        let Some(value) = present else {
            if required {
                errors.push(FieldError::new(
                    field.name.clone(),
                    format!("{} is required", field.label),
                    "required",
                ));
            }
            continue;
        };

        match validate_value(field, &value, today) {
            Ok(()) => {
                normalised.insert(field.name.clone(), value);
            }
            Err(e) => errors.push(e),
        }
    }

    if errors.is_empty() {
        Ok(normalised)
    } else {
        Err(AppError::validation(
            "one or more fields are invalid",
            errors,
        ))
    }
}

/// Resolve the submitted value to `Some` only when the field was genuinely
/// answered. JSON `null`, an absent key, and a string that is empty after
/// trimming all collapse to `None`, so "answered with whitespace" and "not
/// answered" behave identically.
fn normalise_present(field: &FormFieldResponse, raw: Option<&Value>) -> Option<Value> {
    let raw = raw?;
    if raw.is_null() {
        return None;
    }
    match raw {
        Value::String(s) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(Value::String(trimmed.to_string()))
            }
        }
        // A boolean field answered `false` IS an answer. Treating it as
        // absent would make a required checkbox impossible to say "no" to.
        other => {
            let _ = field;
            Some(other.clone())
        }
    }
}

/// Whether a cross-field rule makes this field required for this submission.
///
/// A rule naming a field that does not exist on the definition is inert here.
/// The service rejects such a rule at write time, so this is defence in depth
/// for a definition that predates that check, not the primary guard.
fn required_by_rule(
    field: &FormFieldResponse,
    rules: &[FormRule],
    object: &Map<String, Value>,
) -> bool {
    rules.iter().any(|rule| match rule {
        FormRule::RequiredIf {
            field: target,
            when_field,
            equals,
        } => {
            target == &field.name
                && object
                    .get(when_field)
                    .and_then(|v| v.as_str())
                    .map(|v| v.trim() == equals)
                    .unwrap_or(false)
        }
    })
}

/// Type and rule checks for a value already known to be present.
fn validate_value(
    field: &FormFieldResponse,
    value: &Value,
    today: NaiveDate,
) -> Result<(), FieldError> {
    let err = |message: String, code: &str| FieldError::new(field.name.clone(), message, code);

    match field.field_type {
        FieldType::Boolean => {
            if !value.is_boolean() {
                return Err(err(
                    format!("{} must be true or false", field.label),
                    "type",
                ));
            }
        }
        FieldType::Text | FieldType::Textarea | FieldType::Email => {
            let s = as_string(field, value)?;
            check_length(field, s).map_err(|(m, c)| err(m, c))?;
            if field.field_type == FieldType::Email && validate_email(s).is_err() {
                return Err(err(
                    format!("{} must be a valid email address", field.label),
                    "email",
                ));
            }
        }
        FieldType::Date => {
            let s = as_string(field, value)?;
            let Ok(parsed) = NaiveDate::parse_from_str(s, DATE_FORMAT) else {
                return Err(err(
                    format!("{} must be a date in YYYY-MM-DD format", field.label),
                    "date_format",
                ));
            };
            if field.date_not_in_past && parsed < today {
                return Err(err(
                    format!("{} cannot be in the past", field.label),
                    "date_in_past",
                ));
            }
        }
        FieldType::Select => {
            let s = as_string(field, value)?;
            let permitted = field.options.as_deref().unwrap_or(&[]);
            if !permitted.iter().any(|o| o == s) {
                return Err(err(
                    format!("{} must be one of: {}", field.label, permitted.join(", ")),
                    "option",
                ));
            }
        }
    }
    Ok(())
}

fn as_string<'v>(field: &FormFieldResponse, value: &'v Value) -> Result<&'v str, FieldError> {
    value.as_str().ok_or_else(|| {
        FieldError::new(
            field.name.clone(),
            format!("{} must be text", field.label),
            "type",
        )
    })
}

/// Length bounds count CHARACTERS, not bytes, so a limit means the same thing
/// to a client counting what it typed as it does here.
fn check_length(field: &FormFieldResponse, s: &str) -> Result<(), (String, &'static str)> {
    if !field.field_type.honours_length() {
        return Ok(());
    }
    let len = s.chars().count() as i64;
    if let Some(min) = field.min_length {
        if len < min as i64 {
            return Err((
                format!("{} must be at least {min} characters", field.label),
                "length_min",
            ));
        }
    }
    if let Some(max) = field.max_length {
        if len > max as i64 {
            return Err((
                format!("{} must be at most {max} characters", field.label),
                "length_max",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn today() -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 8, 6).expect("valid date")
    }

    fn field(name: &str, field_type: FieldType, is_required: bool) -> FormFieldResponse {
        FormFieldResponse {
            id: Uuid::new_v4(),
            name: name.to_string(),
            label: name.to_string(),
            help_text: None,
            field_type,
            is_required,
            min_length: None,
            max_length: None,
            options: None,
            date_not_in_past: false,
            sort_order: 0,
        }
    }

    fn codes(err: &AppError) -> Vec<String> {
        match err {
            AppError::Validation { errors, .. } => errors.iter().map(|e| e.code.clone()).collect(),
            other => panic!("expected a validation error, got {other:?}"),
        }
    }

    fn fields_of(err: &AppError) -> Vec<String> {
        match err {
            AppError::Validation { errors, .. } => errors.iter().map(|e| e.field.clone()).collect(),
            other => panic!("expected a validation error, got {other:?}"),
        }
    }

    #[test]
    fn required_fields_report_every_error_at_once() {
        let fields = vec![
            field("first_name", FieldType::Text, true),
            field("last_name", FieldType::Text, true),
            field("manager_email", FieldType::Email, true),
        ];
        let err = validate_submission(&fields, &[], &serde_json::json!({}), today())
            .expect_err("empty payload must fail");
        assert_eq!(codes(&err), vec!["required", "required", "required"]);
        assert_eq!(
            fields_of(&err),
            vec!["first_name", "last_name", "manager_email"]
        );
    }

    #[test]
    fn whitespace_only_answer_counts_as_missing() {
        let fields = vec![field("first_name", FieldType::Text, true)];
        let err = validate_submission(
            &fields,
            &[],
            &serde_json::json!({"first_name": "   "}),
            today(),
        )
        .expect_err("whitespace is not an answer");
        assert_eq!(codes(&err), vec!["required"]);
    }

    #[test]
    fn strings_are_trimmed_before_storage() {
        let fields = vec![field("first_name", FieldType::Text, true)];
        let out = validate_submission(
            &fields,
            &[],
            &serde_json::json!({"first_name": "  Dana  "}),
            today(),
        )
        .expect("valid");
        assert_eq!(out["first_name"], serde_json::json!("Dana"));
    }

    #[test]
    fn optional_field_left_blank_is_omitted_not_stored_empty() {
        let fields = vec![
            field("first_name", FieldType::Text, true),
            field("notes", FieldType::Textarea, false),
        ];
        let out = validate_submission(
            &fields,
            &[],
            &serde_json::json!({"first_name": "Dana", "notes": "  "}),
            today(),
        )
        .expect("valid");
        assert!(!out.contains_key("notes"), "blank optional must be omitted");
    }

    #[test]
    fn unknown_keys_are_rejected_rather_than_dropped() {
        let fields = vec![field("first_name", FieldType::Text, true)];
        let err = validate_submission(
            &fields,
            &[],
            &serde_json::json!({"first_name": "Dana", "frist_name": "typo"}),
            today(),
        )
        .expect_err("a typo'd key must not be silently dropped");
        assert_eq!(codes(&err), vec!["unknown_field"]);
    }

    #[test]
    fn email_pattern_is_enforced() {
        let fields = vec![field("manager_email", FieldType::Email, true)];
        let err = validate_submission(
            &fields,
            &[],
            &serde_json::json!({"manager_email": "not-an-email"}),
            today(),
        )
        .expect_err("bad email");
        assert_eq!(codes(&err), vec!["email"]);
    }

    #[test]
    fn length_bounds_count_characters_not_bytes() {
        let mut f = field("first_name", FieldType::Text, true);
        f.max_length = Some(3);
        // Four characters, but more than four bytes in UTF-8.
        let err = validate_submission(
            &[f],
            &[],
            &serde_json::json!({"first_name": "café"}),
            today(),
        )
        .expect_err("four characters exceeds a three character bound");
        assert_eq!(codes(&err), vec!["length_max"]);
    }

    #[test]
    fn date_must_parse_and_may_be_barred_from_the_past() {
        let mut f = field("start_date", FieldType::Date, true);
        f.date_not_in_past = true;

        let bad_format = validate_submission(
            std::slice::from_ref(&f),
            &[],
            &serde_json::json!({"start_date": "06/08/2026"}),
            today(),
        )
        .expect_err("non ISO date");
        assert_eq!(codes(&bad_format), vec!["date_format"]);

        let past = validate_submission(
            std::slice::from_ref(&f),
            &[],
            &serde_json::json!({"start_date": "2026-08-05"}),
            today(),
        )
        .expect_err("yesterday");
        assert_eq!(codes(&past), vec!["date_in_past"]);

        // Today itself is allowed: a same-day start is a real request.
        validate_submission(
            std::slice::from_ref(&f),
            &[],
            &serde_json::json!({"start_date": "2026-08-06"}),
            today(),
        )
        .expect("today is not in the past");
    }

    #[test]
    fn select_answer_must_come_from_the_option_set() {
        let mut f = field("laptop", FieldType::Select, true);
        f.options = Some(vec!["new".into(), "reuse existing".into(), "none".into()]);
        let err = validate_submission(
            std::slice::from_ref(&f),
            &[],
            &serde_json::json!({"laptop": "gaming rig"}),
            today(),
        )
        .expect_err("off-menu option");
        assert_eq!(codes(&err), vec!["option"]);

        validate_submission(
            std::slice::from_ref(&f),
            &[],
            &serde_json::json!({"laptop": "reuse existing"}),
            today(),
        )
        .expect("on-menu option");
    }

    #[test]
    fn required_boolean_accepts_false_as_an_answer() {
        let f = field("equipment_moves", FieldType::Boolean, true);
        let out = validate_submission(
            std::slice::from_ref(&f),
            &[],
            &serde_json::json!({"equipment_moves": false}),
            today(),
        )
        .expect("false is an answer, not a blank");
        assert_eq!(out["equipment_moves"], serde_json::json!(false));

        let err = validate_submission(
            std::slice::from_ref(&f),
            &[],
            &serde_json::json!({"equipment_moves": "yes"}),
            today(),
        )
        .expect_err("a string is not a boolean");
        assert_eq!(codes(&err), vec!["type"]);
    }

    /// The PMS-731 field-list conflict: `forward_to` on the MACD departure
    /// form is required only when `mailbox_handling = forward`. One
    /// form-level rule covers it without a conditional-display engine.
    #[test]
    fn required_if_applies_only_when_the_condition_holds() {
        let mut handling = field("mailbox_handling", FieldType::Select, true);
        handling.options = Some(vec![
            "forward".into(),
            "convert to shared".into(),
            "delete after retention".into(),
        ]);
        let fields = vec![handling, field("forward_to", FieldType::Email, false)];
        let rules = vec![FormRule::RequiredIf {
            field: "forward_to".into(),
            when_field: "mailbox_handling".into(),
            equals: "forward".into(),
        }];

        // Condition holds and the dependent field is missing -> required.
        let err = validate_submission(
            &fields,
            &rules,
            &serde_json::json!({"mailbox_handling": "forward"}),
            today(),
        )
        .expect_err("forward without an address");
        assert_eq!(codes(&err), vec!["required"]);
        assert_eq!(fields_of(&err), vec!["forward_to"]);

        // Condition does not hold -> the dependent field stays optional.
        validate_submission(
            &fields,
            &rules,
            &serde_json::json!({"mailbox_handling": "convert to shared"}),
            today(),
        )
        .expect("no address needed when not forwarding");

        // Present but invalid is still checked when the condition is off.
        let err = validate_submission(
            &fields,
            &rules,
            &serde_json::json!({"mailbox_handling": "convert to shared", "forward_to": "nope"}),
            today(),
        )
        .expect_err("an optional field that IS answered must still be valid");
        assert_eq!(codes(&err), vec!["email"]);
    }

    #[test]
    fn a_rule_naming_an_unknown_field_is_inert() {
        let fields = vec![field("first_name", FieldType::Text, true)];
        let rules = vec![FormRule::RequiredIf {
            field: "ghost".into(),
            when_field: "first_name".into(),
            equals: "Dana".into(),
        }];
        validate_submission(
            &fields,
            &rules,
            &serde_json::json!({"first_name": "Dana"}),
            today(),
        )
        .expect("a rule about a field that does not exist cannot block a submission");
    }

    #[test]
    fn a_non_object_payload_is_rejected() {
        let fields = vec![field("first_name", FieldType::Text, true)];
        let err = validate_submission(&fields, &[], &serde_json::json!("nope"), today())
            .expect_err("array or scalar payload");
        assert_eq!(fields_of(&err), vec!["payload"]);
    }
}
