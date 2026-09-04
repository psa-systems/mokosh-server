//! PMS-896: the organisation record an account owns.
//!
//! The organisation IS the tenant row: the name in `tenants.name`, the contact
//! details in `tenants.branding` (MAPPS-429, PMS-755, and `website` here). What
//! did not exist was a surface stating which of those fields an account must
//! supply. `PUT /api/v1/tenants/{current,{id}}` cannot state it: its `branding`
//! is a PATCH document shared with the logo upload and the per-key settings
//! writer (PMS-758), so a logo upload sends two keys and must not be refused
//! for carrying no phone number.
//!
//! This is that surface, and it is a whole-record submission: an optional field
//! the caller omits is written as an explicit null, so what the account last
//! submitted is what the record holds. Phone and email are required, website is
//! optional, matching the Mokosh Apps onboarding flow (MAPPS-429).
//!
//! Which tenant the record hangs off is never in the request: it is the
//! caller's own tenant, resolved by the auth path from local membership state
//! (PMS-244). bunyip owns no organisation record and needs no change for this.

use serde_json::{json, Value};

use mokosh_types::contacts::normalize_website;
use mokosh_types::tenants::{OrganizationProfileRequest, UpdateTenantRequest};

use super::branding::validate_branding_value_as;
use crate::utils::error::{AppError, AppResult};

/// Longest organisation name, matching `CreateTenantRequest::name`.
const MAX_ORG_NAME: usize = 255;

/// Turn a submitted organisation record into the tenant update that persists it.
///
/// Split from the handler so the required/optional rules are testable without a
/// database or a session.
pub fn organization_update(request: &OrganizationProfileRequest) -> AppResult<UpdateTenantRequest> {
    let name = org_name(request.name.as_deref())?;
    let phone = required("phone", "support_phone", request.phone.as_deref())?;
    let email = required("email", "support_email", request.email.as_deref())?;
    let contact_name = optional(
        "contact_name",
        "support_contact_name",
        request.contact_name.as_deref(),
    )?;
    // PMS-805's rule, so an MSP who types `acme.example` stores
    // `https://acme.example` exactly as a company website would.
    let website = optional(
        "website",
        "website",
        clean(request.website.as_deref())
            .and_then(|w| normalize_website(&w))
            .as_deref(),
    )?;

    Ok(UpdateTenantRequest {
        name: Some(name),
        // The organisation submission never renames the tenant's portal
        // slug (MAPPS-449 owns that surface); pass `None` so the update
        // is a no-op for the slug column.
        slug: None,
        billing_email: None,
        billing_contact_name: None,
        settings: None,
        // Nulls, not omissions: this is the whole record, and a merged document
        // clears a key with an explicit null (PMS-758).
        branding: Some(json!({
            "support_phone": phone,
            "support_email": email,
            "support_contact_name": contact_name,
            "website": website,
        })),
    })
}

/// The organisation name: required, and bounded by the column it lands in
/// rather than by the branding table (this one is `tenants.name`).
fn org_name(value: Option<&str>) -> AppResult<String> {
    let name =
        clean(value).ok_or_else(|| AppError::validation_field("name", "`name` is required"))?;
    if name.chars().count() > MAX_ORG_NAME {
        return Err(AppError::validation_field(
            "name",
            format!("`name` must be at most {MAX_ORG_NAME} characters"),
        ));
    }
    if name.chars().any(char::is_control) {
        return Err(AppError::validation_field(
            "name",
            "`name` must be a single line",
        ));
    }
    Ok(name)
}

/// A required contact field, checked against its branding rule and reported
/// against the name the caller sent.
fn required(field: &str, key: &str, value: Option<&str>) -> AppResult<Value> {
    let value = clean(value)
        .ok_or_else(|| AppError::validation_field(field, format!("`{field}` is required")))?;
    checked(field, key, Some(value))
}

/// An optional contact field. Absent (or blank) is an explicit null.
fn optional(field: &str, key: &str, value: Option<&str>) -> AppResult<Value> {
    checked(field, key, clean(value))
}

fn checked(field: &str, key: &str, value: Option<String>) -> AppResult<Value> {
    let value = value.map(Value::String).unwrap_or(Value::Null);
    validate_branding_value_as(key, field, &value)
        .map_err(|message| AppError::validation_field(field, message))?;
    Ok(value)
}

/// Trim, and treat whitespace-only as absent - the same normalisation
/// [`super::identity::OrgIdentity`] applies on the way out.
fn clean(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn submission() -> OrganizationProfileRequest {
        OrganizationProfileRequest {
            name: Some("Contoso IT".to_string()),
            contact_name: Some("Dana".to_string()),
            phone: Some("555-0100".to_string()),
            email: Some("help@contoso.example".to_string()),
            website: None,
        }
    }

    fn branding(request: &OrganizationProfileRequest) -> Value {
        organization_update(request)
            .expect("a valid submission")
            .branding
            .expect("a branding patch")
    }

    fn field(err: AppError) -> String {
        match err {
            AppError::Validation { errors, .. } => errors[0].field.clone(),
            other => panic!("expected a validation error, got {other:?}"),
        }
    }

    /// The optional field is present: it is stored, scheme and all.
    #[test]
    fn a_submission_with_a_website_persists_it() {
        let mut request = submission();
        request.website = Some("https://contoso.example".to_string());
        assert_eq!(
            branding(&request)["website"],
            json!("https://contoso.example")
        );
    }

    /// The optional field is absent: the submission still succeeds, and the key
    /// is an explicit null so a previously-set website is cleared rather than
    /// silently kept.
    #[test]
    fn a_submission_without_a_website_is_accepted_and_clears_the_key() {
        let request = submission();
        let patch = branding(&request);
        assert_eq!(patch["website"], Value::Null);
        assert_eq!(patch["support_phone"], json!("555-0100"));
        assert_eq!(patch["support_email"], json!("help@contoso.example"));
        assert_eq!(patch["support_contact_name"], json!("Dana"));
        assert_eq!(
            organization_update(&request).expect("valid").name,
            Some("Contoso IT".to_string())
        );
        // Blank reads the same as absent, because a cleared input arrives as "".
        let mut blank = submission();
        blank.website = Some("   ".to_string());
        assert_eq!(branding(&blank)["website"], Value::Null);
    }

    #[test]
    fn a_website_without_a_scheme_is_normalised_rather_than_refused() {
        let mut request = submission();
        request.website = Some("Contoso.example/support".to_string());
        assert_eq!(
            branding(&request)["website"],
            json!("https://contoso.example/support")
        );
    }

    #[test]
    fn the_phone_and_the_email_are_required() {
        for (missing, expected) in [("phone", "phone"), ("email", "email")] {
            let mut request = submission();
            match missing {
                "phone" => request.phone = None,
                _ => request.email = None,
            }
            let err = organization_update(&request).expect_err("required field");
            assert_eq!(field(err), expected);
            // Blank is the same as missing: an emptied input arrives as "".
            let mut blank = submission();
            match missing {
                "phone" => blank.phone = Some("  ".to_string()),
                _ => blank.email = Some(String::new()),
            }
            assert_eq!(
                field(organization_update(&blank).expect_err("blank field")),
                expected
            );
        }
    }

    #[test]
    fn the_name_is_required() {
        let mut request = submission();
        request.name = None;
        assert_eq!(
            field(organization_update(&request).expect_err("required name")),
            "name"
        );
    }

    /// The contact name is the one field of the three that stays optional
    /// (MAPPS-429 collects it, PMS-896 does not require it).
    #[test]
    fn the_contact_name_is_optional() {
        let mut request = submission();
        request.contact_name = None;
        assert_eq!(branding(&request)["support_contact_name"], Value::Null);
    }

    /// A bad value is reported against the field the caller sent, not against
    /// the branding key it lands in.
    #[test]
    fn a_bad_value_is_reported_against_the_submitted_field_name() {
        let mut request = submission();
        request.email = Some("not-an-address".to_string());
        assert_eq!(
            field(organization_update(&request).expect_err("bad email")),
            "email"
        );
        let mut request = submission();
        request.phone = Some("call the service desk".to_string());
        assert_eq!(
            field(organization_update(&request).expect_err("bad phone")),
            "phone"
        );
        let mut request = submission();
        request.website = Some("javascript:alert(1)".to_string());
        assert_eq!(
            field(organization_update(&request).expect_err("bad website")),
            "website"
        );
    }
}
