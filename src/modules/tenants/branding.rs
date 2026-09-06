//! PMS-776: the shape of a branding value a client will be shown.
//!
//! `tenants.branding` is a PATCH document (PMS-758) whose keys reach people who
//! have no account here: `support_contact_name`, `support_phone` and
//! `support_email` compose the contact sentence in a client's email, and
//! `logo_url` is interpolated into an `<img src>` in the same message. Both
//! writers used to take those keys verbatim, so a malformed address, a phone
//! number that was a sentence, or a path pointing anywhere the public API base
//! can be joined to went out over the MSP's own SMTP identity.
//!
//! One table, three callers: `PUT /api/v1/tenants/:id` merges a whole document
//! ([`validate_branding_patch`], called from `TenantService::update_tenant`),
//! `PUT /api/v1/settings/{category}/{key}` writes one key at a time
//! ([`validate_branding_value`], called from
//! `settings::models::validate_setting_value`), and PMS-896's
//! `PUT /api/v1/tenants/current/organization` submits the organisation record
//! whole ([`validate_branding_value_as`], called from `super::organization`).
//! They still write to different stores, which is the seam PMS-703 F18 names;
//! what they no longer do is disagree about what a valid value is.
//!
//! Ungated, unlike the rest of the tenant surface: the settings validator is
//! not gated on `multi-tenant`, and a single-tenant build has branding too.

use serde_json::Value;

use crate::modules::settings::models::is_hex_color;
use crate::utils::error::{AppError, AppResult};
use crate::utils::validation::validate_email;

use super::logo::check_mime;

/// The only path prefix this API serves a tenant image from (see
/// [`super::logo::logo_path`]). A `logo_url` outside it is a broken image in
/// every email the tenant sends, or a pointer at something the public API base
/// was never meant to reach.
pub const PUBLIC_TENANT_PATH_PREFIX: &str = "/api/v1/public/tenants/";

/// Caps, in characters, for the free-text keys. Chosen from where each value is
/// rendered rather than from the column: the contact sentence and the form
/// page's contact line are one line in a client's mail client.
const MAX_NAME: usize = 120;
const MAX_PHONE: usize = 40;
const MAX_EMAIL: usize = 254;
const MAX_PATH: usize = 200;
const MAX_DOMAIN: usize = 253;
/// PMS-911: long enough for a VAT number with spaces or a registration line,
/// short enough that it cannot become a paragraph on an invoice.
const MAX_TAX_ID: usize = 60;
/// PMS-911: an address block on an invoice, bounded by both measures.
const MAX_ADDRESS: usize = 300;
const MAX_ADDRESS_LINES: usize = 6;
/// PMS-896: same cap as `companies.website`, so the organisation's own web
/// address and a client's are bounded alike.
const MAX_URL: usize = 255;

/// Validate a whole `branding` PATCH document.
///
/// Every key is checked against the table below and an unknown key is refused
/// rather than merged: the document is read back as [`mokosh_types::tenants::TenantBranding`],
/// so a key outside it is silently invisible to every reader while still
/// sitting in the JSONB the next writer merges into.
pub fn validate_branding_patch(patch: &Value) -> AppResult<()> {
    // PMS-758: an object or nothing. A string or an array here would replace
    // the document with something no reader can destructure, and `||` on two
    // non-objects concatenates rather than merges.
    let Some(obj) = patch.as_object() else {
        return Err(AppError::validation_field(
            "branding",
            "must be an object of branding keys",
        ));
    };
    for (key, value) in obj {
        validate_branding_value(key, value)
            .map_err(|message| AppError::validation_field(format!("branding.{key}"), message))?;
    }
    Ok(())
}

/// Validate one branding key.
///
/// `Err` carries the human message and no field name, because the two callers
/// hang it on different request fields (`branding.{key}` for the tenants PATCH,
/// `value` for the per-key settings write) and one table has to serve both.
pub fn validate_branding_value(key: &str, value: &Value) -> Result<(), String> {
    validate_branding_value_as(key, key, value)
}

/// PMS-896: the same table, reporting against a different field name.
///
/// The organisation submission (`super::organization`) calls its fields `phone`,
/// `email` and `contact_name`, so a message naming `support_phone` would name a
/// key that request does not have. `key` still selects the rule; `label` is
/// what the message calls it.
pub fn validate_branding_value_as(key: &str, label: &str, value: &Value) -> Result<(), String> {
    // PMS-758: an explicit null is how a merged document clears a key, and the
    // logo-delete route sends two of them.
    if value.is_null() {
        return Ok(());
    }
    match key {
        // `accent_color` is the deprecated alias for `secondary_color`, kept
        // accepted per PMS-703 F18 because the settings endpoint has written it
        // since PMS-113.
        "primary_color" | "secondary_color" | "accent_color" => {
            let s = text(label, value, 7)?;
            if is_hex_color(s) {
                Ok(())
            } else {
                Err(format!("`{label}` must be a hex colour like #0066cc"))
            }
        }
        "support_email" => {
            let s = text(label, value, MAX_EMAIL)?;
            validate_email(s.trim()).map_err(|_| format!("`{label}` must be an email address"))
        }
        "support_phone" => {
            let s = text(label, value, MAX_PHONE)?;
            if s.chars().any(|c| c.is_ascii_digit()) {
                Ok(())
            } else {
                Err(format!(
                    "`{label}` must be a phone number; it reads as \"on {{number}}\" in a client's email"
                ))
            }
        }
        "support_contact_name" | "company_name" | "legal_name" => {
            text(label, value, MAX_NAME).map(|_| ())
        }
        // PMS-911: whatever identifier the MSP's jurisdiction requires on an
        // invoice. Nothing parses it, so nothing validates its shape beyond
        // being one printable line: a rule that accepted a VAT number and
        // refused an ABN would be worse than no rule.
        "tax_id" => text(label, value, MAX_TAX_ID).map(|_| ()),
        // PMS-1006: which document template the tenant's invoices, credit
        // notes and statements are laid out with. An enumerated key rather
        // than free text, and the message names the three, because a typo
        // here silently reverts every document to Classic.
        "invoice_template" => {
            let s = text(label, value, 20)?;
            if crate::pdf::Template::from_key(s.trim()).is_some() {
                Ok(())
            } else {
                Err(format!(
                    "`{label}` must be one of {}",
                    crate::pdf::Template::KEYS.join(", ")
                ))
            }
        }
        // PMS-911: the one branding value that is legitimately multi-line,
        // because an address is. Held to a line count as well as a length, so
        // it stays an address block on an invoice rather than a paragraph.
        "postal_address" => multiline(label, value, MAX_ADDRESS, MAX_ADDRESS_LINES).map(|_| ()),
        // PMS-896: the organisation's own web address. Held to the same rule as
        // a company's (`mokosh_types::contacts::validate_website`) rather than a
        // second copy of it: the SPA renders both as a link, so `javascript:`
        // has to be as dead here as it is there.
        "website" => {
            let s = text(label, value, MAX_URL)?;
            mokosh_types::contacts::validate_website(s.trim())
                .map_err(|_| format!("`{label}` must be a web address like https://acme.example"))
        }
        // `logo_url` is what the upload route writes and what the email
        // composer joins to the public API base. `favicon_url` has no reader
        // yet; holding it to the same prefix stops it becoming an arbitrary
        // URL before one arrives.
        "logo_url" | "favicon_url" => {
            let s = text(label, value, MAX_PATH)?;
            if s.starts_with(PUBLIC_TENANT_PATH_PREFIX) {
                Ok(())
            } else {
                Err(format!(
                    "`{label}` must be a public tenant path beginning `{PUBLIC_TENANT_PATH_PREFIX}`"
                ))
            }
        }
        // The content type the public logo route answers with, so it is the
        // same set the upload accepts.
        "logo_mime" => {
            let s = text(label, value, 100)?;
            check_mime(s).map(|_| ()).map_err(|_| {
                format!("`{label}` must be an image type the logo route can serve (PNG, JPEG, WebP or GIF)")
            })
        }
        "portal_domain" => {
            let s = text(label, value, MAX_DOMAIN)?;
            if is_hostname(s.trim()) {
                Ok(())
            } else {
                Err(format!(
                    "`{label}` must be a bare hostname like portal.acme.example"
                ))
            }
        }
        _ => Err(format!(
            "`{label}` is not a branding key; the known keys are {}",
            KNOWN_KEYS.join(", ")
        )),
    }
}

/// Every key the table above accepts, for the message an unknown key gets.
/// Kept beside the match by [`known_keys_match_the_table`].
const KNOWN_KEYS: &[&str] = &[
    "company_name",
    "favicon_url",
    "invoice_template",
    "legal_name",
    "logo_mime",
    "logo_url",
    "portal_domain",
    "postal_address",
    "primary_color",
    "secondary_color",
    "accent_color",
    "support_contact_name",
    "support_email",
    "support_phone",
    "tax_id",
    "website",
];

/// A string value that will be rendered: present, not blank, within its
/// rendered length, and free of control characters. Blank is refused rather
/// than stored because an operator clearing a field means null, and
/// `OrgIdentity` would read `Some("")` back as unset anyway.
fn text<'a>(key: &str, value: &'a Value, max: usize) -> Result<&'a str, String> {
    let Some(s) = value.as_str() else {
        return Err(format!("`{key}` must be a string"));
    };
    if s.trim().is_empty() {
        return Err(format!("`{key}` must not be blank; send null to clear it"));
    }
    if s.chars().count() > max {
        return Err(format!("`{key}` must be at most {max} characters"));
    }
    if s.chars().any(char::is_control) {
        return Err(format!("`{key}` must be a single line"));
    }
    Ok(s)
}

/// PMS-911: a string value rendered as several lines, for the one branding key
/// that is an address. Bounded by line count as well as length, so it stays a
/// block on an invoice; `\r` is folded away so a Windows paste does not become
/// blank lines, and every other control character is still refused.
fn multiline<'a>(
    key: &str,
    value: &'a Value,
    max: usize,
    max_lines: usize,
) -> Result<&'a str, String> {
    let Some(s) = value.as_str() else {
        return Err(format!("`{key}` must be a string"));
    };
    if s.trim().is_empty() {
        return Err(format!("`{key}` must not be blank; send null to clear it"));
    }
    if s.chars().count() > max {
        return Err(format!("`{key}` must be at most {max} characters"));
    }
    if s.chars().any(|c| c.is_control() && c != '\n' && c != '\r') {
        return Err(format!("`{key}` must not contain control characters"));
    }
    if s.replace('\r', "").lines().count() > max_lines {
        return Err(format!("`{key}` must be at most {max_lines} lines"));
    }
    Ok(s)
}

/// A bare hostname: no scheme, no path, no port.
fn is_hostname(s: &str) -> bool {
    s.contains('.')
        && !s.starts_with(['.', '-'])
        && !s.ends_with(['.', '-'])
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use uuid::Uuid;

    fn patch(v: Value) -> Result<(), String> {
        validate_branding_patch(&v).map_err(|e| e.to_string())
    }

    #[test]
    fn a_support_email_must_be_an_email_address() {
        assert!(patch(json!({ "support_email": "help@acme.example" })).is_ok());
        assert!(patch(json!({ "support_email": "call us on 555-0100" })).is_err());
        assert!(patch(json!({ "support_email": "help@acme" })).is_err());
        assert!(patch(json!({ "support_email": 42 })).is_err());
    }

    #[test]
    fn a_logo_url_must_be_a_public_logo_path() {
        // What the upload route writes is what the validator accepts.
        let written = super::super::logo::logo_path(Uuid::nil());
        assert!(patch(json!({ "logo_url": written })).is_ok());
        assert!(patch(json!({ "logo_url": "https://evil.example/logo.png" })).is_err());
        assert!(patch(json!({ "logo_url": "/etc/passwd" })).is_err());
        assert!(
            patch(json!({ "logo_url": null })).is_ok(),
            "the delete-logo route clears the pointer with an explicit null"
        );
    }

    #[test]
    fn an_unknown_key_is_rejected_rather_than_merged() {
        assert!(patch(json!({ "supprt_email": "help@acme.example" })).is_err());
        assert!(patch(json!({ "branding": {} })).is_err());
        let err = validate_branding_value("supprt_email", &json!("help@acme.example")).unwrap_err();
        assert!(err.contains("is not a branding key"), "unexpected: {err}");
    }

    #[test]
    fn known_keys_match_the_table() {
        for key in KNOWN_KEYS {
            assert!(
                validate_branding_value(key, &Value::Null).is_ok(),
                "`{key}` is advertised as known but has no arm"
            );
            let err = validate_branding_value(key, &json!(false)).unwrap_err();
            assert!(
                !err.contains("is not a branding key"),
                "`{key}` is advertised as known but falls through: {err}"
            );
        }
    }

    #[test]
    fn every_branding_field_the_readers_destructure_is_writable() {
        // A key `TenantBranding` reads but this table refuses would make the
        // field unsettable through either endpoint.
        let full = json!({
            "logo_url": "/api/v1/public/tenants/x/logo",
            "logo_mime": "image/png",
            "favicon_url": "/api/v1/public/tenants/x/favicon",
            "primary_color": "#0066cc",
            "secondary_color": "#00AA55",
            "company_name": "Acme IT",
            "support_email": "help@acme.example",
            "support_phone": "555-0100",
            "support_contact_name": "Dana",
            "website": "https://acme.example",
            "portal_domain": "portal.acme.example",
            "legal_name": "Acme IT Services Pty Ltd",
            "tax_id": "ABN 12 345 678 901",
            "postal_address": "12 Example Street\nSuite 4\nSydney NSW 2000",
            "invoice_template": "modern",
        });
        assert!(patch(full.clone()).is_ok());
        let fields: Vec<String> = full
            .as_object()
            .unwrap()
            .keys()
            .map(|k| format!("\"{k}\""))
            .collect();
        let branding = serde_json::to_string(&mokosh_types::tenants::TenantBranding::default())
            .expect("serialize branding");
        for field in fields {
            assert!(
                branding.contains(&field),
                "{field} is accepted but no reader destructures it"
            );
        }
    }

    #[test]
    fn a_rendered_value_stays_one_short_line() {
        assert!(patch(json!({ "support_contact_name": "Dana" })).is_ok());
        assert!(patch(json!({ "support_contact_name": "   " })).is_err());
        assert!(patch(json!({ "support_contact_name": "Dana\nX" })).is_err());
        assert!(patch(json!({ "support_contact_name": "D".repeat(MAX_NAME + 1) })).is_err());
        assert!(patch(json!({ "support_phone": "+1 555-0100 ext. 2" })).is_ok());
        assert!(
            patch(json!({ "support_phone": "call the service desk" })).is_err(),
            "the email renders this as \"on {{phone}}\", so a sentence reads as a number"
        );
    }

    #[test]
    fn the_colour_keys_take_a_hex_colour() {
        assert!(patch(json!({ "primary_color": "#0066cc" })).is_ok());
        assert!(patch(json!({ "secondary_color": "#00AA55" })).is_ok());
        assert!(
            patch(json!({ "accent_color": "#0066cc" })).is_ok(),
            "the deprecated alias stays writable (PMS-703 F18)"
        );
        assert!(patch(json!({ "primary_color": "red" })).is_err());
        assert!(patch(json!({ "primary_color": "#0066cz" })).is_err());
    }

    #[test]
    fn a_logo_mime_is_one_the_public_route_can_serve() {
        assert!(patch(json!({ "logo_mime": "image/png" })).is_ok());
        assert!(patch(json!({ "logo_mime": "image/svg+xml" })).is_err());
    }

    /// PMS-896: the organisation website is a link a client clicks, so the
    /// scheme allowlist that protects `companies.website` protects this too.
    #[test]
    fn a_website_is_an_http_url() {
        assert!(patch(json!({ "website": "https://acme.example" })).is_ok());
        assert!(patch(json!({ "website": "http://acme.example/support" })).is_ok());
        assert!(patch(json!({ "website": "acme.example" })).is_err());
        assert!(patch(json!({ "website": "javascript:alert(1)" })).is_err());
        assert!(
            patch(json!({ "website": null })).is_ok(),
            "an organisation with no website submits an explicit null"
        );
    }

    /// PMS-896: the organisation submission names its fields `phone` / `email`
    /// / `website`, so the message it hands back must not name a branding key
    /// the caller never sent.
    #[test]
    fn a_message_can_be_reported_against_the_callers_own_field_name() {
        let err =
            validate_branding_value_as("support_phone", "phone", &json!("call us")).unwrap_err();
        assert!(err.contains("`phone`"), "unexpected: {err}");
        assert!(!err.contains("support_phone"), "unexpected: {err}");
        let err = validate_branding_value_as("support_email", "email", &json!("   ")).unwrap_err();
        assert!(err.contains("`email`"), "unexpected: {err}");
    }

    /// PMS-911: what an invoice has to show beyond a trading name.
    ///
    /// `tax_id` gets a length and nothing else on purpose: a rule that accepted
    /// a VAT number and refused an ABN would be worse than no rule, because it
    /// would block a real MSP from invoicing.
    #[test]
    fn an_invoice_identity_is_writable() {
        assert!(patch(json!({ "legal_name": "Acme IT Services Pty Ltd" })).is_ok());
        assert!(patch(json!({ "tax_id": "GB123456789" })).is_ok());
        assert!(patch(json!({ "tax_id": "ABN 12 345 678 901" })).is_ok());
        assert!(patch(json!({ "tax_id": "1234-5678" })).is_ok());
        assert!(patch(json!({ "tax_id": "   " })).is_err());
        assert!(patch(json!({ "tax_id": "x".repeat(MAX_TAX_ID + 1) })).is_err());
        assert!(
            patch(json!({ "legal_name": null })).is_ok(),
            "an MSP trading under its own name clears it"
        );
    }

    /// The one branding value that is several lines, because an address is.
    #[test]
    fn a_postal_address_is_the_one_multi_line_value() {
        assert!(patch(json!({ "postal_address": "12 Example St\nSydney NSW 2000" })).is_ok());
        assert!(
            patch(json!({ "postal_address": "12 Example St\r\nSydney NSW 2000" })).is_ok(),
            "a paste from Windows must not be refused for its line endings"
        );
        assert!(
            patch(json!({ "postal_address": "a\nb\nc\nd\ne\nf\ng" })).is_err(),
            "an address block is bounded by lines as well as characters"
        );
        assert!(
            patch(json!({ "postal_address": "12 Example St\tSydney" })).is_err(),
            "every control character except the newline is still refused"
        );
        assert!(patch(json!({ "postal_address": "x".repeat(MAX_ADDRESS + 1) })).is_err());
        assert!(
            patch(json!({ "support_contact_name": "Dana\nX" })).is_err(),
            "and no other key gained a newline"
        );
    }

    /// PMS-1006: exactly three keys, and a refusal that names them, because a
    /// typo would otherwise silently leave every document on Classic.
    #[test]
    fn an_invoice_template_is_one_of_three_keys() {
        for key in crate::pdf::Template::KEYS {
            assert!(
                patch(json!({ "invoice_template": key })).is_ok(),
                "`{key}` must be settable"
            );
        }
        let err = validate_branding_value("invoice_template", &json!("fancy")).unwrap_err();
        for key in crate::pdf::Template::KEYS {
            assert!(err.contains(key), "the message must name `{key}`: {err}");
        }
        assert!(patch(json!({ "invoice_template": "Modern" })).is_err());
        assert!(patch(json!({ "invoice_template": 1 })).is_err());
        assert!(
            patch(json!({ "invoice_template": null })).is_ok(),
            "an explicit null clears the choice back to Classic"
        );
    }

    #[test]
    fn a_portal_domain_is_a_bare_hostname() {
        assert!(patch(json!({ "portal_domain": "portal.acme.example" })).is_ok());
        assert!(patch(json!({ "portal_domain": "https://portal.acme.example/x" })).is_err());
        assert!(patch(json!({ "portal_domain": "localhost" })).is_err());
    }

    #[test]
    fn the_patch_itself_must_be_an_object() {
        assert!(validate_branding_patch(&json!("not-an-object")).is_err());
        assert!(validate_branding_patch(&json!([])).is_err());
        assert!(validate_branding_patch(&json!({})).is_ok());
    }
}
