//! Contact management models

// These model enums expose `from_str(&str) -> Option<Self>` as a deliberate
// infallible-style parser API; they intentionally do not implement
// `std::str::FromStr` (which requires a `Result`).
#![allow(clippy::should_implement_trait)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::{Validate, ValidationError};

// ============================================================================
// REQUEST-LAYER VALIDATORS (PMS-297)
// ============================================================================
//
// Bad input that passes the application layer used to reach Postgres, fail
// there, and surface as HTTP 500 `DATABASE_ERROR`. Reject it at the
// request-model layer so it never reaches the DB and returns a 422 instead.

/// Reject strings containing a NUL byte (U+0000). Postgres `text`/`varchar`
/// columns cannot store NUL: such input fails at the DB layer and surfaces as
/// a 500. Reject it here as a field validation error (422) instead.
fn validate_text_no_nul(value: &str) -> Result<(), ValidationError> {
    if value.contains('\0') {
        Err(ValidationError::new("nul_byte"))
    } else {
        Ok(())
    }
}

/// Reject NUL bytes in any element of a string collection (e.g. `tags`).
fn validate_strings_no_nul(values: &[String]) -> Result<(), ValidationError> {
    if values.iter().any(|v| v.contains('\0')) {
        Err(ValidationError::new("nul_byte"))
    } else {
        Ok(())
    }
}

/// Validate a company name: not whitespace-only and free of control
/// characters (which includes NUL). Length bounds stay on the `length`
/// validator. A bare `" "` passes `length(min = 1)` but is not a real name.
fn validate_company_name(value: &str) -> Result<(), ValidationError> {
    if value.trim().is_empty() {
        return Err(ValidationError::new("blank"));
    }
    if value.chars().any(|c| c.is_control()) {
        return Err(ValidationError::new("control_chars"));
    }
    Ok(())
}

/// Validate a freeform company name (PMS-402). Applied to the inner value of
/// an `Option<String>` field (validator skips it when the field is `None`). An
/// empty string is accepted: on the update path `Some("")` means "clear the
/// stored freeform name". Any other value must satisfy the same not-blank /
/// no-control-character rules as a CRM company name.
fn validate_company_name_opt(value: &str) -> Result<(), ValidationError> {
    if value.is_empty() {
        return Ok(());
    }
    validate_company_name(value)
}

/// Reject supplying BOTH a `company_id` and a non-empty freeform
/// `company_name` at once (PMS-402). The two are mutually exclusive: a contact
/// either links to a CRM company or carries a typed-in label, never both. An
/// empty `company_name` string counts as "not supplied" here.
fn validate_company_link_exclusive(
    company_id: Option<Uuid>,
    company_name: &Option<String>,
) -> Result<(), ValidationError> {
    let has_freeform = company_name.as_deref().is_some_and(|s| !s.is_empty());
    if company_id.is_some() && has_freeform {
        return Err(ValidationError::new("company_id_and_name_both_set"));
    }
    Ok(())
}

/// Struct-level guard for `CreateContactRequest` (PMS-402): a contact may link
/// a CRM `company_id` OR carry a freeform `company_name`, never both.
fn validate_create_company_link(req: &CreateContactRequest) -> Result<(), ValidationError> {
    validate_company_link_exclusive(req.company_id, &req.company_name)
}

/// Struct-level guard for `UpdateContactRequest` (PMS-402): same mutual
/// exclusion as create. Setting a `company_id` while also passing a non-empty
/// `company_name` in the same request is rejected.
fn validate_update_company_link(req: &UpdateContactRequest) -> Result<(), ValidationError> {
    validate_company_link_exclusive(req.company_id, &req.company_name)
}

/// Validate a website as an http(s) URL. An empty string is treated as "no
/// value" and accepted; any other value must use an `http`/`https` scheme and
/// carry a host. The scheme allowlist blocks `javascript:`/`data:` URLs that
/// would otherwise drive stored XSS in the SPA (MAPPS-149).
fn validate_website(value: &str) -> Result<(), ValidationError> {
    if value.is_empty() {
        return Ok(());
    }
    let lower = value.to_ascii_lowercase();
    let host = lower
        .strip_prefix("https://")
        .or_else(|| lower.strip_prefix("http://"));
    match host {
        Some(rest) if !rest.is_empty() && !rest.starts_with('/') => Ok(()),
        _ => {
            // Carry an explicit message so the field surfaces inline like the
            // phone field does (PMS-351), instead of a bare error code. The SPA
            // prefixes the field label, yielding "Website must be a valid URL ...".
            let mut error = ValidationError::new("invalid_url");
            error.message = Some("must be a valid URL (e.g. https://example.com)".into());
            Err(error)
        }
    }
}

/// Normalize a phone number for storage (PMS-325): keep a single leading `+`
/// and drop common formatting characters (spaces, dashes, parentheses, dots),
/// so `+1 (415) 555-1234` becomes `+14155551234`. Returns the digits-only
/// (optionally `+`-prefixed) form; validation of the result is left to
/// [`validate_phone_e164`].
fn normalize_phone(raw: &str) -> String {
    // Strip only common formatting characters, NOT arbitrary non-digits: a value
    // like "not-a-phone" must survive normalization (minus its dashes) so the
    // E.164 check can reject it, rather than collapsing to empty and being
    // silently treated as "no phone".
    raw.chars()
        .filter(|c| !matches!(c, ' ' | '\t' | '\u{00A0}' | '-' | '(' | ')' | '.'))
        .collect()
}

/// Deserialize an optional phone field, normalizing formatting and mapping a
/// blank value to `None` (PMS-325). Pairs with `#[validate(custom = ...)]` on
/// the same field so the stored value is clean and E.164-valid.
fn de_phone_opt<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = Option::<String>::deserialize(deserializer)?;
    Ok(raw.map(|s| normalize_phone(&s)).filter(|s| !s.is_empty()))
}

/// Validate a (normalized) phone number against E.164: an optional leading `+`
/// followed by 1-15 digits, the first of which is 1-9. An empty string is
/// treated as "no value" and accepted (the deserializer maps blanks to `None`,
/// but a required `String` field may still pass `""`). Turns the
/// previously-unvalidated phone path into a clear 422 instead of a downstream
/// failure.
fn validate_phone_e164(value: &str) -> Result<(), ValidationError> {
    if value.is_empty() {
        return Ok(());
    }
    let digits = value.strip_prefix('+').unwrap_or(value);
    let valid = (2..=15).contains(&digits.len())
        && digits.bytes().all(|b| b.is_ascii_digit())
        && digits
            .as_bytes()
            .first()
            .is_some_and(|&b| (b'1'..=b'9').contains(&b));
    if valid {
        Ok(())
    } else {
        let mut error = ValidationError::new("invalid_phone");
        error.message = Some("must be a valid phone number (E.164, e.g. +14155551234)".into());
        Err(error)
    }
}

/// Validate an IANA time zone name (PMS-325) using the tz database. Rejects
/// values such as `America/New York` (a space instead of an underscore) that
/// would otherwise be stored and later fail to resolve to an offset. Empty is
/// accepted as "no value".
fn validate_timezone(value: &str) -> Result<(), ValidationError> {
    if value.is_empty() {
        return Ok(());
    }
    if value.parse::<chrono_tz::Tz>().is_ok() {
        Ok(())
    } else {
        let mut error = ValidationError::new("invalid_timezone");
        error.message = Some("must be a valid IANA time zone (e.g. America/New_York)".into());
        Err(error)
    }
}

/// Validate an ISO 3166-1 alpha-2 country code (PMS-325): exactly two ASCII
/// letters present in the official set. Empty is accepted as "no value".
fn validate_country(value: &str) -> Result<(), ValidationError> {
    if value.is_empty() {
        return Ok(());
    }
    let upper = value.to_ascii_uppercase();
    if ISO_3166_1_ALPHA2.contains(&upper.as_str()) {
        Ok(())
    } else {
        let mut error = ValidationError::new("invalid_country");
        error.message = Some("must be a 2-letter ISO 3166-1 country code (e.g. US)".into());
        Err(error)
    }
}

/// Validate a postal code (PMS-325) with a permissive, country-agnostic rule:
/// 2-12 characters of letters, digits, spaces, or hyphens. Empty is accepted.
fn validate_postal_code(value: &str) -> Result<(), ValidationError> {
    if value.is_empty() {
        return Ok(());
    }
    let len_ok = (2..=12).contains(&value.chars().count());
    let charset_ok = value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == ' ' || c == '-');
    if len_ok && charset_ok {
        Ok(())
    } else {
        let mut error = ValidationError::new("invalid_postal_code");
        error.message = Some("must be 2-12 letters, digits, spaces, or hyphens".into());
        Err(error)
    }
}

/// ISO 3166-1 alpha-2 country codes (officially assigned). Used by
/// [`validate_country`]; kept as a static set so an unknown code is rejected
/// with a 422 rather than stored as free text.
const ISO_3166_1_ALPHA2: [&str; 249] = [
    "AD", "AE", "AF", "AG", "AI", "AL", "AM", "AO", "AQ", "AR", "AS", "AT", "AU", "AW", "AX", "AZ",
    "BA", "BB", "BD", "BE", "BF", "BG", "BH", "BI", "BJ", "BL", "BM", "BN", "BO", "BQ", "BR", "BS",
    "BT", "BV", "BW", "BY", "BZ", "CA", "CC", "CD", "CF", "CG", "CH", "CI", "CK", "CL", "CM", "CN",
    "CO", "CR", "CU", "CV", "CW", "CX", "CY", "CZ", "DE", "DJ", "DK", "DM", "DO", "DZ", "EC", "EE",
    "EG", "EH", "ER", "ES", "ET", "FI", "FJ", "FK", "FM", "FO", "FR", "GA", "GB", "GD", "GE", "GF",
    "GG", "GH", "GI", "GL", "GM", "GN", "GP", "GQ", "GR", "GS", "GT", "GU", "GW", "GY", "HK", "HM",
    "HN", "HR", "HT", "HU", "ID", "IE", "IL", "IM", "IN", "IO", "IQ", "IR", "IS", "IT", "JE", "JM",
    "JO", "JP", "KE", "KG", "KH", "KI", "KM", "KN", "KP", "KR", "KW", "KY", "KZ", "LA", "LB", "LC",
    "LI", "LK", "LR", "LS", "LT", "LU", "LV", "LY", "MA", "MC", "MD", "ME", "MF", "MG", "MH", "MK",
    "ML", "MM", "MN", "MO", "MP", "MQ", "MR", "MS", "MT", "MU", "MV", "MW", "MX", "MY", "MZ", "NA",
    "NC", "NE", "NF", "NG", "NI", "NL", "NO", "NP", "NR", "NU", "NZ", "OM", "PA", "PE", "PF", "PG",
    "PH", "PK", "PL", "PM", "PN", "PR", "PS", "PT", "PW", "PY", "QA", "RE", "RO", "RS", "RU", "RW",
    "SA", "SB", "SC", "SD", "SE", "SG", "SH", "SI", "SJ", "SK", "SL", "SM", "SN", "SO", "SR", "SS",
    "ST", "SV", "SX", "SY", "SZ", "TC", "TD", "TF", "TG", "TH", "TJ", "TK", "TL", "TM", "TN", "TO",
    "TR", "TT", "TV", "TW", "TZ", "UA", "UG", "UM", "US", "UY", "UZ", "VA", "VC", "VE", "VG", "VI",
    "VN", "VU", "WF", "WS", "YE", "YT", "ZA", "ZM", "ZW",
];

// ============================================================================
// COMPANY TYPES
// ============================================================================

/// Company type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CompanyType {
    #[default]
    Client,
    Prospect,
    Vendor,
    Partner,
    /// The tenant's own company (PMS-413). Auto-created on tenant
    /// provisioning and pointed at by `tenants.own_company_id`. Used to
    /// attribute general / overhead time entries that have no customer.
    /// Excluded from the default customer-facing company list.
    Internal,
}

impl CompanyType {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "client" => Some(Self::Client),
            "prospect" => Some(Self::Prospect),
            "vendor" => Some(Self::Vendor),
            "partner" => Some(Self::Partner),
            "internal" => Some(Self::Internal),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Prospect => "prospect",
            Self::Vendor => "vendor",
            Self::Partner => "partner",
            Self::Internal => "internal",
        }
    }
}

/// Company status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CompanyStatus {
    #[default]
    Active,
    Inactive,
    Prospect,
}

impl CompanyStatus {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "active" => Some(Self::Active),
            "inactive" => Some(Self::Inactive),
            "prospect" => Some(Self::Prospect),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Inactive => "inactive",
            Self::Prospect => "prospect",
        }
    }
}

/// Address structure
#[derive(Debug, Clone, Serialize, Deserialize, Default, Validate)]
pub struct Address {
    #[validate(custom(function = "validate_text_no_nul"))]
    pub line1: Option<String>,
    #[validate(custom(function = "validate_text_no_nul"))]
    pub line2: Option<String>,
    #[validate(custom(function = "validate_text_no_nul"))]
    pub city: Option<String>,
    #[validate(custom(function = "validate_text_no_nul"))]
    pub state: Option<String>,
    #[validate(custom(function = "validate_postal_code"))]
    pub postal_code: Option<String>,
    #[validate(custom(function = "validate_country"))]
    pub country: Option<String>,
}

impl Address {
    pub fn is_empty(&self) -> bool {
        self.line1.is_none()
            && self.line2.is_none()
            && self.city.is_none()
            && self.state.is_none()
            && self.postal_code.is_none()
            && self.country.is_none()
    }

    pub fn formatted(&self) -> String {
        let mut parts = Vec::new();
        if let Some(ref line1) = self.line1 {
            parts.push(line1.clone());
        }
        if let Some(ref line2) = self.line2 {
            parts.push(line2.clone());
        }
        let mut city_state = Vec::new();
        if let Some(ref city) = self.city {
            city_state.push(city.clone());
        }
        if let Some(ref state) = self.state {
            city_state.push(state.clone());
        }
        if let Some(ref postal) = self.postal_code {
            city_state.push(postal.clone());
        }
        if !city_state.is_empty() {
            parts.push(city_state.join(", "));
        }
        if let Some(ref country) = self.country {
            parts.push(country.clone());
        }
        parts.join("\n")
    }
}

/// Company database model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Company {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub parent_company_id: Option<Uuid>,
    pub company_type: CompanyType,
    pub status: CompanyStatus,
    pub industry: Option<String>,
    pub website: Option<String>,
    pub phone: Option<String>,
    pub fax: Option<String>,
    pub address: Address,
    pub billing_address: Address,
    pub tax_id: Option<String>,
    pub account_number: Option<String>,
    pub default_billing_contact_id: Option<Uuid>,
    pub default_technical_contact_id: Option<Uuid>,
    pub account_manager_id: Option<Uuid>,
    pub sla_id: Option<Uuid>,
    pub default_contract_id: Option<Uuid>,
    pub payment_terms: Option<String>,
    pub tax_exempt: bool,
    pub custom_fields: serde_json::Value,
    pub tags: Vec<String>,
    pub notes: Option<String>,
    pub logo_url: Option<String>,
    pub portal_enabled: bool,
    /// MAPPS-635 B: the 9-digit numeric Portal ID (`companies.portal_id`,
    /// MAPPS-589 / PMS-928) if one has been assigned. `None` until a
    /// portal-access grant lands.
    pub portal_id: Option<i64>,
    /// MAPPS-635 B: the legacy 16-char Crockford portal slug. Kept
    /// during the Portal-ID transition (see prompt 011). `None` until
    /// a grant assigns one.
    pub portal_slug: Option<String>,
    /// MAPPS-617: per-Company branding overrides. See
    /// [`crate::tenants::TenantBranding`] and
    /// [`crate::tenants::EffectiveBranding`]: the resolver merges the
    /// tenant's brand with these overrides field-by-field, Company keys
    /// winning where set. Empty on rows created before the branding
    /// feature landed (migration ships `NOT NULL DEFAULT '{}'`).
    #[serde(default)]
    pub branding: CompanyBranding,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Per-Company branding overrides. Same field shape as
/// [`crate::tenants::TenantBranding`] so the two merge cleanly through
/// [`crate::tenants::EffectiveBranding`]; every non-`None` field on the
/// Company wins over the tenant default. Missing on both sides stays
/// `None`; the SPA supplies the coded fallback.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct CompanyBranding {
    pub logo_url: Option<String>,
    pub logo_mime: Option<String>,
    pub favicon_url: Option<String>,
    pub favicon_mime: Option<String>,
    pub primary_color: Option<String>,
    pub secondary_color: Option<String>,
    pub background_color: Option<String>,
    pub background_url: Option<String>,
    pub background_mime: Option<String>,
    pub display_name: Option<String>,
    pub company_name: Option<String>,
    pub support_email: Option<String>,
    pub support_phone: Option<String>,
    pub support_contact_name: Option<String>,
    pub portal_domain: Option<String>,
}

/// Create company request
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreateCompanyRequest {
    #[validate(length(min = 1, max = 255), custom(function = "validate_company_name"))]
    pub name: String,
    pub parent_company_id: Option<Uuid>,
    #[serde(default)]
    pub company_type: CompanyType,
    #[serde(default)]
    pub status: CompanyStatus,
    #[validate(custom(function = "validate_text_no_nul"))]
    pub industry: Option<String>,
    #[validate(length(max = 255), custom(function = "validate_website"))]
    pub website: Option<String>,
    #[serde(default, deserialize_with = "de_phone_opt")]
    #[validate(custom(function = "validate_phone_e164"))]
    pub phone: Option<String>,
    #[serde(default, deserialize_with = "de_phone_opt")]
    #[validate(custom(function = "validate_phone_e164"))]
    pub fax: Option<String>,
    #[validate(nested)]
    pub address: Option<Address>,
    #[validate(nested)]
    pub billing_address: Option<Address>,
    #[validate(custom(function = "validate_text_no_nul"))]
    pub tax_id: Option<String>,
    #[validate(custom(function = "validate_text_no_nul"))]
    pub account_number: Option<String>,
    pub account_manager_id: Option<Uuid>,
    pub sla_id: Option<Uuid>,
    #[validate(custom(function = "validate_text_no_nul"))]
    pub payment_terms: Option<String>,
    #[serde(default)]
    pub tax_exempt: bool,
    #[serde(default)]
    pub custom_fields: serde_json::Value,
    #[serde(default)]
    #[validate(custom(function = "validate_strings_no_nul"))]
    pub tags: Vec<String>,
    #[validate(custom(function = "validate_text_no_nul"))]
    pub notes: Option<String>,
    #[serde(default = "crate::default_true")]
    pub portal_enabled: bool,
}

/// Update company request
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpdateCompanyRequest {
    #[validate(length(min = 1, max = 255), custom(function = "validate_company_name"))]
    pub name: Option<String>,
    pub parent_company_id: Option<Uuid>,
    pub company_type: Option<CompanyType>,
    pub status: Option<CompanyStatus>,
    #[validate(custom(function = "validate_text_no_nul"))]
    pub industry: Option<String>,
    #[validate(length(max = 255), custom(function = "validate_website"))]
    pub website: Option<String>,
    #[serde(default, deserialize_with = "de_phone_opt")]
    #[validate(custom(function = "validate_phone_e164"))]
    pub phone: Option<String>,
    #[serde(default, deserialize_with = "de_phone_opt")]
    #[validate(custom(function = "validate_phone_e164"))]
    pub fax: Option<String>,
    #[validate(nested)]
    pub address: Option<Address>,
    #[validate(nested)]
    pub billing_address: Option<Address>,
    #[validate(custom(function = "validate_text_no_nul"))]
    pub tax_id: Option<String>,
    #[validate(custom(function = "validate_text_no_nul"))]
    pub account_number: Option<String>,
    pub default_billing_contact_id: Option<Uuid>,
    pub default_technical_contact_id: Option<Uuid>,
    pub account_manager_id: Option<Uuid>,
    pub sla_id: Option<Uuid>,
    pub default_contract_id: Option<Uuid>,
    #[validate(custom(function = "validate_text_no_nul"))]
    pub payment_terms: Option<String>,
    pub tax_exempt: Option<bool>,
    pub custom_fields: Option<serde_json::Value>,
    #[validate(custom(function = "validate_strings_no_nul"))]
    pub tags: Option<Vec<String>>,
    #[validate(custom(function = "validate_text_no_nul"))]
    pub notes: Option<String>,
    pub portal_enabled: Option<bool>,
    /// MAPPS-618: per-Company branding overrides. Same wire shape as
    /// `UpdateTenantRequest.branding` (PMS-758): a JSONB object of the
    /// subset the caller owns. `None` leaves the row's branding
    /// untouched; a present object is JSONB-merged into the existing
    /// row via `||`, so a caller clears a specific key by sending it
    /// as an explicit `null` and leaves other keys alone by omitting
    /// them. Type-checked at the read side by
    /// [`CompanyBranding`]'s serde derives.
    pub branding: Option<serde_json::Value>,
}

/// Company response for API
#[derive(Debug, Clone, Serialize)]
pub struct CompanyResponse {
    pub id: Uuid,
    pub name: String,
    pub parent_company_id: Option<Uuid>,
    pub company_type: CompanyType,
    pub status: CompanyStatus,
    pub industry: Option<String>,
    pub website: Option<String>,
    pub phone: Option<String>,
    pub address: Address,
    pub account_manager_id: Option<Uuid>,
    pub account_manager_name: Option<String>,
    pub sla_id: Option<Uuid>,
    pub default_contract_id: Option<Uuid>,
    pub contact_count: Option<i64>,
    pub site_count: Option<i64>,
    pub open_ticket_count: Option<i64>,
    pub tags: Vec<String>,
    pub portal_enabled: bool,
    /// MAPPS-635 B: the Company's 9-digit numeric Portal ID (PMS-928)
    /// and its legacy Crockford slug. Both sit on the `companies` row
    /// but were dropped from this DTO, so staff had no way to look up
    /// a Company's portal URL after the original grant email was
    /// filed away. Surfacing them here lets the Portal Access card
    /// render "Portal ID: X" + a "Copy portal link" affordance in
    /// every state (not only in the response to a fresh grant).
    /// `None` when portal access has never been enabled for the
    /// Company: the CHECK constraint on `portal_id` fires when we
    /// write it and the slug is written from the same code path.
    pub portal_id: Option<i64>,
    pub portal_slug: Option<String>,
    /// MAPPS-618 read-side fix: the per-Company branding overrides
    /// need to round-trip on both GET and the PUT-response so the
    /// SPA's editor initialises with the current values (instead of
    /// re-showing an empty form after every save). Previously the DB
    /// persisted the block but the wire response dropped it,
    /// leaving the editor looking like nothing had saved.
    pub branding: CompanyBranding,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<Company> for CompanyResponse {
    fn from(c: Company) -> Self {
        Self {
            id: c.id,
            name: c.name,
            parent_company_id: c.parent_company_id,
            company_type: c.company_type,
            status: c.status,
            industry: c.industry,
            website: c.website,
            phone: c.phone,
            address: c.address,
            account_manager_id: c.account_manager_id,
            account_manager_name: None,
            sla_id: c.sla_id,
            default_contract_id: c.default_contract_id,
            contact_count: None,
            site_count: None,
            open_ticket_count: None,
            tags: c.tags,
            portal_enabled: c.portal_enabled,
            portal_id: c.portal_id,
            portal_slug: c.portal_slug,
            branding: c.branding,
            created_at: c.created_at,
            updated_at: c.updated_at,
        }
    }
}

/// Company detail response with full information
#[derive(Debug, Clone, Serialize)]
pub struct CompanyDetailResponse {
    #[serde(flatten)]
    pub company: CompanyResponse,
    pub billing_address: Address,
    pub tax_id: Option<String>,
    pub account_number: Option<String>,
    pub default_billing_contact: Option<ContactSummary>,
    pub default_technical_contact: Option<ContactSummary>,
    pub payment_terms: Option<String>,
    pub tax_exempt: bool,
    pub custom_fields: serde_json::Value,
    pub notes: Option<String>,
    pub logo_url: Option<String>,
}

// ============================================================================
// CONTACT TYPES
// ============================================================================

/// Contact type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ContactType {
    Primary,
    Technical,
    Billing,
    #[default]
    Other,
}

impl ContactType {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "primary" => Some(Self::Primary),
            "technical" => Some(Self::Technical),
            "billing" => Some(Self::Billing),
            "other" => Some(Self::Other),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Technical => "technical",
            Self::Billing => "billing",
            Self::Other => "other",
        }
    }
}

/// Preferred contact method
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PreferredContactMethod {
    #[default]
    Email,
    Phone,
    Mobile,
}

/// Contact status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ContactStatus {
    #[default]
    Active,
    Inactive,
}

impl ContactStatus {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "active" => Some(Self::Active),
            "inactive" => Some(Self::Inactive),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ContactStatus::Active => "active",
            ContactStatus::Inactive => "inactive",
        }
    }
}

/// Contact database model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    pub id: Uuid,
    pub tenant_id: Uuid,
    /// Optional link to a CRM `companies` row (PMS-402). `None` when the
    /// contact carries a freeform `company_name` instead, or no company at
    /// all (a bare name plus phone).
    pub company_id: Option<Uuid>,
    /// The contact's company name for display. Holds EITHER the joined CRM
    /// name (when `company_id` is set, resolved via a LEFT JOIN in the read
    /// queries, PMS-334) OR the stored freeform value (when `company_id` is
    /// `None`, PMS-402). Surfaced through `COALESCE(co.name, c.company_name)`
    /// so a single authoritative string reaches every consumer.
    #[serde(default)]
    pub company_name: Option<String>,
    pub first_name: String,
    pub last_name: String,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub mobile: Option<String>,
    pub fax: Option<String>,
    pub title: Option<String>,
    pub department: Option<String>,
    pub contact_type: ContactType,
    pub is_portal_user: bool,
    pub portal_user_id: Option<Uuid>,
    pub preferred_contact_method: PreferredContactMethod,
    pub timezone: String,
    pub locale: String,
    pub custom_fields: serde_json::Value,
    pub tags: Vec<String>,
    pub notes: Option<String>,
    pub avatar_url: Option<String>,
    pub status: ContactStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Contact {
    pub fn full_name(&self) -> String {
        format!("{} {}", self.first_name, self.last_name)
    }
}

/// Create contact request
#[derive(Debug, Clone, Deserialize, Validate)]
#[validate(schema(function = validate_create_company_link))]
pub struct CreateContactRequest {
    /// Optional link to an existing CRM company (PMS-402). Mutually exclusive
    /// with a non-empty `company_name`; supplying both is rejected (422).
    #[serde(default)]
    pub company_id: Option<Uuid>,
    /// Optional freeform company label typed by the user (PMS-402). Used when
    /// the contact's company is not (yet) a CRM `companies` row.
    #[serde(default)]
    #[validate(length(max = 255), custom(function = "validate_company_name_opt"))]
    pub company_name: Option<String>,
    #[validate(length(min = 1, max = 100))]
    pub first_name: String,
    #[validate(length(min = 1, max = 100))]
    pub last_name: String,
    #[validate(email)]
    pub email: Option<String>,
    #[serde(default, deserialize_with = "de_phone_opt")]
    #[validate(custom(function = "validate_phone_e164"))]
    pub phone: Option<String>,
    #[serde(default, deserialize_with = "de_phone_opt")]
    #[validate(custom(function = "validate_phone_e164"))]
    pub mobile: Option<String>,
    #[serde(default, deserialize_with = "de_phone_opt")]
    #[validate(custom(function = "validate_phone_e164"))]
    pub fax: Option<String>,
    pub title: Option<String>,
    pub department: Option<String>,
    #[serde(default)]
    pub contact_type: ContactType,
    #[serde(default)]
    pub preferred_contact_method: PreferredContactMethod,
    #[validate(custom(function = "validate_timezone"))]
    pub timezone: Option<String>,
    #[serde(default)]
    pub custom_fields: serde_json::Value,
    #[serde(default)]
    pub tags: Vec<String>,
    pub notes: Option<String>,
    /// Create portal access for this contact
    #[serde(default)]
    pub create_portal_access: bool,
}

/// Update contact request
#[derive(Debug, Clone, Deserialize, Validate)]
#[validate(schema(function = validate_update_company_link))]
pub struct UpdateContactRequest {
    pub company_id: Option<Uuid>,
    /// Freeform company label (PMS-402). `Some("")` clears the stored
    /// freeform name; a non-empty value sets it. Setting `company_id` in the
    /// same (or any later) request clears the stored freeform name, since the
    /// CRM name then becomes authoritative. `None` leaves it unchanged.
    #[serde(default)]
    #[validate(length(max = 255), custom(function = "validate_company_name_opt"))]
    pub company_name: Option<String>,
    #[validate(length(min = 1, max = 100))]
    pub first_name: Option<String>,
    #[validate(length(min = 1, max = 100))]
    pub last_name: Option<String>,
    #[validate(email)]
    pub email: Option<String>,
    #[serde(default, deserialize_with = "de_phone_opt")]
    #[validate(custom(function = "validate_phone_e164"))]
    pub phone: Option<String>,
    #[serde(default, deserialize_with = "de_phone_opt")]
    #[validate(custom(function = "validate_phone_e164"))]
    pub mobile: Option<String>,
    #[serde(default, deserialize_with = "de_phone_opt")]
    #[validate(custom(function = "validate_phone_e164"))]
    pub fax: Option<String>,
    pub title: Option<String>,
    pub department: Option<String>,
    pub contact_type: Option<ContactType>,
    pub preferred_contact_method: Option<PreferredContactMethod>,
    #[validate(custom(function = "validate_timezone"))]
    pub timezone: Option<String>,
    pub custom_fields: Option<serde_json::Value>,
    pub tags: Option<Vec<String>>,
    pub notes: Option<String>,
    pub status: Option<ContactStatus>,
    /// Grant (or revoke) customer-portal access. Transitioning `false ->
    /// true` mints a single-use setup token and emails the contact a
    /// `/portal/set-password` link (PMS-136). Setting `false` revokes
    /// access (PMS-17 flag transition). `None` leaves the flag untouched.
    pub is_portal_user: Option<bool>,
}

/// Contact summary (for embedding in other responses)
#[derive(Debug, Clone, Serialize)]
pub struct ContactSummary {
    pub id: Uuid,
    pub full_name: String,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub title: Option<String>,
}

impl From<Contact> for ContactSummary {
    fn from(c: Contact) -> Self {
        Self {
            id: c.id,
            full_name: c.full_name(),
            email: c.email,
            phone: c.phone,
            title: c.title,
        }
    }
}

/// Contact response for API
#[derive(Debug, Clone, Serialize)]
pub struct ContactResponse {
    pub id: Uuid,
    /// Optional CRM company link (PMS-402); `None` for a freeform or
    /// company-less contact.
    pub company_id: Option<Uuid>,
    pub company_name: Option<String>,
    pub first_name: String,
    pub last_name: String,
    pub full_name: String,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub mobile: Option<String>,
    pub title: Option<String>,
    pub department: Option<String>,
    pub contact_type: ContactType,
    pub is_portal_user: bool,
    pub preferred_contact_method: PreferredContactMethod,
    pub timezone: String,
    pub tags: Vec<String>,
    pub avatar_url: Option<String>,
    pub status: ContactStatus,
    pub created_at: DateTime<Utc>,
}

impl From<Contact> for ContactResponse {
    fn from(c: Contact) -> Self {
        Self {
            id: c.id,
            company_id: c.company_id,
            company_name: c.company_name.clone(),
            first_name: c.first_name.clone(),
            last_name: c.last_name.clone(),
            full_name: c.full_name(),
            email: c.email,
            phone: c.phone,
            mobile: c.mobile,
            title: c.title,
            department: c.department,
            contact_type: c.contact_type,
            is_portal_user: c.is_portal_user,
            preferred_contact_method: c.preferred_contact_method,
            timezone: c.timezone,
            tags: c.tags,
            avatar_url: c.avatar_url,
            status: c.status,
            created_at: c.created_at,
        }
    }
}

// ============================================================================
// SITE TYPES
// ============================================================================

/// Site database model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Site {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub company_id: Uuid,
    pub name: String,
    pub address: Address,
    pub phone: Option<String>,
    pub is_primary: bool,
    pub timezone: String,
    pub notes: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Create site request
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreateSiteRequest {
    pub company_id: Uuid,
    #[validate(length(min = 1, max = 255))]
    pub name: String,
    #[validate(nested)]
    pub address: Option<Address>,
    #[serde(default, deserialize_with = "de_phone_opt")]
    #[validate(custom(function = "validate_phone_e164"))]
    pub phone: Option<String>,
    #[serde(default)]
    pub is_primary: bool,
    #[validate(custom(function = "validate_timezone"))]
    pub timezone: Option<String>,
    pub notes: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
}

/// Update site request
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpdateSiteRequest {
    #[validate(length(min = 1, max = 255))]
    pub name: Option<String>,
    #[validate(nested)]
    pub address: Option<Address>,
    #[serde(default, deserialize_with = "de_phone_opt")]
    #[validate(custom(function = "validate_phone_e164"))]
    pub phone: Option<String>,
    pub is_primary: Option<bool>,
    #[validate(custom(function = "validate_timezone"))]
    pub timezone: Option<String>,
    pub notes: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
}

/// Site response for API
#[derive(Debug, Clone, Serialize)]
pub struct SiteResponse {
    pub id: Uuid,
    pub company_id: Uuid,
    pub company_name: Option<String>,
    pub name: String,
    pub address: Address,
    pub phone: Option<String>,
    pub is_primary: bool,
    pub timezone: String,
    pub created_at: DateTime<Utc>,
}

impl From<Site> for SiteResponse {
    fn from(s: Site) -> Self {
        Self {
            id: s.id,
            company_id: s.company_id,
            company_name: None,
            name: s.name,
            address: s.address,
            phone: s.phone,
            is_primary: s.is_primary,
            timezone: s.timezone,
            created_at: s.created_at,
        }
    }
}

// ============================================================================
// FILTER TYPES
// ============================================================================

/// Company filter parameters
#[derive(Debug, Clone, Deserialize, Default, validator::Validate)]
pub struct CompanyFilter {
    #[validate(length(max = 200))]
    pub q: Option<String>,
    pub company_type: Option<CompanyType>,
    pub status: Option<CompanyStatus>,
    pub account_manager_id: Option<Uuid>,
    #[validate(length(max = 500))]
    pub tags: Option<String>,
}

/// Contact filter parameters
#[derive(Debug, Clone, Deserialize, Default, validator::Validate)]
pub struct ContactFilter {
    #[validate(length(max = 200))]
    pub q: Option<String>,
    pub company_id: Option<Uuid>,
    pub contact_type: Option<ContactType>,
    pub status: Option<ContactStatus>,
    pub is_portal_user: Option<bool>,
    #[validate(length(max = 500))]
    pub tags: Option<String>,
}

/// PMS-583: which free-text contact field to pull distinct values for.
/// A closed enum so the column name interpolated into the suggestion query
/// is never user-controlled (the `q` term is always bound, never formatted).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContactSuggestField {
    Title,
    Department,
}

impl ContactSuggestField {
    /// The whitelisted column this field maps to. Safe to interpolate.
    pub fn column(&self) -> &'static str {
        match self {
            Self::Title => "title",
            Self::Department => "department",
        }
    }
}

/// PMS-583: query for `GET /contacts/field-values`. Returns the tenant's
/// existing distinct values of `field` for the free-text autocomplete on the
/// contact form (Title / Department). `q` is an optional substring filter.
#[derive(Debug, Clone, Deserialize, validator::Validate)]
pub struct ContactFieldValuesQuery {
    pub field: ContactSuggestField,
    #[validate(length(max = 100))]
    pub q: Option<String>,
}

/// PMS-601: a row in the tenant-scoped company-industry lookup that backs the
/// company Industry combobox's suggestions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompanyIndustryResponse {
    pub id: Uuid,
    pub name: String,
    pub is_active: bool,
}

/// PMS-601: create/update payload for a company-industry lookup row. One DTO
/// for both, matching the asset-types `Upsert*` convention.
#[derive(Debug, Clone, Deserialize, validator::Validate)]
pub struct UpsertCompanyIndustryRequest {
    #[validate(length(min = 1, max = 100))]
    pub name: String,
    #[serde(default = "crate::default_true")]
    pub is_active: bool,
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// PMS-583: the suggestion field enum maps only to whitelisted columns and
    /// deserializes from the snake_case query value. This is the SQL-injection
    /// guard for the `field-values` endpoint (the column is interpolated, so it
    /// must never be user-controlled beyond these two variants).
    #[test]
    fn suggest_field_deserializes_and_maps_to_whitelisted_column() {
        let title: ContactSuggestField =
            serde_json::from_value(serde_json::json!("title")).unwrap();
        let dept: ContactSuggestField =
            serde_json::from_value(serde_json::json!("department")).unwrap();
        assert_eq!(title.column(), "title");
        assert_eq!(dept.column(), "department");
        // Anything outside the closed set is rejected at deserialization.
        assert!(serde_json::from_value::<ContactSuggestField>(serde_json::json!("email")).is_err());
        assert!(
            serde_json::from_value::<ContactSuggestField>(serde_json::json!("name; DROP TABLE"))
                .is_err()
        );
    }

    /// Build a minimal valid `CreateCompanyRequest` from JSON, merging in the
    /// supplied overrides so each test only states the field it exercises.
    fn create_req(overrides: serde_json::Value) -> CreateCompanyRequest {
        let mut body = serde_json::json!({ "name": "Acme Corp" });
        if let serde_json::Value::Object(extra) = overrides {
            for (k, v) in extra {
                body[k] = v;
            }
        }
        serde_json::from_value(body).expect("request deserializes")
    }

    #[test]
    fn minimal_request_is_valid() {
        assert!(create_req(serde_json::json!({})).validate().is_ok());
    }

    #[test]
    fn overlong_website_rejected() {
        let req = create_req(serde_json::json!({ "website": "h".repeat(5000) }));
        assert!(req.validate().is_err());
    }

    #[test]
    fn nul_byte_in_name_rejected() {
        let req = create_req(serde_json::json!({ "name": "Ac\u{0}me" }));
        assert!(req.validate().is_err());
    }

    #[test]
    fn control_chars_in_name_rejected() {
        let req = create_req(serde_json::json!({ "name": "Acme\u{1}\u{2}" }));
        assert!(req.validate().is_err());
    }

    #[test]
    fn whitespace_only_name_rejected() {
        let req = create_req(serde_json::json!({ "name": "   " }));
        assert!(req.validate().is_err());
    }

    #[test]
    fn nul_byte_in_other_text_field_rejected() {
        let req = create_req(serde_json::json!({ "industry": "Tech\u{0}" }));
        assert!(req.validate().is_err());
    }

    #[test]
    fn nul_byte_in_nested_address_rejected() {
        let req = create_req(serde_json::json!({ "address": { "city": "Town\u{0}" } }));
        assert!(req.validate().is_err());
    }

    #[test]
    fn nul_byte_in_tag_rejected() {
        let req = create_req(serde_json::json!({ "tags": ["good", "bad\u{0}"] }));
        assert!(req.validate().is_err());
    }

    #[test]
    fn javascript_scheme_website_rejected() {
        let req = create_req(serde_json::json!({ "website": "javascript:alert(1)" }));
        assert!(req.validate().is_err());
    }

    #[test]
    fn data_scheme_website_rejected() {
        let req = create_req(serde_json::json!({ "website": "data:text/html,<script>" }));
        assert!(req.validate().is_err());
    }

    #[test]
    fn non_url_website_rejected() {
        let req = create_req(serde_json::json!({ "website": "not a url" }));
        assert!(req.validate().is_err());
    }

    // PMS-351 acceptance criteria: the exact strings the external reviewer
    // entered on the New Company form must be rejected, and a scheme-bearing
    // https URL accepted.
    #[test]
    fn website_acceptance_cases() {
        for bad in ["not-a-valid-url", "example.com", "ftp://example.com"] {
            assert!(
                create_req(serde_json::json!({ "website": bad }))
                    .validate()
                    .is_err(),
                "{bad} should be rejected"
            );
        }
        assert!(
            create_req(serde_json::json!({ "website": "https://example.com" }))
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn http_and_https_websites_accepted() {
        assert!(
            create_req(serde_json::json!({ "website": "http://example.com" }))
                .validate()
                .is_ok()
        );
        assert!(
            create_req(serde_json::json!({ "website": "https://example.com/about" }))
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn empty_website_accepted() {
        let req = create_req(serde_json::json!({ "website": "" }));
        assert!(req.validate().is_ok());
    }

    #[test]
    fn update_request_applies_same_validation() {
        let req: UpdateCompanyRequest =
            serde_json::from_value(serde_json::json!({ "website": "javascript:alert(1)" }))
                .expect("request deserializes");
        assert!(req.validate().is_err());
    }

    // ---- PMS-325: phone / timezone / country / postal validation ----

    /// Build a minimal valid `CreateContactRequest`, merging overrides.
    fn contact_req(overrides: serde_json::Value) -> CreateContactRequest {
        let mut body = serde_json::json!({
            "company_id": "00000000-0000-0000-0000-000000000000",
            "first_name": "Ada",
            "last_name": "Lovelace",
        });
        if let serde_json::Value::Object(extra) = overrides {
            for (k, v) in extra {
                body[k] = v;
            }
        }
        serde_json::from_value(body).expect("contact request deserializes")
    }

    #[test]
    fn phone_normalized_and_e164_validated() {
        // Formatted input is normalized and accepted.
        let req = contact_req(serde_json::json!({ "phone": "+1 (415) 555-1234" }));
        assert!(req.validate().is_ok());
        assert_eq!(req.phone.as_deref(), Some("+14155551234"));
        // Blank -> None.
        assert_eq!(
            contact_req(serde_json::json!({ "phone": "  " })).phone,
            None
        );
        // Letters / nonsense rejected (was previously unvalidated).
        assert!(contact_req(serde_json::json!({ "phone": "not-a-phone" }))
            .validate()
            .is_err());
        // Leading zero is not E.164.
        assert!(contact_req(serde_json::json!({ "mobile": "0412 345 678" }))
            .validate()
            .is_err());
    }

    #[test]
    fn timezone_validated_against_iana() {
        assert!(
            contact_req(serde_json::json!({ "timezone": "America/New_York" }))
                .validate()
                .is_ok()
        );
        // The space variant must be rejected (PMS-325 example).
        assert!(
            contact_req(serde_json::json!({ "timezone": "America/New York" }))
                .validate()
                .is_err()
        );
    }

    #[test]
    fn country_must_be_iso_alpha2() {
        assert!(
            create_req(serde_json::json!({ "address": { "country": "US" } }))
                .validate()
                .is_ok()
        );
        // Lowercase is accepted (normalized to uppercase for the check).
        assert!(
            create_req(serde_json::json!({ "address": { "country": "au" } }))
                .validate()
                .is_ok()
        );
        // Full names / unknown codes rejected.
        assert!(
            create_req(serde_json::json!({ "address": { "country": "United States" } }))
                .validate()
                .is_err()
        );
        assert!(
            create_req(serde_json::json!({ "address": { "country": "ZZ" } }))
                .validate()
                .is_err()
        );
    }

    #[test]
    fn postal_code_permissive_charset_and_length() {
        for ok in ["12345", "90210-1234", "K1A 0B1", "SW1A 1AA"] {
            assert!(
                create_req(serde_json::json!({ "address": { "postal_code": ok } }))
                    .validate()
                    .is_ok(),
                "{ok} should be accepted"
            );
        }
        // Too long, or disallowed characters.
        assert!(
            create_req(serde_json::json!({ "address": { "postal_code": "X".repeat(13) } }))
                .validate()
                .is_err()
        );
        assert!(
            create_req(serde_json::json!({ "address": { "postal_code": "12_34" } }))
                .validate()
                .is_err()
        );
    }

    // ========================================================================
    // PMS-402: freeform company on contacts
    // ========================================================================

    /// Build a `CreateContactRequest` from a body that omits `company_id`,
    /// so freeform / company-less cases can be exercised (the `contact_req`
    /// helper always injects a `company_id`).
    fn contact_req_raw(body: serde_json::Value) -> CreateContactRequest {
        let mut full = serde_json::json!({
            "first_name": "Ada",
            "last_name": "Lovelace",
        });
        if let serde_json::Value::Object(extra) = body {
            for (k, v) in extra {
                full[k] = v;
            }
        }
        serde_json::from_value(full).expect("contact request deserializes")
    }

    #[test]
    fn freeform_company_name_only_is_valid() {
        let req = contact_req_raw(serde_json::json!({ "company_name": "Acme Plumbing" }));
        assert!(req.company_id.is_none());
        assert_eq!(req.company_name.as_deref(), Some("Acme Plumbing"));
        assert!(req.validate().is_ok());
    }

    #[test]
    fn fk_company_id_only_is_valid() {
        let req = contact_req(serde_json::json!({}));
        assert!(req.company_id.is_some());
        assert!(req.company_name.is_none());
        assert!(req.validate().is_ok());
    }

    #[test]
    fn neither_company_id_nor_name_is_valid() {
        let req = contact_req_raw(serde_json::json!({}));
        assert!(req.company_id.is_none());
        assert!(req.company_name.is_none());
        assert!(req.validate().is_ok());
    }

    #[test]
    fn both_company_id_and_name_is_rejected() {
        let req = contact_req(serde_json::json!({ "company_name": "Acme" }));
        assert!(req.company_id.is_some());
        assert_eq!(req.company_name.as_deref(), Some("Acme"));
        assert!(
            req.validate().is_err(),
            "supplying both company_id and a non-empty company_name must be rejected"
        );
    }

    #[test]
    fn company_id_with_empty_name_is_valid() {
        // An empty freeform string counts as "not supplied", so it does not
        // collide with the FK.
        let req = contact_req(serde_json::json!({ "company_name": "" }));
        assert!(req.company_id.is_some());
        assert!(req.validate().is_ok());
    }

    #[test]
    fn blank_freeform_company_name_is_rejected() {
        // A whitespace-only freeform name is not a real name.
        let req = contact_req_raw(serde_json::json!({ "company_name": "   " }));
        assert!(req.validate().is_err());
    }

    #[test]
    fn control_chars_in_freeform_company_name_rejected() {
        let req = contact_req_raw(serde_json::json!({ "company_name": "Acme\u{1}" }));
        assert!(req.validate().is_err());
    }

    #[test]
    fn update_accepts_freeform_company_name() {
        let req: UpdateContactRequest =
            serde_json::from_value(serde_json::json!({ "company_name": "Beta LLC" }))
                .expect("update deserializes");
        assert_eq!(req.company_name.as_deref(), Some("Beta LLC"));
        assert!(req.validate().is_ok());
    }

    #[test]
    fn update_empty_company_name_clears_and_validates() {
        let req: UpdateContactRequest =
            serde_json::from_value(serde_json::json!({ "company_name": "" }))
                .expect("update deserializes");
        assert_eq!(req.company_name.as_deref(), Some(""));
        assert!(req.validate().is_ok());
    }

    #[test]
    fn update_rejects_both_company_id_and_name() {
        let req: UpdateContactRequest = serde_json::from_value(serde_json::json!({
            "company_id": "00000000-0000-0000-0000-000000000000",
            "company_name": "Acme",
        }))
        .expect("update deserializes");
        assert!(req.validate().is_err());
    }
}
