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
        _ => Err(ValidationError::new("invalid_url")),
    }
}

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
}

impl CompanyType {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "client" => Some(Self::Client),
            "prospect" => Some(Self::Prospect),
            "vendor" => Some(Self::Vendor),
            "partner" => Some(Self::Partner),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Prospect => "prospect",
            Self::Vendor => "vendor",
            Self::Partner => "partner",
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
    #[validate(custom(function = "validate_text_no_nul"))]
    pub postal_code: Option<String>,
    #[validate(custom(function = "validate_text_no_nul"))]
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
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
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
    #[validate(custom(function = "validate_text_no_nul"))]
    pub phone: Option<String>,
    #[validate(custom(function = "validate_text_no_nul"))]
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
    #[validate(custom(function = "validate_text_no_nul"))]
    pub phone: Option<String>,
    #[validate(custom(function = "validate_text_no_nul"))]
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
    pub company_id: Uuid,
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
pub struct CreateContactRequest {
    pub company_id: Uuid,
    #[validate(length(min = 1, max = 100))]
    pub first_name: String,
    #[validate(length(min = 1, max = 100))]
    pub last_name: String,
    #[validate(email)]
    pub email: Option<String>,
    pub phone: Option<String>,
    pub mobile: Option<String>,
    pub fax: Option<String>,
    pub title: Option<String>,
    pub department: Option<String>,
    #[serde(default)]
    pub contact_type: ContactType,
    #[serde(default)]
    pub preferred_contact_method: PreferredContactMethod,
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
pub struct UpdateContactRequest {
    pub company_id: Option<Uuid>,
    #[validate(length(min = 1, max = 100))]
    pub first_name: Option<String>,
    #[validate(length(min = 1, max = 100))]
    pub last_name: Option<String>,
    #[validate(email)]
    pub email: Option<String>,
    pub phone: Option<String>,
    pub mobile: Option<String>,
    pub fax: Option<String>,
    pub title: Option<String>,
    pub department: Option<String>,
    pub contact_type: Option<ContactType>,
    pub preferred_contact_method: Option<PreferredContactMethod>,
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
    pub company_id: Uuid,
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
            company_name: None,
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
    pub address: Option<Address>,
    pub phone: Option<String>,
    #[serde(default)]
    pub is_primary: bool,
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
    pub address: Option<Address>,
    pub phone: Option<String>,
    pub is_primary: Option<bool>,
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

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

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
}
