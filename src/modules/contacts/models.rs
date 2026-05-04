//! Contact management models

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

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
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Address {
    pub line1: Option<String>,
    pub line2: Option<String>,
    pub city: Option<String>,
    pub state: Option<String>,
    pub postal_code: Option<String>,
    pub country: Option<String>,
}

impl Address {
    pub fn is_empty(&self) -> bool {
        self.line1.is_none()
            && self.line2.is_none()
            && self.city.is_none()
            && self.state.is_none()
            && self.postal_code.is_none()
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
    #[validate(length(min = 1, max = 255))]
    pub name: String,
    pub parent_company_id: Option<Uuid>,
    #[serde(default)]
    pub company_type: CompanyType,
    #[serde(default)]
    pub status: CompanyStatus,
    pub industry: Option<String>,
    pub website: Option<String>,
    pub phone: Option<String>,
    pub fax: Option<String>,
    pub address: Option<Address>,
    pub billing_address: Option<Address>,
    pub tax_id: Option<String>,
    pub account_number: Option<String>,
    pub account_manager_id: Option<Uuid>,
    pub sla_id: Option<Uuid>,
    pub payment_terms: Option<String>,
    #[serde(default)]
    pub tax_exempt: bool,
    #[serde(default)]
    pub custom_fields: serde_json::Value,
    #[serde(default)]
    pub tags: Vec<String>,
    pub notes: Option<String>,
    #[serde(default = "default_true")]
    pub portal_enabled: bool,
}

fn default_true() -> bool {
    true
}

/// Update company request
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpdateCompanyRequest {
    #[validate(length(min = 1, max = 255))]
    pub name: Option<String>,
    pub parent_company_id: Option<Uuid>,
    pub company_type: Option<CompanyType>,
    pub status: Option<CompanyStatus>,
    pub industry: Option<String>,
    pub website: Option<String>,
    pub phone: Option<String>,
    pub fax: Option<String>,
    pub address: Option<Address>,
    pub billing_address: Option<Address>,
    pub tax_id: Option<String>,
    pub account_number: Option<String>,
    pub default_billing_contact_id: Option<Uuid>,
    pub default_technical_contact_id: Option<Uuid>,
    pub account_manager_id: Option<Uuid>,
    pub sla_id: Option<Uuid>,
    pub default_contract_id: Option<Uuid>,
    pub payment_terms: Option<String>,
    pub tax_exempt: Option<bool>,
    pub custom_fields: Option<serde_json::Value>,
    pub tags: Option<Vec<String>>,
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
    pub fn as_str(&self) -> &'static str {
        match self {
            ContactStatus::Active => "active",
            ContactStatus::Inactive => "inactive",
        }
    }
}

impl std::str::FromStr for ContactStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "active" => Ok(ContactStatus::Active),
            "inactive" => Ok(ContactStatus::Inactive),
            _ => Err(format!("Unknown contact status: {}", s)),
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
#[derive(Debug, Clone, Deserialize, Default)]
pub struct CompanyFilter {
    pub q: Option<String>,
    pub company_type: Option<CompanyType>,
    pub status: Option<CompanyStatus>,
    pub account_manager_id: Option<Uuid>,
    pub tags: Option<String>,
}

/// Contact filter parameters
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ContactFilter {
    pub q: Option<String>,
    pub company_id: Option<Uuid>,
    pub contact_type: Option<ContactType>,
    pub status: Option<ContactStatus>,
    pub is_portal_user: Option<bool>,
    pub tags: Option<String>,
}
