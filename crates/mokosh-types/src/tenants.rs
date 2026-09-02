//! Tenant models and types

// These model enums expose `from_str(&str) -> Option<Self>` as a deliberate
// infallible-style parser API; they intentionally do not implement
// `std::str::FromStr` (which requires a `Result`).
#![allow(clippy::should_implement_trait)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

/// Tenant status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TenantStatus {
    #[default]
    Active,
    Suspended,
    Cancelled,
}

impl TenantStatus {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "active" => Some(Self::Active),
            "suspended" => Some(Self::Suspended),
            "cancelled" => Some(Self::Cancelled),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Cancelled => "cancelled",
        }
    }
}

/// Tenant database model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tenant {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub status: TenantStatus,
    pub settings: serde_json::Value,
    pub branding: TenantBranding,
    pub billing_email: Option<String>,
    pub billing_contact_name: Option<String>,
    pub subscription_plan: Option<String>,
    pub subscription_status: Option<String>,
    pub trial_ends_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Tenant branding configuration.
///
/// The full set of brand-controllable fields for a tenant. Consumed by the
/// contact portal, painted by `AuthLayout` + the CSS-custom-property pipeline
/// on the SPA (MAPPS-621). Per-Company overrides live in
/// [`crate::contacts::CompanyBranding`] with EXACTLY the same shape so
/// [`EffectiveBranding`] can merge the two field-by-field.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct TenantBranding {
    pub logo_url: Option<String>,
    /// MAPPS-429: content type of the stored logo, so the public serving route
    /// can answer with the right `Content-Type` without sniffing the bytes or
    /// encoding the format into the filename.
    pub logo_mime: Option<String>,
    pub favicon_url: Option<String>,
    /// MAPPS-617: mime alongside `favicon_url`, same reason as `logo_mime`.
    pub favicon_mime: Option<String>,
    pub primary_color: Option<String>,
    pub secondary_color: Option<String>,
    /// MAPPS-617: solid-color background for the portal (`#RRGGBB` or
    /// `#RRGGBBAA`). Set alongside `background_url` at most one at a time; the
    /// SPA prefers `background_url` when both are present.
    pub background_color: Option<String>,
    /// MAPPS-617: server-served path to a background image (analogous to
    /// `logo_url`). Uploaded via the multipart route prompt 002 introduces.
    pub background_url: Option<String>,
    pub background_mime: Option<String>,
    /// MAPPS-617: portal wordmark (replaces the hardcoded "Mokosh Platform"
    /// string in `AuthLayout`). Painters prefer this over `company_name`.
    pub display_name: Option<String>,
    pub company_name: Option<String>,
    pub support_email: Option<String>,
    pub support_phone: Option<String>,
    /// MAPPS-429: who a client should ask for, as opposed to
    /// [`Tenant::billing_contact_name`], which is who an invoice goes to. These
    /// are routinely different people, so the billing column is not reused.
    pub support_contact_name: Option<String>,
    /// PMS-896: the organisation's own web address, the one optional field of
    /// the organisation record. Read back by every caller of
    /// `GET /api/v1/tenants/current`, which is the organisation settings page.
    pub website: Option<String>,
    pub portal_domain: Option<String>,
    /// PMS-911: the registered company name, where it differs from the trading
    /// name in [`Self::company_name`]. An invoice is a commercial document and
    /// carries the legal entity; a portal header carries the trading name. When
    /// unset the invoice falls back to `company_name` and then to the tenant's
    /// own name, so an MSP that never fills this in still gets a valid invoice.
    pub legal_name: Option<String>,
    /// PMS-911: a VAT number, ABN, EIN or company registration number, whatever
    /// the MSP's jurisdiction requires an invoice to show. One free-text field
    /// rather than a set of country-specific ones, because nothing here parses
    /// it and a wrong parse would be worse than no parse.
    pub tax_id: Option<String>,
    /// PMS-911: the postal address an invoice is issued from. The one branding
    /// value that is deliberately multi-line, because an address is.
    pub postal_address: Option<String>,
}

/// PMS-896: the organisation record, as the onboarding flow submits it.
///
/// A whole-record submission, NOT a patch: this is the one place that states
/// which organisation fields an account must supply, so an omitted optional
/// field is a cleared field rather than an untouched one. The fields are
/// `Option` so a missing key is refused by name (`phone is required`) instead
/// of by a serde rejection that names no field.
///
/// [`UpdateTenantRequest::branding`] cannot carry these rules: it is a PATCH
/// document shared with the logo upload and the per-key settings writer
/// (PMS-758), and a logo upload sends two keys and must not be refused for
/// carrying no phone number.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OrganizationProfileRequest {
    /// The organisation's name; `tenants.name`. Required.
    pub name: Option<String>,
    /// Who a client should ask for. Optional, and cleared when omitted.
    #[serde(default)]
    pub contact_name: Option<String>,
    /// Contact phone. Required (mirrors the MAPPS-429 onboarding flow).
    #[serde(default)]
    pub phone: Option<String>,
    /// Contact email. Required (mirrors the MAPPS-429 onboarding flow).
    #[serde(default)]
    pub email: Option<String>,
    /// The organisation's website. Optional, and cleared when omitted.
    #[serde(default)]
    pub website: Option<String>,
}

/// The merged brand a caller sees. Field-by-field
/// `company.field.or(tenant.field)` (see
/// [`crate::branding::effective_branding`]), so every non-`None` Company
/// override wins over the tenant default. Missing on both sides stays
/// `None`; the SPA supplies the coded fallback.
///
/// Same shape as [`TenantBranding`] on purpose: the wire boundary is a keys
/// union, not a differently-shaped type.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct EffectiveBranding {
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

/// Create tenant request
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreateTenantRequest {
    #[validate(length(min = 1, max = 255))]
    pub name: String,
    #[validate(length(min = 1, max = 100))]
    pub slug: String,
    #[validate(email)]
    pub billing_email: Option<String>,
    pub billing_contact_name: Option<String>,
    pub subscription_plan: Option<String>,
    /// Initial admin user
    #[validate(email)]
    pub admin_email: String,
    pub admin_first_name: String,
    pub admin_last_name: String,
    /// MAPPS-396: optional branding at creation time so the SPA can
    /// set the logo, primary color, and support email in a single
    /// round-trip rather than a create-then-update pair. When omitted
    /// (`None`) the tenant lands with the empty-object default and the
    /// portal renders the generic wordmark, matching pre-MAPPS-396
    /// behavior.
    #[serde(default)]
    pub branding: Option<TenantBranding>,
}

/// Update tenant request
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpdateTenantRequest {
    #[validate(length(min = 1, max = 255))]
    pub name: Option<String>,
    /// MAPPS-449: renames the tenant's portal subdomain.
    /// [`crate::modules::tenants::TenantService::update_tenant`] runs the
    /// same `slugify()` normalisation `create_tenant` uses and re-checks
    /// uniqueness against every OTHER tenant. Immediate-404 policy on the
    /// old slug: no aliasing, no redirect. Pending contact-portal invites
    /// carrying the old slug in their setup link break loudly; the SPA
    /// surfaces a warning banner so the super-admin knows to re-send them.
    #[validate(length(min = 1, max = 100))]
    pub slug: Option<String>,
    #[validate(email)]
    pub billing_email: Option<String>,
    pub billing_contact_name: Option<String>,
    pub settings: Option<serde_json::Value>,
    /// PMS-758: a PATCH document, not a whole `TenantBranding`.
    ///
    /// `tenants.branding` is written by more than one caller: the organisation
    /// settings page owns the contact keys, the logo upload owns `logo_url` and
    /// `logo_mime`. Typed as the struct, serde filled in every field it was not
    /// given as an explicit null, so saving the settings page deleted the
    /// logo's content type and the public logo route began answering 404.
    ///
    /// As a raw object only the keys a caller actually sent are written, and
    /// the service merges them (`branding || $n`). A key set to null still
    /// clears, which is how a contact field is emptied.
    pub branding: Option<serde_json::Value>,
}

/// MAPPS-450: request body for `PUT /api/v1/tenants/{id}/admin`.
///
/// Every field is optional so the caller sends only what changed; the
/// server rejects an empty PATCH so a stray click cannot audit-write a
/// no-op update. `resend_welcome` piggybacks on the same call so the
/// email-changed common case is a single round-trip; the server ignores
/// it when the admin has already redeemed (status != 'pending').
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpdateTenantAdminRequest {
    #[validate(email)]
    pub email: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    #[serde(default)]
    pub resend_welcome: bool,
}

/// MAPPS-450: view of the tenant's admin `users` row that the tenant
/// management modal renders. Returned from `GET /tenants/{id}/admin` and
/// from the PUT above. `status` is the raw column so the SPA can gate
/// the email-editable UI on `pending` vs `active`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantAdminInfo {
    pub user_id: Uuid,
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    /// Raw `users.status` column value: `pending`, `active`, `suspended`,
    /// etc. Only `pending` allows super-admin email edits and welcome
    /// re-sends.
    pub status: String,
}

/// Tenant response for API
#[derive(Debug, Clone, Serialize)]
pub struct TenantResponse {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub status: TenantStatus,
    pub billing_email: Option<String>,
    pub billing_contact_name: Option<String>,
    pub subscription_plan: Option<String>,
    pub subscription_status: Option<String>,
    pub trial_ends_at: Option<DateTime<Utc>>,
    pub branding: TenantBranding,
    pub created_at: DateTime<Utc>,
}

impl From<Tenant> for TenantResponse {
    fn from(t: Tenant) -> Self {
        Self {
            id: t.id,
            name: t.name,
            slug: t.slug,
            status: t.status,
            billing_email: t.billing_email,
            billing_contact_name: t.billing_contact_name,
            subscription_plan: t.subscription_plan,
            subscription_status: t.subscription_status,
            trial_ends_at: t.trial_ends_at,
            branding: t.branding,
            created_at: t.created_at,
        }
    }
}

/// Tenant usage statistics
#[derive(Debug, Clone, Serialize)]
pub struct TenantUsage {
    pub tenant_id: Uuid,
    pub user_count: i64,
    pub company_count: i64,
    pub contact_count: i64,
    pub ticket_count: i64,
    pub asset_count: i64,
    pub storage_bytes: i64,
}
