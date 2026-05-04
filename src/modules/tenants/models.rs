//! Tenant models and types

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

/// Tenant branding configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TenantBranding {
    pub logo_url: Option<String>,
    pub favicon_url: Option<String>,
    pub primary_color: Option<String>,
    pub secondary_color: Option<String>,
    pub company_name: Option<String>,
    pub support_email: Option<String>,
    pub support_phone: Option<String>,
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
    pub admin_email: String,
    pub admin_first_name: String,
    pub admin_last_name: String,
}

/// Update tenant request
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpdateTenantRequest {
    #[validate(length(min = 1, max = 255))]
    pub name: Option<String>,
    #[validate(email)]
    pub billing_email: Option<String>,
    pub billing_contact_name: Option<String>,
    pub settings: Option<serde_json::Value>,
    pub branding: Option<TenantBranding>,
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

/// Module configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleConfig {
    pub module_name: String,
    pub is_enabled: bool,
    pub config: serde_json::Value,
}
