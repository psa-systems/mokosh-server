//! Assets DTOs.

use chrono::{DateTime, NaiveDate, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Clone, Serialize)]
pub struct AssetTypeResponse {
    pub id: Uuid,
    pub name: String,
    pub icon: Option<String>,
    pub parent_type_id: Option<Uuid>,
    pub is_active: bool,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpsertAssetTypeRequest {
    #[validate(length(min = 1, max = 100))]
    pub name: String,
    pub icon: Option<String>,
    pub parent_type_id: Option<Uuid>,
    #[serde(default = "default_true")]
    pub is_active: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize)]
pub struct AssetResponse {
    pub id: Uuid,
    pub asset_tag: Option<String>,
    pub name: String,
    pub asset_type_id: Uuid,
    pub company_id: Uuid,
    pub site_id: Option<Uuid>,
    pub contact_id: Option<Uuid>,
    pub status: String,
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub serial_number: Option<String>,
    pub purchase_date: Option<NaiveDate>,
    pub purchase_price: Option<Decimal>,
    pub warranty_expiry: Option<NaiveDate>,
    pub end_of_life: Option<NaiveDate>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize, Default, validator::Validate)]
pub struct AssetFilter {
    pub company_id: Option<Uuid>,
    pub asset_type_id: Option<Uuid>,
    #[validate(length(max = 100))]
    pub status: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreateAssetRequest {
    pub asset_tag: Option<String>,
    #[validate(length(min = 1, max = 255))]
    pub name: String,
    pub asset_type_id: Uuid,
    pub company_id: Uuid,
    pub site_id: Option<Uuid>,
    pub contact_id: Option<Uuid>,
    #[serde(default = "default_active")]
    pub status: String,
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub serial_number: Option<String>,
    pub purchase_date: Option<NaiveDate>,
    pub purchase_price: Option<Decimal>,
    pub warranty_expiry: Option<NaiveDate>,
    pub end_of_life: Option<NaiveDate>,
}

fn default_active() -> String {
    "active".into()
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpdateAssetRequest {
    pub asset_tag: Option<String>,
    pub name: Option<String>,
    pub asset_type_id: Option<Uuid>,
    pub site_id: Option<Uuid>,
    pub contact_id: Option<Uuid>,
    pub status: Option<String>,
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub serial_number: Option<String>,
    pub purchase_date: Option<NaiveDate>,
    pub purchase_price: Option<Decimal>,
    pub warranty_expiry: Option<NaiveDate>,
    pub end_of_life: Option<NaiveDate>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AssetRelationshipResponse {
    pub id: Uuid,
    pub parent_asset_id: Uuid,
    pub child_asset_id: Uuid,
    pub relationship_type: String,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreateAssetRelationshipRequest {
    pub child_asset_id: Uuid,
    /// "contains" | "connected_to" | "depends_on" | "hosts"
    pub relationship_type: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConfigurationItemResponse {
    pub id: Uuid,
    pub asset_id: Uuid,
    pub name: String,
    pub category: Option<String>,
    pub value: String, // decrypted
    pub notes: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpsertConfigurationItemRequest {
    #[validate(length(min = 1, max = 100))]
    pub name: String,
    pub category: Option<String>,
    pub value: String,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CredentialResponse {
    pub id: Uuid,
    pub name: String,
    pub company_id: Option<Uuid>,
    pub asset_id: Option<Uuid>,
    pub credential_type: String,
    pub username: String,
    pub password: String,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub last_rotated: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreateCredentialRequest {
    #[validate(length(min = 1, max = 100))]
    pub name: String,
    pub credential_type: String,
    pub username: String,
    pub password: String,
    pub url: Option<String>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AssetAuditLogResponse {
    pub id: Uuid,
    pub asset_id: Uuid,
    pub action: String,
    pub changes: Option<serde_json::Value>,
    pub performed_by_id: Option<Uuid>,
    pub performed_at: DateTime<Utc>,
}
