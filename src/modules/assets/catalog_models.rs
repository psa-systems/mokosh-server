//! PMS-1488 asset catalog DTOs: `asset_models`, `asset_templates`, the
//! bulk-create fanout request, and the signature-detector response.

use chrono::{DateTime, NaiveDate, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

// -- asset_models ---------------------------------------------------------

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct AssetModelResponse {
    pub id: Uuid,
    pub manufacturer: String,
    pub model: String,
    pub asset_type_id: Uuid,
    pub warranty_months: Option<i32>,
    pub end_of_life_months: Option<i32>,
    pub default_department: Option<String>,
    pub default_license_vendor: Option<String>,
    pub default_tags: Vec<String>,
    pub specs: serde_json::Value,
    pub image_url: Option<String>,
    pub source: String,
    pub uses_count: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreateAssetModelRequest {
    #[validate(length(min = 1, max = 100))]
    pub manufacturer: String,
    #[validate(length(min = 1, max = 100))]
    pub model: String,
    pub asset_type_id: Uuid,
    #[validate(range(min = 0, max = 360))]
    pub warranty_months: Option<i32>,
    #[validate(range(min = 0, max = 360))]
    pub end_of_life_months: Option<i32>,
    #[validate(length(max = 100))]
    pub default_department: Option<String>,
    #[validate(length(max = 150))]
    pub default_license_vendor: Option<String>,
    #[serde(default)]
    pub default_tags: Vec<String>,
    #[serde(default)]
    pub specs: serde_json::Value,
    pub image_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default, Validate)]
pub struct UpdateAssetModelRequest {
    #[validate(length(min = 1, max = 100))]
    pub manufacturer: Option<String>,
    #[validate(length(min = 1, max = 100))]
    pub model: Option<String>,
    pub asset_type_id: Option<Uuid>,
    #[validate(range(min = 0, max = 360))]
    pub warranty_months: Option<i32>,
    #[validate(range(min = 0, max = 360))]
    pub end_of_life_months: Option<i32>,
    #[validate(length(max = 100))]
    pub default_department: Option<String>,
    #[validate(length(max = 150))]
    pub default_license_vendor: Option<String>,
    pub default_tags: Option<Vec<String>>,
    pub specs: Option<serde_json::Value>,
    pub image_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default, Validate)]
pub struct AssetModelListFilter {
    /// Case-insensitive substring over manufacturer and model, matched
    /// via the trgm GIN on `(lower(manufacturer || ' ' || model))`.
    #[validate(length(max = 200))]
    pub q: Option<String>,
    pub asset_type_id: Option<Uuid>,
}

// -- asset_templates ------------------------------------------------------

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct AssetTemplateResponse {
    pub id: Uuid,
    pub name: String,
    pub asset_model_id: Uuid,
    pub company_id: Option<Uuid>,
    pub site_id: Option<Uuid>,
    pub default_assigned_user_id: Option<Uuid>,
    pub department: Option<String>,
    pub tags: Vec<String>,
    pub notes: Option<String>,
    pub license_seat_count: Option<i32>,
    pub uses_count: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreateAssetTemplateRequest {
    #[validate(length(min = 1, max = 150))]
    pub name: String,
    pub asset_model_id: Uuid,
    pub company_id: Option<Uuid>,
    pub site_id: Option<Uuid>,
    pub default_assigned_user_id: Option<Uuid>,
    #[validate(length(max = 100))]
    pub department: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    pub notes: Option<String>,
    #[validate(range(min = 0))]
    pub license_seat_count: Option<i32>,
}

#[derive(Debug, Clone, Deserialize, Default, Validate)]
pub struct UpdateAssetTemplateRequest {
    #[validate(length(min = 1, max = 150))]
    pub name: Option<String>,
    pub asset_model_id: Option<Uuid>,
    pub company_id: Option<Uuid>,
    pub site_id: Option<Uuid>,
    pub default_assigned_user_id: Option<Uuid>,
    #[validate(length(max = 100))]
    pub department: Option<String>,
    pub tags: Option<Vec<String>>,
    pub notes: Option<String>,
    #[validate(range(min = 0))]
    pub license_seat_count: Option<i32>,
}

// -- bulk create ----------------------------------------------------------

/// `POST /api/v1/assets/bulk-create` fans N `CreateAssetRequest`s out
/// of (one template OR one model) + a per-batch context (`company_id`,
/// `site_id`, dates, assigned user) + one `BulkSerial` per asset. One
/// of `template_id` / `asset_model_id` is required; `template_id`
/// wins when both are present.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct BulkCreateAssetsRequest {
    pub template_id: Option<Uuid>,
    pub asset_model_id: Option<Uuid>,

    pub company_id: Uuid,
    pub site_id: Option<Uuid>,
    pub assigned_user_id: Option<Uuid>,
    #[validate(length(max = 100))]
    pub department: Option<String>,
    pub purchase_date: Option<NaiveDate>,
    pub purchase_price: Option<Decimal>,
    pub installed_date: Option<NaiveDate>,

    /// One row per serial. Cap matches the design doc: 500 per call so
    /// the single transaction stays bounded. A larger submit is the
    /// SPA's job to split into two calls.
    #[validate(length(min = 1, max = 500))]
    pub serials: Vec<BulkSerial>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Validate)]
pub struct BulkSerial {
    #[validate(length(min = 1, max = 100))]
    pub serial_number: String,
    /// Defaults to `{manufacturer} {model} #{serial}` when absent.
    #[validate(length(max = 255))]
    pub name: Option<String>,
    #[validate(length(max = 100))]
    pub asset_tag: Option<String>,
    #[validate(length(max = 255))]
    pub hostname: Option<String>,
    #[validate(length(max = 50))]
    pub mac_address: Option<String>,
    #[validate(length(max = 45))]
    pub ip_address: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BulkCreateAssetsResponse {
    pub created: Vec<Uuid>,
    pub count: usize,
    pub model_id: Uuid,
    pub template_id: Option<Uuid>,
}

// -- signature detector --------------------------------------------------

/// `GET /api/v1/asset-models/signature-detector` returns zero or one
/// row. When a tenant has produced `>= 5` identical creates in the
/// last 7 days AND the matching catalog row is either absent OR
/// already `source = auto_derived`, the SPA shows the "save as a
/// template" banner on top of the Assets list.
#[derive(Debug, Clone, Serialize)]
pub struct SignatureCandidateResponse {
    pub manufacturer: String,
    pub model: String,
    pub asset_type_id: Uuid,
    pub recent_count: i64,
    pub window_days: i64,
    /// If an `asset_models` row already exists for the triple AND it
    /// is `source = auto_derived`, this is its id; the SPA offers "add
    /// to this template" rather than "save as new". `None` means no
    /// row exists.
    pub existing_model_id: Option<Uuid>,
    pub template_suggestion: TemplateSuggestion,
}

#[derive(Debug, Clone, Serialize)]
pub struct TemplateSuggestion {
    /// Pre-filled template name. The SPA shows this as the default on
    /// the save-template modal.
    pub name_hint: String,
    /// Fields common across every one of the N recent creates. The SPA
    /// shows them as the body of the save-template modal.
    pub common_fields: serde_json::Value,
}
