//! Wire shapes for the asset-catalog surface.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

/// A row from `asset_models`.
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
    pub default_tags: Option<Vec<String>>,
    pub specs: serde_json::Value,
    pub image_url: Option<String>,
    /// `seeded` / `tenant_authored` / `auto_derived`.
    pub source: String,
    pub uses_count: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// `POST /api/v1/asset-models` body. `source` is intentionally not a
/// field: the handler stamps it to `tenant_authored` so a caller
/// cannot forge `seeded` (which belongs to the DEFAULT-tenant seed
/// migration) or `auto_derived` (which belongs to the signature
/// detector's write path, MR3).
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreateAssetModelRequest {
    #[validate(length(min = 1, max = 100))]
    pub manufacturer: String,
    #[validate(length(min = 1, max = 100))]
    pub model: String,
    pub asset_type_id: Uuid,
    #[validate(range(min = 0, max = 600))]
    pub warranty_months: Option<i32>,
    #[validate(range(min = 0, max = 600))]
    pub end_of_life_months: Option<i32>,
    #[validate(length(max = 100))]
    pub default_department: Option<String>,
    #[validate(length(max = 150))]
    pub default_license_vendor: Option<String>,
    #[serde(default)]
    pub default_tags: Option<Vec<String>>,
    #[serde(default = "default_specs")]
    pub specs: serde_json::Value,
    pub image_url: Option<String>,
}

fn default_specs() -> serde_json::Value {
    serde_json::json!({})
}

/// `PUT /api/v1/asset-models/{id}`. Every field is Option; absent fields
/// leave the column untouched. (MR1 ships CREATE only; this type is
/// filed for MR2 so the models stay colocated.)
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpdateAssetModelRequest {
    #[validate(length(min = 1, max = 100))]
    pub manufacturer: Option<String>,
    #[validate(length(min = 1, max = 100))]
    pub model: Option<String>,
    pub asset_type_id: Option<Uuid>,
    #[validate(range(min = 0, max = 600))]
    pub warranty_months: Option<i32>,
    #[validate(range(min = 0, max = 600))]
    pub end_of_life_months: Option<i32>,
    #[validate(length(max = 100))]
    pub default_department: Option<String>,
    #[validate(length(max = 150))]
    pub default_license_vendor: Option<String>,
    pub default_tags: Option<Vec<String>>,
    pub specs: Option<serde_json::Value>,
    pub image_url: Option<String>,
}

/// `GET /api/v1/asset-models?q=&limit=` query shape. The typeahead
/// matches the trimmed, lowercased `q` against the trigram GIN on
/// `lower(manufacturer || ' ' || model)`.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct AssetModelsQuery {
    #[serde(default)]
    #[validate(length(max = 200))]
    pub q: Option<String>,
    /// Hard-capped at 50 server-side regardless of the request's value.
    /// Omitted defaults to 10 (what the SPA typeahead expects).
    #[serde(default)]
    pub limit: Option<i64>,
}
