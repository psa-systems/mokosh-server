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

/// A row from `asset_templates` with its model eagerly joined so the SPA
/// typeahead can render "<Template name> - <manufacturer> <model>" inline.
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct AssetTemplateResponse {
    pub id: Uuid,
    pub name: String,
    pub asset_model_id: Uuid,
    pub manufacturer: String,
    pub model: String,
    pub asset_type_id: Uuid,
    pub company_id: Option<Uuid>,
    pub site_id: Option<Uuid>,
    pub default_assigned_user_id: Option<Uuid>,
    pub department: Option<String>,
    pub tags: Option<Vec<String>>,
    pub notes: Option<String>,
    pub license_seat_count: Option<i32>,
    pub created_by: Option<Uuid>,
    pub uses_count: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// `GET /api/v1/asset-models/signature-detector` response.
///
/// Zero or one row: the top signature candidate for the caller's
/// tenant that has no `tenant_authored` catalog row yet (so the SPA's
/// "save as template" prompt is useful rather than a reminder that the
/// operator already wrote the catalog row).
#[derive(Debug, Clone, Serialize)]
pub struct SignatureDetectorResponse {
    pub signature: Option<SignatureCandidate>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct SignatureCandidate {
    pub manufacturer: String,
    pub model: String,
    pub asset_type_id: Uuid,
    pub recent_count: i64,
    pub window_days: i32,
    /// `Some(uuid)` when a catalog row of this shape already exists
    /// (which the handler only ever returns when that row is
    /// `auto_derived`; a `tenant_authored` row suppresses the
    /// candidate entirely).
    pub existing_model_id: Option<Uuid>,
    pub template_suggestion: TemplateSuggestion,
}

#[derive(Debug, Clone, Serialize)]
pub struct TemplateSuggestion {
    pub name_hint: String,
}

/// `POST /api/v1/asset-templates` body.
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
    pub tags: Option<Vec<String>>,
    pub notes: Option<String>,
    #[validate(range(min = 0, max = 100_000))]
    pub license_seat_count: Option<i32>,
}

/// `PUT /api/v1/asset-templates/{id}` body. Every field Option; absent
/// fields leave the column untouched. (`company_id` and friends are
/// Option<Option<T>> so the SPA can clear them explicitly; the service
/// treats a bare `None` as "do not touch".)
#[derive(Debug, Clone, Deserialize, Validate)]
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
    #[validate(range(min = 0, max = 100_000))]
    pub license_seat_count: Option<i32>,
}
