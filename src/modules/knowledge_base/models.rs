//! Knowledge base DTOs.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Clone, Serialize)]
pub struct KbCategoryResponse {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub parent_id: Option<Uuid>,
    pub slug: String,
    pub visibility: String,
    pub sort_order: i32,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpsertKbCategoryRequest {
    #[validate(length(min = 1, max = 100))]
    pub name: String,
    pub description: Option<String>,
    pub parent_id: Option<Uuid>,
    #[validate(length(min = 1, max = 100))]
    pub slug: String,
    /// "public" | "internal" | "client_specific"
    #[serde(default = "default_internal")]
    pub visibility: String,
    #[serde(default)]
    pub sort_order: i32,
}

fn default_internal() -> String {
    "internal".into()
}

#[derive(Debug, Clone, Serialize)]
pub struct KbArticleResponse {
    pub id: Uuid,
    pub title: String,
    pub slug: String,
    pub content: String,
    pub summary: Option<String>,
    pub category_id: Option<Uuid>,
    pub visibility: String,
    pub status: String,
    pub author_id: Uuid,
    pub view_count: i32,
    pub helpful_count: i32,
    pub not_helpful_count: i32,
    pub published_at: Option<DateTime<Utc>>,
    pub tags: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreateKbArticleRequest {
    #[validate(length(min = 1, max = 255))]
    pub title: String,
    #[validate(length(min = 1, max = 255))]
    pub slug: String,
    #[validate(length(min = 1))]
    pub content: String,
    pub summary: Option<String>,
    pub category_id: Option<Uuid>,
    #[serde(default = "default_internal")]
    pub visibility: String,
    #[serde(default = "default_draft")]
    pub status: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

fn default_draft() -> String {
    "draft".into()
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpdateKbArticleRequest {
    pub title: Option<String>,
    pub slug: Option<String>,
    pub content: Option<String>,
    pub summary: Option<String>,
    pub category_id: Option<Uuid>,
    pub visibility: Option<String>,
    pub status: Option<String>,
    pub tags: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize, Default, validator::Validate)]
pub struct KbArticleFilter {
    pub category_id: Option<Uuid>,
    #[validate(length(max = 100))]
    pub status: Option<String>,
    #[validate(length(max = 100))]
    pub visibility: Option<String>,
    /// Free-text search. Capped to 200 chars to keep the pg_trgm
    /// similarity scan bounded; matched against the
    /// `(title || ' ' || content) gin_trgm_ops` GIN index via the `%`
    /// operator and ranked by `similarity()` DESC.
    #[validate(length(max = 200))]
    pub q: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct KbArticleVersionResponse {
    pub id: Uuid,
    pub article_id: Uuid,
    pub version_number: i32,
    pub title: String,
    pub content: String,
    pub edited_by_id: Uuid,
    pub created_at: DateTime<Utc>,
}

/// Returned by the helpful / not_helpful feedback endpoints so the portal
/// (or agent UI) can render the updated tallies without a follow-up GET.
///
/// `my_vote` is the calling user's current vote on the article AFTER the
/// toggle (`Some("helpful")`, `Some("not_helpful")`, or `None` if they
/// have no vote / just un-voted), so the staff KB detail page can render
/// the active thumb state without a separate lookup.
#[derive(Debug, Clone, Serialize)]
pub struct KbArticleFeedbackResponse {
    pub id: Uuid,
    pub helpful_count: i32,
    pub not_helpful_count: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub my_vote: Option<String>,
}
