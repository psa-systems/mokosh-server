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
    /// PMS-1126: the author's display name, "Unknown" when the user row is
    /// gone. Names, never ids, are what the page shows.
    pub author_name: String,
    /// PMS-1126: who last wrote the row through any path (edit, restore,
    /// task toggle, metadata-only edit). `None` only for an article that
    /// has never been written since creation AND carries no version, which
    /// no API path produces; a row from before migration 200 falls back to
    /// the latest version's editor.
    pub updated_by_id: Option<Uuid>,
    pub updated_by_name: Option<String>,
    /// PMS-1126: the highest version number, so a client can mark the
    /// current row in the history without a second request.
    pub current_version: i32,
    pub view_count: i32,
    pub helpful_count: i32,
    pub not_helpful_count: i32,
    pub published_at: Option<DateTime<Utc>>,
    pub tags: Vec<String>,
    /// Companies a `client_specific` article is scoped to. Empty for
    /// `public` / `internal` articles. Returned so the editor can
    /// round-trip the multi-select selection (PMS-341).
    pub company_ids: Vec<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// PMS-1082: the customer's projection of an article, what the contact
/// arm of `GET /kb/articles` and `GET /kb/articles/{id}` answers with.
/// Deliberately NOT `KbArticleResponse` (the PMS-1061 rule): a contact
/// only ever sees a published article it is allowed to read, so
/// `status`, `visibility` and `company_ids` would only describe the
/// filter that let it through, and `author_id`, `view_count` and the
/// vote tallies are the MSP's own signals about its staff and its
/// readers.
#[derive(Debug, Clone, Serialize)]
pub struct ContactKbArticleResponse {
    pub id: Uuid,
    pub title: String,
    pub slug: String,
    pub content: String,
    pub summary: Option<String>,
    pub category_id: Option<Uuid>,
    pub published_at: Option<DateTime<Utc>>,
    pub tags: Vec<String>,
    pub updated_at: DateTime<Utc>,
}

impl From<KbArticleResponse> for ContactKbArticleResponse {
    fn from(a: KbArticleResponse) -> Self {
        Self {
            id: a.id,
            title: a.title,
            slug: a.slug,
            content: a.content,
            summary: a.summary,
            category_id: a.category_id,
            published_at: a.published_at,
            tags: a.tags,
            updated_at: a.updated_at,
        }
    }
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
    /// Companies a `client_specific` article is scoped to (PMS-341).
    /// Required (non-empty) when `visibility = client_specific`; ignored
    /// and stored empty for `public` / `internal`.
    #[serde(default)]
    pub company_ids: Option<Vec<Uuid>>,
}

fn default_draft() -> String {
    "draft".into()
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpdateKbArticleRequest {
    #[validate(length(min = 1, max = 255))]
    pub title: Option<String>,
    #[validate(length(min = 1, max = 255))]
    pub slug: Option<String>,
    #[validate(length(min = 1))]
    pub content: Option<String>,
    pub summary: Option<String>,
    pub category_id: Option<Uuid>,
    pub visibility: Option<String>,
    pub status: Option<String>,
    pub tags: Option<Vec<String>>,
    /// Companies a `client_specific` article is scoped to (PMS-341). When
    /// omitted the existing scope is kept; when the (effective) visibility
    /// is not `client_specific` the scope is cleared regardless.
    #[serde(default)]
    pub company_ids: Option<Vec<Uuid>>,
    /// PMS-1126: why this edit was made, stored on the version the save
    /// creates. Trimmed; blank is the same as absent. A save that creates
    /// no version (a metadata-only edit) keeps no note, because there is
    /// no version for it to explain.
    #[validate(length(max = 500))]
    pub change_note: Option<String>,
}

/// PMS-1126: the body of `POST /kb/articles/{id}/versions/{n}/restore`.
/// Optional, and an empty body is the same as `{}`.
#[derive(Debug, Clone, Default, Deserialize, Validate)]
pub struct RestoreKbArticleVersionRequest {
    /// Why the version was brought back, stored on the restore's own
    /// version row beside `restored_from_version`.
    #[validate(length(max = 500))]
    pub change_note: Option<String>,
}

/// PMS-922: the in-progress body an author has not saved yet.
///
/// Deliberately NOT `UpdateKbArticleRequest`. A draft holds the two fields the
/// editor changes continuously; everything else (visibility, status, category,
/// scope) is a deliberate act the author performs once and saves. Widening this
/// to the whole article would make a draft a shadow copy that can drift from
/// the record in ways nothing reconciles.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct SaveKbDraftRequest {
    #[validate(length(min = 1, max = 255))]
    pub title: String,
    pub content: String,
}

/// A stored draft, as the editor reads it back.
#[derive(Debug, Clone, Serialize)]
pub struct KbDraftResponse {
    pub article_id: Uuid,
    pub title: String,
    pub content: String,
    pub updated_at: DateTime<Utc>,
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
    /// PMS-1126: the editor's display name, "Unknown" when the user row is
    /// gone.
    pub edited_by_name: String,
    /// PMS-1126: what the editor said the change was for, when they said.
    pub change_note: Option<String>,
    /// PMS-1126: `create` for the snapshot seeded with the article, `edit`
    /// for a save that changed the title or content, `restore` for a
    /// version brought back through the restore route.
    pub change_kind: String,
    /// PMS-1126: for a `restore`, the version it brought back.
    pub restored_from_version: Option<i32>,
    pub created_at: DateTime<Utc>,
}

/// PMS-485: row in the "Top ticket-driving articles" widget. One row
/// per published KB article, ordered by descending `ticket_count` over
/// the configurable `since` window.
#[derive(Debug, Clone, Serialize)]
pub struct TopTicketDrivingArticleRow {
    pub id: Uuid,
    pub title: String,
    pub ticket_count: i64,
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
