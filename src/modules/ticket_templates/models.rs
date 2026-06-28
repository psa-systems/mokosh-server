//! PMS-448 AC4: ticket-template DTOs.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Clone, Serialize)]
pub struct TicketTemplateResponse {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    /// Seeds `tickets.title`.
    pub subject: String,
    /// Seeds `tickets.description`.
    pub body: Option<String>,
    pub category_id: Option<Uuid>,
    pub priority_id: Option<Uuid>,
    pub type_id: Option<Uuid>,
    pub is_active: bool,
    pub created_by_id: Uuid,
    pub created_by_name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreateTicketTemplateRequest {
    #[validate(length(min = 1, max = 200))]
    pub name: String,
    pub description: Option<String>,
    #[validate(length(min = 1, max = 500))]
    pub subject: String,
    pub body: Option<String>,
    pub category_id: Option<Uuid>,
    pub priority_id: Option<Uuid>,
    pub type_id: Option<Uuid>,
    #[serde(default = "default_true")]
    pub is_active: bool,
}

/// PATCH semantics: every field is optional and only the keys present
/// in the request body are written. The lookup FKs use a nested
/// `Option<Option<Uuid>>` so the caller can distinguish "leave the
/// category alone" (key absent) from "clear the category" (key present
/// and `null`).
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpdateTicketTemplateRequest {
    #[validate(length(min = 1, max = 200))]
    pub name: Option<String>,
    #[serde(default, deserialize_with = "double_option")]
    pub description: Option<Option<String>>,
    #[validate(length(min = 1, max = 500))]
    pub subject: Option<String>,
    #[serde(default, deserialize_with = "double_option")]
    pub body: Option<Option<String>>,
    #[serde(default, deserialize_with = "double_option")]
    pub category_id: Option<Option<Uuid>>,
    #[serde(default, deserialize_with = "double_option")]
    pub priority_id: Option<Option<Uuid>>,
    #[serde(default, deserialize_with = "double_option")]
    pub type_id: Option<Option<Uuid>>,
    pub is_active: Option<bool>,
}

fn default_true() -> bool {
    true
}

/// Deserialize a present-but-nullable field into `Some(None)` for an
/// explicit JSON `null` and `Some(Some(v))` for a value, while an
/// absent key stays `None` (via `#[serde(default)]`). Lets PATCH tell
/// "clear this FK" apart from "don't touch this FK".
fn double_option<'de, T, D>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    T: Deserialize<'de>,
    D: serde::Deserializer<'de>,
{
    Ok(Some(Option::deserialize(deserializer)?))
}
