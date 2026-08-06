//! PMS-731: form definition, field and submission DTOs.

// `FieldType::from_str` mirrors the infallible-style parser the other model
// enums expose (`TicketSource`, `BillingStatus`, `NoteType`): it returns
// `Option<Self>`, so it deliberately does not implement `std::str::FromStr`,
// which requires a `Result`.
#![allow(clippy::should_implement_trait)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

/// The field types the MACD field list reviewed on PMS-731 needs, and no
/// others. Adding a variant means adding its validation arm in
/// [`super::validation`] and widening the `field_type` CHECK in a NEW
/// migration (migrations are immutable once committed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldType {
    Text,
    Textarea,
    Email,
    Date,
    Select,
    Boolean,
}

impl FieldType {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "text" => Some(Self::Text),
            "textarea" => Some(Self::Textarea),
            "email" => Some(Self::Email),
            "date" => Some(Self::Date),
            "select" => Some(Self::Select),
            "boolean" => Some(Self::Boolean),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Textarea => "textarea",
            Self::Email => "email",
            Self::Date => "date",
            Self::Select => "select",
            Self::Boolean => "boolean",
        }
    }

    /// Whether `min_length` / `max_length` mean anything for this type. A
    /// bound set on any other type is inert rather than an error, so a
    /// definition authored with a stray bound still works.
    pub fn honours_length(&self) -> bool {
        matches!(self, Self::Text | Self::Textarea | Self::Email)
    }
}

/// A cross-field rule evaluated after every field has passed its own checks.
///
/// Exactly one kind in v1. The MACD departure form needs `forward_to` only
/// when `mailbox_handling = forward`, which is conditional REQUIREDNESS, not
/// conditional display. Modelling it as one form-level rule buys that single
/// behaviour without a per-field condition engine; see migration 100 and the
/// field-list review on PMS-731.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FormRule {
    /// `field` is required when `when_field`'s submitted answer equals
    /// `equals`. When the condition does not hold, `field` is optional and
    /// still validated normally if present.
    RequiredIf {
        field: String,
        when_field: String,
        equals: String,
    },
}

// ============================================================================
// RESPONSES
// ============================================================================

#[derive(Debug, Clone, Serialize)]
pub struct FormFieldResponse {
    pub id: Uuid,
    pub name: String,
    pub label: String,
    pub help_text: Option<String>,
    pub field_type: FieldType,
    pub is_required: bool,
    pub min_length: Option<i32>,
    pub max_length: Option<i32>,
    pub options: Option<Vec<String>>,
    pub date_not_in_past: bool,
    pub sort_order: i32,
}

#[derive(Debug, Clone, Serialize)]
pub struct FormDefinitionResponse {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    pub kb_article_id: Option<Uuid>,
    /// Resolved title for `kb_article_id`, so a client can render the
    /// procedure link without a second fetch (the PMS-344 asset pattern).
    pub kb_article_title: Option<String>,
    pub rules: Vec<FormRule>,
    pub is_active: bool,
    pub created_by_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// Ordered by `sort_order`, then `name` for determinism.
    pub fields: Vec<FormFieldResponse>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FormSubmissionResponse {
    pub id: Uuid,
    pub form_definition_id: Uuid,
    pub payload: serde_json::Value,
    pub submitted_by_contact_id: Option<Uuid>,
    pub ticket_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

// ============================================================================
// REQUESTS
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct CreateFormFieldRequest {
    #[validate(length(min = 1, max = 100), custom(function = "validate_field_name"))]
    pub name: String,
    #[validate(length(min = 1, max = 200))]
    pub label: String,
    pub help_text: Option<String>,
    pub field_type: FieldType,
    #[serde(default)]
    pub is_required: bool,
    #[validate(range(min = 0))]
    pub min_length: Option<i32>,
    #[validate(range(min = 1))]
    pub max_length: Option<i32>,
    pub options: Option<Vec<String>>,
    #[serde(default)]
    pub date_not_in_past: bool,
    #[serde(default)]
    pub sort_order: i32,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreateFormDefinitionRequest {
    #[validate(length(min = 1, max = 200))]
    pub name: String,
    #[validate(
        length(min = 1, max = 100),
        custom(function = "crate::utils::validation::validate_slug")
    )]
    pub slug: String,
    pub description: Option<String>,
    pub kb_article_id: Option<Uuid>,
    #[serde(default)]
    pub rules: Vec<FormRule>,
    #[serde(default = "default_true")]
    pub is_active: bool,
    /// The ordered field set. A definition with no fields is rejected: it
    /// could never collect anything, and accepting it only defers the error
    /// to the first client who opens the form.
    #[validate(length(min = 1), nested)]
    pub fields: Vec<CreateFormFieldRequest>,
}

/// PATCH semantics: absent keys are left alone. `fields`, when present,
/// REPLACES the whole field set rather than merging, because field identity
/// is the payload key and a partial merge cannot express a rename or a
/// deletion unambiguously.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpdateFormDefinitionRequest {
    #[validate(length(min = 1, max = 200))]
    pub name: Option<String>,
    #[serde(default, deserialize_with = "double_option")]
    pub description: Option<Option<String>>,
    #[serde(default, deserialize_with = "double_option")]
    pub kb_article_id: Option<Option<Uuid>>,
    pub rules: Option<Vec<FormRule>>,
    pub is_active: Option<bool>,
    #[validate(length(min = 1), nested)]
    pub fields: Option<Vec<CreateFormFieldRequest>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SubmitFormRequest {
    /// Answers keyed by `form_fields.name`. Validated field by field against
    /// the definition before anything is stored.
    pub payload: serde_json::Value,
}

fn default_true() -> bool {
    true
}

/// A field name is the key its answer occupies in the submission payload, so
/// it is held to the same shape as a slug but with underscores instead of
/// hyphens (payload keys read as identifiers, not URL segments).
fn validate_field_name(name: &str) -> Result<(), validator::ValidationError> {
    let ok = !name.is_empty()
        && name.starts_with(|c: char| c.is_ascii_lowercase())
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        && !name.ends_with('_')
        && !name.contains("__");
    if ok {
        return Ok(());
    }
    let mut err = validator::ValidationError::new("field_name");
    err.message = Some(
        "must be lowercase letters, digits and single underscores, starting with a letter".into(),
    );
    Err(err)
}

/// Deserialize a present-but-nullable field into `Some(None)` for an explicit
/// JSON `null` and `Some(Some(v))` for a value, while an absent key stays
/// `None`. Lets PATCH tell "clear this" apart from "don't touch this".
fn double_option<'de, T, D>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    T: Deserialize<'de>,
    D: serde::Deserializer<'de>,
{
    Ok(Some(Option::deserialize(deserializer)?))
}

// ============================================================================
// PMS-730: REQUEST LINKS
// ============================================================================

/// Issue a magic link for a client to fill in a form. Either `contact_id` or
/// `recipient_email` must be present; a contact supplies the address and the
/// greeting, an explicit address overrides it (or stands alone when the
/// addressee is not a contact yet).
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct IssueRequestLinkRequest {
    pub form_definition_id: Uuid,
    pub company_id: Uuid,
    pub contact_id: Option<Uuid>,
    #[validate(email)]
    pub recipient_email: Option<String>,
}

/// The issued link as the agent surface sees it. Deliberately WITHOUT the
/// token: only the recipient should ever hold it, and echoing it back would
/// put a credential into every response log and browser history entry that
/// touches this endpoint.
#[derive(Debug, Clone, Serialize)]
pub struct RequestLinkResponse {
    pub id: Uuid,
    pub form_definition_id: Uuid,
    pub form_name: String,
    pub company_id: Uuid,
    pub company_name: String,
    pub contact_id: Option<Uuid>,
    pub recipient_email: String,
    pub expires_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
    pub submission_id: Option<Uuid>,
}

/// What a presented token resolves to. Internal: never serialised, because
/// every field is a tenant-internal id.
#[derive(Debug, Clone)]
pub struct ResolvedRequestToken {
    pub token_id: Uuid,
    pub tenant_id: crate::modules::auth::TenantId,
    pub form_definition_id: Uuid,
    pub company_id: Uuid,
    pub contact_id: Option<Uuid>,
    /// The MSP user who issued the link. Becomes the created ticket's
    /// `created_by_id`, since the submitter is a client with no `users` row
    /// and that column is NOT NULL.
    pub created_by_id: Uuid,
}

/// The client-facing view of a form: what is needed to render and validate the
/// inputs, and nothing more. No ids, no author, no timestamps, and no KB
/// article, which is an internal procedure for whoever works the ticket rather
/// than something the client is entitled to read.
#[derive(Debug, Clone, Serialize)]
pub struct PublicFormResponse {
    pub name: String,
    pub description: Option<String>,
    pub rules: Vec<FormRule>,
    pub fields: Vec<PublicFormField>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PublicFormField {
    pub name: String,
    pub label: String,
    pub help_text: Option<String>,
    pub field_type: FieldType,
    pub is_required: bool,
    pub min_length: Option<i32>,
    pub max_length: Option<i32>,
    pub options: Option<Vec<String>>,
    pub date_not_in_past: bool,
}

/// What the client gets back after a successful submission: the ticket number
/// to quote, and nothing else about the tenant's internals.
#[derive(Debug, Clone, Serialize)]
pub struct PublicSubmissionReceipt {
    pub ticket_number: String,
}
