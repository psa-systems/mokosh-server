//! Form definition, field, submission and public-link DTOs (PMS-731, PMS-898).
//!
//! Moved here from `mokosh-server/src/modules/forms/models.rs`, which was the
//! last module whose wire types were hand-copied across the repo boundary -
//! twice on the client side, once under its own names and once again for the
//! public subset in the request-form page.
//!
//! `ResolvedRequestToken` deliberately did NOT move: it is never serialised,
//! so it is not a wire type, and every field on it is a tenant-internal id.

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
    /// PMS-898: a field type this build does not know.
    ///
    /// Same tolerant-read, strict-write split as [`FormRule::Unknown`], and for
    /// a sharper reason: the public request form is rendered for a client with
    /// no account, off an emailed link. Without this, a server that grows a
    /// field type would make that whole page fail to deserialise rather than
    /// render the unknown field as a text input and let the server judge the
    /// answer. A blank page is the worst outcome available there.
    ///
    /// Refused on write, so a definition cannot store a type the server cannot
    /// validate.
    #[serde(other)]
    Unknown,
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
            // Never authored: `from_str` cannot produce it and the write path
            // refuses it. Spelled so the round trip is total.
            Self::Unknown => "unknown",
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
    /// PMS-898: a rule kind this build does not know.
    ///
    /// On the READ path this is what keeps an older client rendering a form
    /// whose server has grown a new rule: the unknown rule deserialises here
    /// and is ignored, so enforcement falls back to the server instead of the
    /// page failing to render.
    ///
    /// On the WRITE path it must be refused. A definition may not be created or
    /// updated with a rule the server cannot name, or it would store a rule it
    /// can never enforce. `check_rules_against_fields` rejects it, and the
    /// compiler made that unavoidable: it used to destructure this enum
    /// irrefutably, so adding this variant broke the build until someone
    /// decided what an unnamed rule means.
    #[serde(other)]
    Unknown,
}

// ============================================================================
// RESPONSES
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FormDefinitionResponse {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    /// PMS-748: how a client reaches the MSP about this request.
    #[serde(default)]
    pub contact_info: Option<String>,
    pub kb_article_id: Option<Uuid>,
    /// Resolved title for `kb_article_id`, so a client can render the
    /// procedure link without a second fetch (the PMS-344 asset pattern).
    pub kb_article_title: Option<String>,
    #[serde(default)]
    pub rules: Vec<FormRule>,
    pub is_active: bool,
    pub created_by_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// Ordered by `sort_order`, then `name` for determinism.
    pub fields: Vec<FormFieldResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Validate)]
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Validate)]
pub struct CreateFormDefinitionRequest {
    #[validate(length(min = 1, max = 200))]
    pub name: String,
    #[validate(
        length(min = 1, max = 100),
        custom(function = "crate::validation::validate_slug")
    )]
    pub slug: String,
    pub description: Option<String>,
    /// PMS-748: how a client reaches the MSP about this request, shown on the
    /// form page and in the email. Optional; the MSP's NAME is shown either
    /// way, so a form without this is still attributable.
    #[validate(length(max = 200))]
    pub contact_info: Option<String>,
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Validate)]
pub struct UpdateFormDefinitionRequest {
    #[validate(length(min = 1, max = 200))]
    pub name: Option<String>,
    #[serde(default, deserialize_with = "double_option")]
    pub description: Option<Option<String>>,
    /// PMS-748. Double-optioned like `description`, so a form's contact line
    /// can be cleared as well as changed.
    /// PMS-841: the same 200-character cap the create path carries. `length`
    /// recurses through both `Option`s, so a null still clears.
    #[validate(length(max = 200))]
    #[serde(default, deserialize_with = "double_option")]
    pub contact_info: Option<Option<String>>,
    #[serde(default, deserialize_with = "double_option")]
    pub kb_article_id: Option<Option<Uuid>>,
    pub rules: Option<Vec<FormRule>>,
    pub is_active: Option<bool>,
    #[validate(length(min = 1), nested)]
    pub fields: Option<Vec<CreateFormFieldRequest>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Validate)]
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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

/// The client-facing view of a form: what is needed to render and validate the
/// inputs, and nothing more. No ids, no author, no timestamps, and no KB
/// article, which is an internal procedure for whoever works the ticket rather
/// than something the client is entitled to read.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PublicFormResponse {
    pub name: String,
    // PMS-898: every optional field below carries `#[serde(default)]`, which
    // the server-only copy did not need because it only ever serialised. The
    // client's copy had them deliberately: a build talking to a server that
    // predates PMS-748 or MAPPS-429 renders the form unattributed rather than
    // failing to render it. Moving the type without them would have turned a
    // graceful degrade into a blank page.
    #[serde(default)]
    pub description: Option<String>,
    /// PMS-748: the MSP asking for this. A client arriving from an email link
    /// otherwise reads a page of personal questions with no name on it. Always
    /// present: attribution is not optional.
    #[serde(default)]
    pub tenant_name: String,
    /// PMS-748: how to reach that MSP, when the definition carries it.
    ///
    /// MAPPS-429: falls back to the organisation's own contact, so a form that
    /// defines nothing still tells the client who to ask.
    pub contact_info: Option<String>,
    /// MAPPS-429: relative path to the MSP's logo, when it has one. Relative
    /// because the client renders it against the API base it already resolved
    /// to fetch this payload.
    #[serde(default)]
    pub logo_url: Option<String>,
    pub rules: Vec<FormRule>,
    pub fields: Vec<PublicFormField>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PublicSubmissionReceipt {
    pub ticket_number: String,
}
