//! PMS-450: email-intake DTOs.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

/// Optional structured headers carried alongside the parsed fields.
/// PMS-469: the email-intake log audit table persists these verbatim
/// so a malformed sender can be debugged post-hoc without recovering
/// the raw payload from the gateway side. Phase 1 ignored the field
/// entirely; senders that omit it land an empty object.
type RawHeaders = serde_json::Value;

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct EmailIntakeRequest {
    /// RFC 5322 Message-Id of the inbound email, headers included
    /// (the surrounding `<...>` is preserved verbatim so the gateway
    /// does not have to normalise). Used as the dedup key on
    /// (tenant_id, email_message_id).
    #[validate(length(min = 1, max = 255))]
    pub message_id: String,
    /// From: address (mailbox, no display name). Lowercased at the
    /// service boundary before the contact lookup so casing in the
    /// header does not produce a miss.
    #[validate(email, length(max = 254))]
    pub from_email: String,
    /// Optional From: display name. Not used for contact matching;
    /// passed through onto the ticket's description prologue so the
    /// agent reading the ticket sees who sent it without an extra
    /// header lookup.
    #[validate(length(max = 200))]
    pub from_name: Option<String>,
    /// Subject: header, becomes the ticket title. RFC 2047 decoding
    /// is the gateway's job; we treat it as opaque text.
    #[validate(length(min = 1, max = 500))]
    pub subject: String,
    /// text/plain body. Becomes the ticket description.
    pub body_text: Option<String>,
    /// text/html body. Currently ignored by Phase 1 (description
    /// stays plaintext); Phase 2 will store it in the audit log so
    /// rich-text replies are preserved.
    #[allow(dead_code)]
    pub body_html: Option<String>,
    /// Concatenation of `In-Reply-To` + `References` headers. If any
    /// matches an existing ticket's `email_message_id`, the intake
    /// treats this as a reply and (PMS-469) appends the body to that
    /// ticket as a `note_type='public'` row attributed to the
    /// matched sender contact.
    #[serde(default)]
    pub references: Vec<String>,
    /// PMS-469: structured header bag persisted into `email_intake_log`
    /// for debugging. Treated as opaque JSON; the gateway can ship
    /// whatever subset is convenient. Defaults to `{}` when absent.
    #[serde(default = "default_empty_object")]
    pub raw_headers: RawHeaders,
    /// PMS-450 AC3: inbound MIME attachments. The gateway decodes the
    /// MIME parts and ships each as base64 so the JSON payload stays
    /// transport-safe. Stored against the created ticket (or the reply
    /// note on a threading hit) via the shared `ticket_attachments`
    /// blob path. Defaults to an empty list; a body with no attachments
    /// is unchanged from the Phase 1 shape.
    #[serde(default)]
    #[validate(nested)]
    pub attachments: Vec<EmailIntakeAttachment>,
}

/// PMS-450 AC3: one inbound email attachment. The bytes ride on the
/// JSON payload as standard (padded) base64; the service decodes and
/// hands them to `AttachmentService`, which enforces the same on-disk
/// layout and size cap as the interactive upload paths.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct EmailIntakeAttachment {
    /// Original filename from the MIME part's `Content-Disposition`.
    /// Sanitised again at the storage boundary, so a hostile name
    /// cannot escape the per-tenant directory.
    #[validate(length(min = 1, max = 255))]
    pub file_name: String,
    /// MIME type from the part's `Content-Type`. Optional; the storage
    /// layer falls back to `application/octet-stream` when absent.
    #[validate(length(max = 100))]
    pub mime_type: Option<String>,
    /// Standard base64 (with padding, RFC 4648) of the raw bytes. The
    /// service rejects a part whose payload does not decode rather than
    /// failing the whole intake.
    #[validate(length(min = 1))]
    pub content_base64: String,
}

fn default_empty_object() -> serde_json::Value {
    serde_json::json!({})
}

#[derive(Debug, Clone, Serialize)]
pub struct EmailIntakeResponse {
    pub ticket_id: Uuid,
    pub ticket_number: String,
    /// True when a fresh ticket was created. False when the intake
    /// matched a previously-seen Message-Id (dedup) or threaded onto
    /// an existing ticket (reply).
    pub created: bool,
    /// True when the Message-Id was already present on a ticket in
    /// the caller's tenant. The existing ticket id is returned.
    pub deduplicated: bool,
    /// True when a `references` header matched a prior ticket's
    /// Message-Id and the intake was routed to that ticket as a
    /// reply. PMS-469 phase 2 adds the reply as a public comment on
    /// the matched ticket; see `comment_added` for whether the
    /// comment actually landed.
    pub threaded: bool,
    /// PMS-469: true when threading hit AND the reply body was
    /// appended to the matched ticket as a `note_type='public'` row
    /// attributed to the matched sender contact. False when threading
    /// did not hit, or when no contact could be resolved for the
    /// sender so the note had no Customer to attribute to.
    #[serde(default)]
    pub comment_added: bool,
    /// PMS-450 AC3: count of inbound attachments persisted to the
    /// ticket (create path) or the reply note (threading path). Best-
    /// effort: a part that fails to decode or exceeds the size cap is
    /// skipped and not counted, so this can be less than the number of
    /// `attachments` the gateway sent.
    #[serde(default)]
    pub attachments_stored: u32,
}

/// PMS-469 phase 2: the audit row for one inbound email-intake. The
/// admin GET /email-intake-log/{id} endpoint serialises one of these.
#[derive(Debug, Clone, Serialize)]
pub struct EmailIntakeLogResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub message_id: String,
    pub ticket_id: Option<Uuid>,
    pub raw_headers: serde_json::Value,
    pub raw_body_text: Option<String>,
    pub raw_body_html: Option<String>,
    pub received_at: DateTime<Utc>,
    pub error: Option<String>,
}

/// PMS-450 phase 2: admin-listable intake token. The plaintext is
/// NEVER on this DTO - only the SHA-256 hash hits the DB and the
/// plaintext lives only on the create response. List + get rows
/// surface the metadata an operator needs to revoke a stale token
/// confidently.
#[derive(Debug, Clone, Serialize)]
pub struct IntakeTokenResponse {
    pub id: Uuid,
    pub kind: String,
    pub label: String,
    pub last_used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreateIntakeTokenRequest {
    /// What surface the token authenticates against. Phase 2 only
    /// recognises `email_intake`; the service rejects anything else
    /// with 400 so an admin does not silently create a never-used
    /// token. The column is VARCHAR(50) so future surfaces
    /// (rmm-intake, billing-webhook) can land without a migration.
    #[validate(length(min = 1, max = 50))]
    pub kind: String,
    /// Operator-facing label ("Cloudron mail hook", "Helpdesk inbox
    /// forwarder"). Mandatory because a list of unlabelled tokens
    /// becomes a UUID guessing game at revocation time.
    #[validate(length(min = 1, max = 200))]
    pub label: String,
}

/// Returned by `POST /api/v1/intake-tokens`. The `token` field
/// carries the plaintext bearer the operator must copy into their
/// mail gateway IMMEDIATELY; it is never recoverable - only the
/// SHA-256 hash is stored on the DB and the list endpoint surfaces
/// metadata, not the secret. A subsequent GET on the same id will
/// have no `token` field at all (see `IntakeTokenResponse`).
#[derive(Debug, Clone, Serialize)]
pub struct CreatedIntakeTokenResponse {
    /// The row metadata, same shape as the list endpoint returns.
    #[serde(flatten)]
    pub token_metadata: IntakeTokenResponse,
    /// The PLAINTEXT bearer. Shown exactly once. The SPA must
    /// surface this in a copy-to-clipboard modal with a "you cannot
    /// see this again" warning.
    pub token: String,
}
