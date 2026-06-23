//! PMS-450: email-intake DTOs.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

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
    /// treats this as a reply and returns the existing ticket
    /// instead of creating a new one. Phase 2 will turn the reply
    /// into a comment on that ticket.
    #[serde(default)]
    pub references: Vec<String>,
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
    /// reply (Phase 1: returns the existing id; Phase 2: adds a
    /// comment).
    pub threaded: bool,
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
