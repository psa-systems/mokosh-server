//! PMS-450 phase 1: email-intake service.

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use super::models::{EmailIntakeRequest, EmailIntakeResponse};
use crate::modules::auth::TenantId;
use crate::modules::tickets::TicketService;
use crate::utils::error::{AppError, AppResult};

#[derive(Debug, Clone)]
pub struct ResolvedTenantToken {
    pub tenant_id: TenantId,
    pub token_id: Uuid,
}

#[derive(Clone)]
pub struct EmailIntakeService {
    pool: PgPool,
    tickets: TicketService,
}

impl EmailIntakeService {
    pub fn new(pool: PgPool, tickets: TicketService) -> Self {
        Self { pool, tickets }
    }

    /// Resolve a presented bearer to its owning tenant. The bearer is
    /// SHA-256-hashed and matched against `tenant_intake_tokens`.
    /// Revoked tokens (`revoked_at IS NOT NULL`) and tokens of the
    /// wrong `kind` are rejected here so the route handler does not
    /// have to repeat the check. Bumps `last_used_at` so an operator
    /// can see at a glance which tokens are live.
    pub async fn resolve_token(&self, bearer: &str) -> AppResult<ResolvedTenantToken> {
        let hash = sha256_hex(bearer.as_bytes());
        let row: Option<(Uuid, Uuid)> = sqlx::query_as(
            "SELECT id, tenant_id FROM tenant_intake_tokens \
             WHERE token_hash = $1 \
               AND kind = 'email_intake' \
               AND revoked_at IS NULL",
        )
        .bind(&hash)
        .fetch_optional(&self.pool)
        .await?;
        let (token_id, tenant_uuid) = row.ok_or(AppError::Unauthorized)?;
        sqlx::query("UPDATE tenant_intake_tokens SET last_used_at = NOW() WHERE id = $1")
            .bind(token_id)
            .execute(&self.pool)
            .await?;
        // `from_trusted` is the documented seam for cases that have no
        // request context to source the tenant from. Email-intake's
        // identity is the presented bearer; the tenant_id we just
        // SELECT'd from the token row IS the trust boundary.
        Ok(ResolvedTenantToken {
            tenant_id: TenantId::from_trusted(tenant_uuid),
            token_id,
        })
    }

    /// Process a single inbound email. The flow is:
    ///   1. Dedup on (tenant_id, message_id). If hit, return the
    ///      existing ticket with `deduplicated=true`. Idempotent: a
    ///      gateway retrying the same Message-Id always gets the
    ///      same ticket id.
    ///   2. Thread: if any `references` entry matches an existing
    ///      ticket's `email_message_id` in the same tenant, return
    ///      that ticket with `threaded=true`. Phase 1 only returns
    ///      the existing id; Phase 2 will append a comment.
    ///   3. Contact lookup: find a contact by (tenant_id,
    ///      lower(email) = lower(from_email)). If absent, return 422
    ///      so the gateway can either drop the message or surface the
    ///      "sender not allowlisted" reason. Auto-creating contacts
    ///      is Phase 2 (requires a tenant-configured fallback
    ///      company so the new contact has somewhere to live).
    ///   4. Creator lookup: first active admin/manager in the tenant
    ///      (mirrors `TicketService::create_portal_ticket`'s
    ///      attribution pattern - email-intake has no agent
    ///      identity, so attribution falls on the tenant's default
    ///      operator).
    ///   5. Create the ticket via `TicketService::create_ticket`
    ///      with `source='email'` and `email_message_id` set. The
    ///      partial unique index on (tenant_id, email_message_id)
    ///      catches concurrent dedup races at the DB layer; the
    ///      service translates the constraint hit back to a dedup
    ///      response by re-running step 1.
    pub async fn intake(
        &self,
        tenant_id: TenantId,
        req: EmailIntakeRequest,
    ) -> AppResult<EmailIntakeResponse> {
        // Step 1: dedup.
        if let Some((id, number)) = self.find_by_message_id(tenant_id, &req.message_id).await? {
            return Ok(EmailIntakeResponse {
                ticket_id: id,
                ticket_number: number,
                created: false,
                deduplicated: true,
                threaded: false,
            });
        }
        // Step 2: thread by References / In-Reply-To.
        if !req.references.is_empty() {
            if let Some((id, number)) = self.find_by_references(tenant_id, &req.references).await? {
                return Ok(EmailIntakeResponse {
                    ticket_id: id,
                    ticket_number: number,
                    created: false,
                    deduplicated: false,
                    threaded: true,
                });
            }
        }
        // Step 3: contact lookup (case-insensitive). Email-intake has
        // no portal-like identity to associate the ticket with; the
        // From: address is the only signal.
        let from = req.from_email.to_lowercase();
        let contact_row: Option<(Uuid, Uuid)> = sqlx::query_as(
            "SELECT id, company_id FROM contacts \
             WHERE tenant_id = $1 AND lower(email) = $2 LIMIT 1",
        )
        .bind(tenant_id)
        .bind(&from)
        .fetch_optional(&self.pool)
        .await?;
        let (contact_id, company_id) = contact_row.ok_or_else(|| {
            AppError::BadRequest(format!(
                "No contact found for from_email='{from}'; the sender must exist as a tenant contact before email-intake can create a ticket",
            ))
        })?;
        // Step 4: creator (first admin/manager). Mirrors the portal
        // ticket path - the FK on `tickets.created_by_id` is NOT NULL
        // and email-intake has no agent identity to attribute to.
        let creator: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM users \
             WHERE tenant_id = $1 AND status = 'active' \
               AND role IN ('super_admin', 'admin', 'manager') \
             ORDER BY created_at LIMIT 1",
        )
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?;
        let creator = creator.ok_or(AppError::Configuration(
            "Cannot create email-intake ticket: tenant has no admin/manager user to attribute it to"
                .into(),
        ))?;
        // Step 5: build the request and create. The description
        // prologue carries the From: display name + address so the
        // agent reading the ticket immediately knows who sent it,
        // even when the contact record is missing fields.
        let description = build_description(&req);
        let create_req = mokosh_types::tickets::CreateTicketRequest {
            title: req.subject.clone(),
            description: Some(description),
            priority_id: None,
            type_id: None,
            category_id: None,
            queue_id: None,
            source: mokosh_types::tickets::TicketSource::Email,
            company_id,
            contact_id: Some(contact_id),
            site_id: None,
            assigned_to_id: None,
            team_id: None,
            contract_id: None,
            sla_id: None,
            scheduled_start: None,
            scheduled_end: None,
            estimated_hours: None,
            is_billable: false,
            asset_id: None,
            custom_fields: serde_json::Value::Null,
            tags: vec![],
            source_kb_article_id: None,
            email_message_id: Some(req.message_id.clone()),
            email_thread_id: None,
        };
        let ctx = crate::modules::audit::AuditCtx::system(tenant_id.get());
        match self
            .tickets
            .create_ticket(tenant_id, creator, &create_req, &ctx)
            .await
        {
            Ok(ticket) => Ok(EmailIntakeResponse {
                ticket_id: ticket.id,
                ticket_number: ticket.ticket_number,
                created: true,
                deduplicated: false,
                threaded: false,
            }),
            Err(e) => {
                // The partial unique index on (tenant_id,
                // email_message_id) catches a concurrent dedup race:
                // a sibling intake of the same Message-Id won the
                // INSERT, this one fails with a unique violation.
                // Re-run step 1 to fetch the winner and return its
                // id with `deduplicated=true`, so the gateway sees
                // the same idempotent response it would have seen on
                // a sequential retry.
                if is_unique_violation(&e) {
                    if let Some((id, number)) =
                        self.find_by_message_id(tenant_id, &req.message_id).await?
                    {
                        return Ok(EmailIntakeResponse {
                            ticket_id: id,
                            ticket_number: number,
                            created: false,
                            deduplicated: true,
                            threaded: false,
                        });
                    }
                }
                Err(e)
            }
        }
    }

    async fn find_by_message_id(
        &self,
        tenant_id: TenantId,
        message_id: &str,
    ) -> AppResult<Option<(Uuid, String)>> {
        let row = sqlx::query_as::<_, (Uuid, String)>(
            "SELECT id, ticket_number FROM tickets \
             WHERE tenant_id = $1 AND email_message_id = $2 LIMIT 1",
        )
        .bind(tenant_id)
        .bind(message_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    async fn find_by_references(
        &self,
        tenant_id: TenantId,
        references: &[String],
    ) -> AppResult<Option<(Uuid, String)>> {
        let row = sqlx::query_as::<_, (Uuid, String)>(
            "SELECT id, ticket_number FROM tickets \
             WHERE tenant_id = $1 AND email_message_id = ANY($2) \
             ORDER BY created_at DESC LIMIT 1",
        )
        .bind(tenant_id)
        .bind(references)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }
}

/// Surface From-line + arrival timestamp into the ticket description
/// prologue so the agent has the email context at a glance. The
/// original body follows unmodified.
fn build_description(req: &EmailIntakeRequest) -> String {
    let now: DateTime<Utc> = Utc::now();
    let from = match &req.from_name {
        Some(name) if !name.trim().is_empty() => format!("{} <{}>", name.trim(), req.from_email),
        _ => req.from_email.clone(),
    };
    let body = req
        .body_text
        .as_deref()
        .unwrap_or("(no plaintext body provided)");
    format!(
        "From: {from}\nReceived: {received}\n\n{body}",
        received = now.to_rfc3339(),
    )
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    let out = h.finalize();
    let mut s = String::with_capacity(64);
    for b in out {
        use std::fmt::Write;
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

fn is_unique_violation(err: &AppError) -> bool {
    // AppError wraps sqlx::Error; the constraint hit surfaces as a
    // Database error with the SQLSTATE `23505`. The wrapped error
    // round-trips its string representation, which always carries
    // the SQLSTATE on the standard sqlx Display impl, so a substring
    // check is a tight enough match without taking a typed
    // dependency on sqlx's `Postgres` driver here.
    err.to_string().contains("23505")
}
