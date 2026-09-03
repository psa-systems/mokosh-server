//! PMS-450 phase 1: email-intake service.

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use rand::RngCore;

use super::models::{
    CreateIntakeTokenRequest, CreatedIntakeTokenResponse, EmailIntakeLogResponse,
    EmailIntakeRequest, EmailIntakeResponse, IntakeTokenResponse,
};
use crate::db::Database;
use crate::modules::auth::TenantId;
use crate::modules::tickets::{AttachmentService, TicketService};
use crate::utils::error::{AppError, AppResult};

#[derive(Debug, Clone)]
pub struct ResolvedTenantToken {
    pub tenant_id: TenantId,
    pub token_id: Uuid,
}

/// PMS-683: `email_intake_log` and `tenant_intake_tokens` reads/writes run
/// through `Database::begin_with_tenant` (GUC-safe under the fail-closed
/// `tenant_isolation` RLS policy, migration 095). The one exception is the
/// cross-tenant `resolve_token` hash lookup, which by design has no tenant
/// context and runs on the BYPASSRLS migrator pool.
///
/// PMS-692: the cross-table helper reads/writes (contacts / tickets / users /
/// ticket_notes / tenant_settings) are ALSO RLS-covered (migration 038), so they
/// too run through `begin_with_tenant` - the earlier note that they used
/// `self.db.pool()` "as before" was wrong: on the NOBYPASSRLS serving connection
/// they fail-closed (no creator found -> intake errors; contact lookup empty ->
/// duplicate contacts).
#[derive(Clone)]
pub struct EmailIntakeService {
    db: Database,
    tickets: TicketService,
    attachments: AttachmentService,
}

impl EmailIntakeService {
    pub fn new(db: Database, tickets: TicketService, attachments: AttachmentService) -> Self {
        Self {
            db,
            tickets,
            attachments,
        }
    }

    /// Resolve a presented bearer to its owning tenant. The bearer is
    /// SHA-256-hashed and matched against `tenant_intake_tokens`.
    /// Revoked tokens (`revoked_at IS NOT NULL`) and tokens of the
    /// wrong `kind` are rejected here so the route handler does not
    /// have to repeat the check. Bumps `last_used_at` so an operator
    /// can see at a glance which tokens are live.
    pub async fn resolve_token(&self, bearer: &str) -> AppResult<ResolvedTenantToken> {
        let hash = sha256_hex(bearer.as_bytes());
        // SAFETY (PMS-683): resolve-by-hash is cross-tenant BY DESIGN - the
        // presented bearer is the only identity, so there is no tenant context
        // to set as the RLS GUC. This lookup, and the paired `last_used_at`
        // bump, run on the BYPASSRLS migrator pool. `tenant_intake_tokens` has
        // RLS enabled (migration 095); every OTHER access to it is tenant-scoped
        // via `begin_with_tenant`. `token_hash` is a unique SHA-256, so the
        // lookup still resolves exactly one tenant.
        let row: Option<(Uuid, Uuid)> = sqlx::query_as(
            "SELECT id, tenant_id FROM tenant_intake_tokens \
             WHERE token_hash = $1 \
               AND kind = 'email_intake' \
               AND revoked_at IS NULL",
        )
        .bind(&hash)
        .fetch_optional(self.db.migrator_pool())
        .await?;
        let (token_id, tenant_uuid) = row.ok_or(AppError::Unauthorized)?;
        sqlx::query("UPDATE tenant_intake_tokens SET last_used_at = NOW() WHERE id = $1")
            .bind(token_id)
            .execute(self.db.migrator_pool())
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
        // PMS-469: log the raw payload BEFORE any matching so even a
        // hard error has an audit row to debug from. The row id is
        // threaded into `intake_inner` and UPDATEd at the tail with
        // `ticket_id` (success) or `error` (failure).
        let log_id = self.record_intake_log(tenant_id, &req).await?;
        let result = self.intake_inner(tenant_id, &req).await;
        self.finalise_intake_log(tenant_id, log_id, &result).await?;
        result
    }

    async fn intake_inner(
        &self,
        tenant_id: TenantId,
        req: &EmailIntakeRequest,
    ) -> AppResult<EmailIntakeResponse> {
        // Step 1: dedup.
        if let Some((id, number)) = self.find_by_message_id(tenant_id, &req.message_id).await? {
            return Ok(EmailIntakeResponse {
                ticket_id: id,
                ticket_number: number,
                created: false,
                deduplicated: true,
                threaded: false,
                comment_added: false,
                attachments_stored: 0,
            });
        }
        // Step 2: thread by References / In-Reply-To. PMS-469 phase 2:
        // when we hit, append the body as a `public` note on the
        // matched ticket attributed (via `created_by_contact_id`) to
        // the resolved sender contact. The note's `created_by_id`
        // (NOT NULL FK on users) falls back to a tenant admin -
        // email-intake has no agent identity, so attribution mirrors
        // the create path's "first active admin" pattern.
        if !req.references.is_empty() {
            if let Some((id, number)) = self.find_by_references(tenant_id, &req.references).await? {
                let resolved_contact = self
                    .resolve_or_create_contact(tenant_id, req)
                    .await
                    .ok()
                    .flatten();
                // PMS-450 AC3: the reply body becomes a public note and
                // its attachments hang off that note (so the SPA renders
                // them in the reply, not loose on the ticket). When no
                // contact resolves, the note is skipped and so are its
                // attachments - there is no Customer to attribute either to.
                let (comment_added, attachments_stored) = if let Some((contact_id, _)) =
                    resolved_contact
                {
                    match self
                        .append_reply_comment(tenant_id, id, contact_id, req)
                        .await
                    {
                        Ok(note_id) => {
                            let stored = self
                                .store_attachments(tenant_id, id, Some(note_id), contact_id, req)
                                .await;
                            (true, stored)
                        }
                        Err(_) => (false, 0),
                    }
                } else {
                    (false, 0)
                };
                return Ok(EmailIntakeResponse {
                    ticket_id: id,
                    ticket_number: number,
                    created: false,
                    deduplicated: false,
                    threaded: true,
                    comment_added,
                    attachments_stored,
                });
            }
        }
        // Step 3: contact lookup (case-insensitive) + PMS-469 auto-
        // create fallback. The Phase 1 posture (422 on unknown sender)
        // is preserved when no fallback company is configured; when
        // the `email_intake/default_company_id` setting is set, a new
        // contact is inserted under that company before the create.
        let (contact_id, company_id) = self
            .resolve_or_create_contact(tenant_id, req)
            .await?
            .ok_or_else(|| {
                AppError::BadRequest(format!(
                    "No contact found for from_email='{from}'; the sender must exist as a tenant contact before email-intake can create a ticket. Configure tenant_settings(email_intake/default_company_id) to auto-create contacts under a fallback company.",
                    from = req.from_email.to_lowercase(),
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
        .fetch_optional(&mut *self.db.begin_with_tenant(tenant_id).await?)
        .await?;
        let creator = creator.ok_or(AppError::Configuration(
            "Cannot create email-intake ticket: tenant has no admin/manager user to attribute it to"
                .into(),
        ))?;
        // Step 5: build the request and create. The description
        // prologue carries the From: display name + address so the
        // agent reading the ticket immediately knows who sent it,
        // even when the contact record is missing fields.
        let description = build_description(req);
        let create_req = mokosh_types::tickets::CreateTicketRequest {
            title: req.subject.clone(),
            description: Some(description),
            source: mokosh_types::tickets::TicketSource::Email,
            company_id,
            contact_id: Some(contact_id),
            is_billable: false,
            email_message_id: Some(req.message_id.clone()),
            ..Default::default()
        };
        let ctx = crate::modules::audit::AuditCtx::system(tenant_id.get());
        match self
            .tickets
            .create_ticket(tenant_id, creator, &create_req, &ctx)
            .await
        {
            Ok(ticket) => {
                // PMS-450 AC3: store inbound attachments against the new
                // ticket (note_id = None - they belong to the opening
                // message, not a note). Attributed to the sender contact.
                let attachments_stored = self
                    .store_attachments(tenant_id, ticket.id, None, contact_id, req)
                    .await;
                Ok(EmailIntakeResponse {
                    ticket_id: ticket.id,
                    ticket_number: ticket.ticket_number,
                    created: true,
                    deduplicated: false,
                    threaded: false,
                    comment_added: false,
                    attachments_stored,
                })
            }
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
                            comment_added: false,
                            attachments_stored: 0,
                        });
                    }
                }
                Err(e)
            }
        }
    }

    /// PMS-469: contact lookup that auto-creates when the per-tenant
    /// `email_intake/default_company_id` setting is configured. Returns
    /// `Ok(Some((contact_id, company_id)))` on lookup-or-create,
    /// `Ok(None)` when the setting is unset AND no existing contact
    /// matches. Errors surface only on SQL failures.
    async fn resolve_or_create_contact(
        &self,
        tenant_id: TenantId,
        req: &EmailIntakeRequest,
    ) -> AppResult<Option<(Uuid, Uuid)>> {
        let from = req.from_email.to_lowercase();
        // PMS-692: `contacts` and `tenant_settings` are RLS-covered, so the
        // lookup, the default-company setting read, and the auto-create INSERT
        // all run under one tenant-GUC transaction.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        // `contacts.company_id` is nullable (PMS-402) and deleting a company
        // now nulls it instead of deleting the contact (PMS-812), so decoding
        // it as a bare `Uuid` turned a company-less sender into a decode error
        // and a 500. A ticket still needs a company, so a company-less sender
        // falls through to the same `email_intake/default_company_id` setting
        // the auto-create path uses; with that unset the caller's explicit 400
        // fires instead.
        let existing: Option<(Uuid, Option<Uuid>)> = sqlx::query_as(
            "SELECT id, company_id FROM contacts \
             WHERE tenant_id = $1 AND lower(email) = $2 LIMIT 1",
        )
        .bind(tenant_id)
        .bind(&from)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some((contact_id, Some(company_id))) = existing {
            return Ok(Some((contact_id, company_id)));
        }
        let default_company =
            crate::modules::settings::read_email_intake_default_company(&mut tx, tenant_id.get())
                .await?;
        let Some(company_id) = default_company else {
            return Ok(None);
        };
        if let Some((contact_id, None)) = existing {
            tracing::warn!(
                %contact_id,
                %company_id,
                "email-intake sender has no company; using the tenant default company",
            );
            return Ok(Some((contact_id, company_id)));
        }
        let (first, last) = split_display_name(req.from_name.as_deref());
        let contact_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO contacts \
                 (id, tenant_id, company_id, first_name, last_name, email, contact_type) \
             VALUES ($1, $2, $3, $4, $5, $6, 'primary')",
        )
        .bind(contact_id)
        .bind(tenant_id)
        .bind(company_id)
        .bind(first)
        .bind(last)
        .bind(&from)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(Some((contact_id, company_id)))
    }

    /// PMS-469: append the reply body to the matched ticket as a
    /// `note_type='public'` row attributed to the sender contact.
    /// `created_by_id` (NOT NULL FK on users) falls back to the
    /// tenant's first active admin/manager - email-intake has no
    /// agent identity. The SPA renders Customer when
    /// `created_by_contact_id IS NOT NULL`, so the attribution is
    /// surfaced even though a user row also hangs off the note.
    async fn append_reply_comment(
        &self,
        tenant_id: TenantId,
        ticket_id: Uuid,
        contact_id: Uuid,
        req: &EmailIntakeRequest,
    ) -> AppResult<Uuid> {
        let creator: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM users \
             WHERE tenant_id = $1 AND status = 'active' \
               AND role IN ('super_admin', 'admin', 'manager') \
             ORDER BY created_at LIMIT 1",
        )
        .bind(tenant_id)
        .fetch_optional(&mut *self.db.begin_with_tenant(tenant_id).await?)
        .await?;
        let Some(creator) = creator else {
            return Err(AppError::Configuration(
                "Cannot append reply comment: tenant has no admin/manager user to attribute to"
                    .into(),
            ));
        };
        let content = req
            .body_text
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or("(reply body empty)");
        // PMS-692: `ticket_notes` is RLS-covered; the INSERT's WITH CHECK needs
        // the tenant GUC, so run it in a `begin_with_tenant` transaction.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let note_id: Uuid = sqlx::query_scalar(
            "INSERT INTO ticket_notes \
                 (tenant_id, ticket_id, note_type, content, created_by_id, created_by_contact_id) \
             VALUES ($1, $2, 'public', $3, $4, $5) RETURNING id",
        )
        .bind(tenant_id)
        .bind(ticket_id)
        .bind(content)
        .bind(creator)
        .bind(contact_id)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(note_id)
    }

    /// PMS-450 AC3: decode and persist every inbound attachment to the
    /// shared `ticket_attachments` blob path, attributed to the sender
    /// contact. Best-effort per part: a base64 payload that fails to
    /// decode, or a blob that exceeds the storage size cap, is logged
    /// and skipped rather than failing the whole intake (the ticket /
    /// reply must still land). Returns the count actually stored.
    async fn store_attachments(
        &self,
        tenant_id: TenantId,
        ticket_id: Uuid,
        note_id: Option<Uuid>,
        contact_id: Uuid,
        req: &EmailIntakeRequest,
    ) -> u32 {
        let mut stored = 0u32;
        for att in &req.attachments {
            let bytes = match STANDARD.decode(att.content_base64.as_bytes()) {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!(
                        %ticket_id, file_name = %att.file_name,
                        "skipping email attachment: base64 decode failed: {e}"
                    );
                    continue;
                }
            };
            let mime = att
                .mime_type
                .clone()
                .unwrap_or_else(|| "application/octet-stream".to_string());
            match self
                .attachments
                .store_email_attachment(
                    tenant_id.get(),
                    ticket_id,
                    note_id,
                    contact_id,
                    att.file_name.clone(),
                    mime,
                    bytes,
                )
                .await
            {
                Ok(_) => stored += 1,
                Err(e) => {
                    tracing::warn!(
                        %ticket_id, file_name = %att.file_name,
                        "skipping email attachment: storage failed: {e}"
                    );
                }
            }
        }
        stored
    }

    /// PMS-469: insert the `email_intake_log` row at the top of the
    /// flow with the raw payload. The row is later UPDATEd via
    /// `finalise_intake_log` with `ticket_id` (success) or `error`
    /// (failure) so an admin filter by `ticket_id IS NULL` plus
    /// `error IS NOT NULL` surfaces the recent failures.
    async fn record_intake_log(
        &self,
        tenant_id: TenantId,
        req: &EmailIntakeRequest,
    ) -> AppResult<Uuid> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let log_id: Uuid = sqlx::query_scalar(
            "INSERT INTO email_intake_log \
                 (tenant_id, message_id, raw_headers, raw_body_text, raw_body_html) \
             VALUES ($1, $2, $3, $4, $5) RETURNING id",
        )
        .bind(tenant_id)
        .bind(&req.message_id)
        .bind(&req.raw_headers)
        .bind(req.body_text.as_deref())
        .bind(req.body_html.as_deref())
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(log_id)
    }

    /// PMS-469: settle the in-flight log row. On success, stamp
    /// `ticket_id`. On failure, stamp `error` (truncated to fit the
    /// TEXT column safely). Best-effort: a failed UPDATE here is
    /// logged but does NOT mask the original intake outcome.
    async fn finalise_intake_log(
        &self,
        tenant_id: TenantId,
        log_id: Uuid,
        result: &AppResult<EmailIntakeResponse>,
    ) -> AppResult<()> {
        let (ticket_id, error): (Option<Uuid>, Option<String>) = match result {
            Ok(resp) => (Some(resp.ticket_id), None),
            Err(e) => (None, Some(e.to_string())),
        };
        // Best-effort settle inside a tenant-GUC transaction so the UPDATE is
        // RLS-scoped (the row was written under the same tenant). A failure
        // here is logged but does NOT mask the original intake outcome.
        let r: AppResult<()> = async {
            let mut tx = self.db.begin_with_tenant(tenant_id).await?;
            sqlx::query("UPDATE email_intake_log SET ticket_id = $1, error = $2 WHERE id = $3")
                .bind(ticket_id)
                .bind(error)
                .bind(log_id)
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
            Ok(())
        }
        .await;
        if let Err(e) = r {
            tracing::warn!(?e, %log_id, "failed to finalise email_intake_log row");
        }
        Ok(())
    }

    /// PMS-469: read one log row for the admin GET endpoint. Tenant-
    /// scoped so an admin cannot read another tenant's log even with
    /// a guessed UUID.
    pub async fn get_intake_log(
        &self,
        tenant_id: TenantId,
        id: Uuid,
    ) -> AppResult<EmailIntakeLogResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row: Option<IntakeLogRow> = sqlx::query_as(
            "SELECT id, tenant_id, message_id, ticket_id, raw_headers, \
                    raw_body_text, raw_body_html, received_at, error \
             FROM email_intake_log \
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        row.map(Into::into)
            .ok_or(AppError::NotFound("Email intake log".into()))
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
        .fetch_optional(&mut *self.db.begin_with_tenant(tenant_id).await?)
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
        .fetch_optional(&mut *self.db.begin_with_tenant(tenant_id).await?)
        .await?;
        Ok(row)
    }

    // --- PMS-450 phase 2: admin-facing intake-token CRUD --------------------

    /// List every intake token (active + revoked) for the caller's
    /// tenant. Operator-facing surface, so includes revoked rows
    /// (the operator wants to confirm they revoked the right one);
    /// the auth-resolving `resolve_token` path keeps filtering them.
    pub async fn list_tokens(&self, tenant_id: TenantId) -> AppResult<Vec<IntakeTokenResponse>> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows = sqlx::query_as::<_, IntakeTokenRow>(
            "SELECT id, kind, label, last_used_at, created_at, revoked_at \
             FROM tenant_intake_tokens \
             WHERE tenant_id = $1 \
             ORDER BY revoked_at NULLS FIRST, created_at DESC",
        )
        .bind(tenant_id)
        .fetch_all(&mut *tx)
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    /// Mint a new bearer for the caller's tenant. Returns the
    /// plaintext token EXACTLY ONCE in the response; only the
    /// SHA-256 hash hits the DB. Re-fetching the row later yields
    /// the metadata-only `IntakeTokenResponse`. Rotation = revoke +
    /// mint a fresh one; there is no update endpoint.
    pub async fn create_token(
        &self,
        tenant_id: TenantId,
        req: CreateIntakeTokenRequest,
    ) -> AppResult<CreatedIntakeTokenResponse> {
        if req.kind != "email_intake" {
            return Err(AppError::BadRequest(format!(
                "Unsupported kind='{}'. Phase 2 only accepts 'email_intake'.",
                req.kind,
            )));
        }
        // 32 random bytes URL-safe base64-encoded gives ~43 chars of
        // bearer with 256 bits of entropy. Matches the OIDC client-
        // secret minting pattern in mokosh-bootstrap.rs (PMS-122).
        let mut bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        let plaintext = URL_SAFE_NO_PAD.encode(bytes);
        let hash = sha256_hex(plaintext.as_bytes());

        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row: IntakeTokenRow = sqlx::query_as(
            "INSERT INTO tenant_intake_tokens (tenant_id, kind, token_hash, label) \
             VALUES ($1, $2, $3, $4) \
             RETURNING id, kind, label, last_used_at, created_at, revoked_at",
        )
        .bind(tenant_id)
        .bind(&req.kind)
        .bind(&hash)
        .bind(&req.label)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        let metadata: IntakeTokenResponse = row.into();
        Ok(CreatedIntakeTokenResponse {
            token_metadata: metadata,
            token: plaintext,
        })
    }

    /// Revoke a token by setting `revoked_at = NOW()`. Idempotent:
    /// a re-revoke of an already-revoked row is a no-op (does not
    /// move the timestamp), and a missing id surfaces as 404 so the
    /// SPA can confirm the row really existed.
    pub async fn revoke_token(&self, tenant_id: TenantId, id: Uuid) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows = sqlx::query(
            "UPDATE tenant_intake_tokens \
                 SET revoked_at = COALESCE(revoked_at, NOW()) \
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        tx.commit().await?;
        if rows == 0 {
            return Err(AppError::NotFound("Intake token".into()));
        }
        Ok(())
    }
}

#[derive(Debug, sqlx::FromRow)]
struct IntakeTokenRow {
    id: Uuid,
    kind: String,
    label: String,
    last_used_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
}

impl From<IntakeTokenRow> for IntakeTokenResponse {
    fn from(r: IntakeTokenRow) -> Self {
        Self {
            id: r.id,
            kind: r.kind,
            label: r.label,
            last_used_at: r.last_used_at,
            created_at: r.created_at,
            revoked_at: r.revoked_at,
        }
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

/// Split a `From: "First Last" <addr>` display name into a
/// (first_name, last_name) pair for the auto-create contact path.
/// Empty / whitespace-only inputs fall back to ("Contact", "")
/// because `contacts.first_name` is NOT NULL.
fn split_display_name(raw: Option<&str>) -> (String, String) {
    let trimmed = raw.map(|s| s.trim()).unwrap_or("");
    if trimmed.is_empty() {
        return ("Contact".into(), String::new());
    }
    match trimmed.split_once(' ') {
        Some((first, rest)) if !rest.trim().is_empty() => {
            (first.to_string(), rest.trim().to_string())
        }
        _ => (trimmed.to_string(), String::new()),
    }
}

#[derive(Debug, sqlx::FromRow)]
struct IntakeLogRow {
    id: Uuid,
    tenant_id: Uuid,
    message_id: String,
    ticket_id: Option<Uuid>,
    raw_headers: serde_json::Value,
    raw_body_text: Option<String>,
    raw_body_html: Option<String>,
    received_at: DateTime<Utc>,
    error: Option<String>,
}

impl From<IntakeLogRow> for EmailIntakeLogResponse {
    fn from(r: IntakeLogRow) -> Self {
        Self {
            id: r.id,
            tenant_id: r.tenant_id,
            message_id: r.message_id,
            ticket_id: r.ticket_id,
            raw_headers: r.raw_headers,
            raw_body_text: r.raw_body_text,
            raw_body_html: r.raw_body_html,
            received_at: r.received_at,
            error: r.error,
        }
    }
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
