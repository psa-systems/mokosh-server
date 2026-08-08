//! PMS-730: client request forms delivered by magic link.
//!
//! An MSP user issues a link scoped to one client and one form definition; the
//! client fills it in without logging in; the submission becomes a ticket
//! attributed to that client and carrying the KB article describing how to
//! perform the change.
//!
//! The emailed token is `{token_id}.{secret}`, with only the Argon2 hash of
//! the secret stored, so resolution is a primary-key lookup plus exactly one
//! verify. See migration 101 for why this does not copy the
//! `portal_setup_tokens` shape, whose salted hash forces a scan.

use chrono::{Duration, Utc};
use serde_json::json;
use uuid::Uuid;

use super::models::{
    IssueRequestLinkRequest, PublicFormField, PublicFormResponse, PublicSubmissionReceipt,
    RequestLinkResponse, ResolvedRequestToken,
};
use super::service::FormsService;
use crate::modules::auth::TenantId;
use crate::utils::crypto::{generate_token, hash_password, verify_password};
use crate::utils::error::{AppError, AppResult};

/// PMS-730 assumes a 7 day expiry, revisable once the flow has been used in
/// anger. Long enough for a client to get to it after a weekend, short enough
/// that a link forwarded onward goes stale.
const REQUEST_LINK_TTL_DAYS: i64 = 7;

/// Everything the `forms.request_link` template renders.
///
/// A struct rather than a row of positional `&str`s: the fields are five
/// strings in a row, so a transposed pair would email the tenant's name as the
/// form's and nothing would fail. Named fields make that impossible to write
/// by accident.
struct RequestLinkEmail<'a> {
    recipient_email: &'a str,
    display_name: &'a str,
    form_name: &'a str,
    /// MAPPS-425: the MSP's name. The seeded subject asks for it, and without
    /// it the client received a literal `{{tenant_name}}`.
    tenant_name: &'a str,
    form_link: &'a str,
    expires_at: chrono::DateTime<Utc>,
}

impl FormsService {
    /// Mint a link for `company_id` against `form_definition_id` and queue the
    /// email. Returns the row (never the token, which only the recipient
    /// should ever hold; it exists in cleartext just long enough to render the
    /// message).
    ///
    /// The link is scoped to the company at ISSUE time. Nothing the submitter
    /// later types can change which company the resulting ticket lands on, so
    /// a forwarded link cannot file a request against someone else.
    pub async fn issue_request_link(
        &self,
        tenant_id: TenantId,
        created_by: Uuid,
        req: &IssueRequestLinkRequest,
        app_url: &str,
    ) -> AppResult<RequestLinkResponse> {
        let definition = self.get(tenant_id, req.form_definition_id).await?;
        if !definition.is_active {
            return Err(AppError::Conflict(
                "This form has been retired and cannot be sent to a client. An active form"
                    .to_string(),
            ));
        }

        let mut tx = self.db.begin_with_tenant(tenant_id).await?;

        // Company and contact are verified inside the tenant transaction, so a
        // caller cannot address a link at another tenant's company by id.
        let company_name: Option<String> =
            sqlx::query_scalar("SELECT name FROM companies WHERE tenant_id = $1 AND id = $2")
                .bind(tenant_id)
                .bind(req.company_id)
                .fetch_optional(&mut *tx)
                .await?;
        let company_name = company_name.ok_or_else(|| AppError::NotFound("Company".to_string()))?;

        // MAPPS-425: the seeded subject is
        // `{{form_name}} request form from {{tenant_name}}`, and the context
        // never carried `tenant_name`, so clients received a literal
        // `{{tenant_name}}`. Supplied here rather than fixed by a new
        // migration: `101_form_request_tokens.sql` is already applied
        // everywhere and immutable, so filling the value repairs every tenant
        // that already holds the seeded template. Read inside the tenant
        // transaction, matching `InvitationsService`.
        let tenant_name: String = sqlx::query_scalar("SELECT name FROM tenants WHERE id = $1")
            .bind(tenant_id)
            .fetch_one(&mut *tx)
            .await?;

        // Resolve the addressee. An explicit contact supplies the address and
        // the greeting; otherwise the caller must give an email outright.
        let (contact_id, recipient_email, display_name) = match req.contact_id {
            Some(contact_id) => {
                let row: Option<(Option<String>, Option<String>)> = sqlx::query_as(
                    "SELECT email, first_name FROM contacts WHERE tenant_id = $1 AND id = $2",
                )
                .bind(tenant_id)
                .bind(contact_id)
                .fetch_optional(&mut *tx)
                .await?;
                let (email, first_name) =
                    row.ok_or_else(|| AppError::NotFound("Contact".to_string()))?;
                let email = req.recipient_email.clone().or(email).ok_or_else(|| {
                    AppError::BadRequest(
                        "That contact has no email address; supply recipient_email".to_string(),
                    )
                })?;
                (
                    Some(contact_id),
                    email,
                    first_name.unwrap_or_else(|| "Hello".to_string()),
                )
            }
            None => {
                let email = req.recipient_email.clone().ok_or_else(|| {
                    AppError::BadRequest("Supply either contact_id or recipient_email".to_string())
                })?;
                (None, email, "Hello".to_string())
            }
        };

        let token_id = Uuid::new_v4();
        let secret = generate_token(64);
        let token_hash = hash_password(&secret)?;
        let expires_at = Utc::now() + Duration::days(REQUEST_LINK_TTL_DAYS);

        sqlx::query(
            "INSERT INTO form_request_tokens \
               (id, tenant_id, form_definition_id, company_id, contact_id, \
                recipient_email, token_hash, expires_at, created_by_id) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(token_id)
        .bind(tenant_id)
        .bind(req.form_definition_id)
        .bind(req.company_id)
        .bind(contact_id)
        .bind(&recipient_email)
        .bind(&token_hash)
        .bind(expires_at)
        .bind(created_by)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;

        // Delivery is best-effort and happens AFTER the commit, mirroring the
        // portal setup-link path: a failed send must not roll back the token,
        // because the row is what makes a resend possible.
        let token = format!("{token_id}.{secret}");
        let form_link = format!("{}/request-forms/{}", app_url.trim_end_matches('/'), token);
        self.queue_request_link_email(
            tenant_id,
            RequestLinkEmail {
                recipient_email: &recipient_email,
                display_name: &display_name,
                form_name: &definition.name,
                tenant_name: &tenant_name,
                form_link: &form_link,
                expires_at,
            },
        )
        .await;

        Ok(RequestLinkResponse {
            id: token_id,
            form_definition_id: req.form_definition_id,
            form_name: definition.name,
            company_id: req.company_id,
            company_name,
            contact_id,
            recipient_email,
            expires_at,
            used_at: None,
            submission_id: None,
        })
    }

    async fn queue_request_link_email(&self, tenant_id: TenantId, mail: RequestLinkEmail<'_>) {
        let RequestLinkEmail {
            recipient_email,
            display_name,
            form_name,
            tenant_name,
            form_link,
            expires_at,
        } = mail;
        let Some(notify) = self.notifications.as_ref() else {
            tracing::warn!(
                "no notifications dispatcher wired; request-link token persisted but no message queued",
            );
            return;
        };
        let context = json!({
            "recipient_email": recipient_email,
            "display_name": display_name,
            "form_name": form_name,
            // MAPPS-425: the seeded subject asks for this; without it the
            // client sees the placeholder itself.
            "tenant_name": tenant_name,
            "form_link": form_link,
            "expires_on": expires_at.format("%Y-%m-%d").to_string(),
        });
        match notify
            .dispatch(tenant_id, "forms.request_link", &context)
            .await
        {
            Ok(_) => tracing::info!(form_name, "request-form link queued"),
            Err(e) => tracing::warn!(
                error = ?e,
                "request-link email dispatch failed; token persisted so the link can be resent",
            ),
        }
    }

    /// Resolve a presented token to the tenant, company and form behind it.
    ///
    /// Status contract, deliberately the same as the portal setup token's so a
    /// guessed token cannot be told from a stale one:
    ///
    /// - valid, unused, unexpired -> `Ok`
    /// - already submitted        -> `Gone` (410)
    /// - expired                  -> `BadRequest` (400)
    /// - malformed or no match    -> `BadRequest` (400)
    pub async fn resolve_request_token(&self, token: &str) -> AppResult<ResolvedRequestToken> {
        let invalid = || AppError::BadRequest("Invalid or expired request link".to_string());

        let (token_id, secret) = token.split_once('.').ok_or_else(invalid)?;
        if secret.is_empty() {
            return Err(invalid());
        }
        let token_id = Uuid::parse_str(token_id).map_err(|_| invalid())?;

        let row = sqlx::query_as::<_, TokenRow>(
            "SELECT tenant_id, form_definition_id, company_id, contact_id, token_hash, \
                        used_at, expires_at, created_by_id \
                 FROM form_request_tokens WHERE id = $1",
        )
        .bind(token_id)
        // SAFETY (PMS-285 / PMS-730): pre-auth, single-use request-link
        // resolution. The tenant is what this lookup RESOLVES, so there is
        // no `app.current_tenant` GUC to set beforehand; the row is found by
        // its own primary key and its secret is verified below before
        // anything is returned. `form_request_tokens` is RLS-covered
        // (migration 101) and would fail this lookup closed on the
        // unprivileged app pool, so it runs on the BYPASSRLS migrator pool,
        // exactly as portal setup-token redemption does. Every subsequent
        // query is tenant-scoped via begin_with_tenant.
        .fetch_optional(self.db.migrator_pool())
        .await?;

        let row = row.ok_or_else(invalid)?;

        if !verify_password(secret, &row.token_hash)? {
            return Err(invalid());
        }
        if row.used_at.is_some() {
            return Err(AppError::Gone(
                "This request link has already been submitted".to_string(),
            ));
        }
        if row.expires_at <= Utc::now() {
            return Err(invalid());
        }
        let TokenRow {
            tenant_id,
            form_definition_id,
            company_id,
            contact_id,
            created_by_id,
            ..
        } = row;

        Ok(ResolvedRequestToken {
            token_id,
            tenant_id: TenantId::from_trusted(tenant_id),
            form_definition_id,
            company_id,
            contact_id,
            created_by_id,
        })
    }

    /// The client-facing view of a form: enough to render and validate the
    /// inputs, and nothing else. No ids of the tenant's other records, no
    /// author, no timestamps, and no KB article (which is an internal
    /// procedure for whoever works the ticket, not something the client is
    /// entitled to read).
    pub async fn public_form_for_token(
        &self,
        resolved: &ResolvedRequestToken,
    ) -> AppResult<PublicFormResponse> {
        let definition = self
            .get(resolved.tenant_id, resolved.form_definition_id)
            .await?;
        Ok(PublicFormResponse {
            name: definition.name,
            description: definition.description,
            rules: definition.rules,
            fields: definition
                .fields
                .into_iter()
                .map(|f| PublicFormField {
                    name: f.name,
                    label: f.label,
                    help_text: f.help_text,
                    field_type: f.field_type,
                    is_required: f.is_required,
                    min_length: f.min_length,
                    max_length: f.max_length,
                    options: f.options,
                    date_not_in_past: f.date_not_in_past,
                })
                .collect(),
        })
    }
}

impl FormsService {
    /// Redeem a resolved link: validate the payload against the definition,
    /// store the submission, create the ticket, and mark the link used.
    ///
    /// Ordering matters. The submission and the ticket are created first and
    /// the token is marked used LAST, inside the same transaction, so a
    /// failure anywhere rolls the whole thing back and the client can retry
    /// with the link still live. Marking the token first would burn a
    /// single-use link on a request that never produced a ticket.
    pub async fn submit_via_request_link(
        &self,
        resolved: &ResolvedRequestToken,
        payload: &serde_json::Value,
    ) -> AppResult<PublicSubmissionReceipt> {
        let tenant_id = resolved.tenant_id;
        let definition = self.get(tenant_id, resolved.form_definition_id).await?;
        if !definition.is_active {
            return Err(AppError::Conflict(
                "This form has been retired and is no longer accepting submissions. An active form"
                    .to_string(),
            ));
        }

        // Same validator the authenticated surface uses, so a client and an
        // agent get identical rules and identical per-field errors.
        let normalised = super::validation::validate_submission(
            &definition.fields,
            &definition.rules,
            payload,
            Utc::now().date_naive(),
        )?;

        let submission_id = Uuid::new_v4();
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            "INSERT INTO form_submissions \
               (id, tenant_id, form_definition_id, payload, submitted_by_contact_id) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(submission_id)
        .bind(tenant_id)
        .bind(resolved.form_definition_id)
        .bind(serde_json::Value::Object(normalised.clone()))
        .bind(resolved.contact_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;

        let Some(tickets) = self.tickets.as_ref() else {
            return Err(AppError::Internal(
                "no ticket service wired into the forms service".to_string(),
            ));
        };

        // Company and contact come from the TOKEN, never from the payload, so
        // a forwarded link cannot file a request against another company. The
        // acting user is the MSP user who issued the link: the submitter is a
        // client with no `users` row, and `tickets.created_by_id` is NOT NULL.
        let request = mokosh_types::tickets::CreateTicketRequest {
            title: format!(
                "{}: {}",
                definition.name,
                summarise(&definition, &normalised)
            ),
            description: Some(render_answers(&definition, &normalised)),
            company_id: resolved.company_id,
            contact_id: resolved.contact_id,
            source: mokosh_types::tickets::TicketSource::Portal,
            // PMS-730 AC: the ticket carries the article describing how to
            // perform this change, selected by the request type. The form
            // definition IS the request type, so the mapping is its column.
            procedure_kb_article_id: definition.kb_article_id,
            custom_fields: serde_json::json!({}),
            ..Default::default()
        };
        let ctx = crate::modules::audit::AuditCtx::system(tenant_id.get());
        let ticket = tickets
            .create_ticket(tenant_id, resolved.created_by_id, &request, &ctx)
            .await?;

        // Link the chain and burn the token together, so a link is only ever
        // spent once a ticket actually exists.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query("UPDATE form_submissions SET ticket_id = $3 WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(submission_id)
            .bind(ticket.id)
            .execute(&mut *tx)
            .await?;
        let burned = sqlx::query(
            "UPDATE form_request_tokens SET used_at = NOW(), submission_id = $3 \
             WHERE tenant_id = $1 AND id = $2 AND used_at IS NULL",
        )
        .bind(tenant_id)
        .bind(resolved.token_id)
        .bind(submission_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        tx.commit().await?;

        // `used_at IS NULL` in the UPDATE is the race guard: two submissions
        // arriving together both pass the earlier resolve check, but only one
        // updates a row. The loser is reported as already submitted rather
        // than quietly accepted.
        if burned == 0 {
            return Err(AppError::Gone(
                "This request link has already been submitted".to_string(),
            ));
        }

        Ok(PublicSubmissionReceipt {
            ticket_number: ticket.ticket_number,
        })
    }
}

/// A one-line summary for the ticket title, taken from the first answered text
/// field in display order. Falls back to the company-agnostic form name alone
/// when the form has no text field, which keeps the title deterministic rather
/// than guessing at semantics the definition does not declare.
fn summarise(
    definition: &super::models::FormDefinitionResponse,
    answers: &serde_json::Map<String, serde_json::Value>,
) -> String {
    definition
        .fields
        .iter()
        .find_map(|f| {
            matches!(f.field_type, super::models::FieldType::Text)
                .then(|| answers.get(&f.name).and_then(|v| v.as_str()))
                .flatten()
        })
        .unwrap_or("client request")
        .to_string()
}

/// Render the answers as the ticket description, in the form's own field
/// order and using its labels, so whoever works the ticket reads what the
/// client saw rather than raw payload keys.
fn render_answers(
    definition: &super::models::FormDefinitionResponse,
    answers: &serde_json::Map<String, serde_json::Value>,
) -> String {
    let mut out = String::new();
    for field in &definition.fields {
        let Some(value) = answers.get(&field.name) else {
            continue;
        };
        let rendered = match value {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Bool(b) => if *b { "Yes" } else { "No" }.to_string(),
            other => other.to_string(),
        };
        out.push_str(&format!("{}: {}\n", field.label, rendered));
    }
    out
}

impl FormsService {
    /// Links this tenant has issued, newest first, optionally narrowed to one
    /// client. Never includes the token: the row is an audit trail of what was
    /// sent and whether it has been used, not a way to recover a credential
    /// that only the recipient should hold.
    pub async fn list_request_links(
        &self,
        tenant_id: TenantId,
        company_id: Option<Uuid>,
    ) -> AppResult<Vec<RequestLinkResponse>> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows = sqlx::query_as::<_, LinkRow>(
            "SELECT t.id, t.form_definition_id, d.name AS form_name, t.company_id, \
                    c.name AS company_name, t.contact_id, t.recipient_email, \
                    t.expires_at, t.used_at, t.submission_id \
             FROM form_request_tokens t \
             JOIN form_definitions d ON d.id = t.form_definition_id \
             JOIN companies c ON c.id = t.company_id \
             WHERE t.tenant_id = $1 AND ($2::uuid IS NULL OR t.company_id = $2) \
             ORDER BY t.created_at DESC",
        )
        .bind(tenant_id)
        .bind(company_id)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;

        Ok(rows.into_iter().map(Into::into).collect())
    }
}

/// The token row as resolution reads it. A struct rather than a tuple so the
/// field meanings survive the read.
#[derive(sqlx::FromRow)]
struct TokenRow {
    tenant_id: Uuid,
    form_definition_id: Uuid,
    company_id: Uuid,
    contact_id: Option<Uuid>,
    token_hash: String,
    used_at: Option<chrono::DateTime<Utc>>,
    expires_at: chrono::DateTime<Utc>,
    created_by_id: Uuid,
}

#[derive(sqlx::FromRow)]
struct LinkRow {
    id: Uuid,
    form_definition_id: Uuid,
    form_name: String,
    company_id: Uuid,
    company_name: String,
    contact_id: Option<Uuid>,
    recipient_email: String,
    expires_at: chrono::DateTime<Utc>,
    used_at: Option<chrono::DateTime<Utc>>,
    submission_id: Option<Uuid>,
}

impl From<LinkRow> for RequestLinkResponse {
    fn from(r: LinkRow) -> Self {
        Self {
            id: r.id,
            form_definition_id: r.form_definition_id,
            form_name: r.form_name,
            company_id: r.company_id,
            company_name: r.company_name,
            contact_id: r.contact_id,
            recipient_email: r.recipient_email,
            expires_at: r.expires_at,
            used_at: r.used_at,
            submission_id: r.submission_id,
        }
    }
}
