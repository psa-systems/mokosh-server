//! PMS-731: form definition / field / submission service.
//!
//! PMS-683 posture: every query runs inside `Database::begin_with_tenant`,
//! which sets the `app.current_tenant` GUC transaction-locally, so the three
//! tables added by migration 100 are safe under their fail-closed
//! `tenant_isolation` policies. There is no pre-auth path here: the public
//! magic-link submission arrives with PMS-730, and that path will resolve a
//! tenant from its token before calling in.

use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

use super::models::{
    CreateFormDefinitionRequest, CreateFormFieldRequest, FieldType, FormDefinitionResponse,
    FormFieldResponse, FormRule, FormSubmissionResponse, UpdateFormDefinitionRequest,
};
use super::validation::validate_submission;
use crate::db::{Database, TenantTransaction};
use crate::modules::auth::TenantId;
use crate::utils::error::{AppError, AppResult, FieldError};

#[derive(Debug, FromRow)]
struct DefinitionRow {
    id: Uuid,
    name: String,
    slug: String,
    description: Option<String>,
    kb_article_id: Option<Uuid>,
    kb_article_title: Option<String>,
    rules: serde_json::Value,
    is_active: bool,
    created_by_id: Uuid,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, FromRow)]
struct FieldRow {
    id: Uuid,
    form_definition_id: Uuid,
    name: String,
    label: String,
    help_text: Option<String>,
    field_type: String,
    is_required: bool,
    min_length: Option<i32>,
    max_length: Option<i32>,
    options: Option<Vec<String>>,
    date_not_in_past: bool,
    sort_order: i32,
}

impl From<FieldRow> for FormFieldResponse {
    fn from(r: FieldRow) -> Self {
        Self {
            id: r.id,
            name: r.name,
            label: r.label,
            help_text: r.help_text,
            // A row whose `field_type` does not parse would mean the CHECK
            // constraint and this enum have drifted. Fall back to text rather
            // than panicking in a request path; the CHECK makes it unreachable.
            field_type: FieldType::from_str(&r.field_type).unwrap_or(FieldType::Text),
            is_required: r.is_required,
            min_length: r.min_length,
            max_length: r.max_length,
            options: r.options,
            date_not_in_past: r.date_not_in_past,
            sort_order: r.sort_order,
        }
    }
}

#[derive(Debug, FromRow)]
struct SubmissionRow {
    id: Uuid,
    form_definition_id: Uuid,
    payload: serde_json::Value,
    submitted_by_contact_id: Option<Uuid>,
    ticket_id: Option<Uuid>,
    created_at: DateTime<Utc>,
}

impl From<SubmissionRow> for FormSubmissionResponse {
    fn from(r: SubmissionRow) -> Self {
        Self {
            id: r.id,
            form_definition_id: r.form_definition_id,
            payload: r.payload,
            submitted_by_contact_id: r.submitted_by_contact_id,
            ticket_id: r.ticket_id,
            created_at: r.created_at,
        }
    }
}

const DEFINITION_SELECT: &str = "
    d.id, d.name, d.slug, d.description, d.kb_article_id,
    a.title AS kb_article_title,
    d.rules, d.is_active, d.created_by_id, d.created_at, d.updated_at
";

const FIELD_SELECT: &str = "
    f.id, f.form_definition_id, f.name, f.label, f.help_text, f.field_type,
    f.is_required, f.min_length, f.max_length, f.options, f.date_not_in_past,
    f.sort_order
";

#[derive(Clone)]
pub struct FormsService {
    // `pub(super)` so the PMS-730 request-link half in `super::request_links`
    // can reach them: field privacy is module-scoped, and that is a sibling
    // module rather than a descendant of this one.
    pub(super) db: Database,
    /// Queues the request-link email (PMS-730). `None` in the tests and in
    /// any build with no dispatcher wired, where the token is still persisted
    /// so the link can be resent.
    pub(super) notifications: Option<crate::modules::notifications::NotificationsService>,
    /// Turns a submission into a ticket (PMS-730). `None` on the
    /// definition-only surface, where submissions are stored but not converted.
    pub(super) tickets: Option<crate::modules::tickets::TicketService>,
}

impl FormsService {
    pub fn new(db: Database) -> Self {
        Self {
            db,
            notifications: None,
            tickets: None,
        }
    }

    /// Wire the PMS-730 request-link flow: emailing a client their link needs
    /// the dispatcher, and converting their submission needs the ticket
    /// service.
    pub fn with_request_links(
        db: Database,
        notifications: crate::modules::notifications::NotificationsService,
        tickets: crate::modules::tickets::TicketService,
    ) -> Self {
        Self {
            db,
            notifications: Some(notifications),
            tickets: Some(tickets),
        }
    }

    pub async fn list(
        &self,
        tenant_id: TenantId,
        active_only: bool,
    ) -> AppResult<Vec<FormDefinitionResponse>> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let defs = sqlx::query_as::<_, DefinitionRow>(&format!(
            "SELECT {DEFINITION_SELECT} \
             FROM form_definitions d \
             LEFT JOIN kb_articles a ON a.id = d.kb_article_id \
             WHERE d.tenant_id = $1 AND ($2 = false OR d.is_active = true) \
             ORDER BY d.name ASC"
        ))
        .bind(tenant_id)
        .bind(active_only)
        .fetch_all(&mut *tx)
        .await?;

        let ids: Vec<Uuid> = defs.iter().map(|d| d.id).collect();
        let fields = sqlx::query_as::<_, FieldRow>(&format!(
            "SELECT {FIELD_SELECT} FROM form_fields f \
             WHERE f.tenant_id = $1 AND f.form_definition_id = ANY($2) \
             ORDER BY f.sort_order ASC, f.name ASC"
        ))
        .bind(tenant_id)
        .bind(&ids)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;

        Ok(defs
            .into_iter()
            .map(|d| {
                let own: Vec<FormFieldResponse> = fields
                    .iter()
                    .filter(|f| f.form_definition_id == d.id)
                    .map(|f| FormFieldResponse {
                        id: f.id,
                        name: f.name.clone(),
                        label: f.label.clone(),
                        help_text: f.help_text.clone(),
                        field_type: FieldType::from_str(&f.field_type).unwrap_or(FieldType::Text),
                        is_required: f.is_required,
                        min_length: f.min_length,
                        max_length: f.max_length,
                        options: f.options.clone(),
                        date_not_in_past: f.date_not_in_past,
                        sort_order: f.sort_order,
                    })
                    .collect();
                build_response(d, own)
            })
            .collect())
    }

    pub async fn get(&self, tenant_id: TenantId, id: Uuid) -> AppResult<FormDefinitionResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let def = sqlx::query_as::<_, DefinitionRow>(&format!(
            "SELECT {DEFINITION_SELECT} \
             FROM form_definitions d \
             LEFT JOIN kb_articles a ON a.id = d.kb_article_id \
             WHERE d.tenant_id = $1 AND d.id = $2"
        ))
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| AppError::NotFound("Form definition".to_string()))?;

        let fields = fetch_fields(&mut tx, tenant_id, id).await?;
        tx.commit().await?;
        Ok(build_response(def, fields))
    }

    pub async fn create(
        &self,
        tenant_id: TenantId,
        created_by: Uuid,
        req: CreateFormDefinitionRequest,
    ) -> AppResult<FormDefinitionResponse> {
        check_field_set(&req.fields)?;
        check_rules(&req.rules, &req.fields)?;

        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let taken: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM form_definitions WHERE tenant_id = $1 AND slug = $2)",
        )
        .bind(tenant_id)
        .bind(&req.slug)
        .fetch_one(&mut *tx)
        .await?;
        if taken {
            return Err(AppError::Conflict(format!(
                "A form with slug `{}`",
                req.slug
            )));
        }

        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO form_definitions \
             (id, tenant_id, name, slug, description, kb_article_id, rules, is_active, created_by_id) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(&req.name)
        .bind(&req.slug)
        .bind(&req.description)
        .bind(req.kb_article_id)
        .bind(serde_json::to_value(&req.rules).unwrap_or_else(|_| serde_json::json!([])))
        .bind(req.is_active)
        .bind(created_by)
        .execute(&mut *tx)
        .await?;

        insert_fields(&mut tx, tenant_id, id, &req.fields).await?;
        tx.commit().await?;
        self.get(tenant_id, id).await
    }

    pub async fn update(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        req: UpdateFormDefinitionRequest,
    ) -> AppResult<FormDefinitionResponse> {
        let existing = self.get(tenant_id, id).await?;

        // Rules are checked against whichever field set will be in force AFTER
        // this update, against whichever rule set will be in force after it.
        // Both halves matter: replacing the field set without touching the
        // rules can strand a rule on a field that no longer exists, which
        // would leave it silently inert rather than rejected. So the check
        // runs whenever EITHER half changes, using the post-update value of
        // each.
        if let Some(fields) = &req.fields {
            check_field_set(fields)?;
        }
        if req.fields.is_some() || req.rules.is_some() {
            let names: Vec<(String, Option<Vec<String>>)> = match &req.fields {
                Some(fields) => fields
                    .iter()
                    .map(|f| (f.name.clone(), f.options.clone()))
                    .collect(),
                None => existing
                    .fields
                    .iter()
                    .map(|f| (f.name.clone(), f.options.clone()))
                    .collect(),
            };
            let rules = req.rules.as_deref().unwrap_or(&existing.rules);
            check_rules_against_names(rules, &names)?;
        }

        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            "UPDATE form_definitions SET \
               name = COALESCE($3, name), \
               description = CASE WHEN $4 THEN $5 ELSE description END, \
               kb_article_id = CASE WHEN $6 THEN $7 ELSE kb_article_id END, \
               rules = COALESCE($8, rules), \
               is_active = COALESCE($9, is_active), \
               updated_at = NOW() \
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .bind(&req.name)
        .bind(req.description.is_some())
        .bind(req.description.clone().flatten())
        .bind(req.kb_article_id.is_some())
        .bind(req.kb_article_id.flatten())
        .bind(
            req.rules
                .as_ref()
                .map(|r| serde_json::to_value(r).unwrap_or_else(|_| serde_json::json!([]))),
        )
        .bind(req.is_active)
        .execute(&mut *tx)
        .await?;

        // A field set is REPLACED wholesale, never merged: field identity is
        // the payload key, and a merge cannot express a rename or a deletion
        // unambiguously. Submissions already taken keep their own payload, so
        // rewriting the field set does not rewrite history.
        if let Some(fields) = &req.fields {
            sqlx::query("DELETE FROM form_fields WHERE tenant_id = $1 AND form_definition_id = $2")
                .bind(tenant_id)
                .bind(id)
                .execute(&mut *tx)
                .await?;
            insert_fields(&mut tx, tenant_id, id, fields).await?;
        }
        tx.commit().await?;
        self.get(tenant_id, id).await
    }

    /// Delete a definition. Submissions hold an `ON DELETE RESTRICT` FK, so a
    /// definition that has ever been submitted cannot be deleted; retire it
    /// with `is_active = false` instead. That is reported as a 409 rather
    /// than a raw database error.
    pub async fn delete(&self, tenant_id: TenantId, id: Uuid) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let submitted: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM form_submissions WHERE tenant_id = $1 AND form_definition_id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
        if submitted > 0 {
            return Err(AppError::Conflict(format!(
                "This form has {submitted} submission(s) and cannot be deleted; set is_active to false to retire it. A conflicting form"
            )));
        }
        let affected = sqlx::query("DELETE FROM form_definitions WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        tx.commit().await?;
        if affected == 0 {
            return Err(AppError::NotFound("Form definition".to_string()));
        }
        Ok(())
    }

    /// Validate a payload against a definition and store it.
    ///
    /// A retired (`is_active = false`) definition refuses new submissions:
    /// retiring is how an operator stops collecting, so accepting one anyway
    /// would make the flag decorative.
    pub async fn submit(
        &self,
        tenant_id: TenantId,
        definition_id: Uuid,
        payload: &serde_json::Value,
        submitted_by_contact_id: Option<Uuid>,
    ) -> AppResult<FormSubmissionResponse> {
        let definition = self.get(tenant_id, definition_id).await?;
        if !definition.is_active {
            return Err(AppError::Conflict(
                "This form has been retired and is no longer accepting submissions. An active form"
                    .to_string(),
            ));
        }

        let normalised = validate_submission(
            &definition.fields,
            &definition.rules,
            payload,
            Utc::now().date_naive(),
        )?;

        let id = Uuid::new_v4();
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row = sqlx::query_as::<_, SubmissionRow>(
            "INSERT INTO form_submissions \
               (id, tenant_id, form_definition_id, payload, submitted_by_contact_id) \
             VALUES ($1, $2, $3, $4, $5) \
             RETURNING id, form_definition_id, payload, submitted_by_contact_id, ticket_id, created_at",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(definition_id)
        .bind(serde_json::Value::Object(normalised))
        .bind(submitted_by_contact_id)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(row.into())
    }

    /// PMS-729 phase 2 §7 slice B / I8: list every portal-visible active
    /// form for a tenant. `portal_visible = TRUE AND is_active = TRUE`;
    /// a retired form or one flagged internal-only stays out of the
    /// picker.
    pub async fn list_portal_forms(
        &self,
        tenant_id: TenantId,
    ) -> AppResult<Vec<super::models::PortalFormListItem>> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows: Vec<(Uuid, String, String, Option<String>)> = sqlx::query_as(
            r#"
            SELECT id, name, slug, description
            FROM form_definitions
            WHERE tenant_id = $1
              AND is_active = TRUE
              AND portal_visible = TRUE
            ORDER BY name ASC
            "#,
        )
        .bind(tenant_id)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(rows
            .into_iter()
            .map(
                |(id, name, slug, description)| super::models::PortalFormListItem {
                    id,
                    name,
                    slug,
                    description,
                },
            )
            .collect())
    }

    /// PMS-729 phase 2 §7 slice B / I8: fetch the client-facing view of
    /// one portal-visible form. Retired / non-portal forms surface as
    /// 404 so the endpoint cannot be used to enumerate internal forms.
    pub async fn get_portal_form(
        &self,
        tenant_id: TenantId,
        form_id: Uuid,
    ) -> AppResult<super::models::PublicFormResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let exists: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS (
                SELECT 1 FROM form_definitions
                WHERE tenant_id = $1 AND id = $2
                  AND is_active = TRUE AND portal_visible = TRUE
            )
            "#,
        )
        .bind(tenant_id)
        .bind(form_id)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        if !exists {
            return Err(AppError::NotFound("Form".to_string()));
        }
        // The full definition is already scoped by tenant on `get`, and
        // the portal shape drops ids / timestamps via the same
        // `public_form_from_definition` helper the public magic-link
        // path uses in `super::service::public_form_for_token` (which is
        // just `get(...)` re-wrapped for the token flow, so we reuse
        // `get` directly here).
        let def = self.get(tenant_id, form_id).await?;
        Ok(super::models::PublicFormResponse {
            name: def.name,
            description: def.description,
            rules: def.rules,
            fields: def
                .fields
                .into_iter()
                .map(|f| super::models::PublicFormField {
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

    /// PMS-729 phase 2 §7 slice B / I8: submit a portal-visible form on
    /// behalf of a portal contact. Same validation as the public
    /// magic-link path, but the submitter identity comes from the
    /// authenticated portal session (`contact_id`, `company_id`), not a
    /// resolved token, and there is no rate limiter here because the
    /// portal auth middleware already gates access.
    ///
    /// Opens a ticket via `TicketService::create_portal_ticket`, which
    /// picks a fallback admin as `created_by_id` so the ticket's
    /// NOT-NULL FK to `users` is satisfied even though the caller is a
    /// contact. Returns the ticket number the customer can quote.
    pub async fn submit_portal_form(
        &self,
        tenant_id: TenantId,
        form_id: Uuid,
        company_id: Uuid,
        contact_id: Uuid,
        payload: &serde_json::Value,
    ) -> AppResult<super::models::PublicSubmissionReceipt> {
        // Preflight: form must exist AND be portal-visible AND active.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let exists: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS (
                SELECT 1 FROM form_definitions
                WHERE tenant_id = $1 AND id = $2
                  AND is_active = TRUE AND portal_visible = TRUE
            )
            "#,
        )
        .bind(tenant_id)
        .bind(form_id)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        if !exists {
            return Err(AppError::NotFound("Form".to_string()));
        }

        let definition = self.get(tenant_id, form_id).await?;
        let normalised = validate_submission(
            &definition.fields,
            &definition.rules,
            payload,
            Utc::now().date_naive(),
        )?;

        // Persist the submission first so we can link a ticket to it.
        let submission_id = Uuid::new_v4();
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            "INSERT INTO form_submissions \
               (id, tenant_id, form_definition_id, payload, submitted_by_contact_id) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(submission_id)
        .bind(tenant_id)
        .bind(form_id)
        .bind(serde_json::Value::Object(normalised.clone()))
        .bind(contact_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;

        let Some(tickets) = self.tickets.as_ref() else {
            return Err(AppError::Internal(
                "no ticket service wired into the forms service".to_string(),
            ));
        };

        // Ticket title / body come out of the same helpers PMS-730 uses
        // for the magic-link path so an agent picking up a portal-form
        // ticket sees the same shape.
        let title = format!(
            "{}: {}",
            definition.name,
            super::request_links::summarise(&definition, &normalised)
        );
        let description = Some(super::request_links::render_answers(
            &definition,
            &normalised,
        ));
        let ticket = tickets
            .create_portal_ticket(
                tenant_id,
                company_id,
                contact_id,
                title,
                description,
                None,
                None,
            )
            .await?;

        // Link the submission to the ticket so the portal ticket
        // detail can show "from form X" later.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query("UPDATE form_submissions SET ticket_id = $3 WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(submission_id)
            .bind(ticket.id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;

        Ok(super::models::PublicSubmissionReceipt {
            ticket_number: ticket.ticket_number,
        })
    }

    pub async fn list_submissions(
        &self,
        tenant_id: TenantId,
        definition_id: Uuid,
    ) -> AppResult<Vec<FormSubmissionResponse>> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows = sqlx::query_as::<_, SubmissionRow>(
            "SELECT id, form_definition_id, payload, submitted_by_contact_id, ticket_id, created_at \
             FROM form_submissions \
             WHERE tenant_id = $1 AND form_definition_id = $2 \
             ORDER BY created_at DESC",
        )
        .bind(tenant_id)
        .bind(definition_id)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }
}

fn build_response(d: DefinitionRow, fields: Vec<FormFieldResponse>) -> FormDefinitionResponse {
    FormDefinitionResponse {
        id: d.id,
        name: d.name,
        slug: d.slug,
        description: d.description,
        kb_article_id: d.kb_article_id,
        kb_article_title: d.kb_article_title,
        // A rule shape this build does not understand is dropped rather than
        // failing the read: an unreadable rule must not make the form
        // unopenable. `check_rules` is what keeps the column well-formed.
        rules: serde_json::from_value(d.rules).unwrap_or_default(),
        is_active: d.is_active,
        created_by_id: d.created_by_id,
        created_at: d.created_at,
        updated_at: d.updated_at,
        fields,
    }
}

async fn fetch_fields(
    tx: &mut TenantTransaction<'_>,
    tenant_id: TenantId,
    definition_id: Uuid,
) -> AppResult<Vec<FormFieldResponse>> {
    let rows: Vec<FieldRow> = sqlx::query_as::<_, FieldRow>(&format!(
        "SELECT {FIELD_SELECT} FROM form_fields f \
         WHERE f.tenant_id = $1 AND f.form_definition_id = $2 \
         ORDER BY f.sort_order ASC, f.name ASC"
    ))
    .bind(tenant_id)
    .bind(definition_id)
    .fetch_all(&mut **tx)
    .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

async fn insert_fields(
    tx: &mut TenantTransaction<'_>,
    tenant_id: TenantId,
    definition_id: Uuid,
    fields: &[CreateFormFieldRequest],
) -> AppResult<()> {
    for f in fields {
        sqlx::query(
            "INSERT INTO form_fields \
               (tenant_id, form_definition_id, name, label, help_text, field_type, \
                is_required, min_length, max_length, options, date_not_in_past, sort_order) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
        )
        .bind(tenant_id)
        .bind(definition_id)
        .bind(&f.name)
        .bind(&f.label)
        .bind(&f.help_text)
        .bind(f.field_type.as_str())
        .bind(f.is_required)
        .bind(f.min_length)
        .bind(f.max_length)
        .bind(&f.options)
        .bind(f.date_not_in_past)
        .bind(f.sort_order)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

/// Definition-time checks the database cannot express as a single constraint.
/// These fail as a 422 with per-field errors, matching how a bad submission
/// is reported, so an author sees the same error shape as a client does.
fn check_field_set(fields: &[CreateFormFieldRequest]) -> AppResult<()> {
    let mut errors = Vec::new();
    for (i, f) in fields.iter().enumerate() {
        if fields.iter().take(i).any(|prior| prior.name == f.name) {
            errors.push(FieldError::new(
                format!("fields[{i}].name"),
                format!("Duplicate field name `{}`", f.name),
                "duplicate",
            ));
        }
        if f.field_type == FieldType::Select && f.options.as_ref().is_none_or(|o| o.is_empty()) {
            errors.push(FieldError::new(
                format!("fields[{i}].options"),
                format!("`{}` is a select and needs at least one option", f.name),
                "required",
            ));
        }
        if let (Some(min), Some(max)) = (f.min_length, f.max_length) {
            if min > max {
                errors.push(FieldError::new(
                    format!("fields[{i}].min_length"),
                    format!("`{}` has min_length above max_length", f.name),
                    "range",
                ));
            }
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(AppError::validation(
            "one or more fields are invalid",
            errors,
        ))
    }
}

fn check_rules(rules: &[FormRule], fields: &[CreateFormFieldRequest]) -> AppResult<()> {
    let names: Vec<(String, Option<Vec<String>>)> = fields
        .iter()
        .map(|f| (f.name.clone(), f.options.clone()))
        .collect();
    check_rules_against_names(rules, &names)
}

/// A rule that names a field the form does not have can never fire, so it is
/// a typo rather than a feature. Rejecting it here means the interpreter
/// never has to explain a silently-inert rule to a confused author.
fn check_rules_against_names(
    rules: &[FormRule],
    names: &[(String, Option<Vec<String>>)],
) -> AppResult<()> {
    let mut errors = Vec::new();
    for (i, rule) in rules.iter().enumerate() {
        let FormRule::RequiredIf {
            field,
            when_field,
            equals,
        } = rule;
        if !names.iter().any(|(n, _)| n == field) {
            errors.push(FieldError::new(
                format!("rules[{i}].field"),
                format!("Rule targets unknown field `{field}`"),
                "unknown_field",
            ));
        }
        match names.iter().find(|(n, _)| n == when_field) {
            None => errors.push(FieldError::new(
                format!("rules[{i}].when_field"),
                format!("Rule reads unknown field `{when_field}`"),
                "unknown_field",
            )),
            // When the condition reads a select, `equals` must be one of its
            // options or the rule can never fire.
            Some((_, Some(options))) if !options.iter().any(|o| o == equals) => {
                errors.push(FieldError::new(
                    format!("rules[{i}].equals"),
                    format!(
                        "`{equals}` is not an option of `{when_field}` (one of: {})",
                        options.join(", ")
                    ),
                    "option",
                ));
            }
            Some(_) => {}
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(AppError::validation(
            "one or more fields are invalid",
            errors,
        ))
    }
}
