//! PMS-936: cap-gate + Company-scope matrix for the five new granular
//! capabilities the foundation pass ships:
//!
//!   - `tickets:reopen`         POST /api/v1/tickets/{id}/reopen
//!   - `tickets:attach_file`    POST /api/v1/tickets/{id}/attachments
//!   - `invoices:download_pdf`  GET  /api/v1/invoices/{id}/pdf (501 stub)
//!   - `assets:report_issue`    POST /api/v1/assets/{id}/report-issue
//!   - `quotes:download_pdf`    GET  /api/v1/quotes/{id}/pdf (501 stub)
//!
//! Shape rows per endpoint mirror the prompt 008 sweep so a regression
//! fires with a message pointing at the missing gate:
//!   1. contact WITH cap, matching Company -> 2xx (or the endpoint's
//!      documented stub status for PDF).
//!   2. contact WITHOUT cap -> 403.
//!   3. contact WITH cap, foreign Company -> 404 (leak-free).
//!   4. staff caller -> 2xx (bypasses the cap gate).
//!
//! Every seed goes through the same portal-role redemption flow as
//! `tests/contact_scope.rs` so the token this suite drives is exactly
//! the one the SPA would carry.

mod common;

use base64::Engine as _;
use reqwest::StatusCode;
use sqlx::PgPool;
use uuid::Uuid;

// ============================================================================
// Seeding helpers - lifted from tests/contact_scope.rs and slimmed to
// the shape this suite needs. Kept local so this file compiles as its
// own integration-test binary.
// ============================================================================

async fn seed_contact_with_roles(
    app: &common::TestApp,
    pool: &PgPool,
    email_local: &str,
    role_names: &[&str],
) -> (Uuid, Uuid, String, String) {
    let tenant_id = common::DEFAULT_TENANT_ID;
    let email = format!("{email_local}@portal-expanded-caps.example");
    let company_id = Uuid::new_v4();
    let slug = format!("pec-{}", &Uuid::new_v4().simple().to_string()[..12]);
    sqlx::query("INSERT INTO companies (id, tenant_id, name, portal_slug) VALUES ($1, $2, $3, $4)")
        .bind(company_id)
        .bind(tenant_id)
        .bind(format!("PEC Co {email_local}"))
        .bind(&slug)
        .execute(pool)
        .await
        .expect("seed company");

    let contact_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO contacts (id, tenant_id, company_id, first_name, last_name, email) \
         VALUES ($1, $2, $3, 'Test', 'Contact', $4)",
    )
    .bind(contact_id)
    .bind(tenant_id)
    .bind(company_id)
    .bind(&email)
    .execute(pool)
    .await
    .expect("seed contact");

    let db = mokosh_server::Database::from_pool(pool.clone());
    let contact_svc = mokosh_server::modules::contacts::ContactService::new(db);
    let mut role_ids = Vec::new();
    for name in role_names {
        let id: Uuid =
            sqlx::query_scalar("SELECT id FROM portal_roles WHERE tenant_id = $1 AND name = $2")
                .bind(tenant_id)
                .bind(name)
                .fetch_one(pool)
                .await
                .unwrap_or_else(|e| panic!("read portal_role {name}: {e}"));
        role_ids.push(id);
    }
    let outcome = contact_svc
        .grant_portal_access(
            mokosh_server::modules::auth::TenantId::from_trusted(tenant_id),
            contact_id,
            &role_ids,
            &mokosh_server::modules::audit::AuditCtx::system(tenant_id),
        )
        .await
        .expect("grant_portal_access");

    let prefix = format!("/portal/{}/set-password?token=", outcome.portal_slug);
    let token = outcome
        .setup_link
        .split(&prefix)
        .nth(1)
        .expect("token in setup_link")
        .to_string();
    let strong = "Kq7$mZ2n#PxR9wLf";
    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/set-password"))
        .json(&serde_json::json!({ "token": token, "password": strong }))
        .send()
        .await
        .expect("set-password");
    assert_eq!(resp.status(), StatusCode::NO_CONTENT, "set-password 204");

    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/login"))
        .json(&serde_json::json!({
            "slug": outcome.portal_slug,
            "email": email,
            "password": strong,
        }))
        .send()
        .await
        .expect("contact login");
    assert_eq!(resp.status(), StatusCode::OK, "contact login 200");
    let body: serde_json::Value = resp.json().await.expect("login JSON");
    let access = body["access_token"]
        .as_str()
        .expect("access_token in login response")
        .to_string();
    (company_id, contact_id, email, access)
}

async fn seed_plain_company(pool: &PgPool, tenant_id: Uuid, label: &str) -> Uuid {
    let company_id = Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, $3)")
        .bind(company_id)
        .bind(tenant_id)
        .bind(label)
        .execute(pool)
        .await
        .expect("seed plain company");
    company_id
}

async fn tenant_default_status(pool: &PgPool, tenant_id: Uuid) -> Uuid {
    sqlx::query_scalar(
        "SELECT id FROM ticket_statuses WHERE tenant_id = $1 AND is_default = TRUE LIMIT 1",
    )
    .bind(tenant_id)
    .fetch_one(pool)
    .await
    .expect("default status")
}

async fn tenant_default_priority(pool: &PgPool, tenant_id: Uuid) -> Uuid {
    sqlx::query_scalar(
        "SELECT id FROM ticket_priorities WHERE tenant_id = $1 AND is_default = TRUE LIMIT 1",
    )
    .bind(tenant_id)
    .fetch_one(pool)
    .await
    .expect("default priority")
}

async fn tenant_default_queue(pool: &PgPool, tenant_id: Uuid) -> Uuid {
    sqlx::query_scalar(
        "SELECT id FROM ticket_queues WHERE tenant_id = $1 AND is_default = TRUE LIMIT 1",
    )
    .bind(tenant_id)
    .fetch_one(pool)
    .await
    .expect("default queue")
}

async fn tenant_closed_status(pool: &PgPool, tenant_id: Uuid) -> Uuid {
    // A `is_closed = TRUE` status must exist per tenant for the reopen
    // flow to be legal. The seeded set includes it.
    sqlx::query_scalar(
        "SELECT id FROM ticket_statuses WHERE tenant_id = $1 AND is_closed = TRUE ORDER BY sort_order LIMIT 1",
    )
    .bind(tenant_id)
    .fetch_one(pool)
    .await
    .expect("closed status")
}

async fn seed_ticket_on_company(
    pool: &PgPool,
    tenant_id: Uuid,
    company_id: Uuid,
    status_id: Uuid,
    admin_id: Uuid,
    label: &str,
) -> Uuid {
    let priority_id = tenant_default_priority(pool, tenant_id).await;
    let queue_id = tenant_default_queue(pool, tenant_id).await;
    let ticket_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO tickets (id, tenant_id, ticket_number, title, status_id, priority_id, \
         queue_id, source, company_id, created_by_id) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, 'internal', $8, $9)",
    )
    .bind(ticket_id)
    .bind(tenant_id)
    .bind(format!("PEC-{}", &ticket_id.simple().to_string()[..8]))
    .bind(label)
    .bind(status_id)
    .bind(priority_id)
    .bind(queue_id)
    .bind(company_id)
    .bind(admin_id)
    .execute(pool)
    .await
    .expect("seed ticket");
    ticket_id
}

async fn seed_asset_on_company(
    pool: &PgPool,
    tenant_id: Uuid,
    company_id: Uuid,
    name: &str,
) -> Uuid {
    let asset_type_id: Uuid = {
        let existing: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM asset_types WHERE tenant_id = $1 ORDER BY name LIMIT 1",
        )
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
        .expect("query asset_types");
        if let Some(id) = existing {
            id
        } else {
            let id = Uuid::new_v4();
            sqlx::query("INSERT INTO asset_types (id, tenant_id, name) VALUES ($1, $2, $3)")
                .bind(id)
                .bind(tenant_id)
                .bind("PMS-936 default")
                .execute(pool)
                .await
                .expect("seed asset_type");
            id
        }
    };
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO assets (id, tenant_id, asset_tag, name, asset_type_id, company_id, status) \
         VALUES ($1, $2, $3, $4, $5, $6, 'active')",
    )
    .bind(id)
    .bind(tenant_id)
    .bind(format!("PEC-A-{}", &id.simple().to_string()[..8]))
    .bind(name)
    .bind(asset_type_id)
    .bind(company_id)
    .execute(pool)
    .await
    .expect("seed asset");
    id
}

async fn seed_invoice_on_company(pool: &PgPool, tenant_id: Uuid, company_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO invoices (id, tenant_id, invoice_number, company_id, status, \
         invoice_date, due_date, subtotal, total, amount_paid, balance_due) \
         VALUES ($1, $2, $3, $4, 'sent', CURRENT_DATE, CURRENT_DATE + 30, 100, 100, 0, 100)",
    )
    .bind(id)
    .bind(tenant_id)
    .bind(format!("PEC-INV-{}", &id.simple().to_string()[..8]))
    .bind(company_id)
    .execute(pool)
    .await
    .expect("seed invoice");
    id
}

/// An ISSUED quote (`sent`): since PMS-1060 a contact's read is limited to
/// the issued statuses, so a draft here would be a 404 before any
/// capability check and the cap matrix below would not be exercised.
async fn seed_quote_on_company(
    pool: &PgPool,
    tenant_id: Uuid,
    company_id: Uuid,
    admin_id: Uuid,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO quotes (id, tenant_id, quote_number, company_id, title, status, \
         valid_until, subtotal, tax_amount, total, currency, requested_by_id, sent_at) \
         VALUES ($1, $2, $3, $4, $5, 'sent', CURRENT_DATE + 30, 100, 0, 100, 'USD', $6, NOW())",
    )
    .bind(id)
    .bind(tenant_id)
    .bind(format!("PEC-Q-{}", &id.simple().to_string()[..8]))
    .bind(company_id)
    .bind(format!("PEC quote {}", &id.simple().to_string()[..8]))
    .bind(admin_id)
    .execute(pool)
    .await
    .expect("seed quote");
    id
}

// ============================================================================
// tickets:reopen
// ============================================================================

#[sqlx::test]
async fn contact_with_tickets_reopen_can_reopen_own_company_ticket_200(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (own_company, _c, _e, token) =
        seed_contact_with_roles(&app, &pool, "reopen-ok", &["Support Contact"]).await;
    let (admin_id, _e, _p) = common::seed_admin(&pool).await;
    let closed_status = tenant_closed_status(&pool, common::DEFAULT_TENANT_ID).await;
    let ticket_id = seed_ticket_on_company(
        &pool,
        common::DEFAULT_TENANT_ID,
        own_company,
        closed_status,
        admin_id,
        "reopen me",
    )
    .await;
    sqlx::query("UPDATE tickets SET closed_at = NOW() WHERE id = $1")
        .bind(ticket_id)
        .execute(&pool)
        .await
        .expect("stamp closed_at");

    let resp = app
        .client
        .post(app.url(&format!("/api/v1/tickets/{ticket_id}/reopen")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "reason": "still broken" }))
        .send()
        .await
        .expect("reopen");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "PMS-936: contact with tickets:reopen must 200 on own-Company reopen"
    );
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(
        body["id"].as_str(),
        Some(ticket_id.to_string().as_str()),
        "reopen response echoes the ticket id"
    );
}

#[sqlx::test]
async fn contact_without_tickets_reopen_cannot_reopen_403(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    // Billing Contact holds NO tickets:reopen (that cap ships to Support Contact only).
    let (own_company, _c, _e, token) =
        seed_contact_with_roles(&app, &pool, "reopen-nocap", &["Billing Contact"]).await;
    let (admin_id, _e, _p) = common::seed_admin(&pool).await;
    let closed_status = tenant_closed_status(&pool, common::DEFAULT_TENANT_ID).await;
    let ticket_id = seed_ticket_on_company(
        &pool,
        common::DEFAULT_TENANT_ID,
        own_company,
        closed_status,
        admin_id,
        "nocap reopen",
    )
    .await;

    let resp = app
        .client
        .post(app.url(&format!("/api/v1/tickets/{ticket_id}/reopen")))
        .bearer_auth(&token)
        .json(&serde_json::json!({}))
        .send()
        .await
        .expect("reopen");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "PMS-936: contact without tickets:reopen must 403"
    );
}

#[sqlx::test]
async fn contact_with_tickets_reopen_cannot_reopen_wrong_company_ticket_404(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (_own_company, _c, _e, token) =
        seed_contact_with_roles(&app, &pool, "reopen-foreign", &["Support Contact"]).await;
    let other_company =
        seed_plain_company(&pool, common::DEFAULT_TENANT_ID, "reopen-other-co").await;
    let (admin_id, _e, _p) = common::seed_admin(&pool).await;
    let closed_status = tenant_closed_status(&pool, common::DEFAULT_TENANT_ID).await;
    let ticket_id = seed_ticket_on_company(
        &pool,
        common::DEFAULT_TENANT_ID,
        other_company,
        closed_status,
        admin_id,
        "foreign ticket",
    )
    .await;

    let resp = app
        .client
        .post(app.url(&format!("/api/v1/tickets/{ticket_id}/reopen")))
        .bearer_auth(&token)
        .json(&serde_json::json!({}))
        .send()
        .await
        .expect("reopen");
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "PMS-936: cross-Company reopen must 404, not 403 (no enumeration)"
    );
}

#[sqlx::test]
async fn staff_bypasses_reopen_cap_200(pool: PgPool) {
    let (admin_id, admin_email, admin_password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let staff_token = common::login(&app, &admin_email, &admin_password).await;
    let plain_co = seed_plain_company(&pool, common::DEFAULT_TENANT_ID, "staff-reopen-co").await;
    let closed_status = tenant_closed_status(&pool, common::DEFAULT_TENANT_ID).await;
    let ticket_id = seed_ticket_on_company(
        &pool,
        common::DEFAULT_TENANT_ID,
        plain_co,
        closed_status,
        admin_id,
        "staff reopen",
    )
    .await;
    sqlx::query("UPDATE tickets SET closed_at = NOW() WHERE id = $1")
        .bind(ticket_id)
        .execute(&pool)
        .await
        .expect("stamp closed_at");

    let resp = app
        .client
        .post(app.url(&format!("/api/v1/tickets/{ticket_id}/reopen")))
        .bearer_auth(&staff_token)
        .json(&serde_json::json!({}))
        .send()
        .await
        .expect("reopen");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "PMS-936: staff caller must bypass the tickets:reopen cap gate"
    );
}

// ============================================================================
// tickets:attach_file
// ============================================================================

fn tiny_base64_blob() -> String {
    base64::engine::general_purpose::STANDARD.encode(b"pms-936-payload")
}

#[sqlx::test]
async fn contact_with_tickets_attach_file_can_attach_own_company_ticket_200(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (own_company, _c, _e, token) =
        seed_contact_with_roles(&app, &pool, "attach-ok", &["Support Contact"]).await;
    let (admin_id, _e, _p) = common::seed_admin(&pool).await;
    let default_status = tenant_default_status(&pool, common::DEFAULT_TENANT_ID).await;
    let ticket_id = seed_ticket_on_company(
        &pool,
        common::DEFAULT_TENANT_ID,
        own_company,
        default_status,
        admin_id,
        "attach me",
    )
    .await;

    let resp = app
        .client
        .post(app.url(&format!("/api/v1/tickets/{ticket_id}/attachments")))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "filename": "note.txt",
            "content_type": "text/plain",
            "data_base64": tiny_base64_blob(),
        }))
        .send()
        .await
        .expect("attach");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "PMS-936: contact with tickets:attach_file must 200 on own-Company attach"
    );
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(
        body["ticket_id"].as_str(),
        Some(ticket_id.to_string().as_str())
    );
    assert!(
        body["created_by_contact_id"].as_str().is_some(),
        "portal-uploaded attachment must stamp created_by_contact_id"
    );
}

#[sqlx::test]
async fn contact_without_tickets_attach_file_cannot_attach_403(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    // Billing Contact has no tickets:attach_file cap.
    let (own_company, _c, _e, token) =
        seed_contact_with_roles(&app, &pool, "attach-nocap", &["Billing Contact"]).await;
    let (admin_id, _e, _p) = common::seed_admin(&pool).await;
    let default_status = tenant_default_status(&pool, common::DEFAULT_TENANT_ID).await;
    let ticket_id = seed_ticket_on_company(
        &pool,
        common::DEFAULT_TENANT_ID,
        own_company,
        default_status,
        admin_id,
        "attach nocap",
    )
    .await;

    let resp = app
        .client
        .post(app.url(&format!("/api/v1/tickets/{ticket_id}/attachments")))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "filename": "note.txt",
            "content_type": "text/plain",
            "data_base64": tiny_base64_blob(),
        }))
        .send()
        .await
        .expect("attach");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "PMS-936: contact without tickets:attach_file must 403"
    );
}

#[sqlx::test]
async fn contact_with_tickets_attach_file_cannot_attach_wrong_company_ticket_404(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (_own_company, _c, _e, token) =
        seed_contact_with_roles(&app, &pool, "attach-foreign", &["Support Contact"]).await;
    let other_company =
        seed_plain_company(&pool, common::DEFAULT_TENANT_ID, "attach-foreign-co").await;
    let (admin_id, _e, _p) = common::seed_admin(&pool).await;
    let default_status = tenant_default_status(&pool, common::DEFAULT_TENANT_ID).await;
    let ticket_id = seed_ticket_on_company(
        &pool,
        common::DEFAULT_TENANT_ID,
        other_company,
        default_status,
        admin_id,
        "attach foreign",
    )
    .await;

    let resp = app
        .client
        .post(app.url(&format!("/api/v1/tickets/{ticket_id}/attachments")))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "filename": "note.txt",
            "content_type": "text/plain",
            "data_base64": tiny_base64_blob(),
        }))
        .send()
        .await
        .expect("attach");
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "PMS-936: cross-Company attach must 404, not 403"
    );
}

#[sqlx::test]
async fn staff_bypasses_attach_file_cap_200(pool: PgPool) {
    let (admin_id, admin_email, admin_password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let staff_token = common::login(&app, &admin_email, &admin_password).await;
    let plain_co = seed_plain_company(&pool, common::DEFAULT_TENANT_ID, "staff-attach-co").await;
    let default_status = tenant_default_status(&pool, common::DEFAULT_TENANT_ID).await;
    let ticket_id = seed_ticket_on_company(
        &pool,
        common::DEFAULT_TENANT_ID,
        plain_co,
        default_status,
        admin_id,
        "staff attach",
    )
    .await;

    let resp = app
        .client
        .post(app.url(&format!("/api/v1/tickets/{ticket_id}/attachments")))
        .bearer_auth(&staff_token)
        .json(&serde_json::json!({
            "filename": "note.txt",
            "content_type": "text/plain",
            "data_base64": tiny_base64_blob(),
        }))
        .send()
        .await
        .expect("attach");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "PMS-936: staff caller must bypass the tickets:attach_file cap gate"
    );
    let body: serde_json::Value = resp.json().await.expect("json");
    assert!(
        body["uploaded_by_id"].as_str().is_some(),
        "staff-uploaded attachment must stamp uploaded_by_id"
    );
}

// ============================================================================
// invoices:download_pdf (501 stub - cap gate is what matters)
// ============================================================================

#[sqlx::test]
async fn contact_with_invoices_download_pdf_reaches_stub_501(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (own_company, _c, _e, token) =
        seed_contact_with_roles(&app, &pool, "inv-pdf-ok", &["Billing Contact"]).await;
    let invoice_id = seed_invoice_on_company(&pool, common::DEFAULT_TENANT_ID, own_company).await;

    let resp = app
        .client
        .get(app.url(&format!("/api/v1/invoices/{invoice_id}/pdf")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("pdf");
    assert_eq!(
        resp.status(),
        StatusCode::NOT_IMPLEMENTED,
        "PMS-936: contact with invoices:download_pdf clears the gate and hits the 501 stub"
    );
}

#[sqlx::test]
async fn contact_without_invoices_download_pdf_403(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    // Support Contact has no invoices:* caps.
    let (_own_company, _c, _e, token) =
        seed_contact_with_roles(&app, &pool, "inv-pdf-nocap", &["Support Contact"]).await;
    let plain_co = seed_plain_company(&pool, common::DEFAULT_TENANT_ID, "inv-pdf-nocap-co").await;
    let invoice_id = seed_invoice_on_company(&pool, common::DEFAULT_TENANT_ID, plain_co).await;

    let resp = app
        .client
        .get(app.url(&format!("/api/v1/invoices/{invoice_id}/pdf")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("pdf");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "PMS-936: contact without invoices:download_pdf must 403"
    );
}

#[sqlx::test]
async fn contact_with_invoices_download_pdf_foreign_company_404(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (_own_company, _c, _e, token) =
        seed_contact_with_roles(&app, &pool, "inv-pdf-foreign", &["Billing Contact"]).await;
    let other_company =
        seed_plain_company(&pool, common::DEFAULT_TENANT_ID, "inv-pdf-foreign-co").await;
    let invoice_id = seed_invoice_on_company(&pool, common::DEFAULT_TENANT_ID, other_company).await;

    let resp = app
        .client
        .get(app.url(&format!("/api/v1/invoices/{invoice_id}/pdf")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("pdf");
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "PMS-936: cross-Company invoice PDF must 404, not 403"
    );
}

#[sqlx::test]
async fn staff_bypasses_invoices_download_pdf_cap_501(pool: PgPool) {
    let (_admin_id, admin_email, admin_password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let staff_token = common::login(&app, &admin_email, &admin_password).await;
    let plain_co = seed_plain_company(&pool, common::DEFAULT_TENANT_ID, "staff-inv-pdf-co").await;
    let invoice_id = seed_invoice_on_company(&pool, common::DEFAULT_TENANT_ID, plain_co).await;

    let resp = app
        .client
        .get(app.url(&format!("/api/v1/invoices/{invoice_id}/pdf")))
        .bearer_auth(&staff_token)
        .send()
        .await
        .expect("pdf");
    assert_eq!(
        resp.status(),
        StatusCode::NOT_IMPLEMENTED,
        "PMS-936: staff caller clears the RequireBilling+RequireFinance gate and hits the 501 stub"
    );
}

// ============================================================================
// assets:report_issue
// ============================================================================

#[sqlx::test]
async fn contact_with_assets_report_issue_can_file_own_company_ticket_200(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (own_company, _c, _e, token) =
        seed_contact_with_roles(&app, &pool, "asset-report-ok", &["Support Contact"]).await;
    let asset_id =
        seed_asset_on_company(&pool, common::DEFAULT_TENANT_ID, own_company, "reportable").await;

    let resp = app
        .client
        .post(app.url(&format!("/api/v1/assets/{asset_id}/report-issue")))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "summary": "printer offline",
            "description": "not responding to ping",
        }))
        .send()
        .await
        .expect("report");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "PMS-936: contact with assets:report_issue must 200 on own-Company report"
    );
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(
        body["company_id"].as_str(),
        Some(own_company.to_string().as_str()),
        "asset report ticket lands on the caller's own Company"
    );
    assert_eq!(
        body["asset_id"].as_str(),
        Some(asset_id.to_string().as_str()),
        "asset report ticket carries the asset_id link"
    );
    assert_eq!(
        body["source"].as_str(),
        Some("portal"),
        "contact-plane asset report must record source=portal"
    );
}

#[sqlx::test]
async fn contact_without_assets_report_issue_cannot_report_403(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    // Read-Only holds assets:read but not assets:report_issue.
    let (own_company, _c, _e, token) =
        seed_contact_with_roles(&app, &pool, "asset-report-nocap", &["Read-Only"]).await;
    let asset_id =
        seed_asset_on_company(&pool, common::DEFAULT_TENANT_ID, own_company, "nocap").await;

    let resp = app
        .client
        .post(app.url(&format!("/api/v1/assets/{asset_id}/report-issue")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "summary": "denied", "description": "n/a" }))
        .send()
        .await
        .expect("report");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "PMS-936: contact without assets:report_issue must 403"
    );
}

#[sqlx::test]
async fn contact_with_assets_report_issue_cannot_report_wrong_company_404(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (_own_company, _c, _e, token) =
        seed_contact_with_roles(&app, &pool, "asset-report-foreign", &["Support Contact"]).await;
    let other_company =
        seed_plain_company(&pool, common::DEFAULT_TENANT_ID, "asset-report-foreign-co").await;
    let asset_id =
        seed_asset_on_company(&pool, common::DEFAULT_TENANT_ID, other_company, "foreign").await;

    let resp = app
        .client
        .post(app.url(&format!("/api/v1/assets/{asset_id}/report-issue")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "summary": "foreign", "description": "n/a" }))
        .send()
        .await
        .expect("report");
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "PMS-936: cross-Company asset report must 404, not 403"
    );
}

#[sqlx::test]
async fn staff_bypasses_assets_report_issue_cap_200(pool: PgPool) {
    let (_admin_id, admin_email, admin_password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let staff_token = common::login(&app, &admin_email, &admin_password).await;
    let plain_co =
        seed_plain_company(&pool, common::DEFAULT_TENANT_ID, "staff-asset-report-co").await;
    let asset_id =
        seed_asset_on_company(&pool, common::DEFAULT_TENANT_ID, plain_co, "staff-report").await;

    let resp = app
        .client
        .post(app.url(&format!("/api/v1/assets/{asset_id}/report-issue")))
        .bearer_auth(&staff_token)
        .json(&serde_json::json!({
            "summary": "staff filed",
            "description": "reported on behalf of the customer",
        }))
        .send()
        .await
        .expect("report");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "PMS-936: staff caller must bypass the assets:report_issue cap gate"
    );
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(
        body["asset_id"].as_str(),
        Some(asset_id.to_string().as_str()),
        "staff-filed asset report also carries the asset_id link"
    );
}

// ============================================================================
// quotes:download_pdf (501 stub)
// ============================================================================

#[sqlx::test]
async fn contact_with_quotes_download_pdf_reaches_stub_501(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (own_company, _c, _e, token) =
        seed_contact_with_roles(&app, &pool, "quote-pdf-ok", &["Billing Contact"]).await;
    let (admin_id, _e, _p) = common::seed_admin(&pool).await;
    let quote_id =
        seed_quote_on_company(&pool, common::DEFAULT_TENANT_ID, own_company, admin_id).await;

    let resp = app
        .client
        .get(app.url(&format!("/api/v1/quotes/{quote_id}/pdf")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("pdf");
    assert_eq!(
        resp.status(),
        StatusCode::NOT_IMPLEMENTED,
        "PMS-936: contact with quotes:download_pdf clears the gate and hits the 501 stub"
    );
}

#[sqlx::test]
async fn contact_without_quotes_download_pdf_403(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    // Support Contact has no quotes:* caps.
    let (_own_company, _c, _e, token) =
        seed_contact_with_roles(&app, &pool, "quote-pdf-nocap", &["Support Contact"]).await;
    let (admin_id, _e, _p) = common::seed_admin(&pool).await;
    let plain_co = seed_plain_company(&pool, common::DEFAULT_TENANT_ID, "quote-pdf-nocap-co").await;
    let quote_id =
        seed_quote_on_company(&pool, common::DEFAULT_TENANT_ID, plain_co, admin_id).await;

    let resp = app
        .client
        .get(app.url(&format!("/api/v1/quotes/{quote_id}/pdf")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("pdf");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "PMS-936: contact without quotes:download_pdf must 403"
    );
}

#[sqlx::test]
async fn contact_with_quotes_download_pdf_foreign_company_404(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (_own_company, _c, _e, token) =
        seed_contact_with_roles(&app, &pool, "quote-pdf-foreign", &["Billing Contact"]).await;
    let (admin_id, _e, _p) = common::seed_admin(&pool).await;
    let other_company =
        seed_plain_company(&pool, common::DEFAULT_TENANT_ID, "quote-pdf-foreign-co").await;
    let quote_id =
        seed_quote_on_company(&pool, common::DEFAULT_TENANT_ID, other_company, admin_id).await;

    let resp = app
        .client
        .get(app.url(&format!("/api/v1/quotes/{quote_id}/pdf")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("pdf");
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "PMS-936: cross-Company quote PDF must 404, not 403"
    );
}

#[sqlx::test]
async fn staff_bypasses_quotes_download_pdf_cap_501(pool: PgPool) {
    let (admin_id, admin_email, admin_password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let staff_token = common::login(&app, &admin_email, &admin_password).await;
    let plain_co = seed_plain_company(&pool, common::DEFAULT_TENANT_ID, "staff-quote-pdf-co").await;
    let quote_id =
        seed_quote_on_company(&pool, common::DEFAULT_TENANT_ID, plain_co, admin_id).await;

    let resp = app
        .client
        .get(app.url(&format!("/api/v1/quotes/{quote_id}/pdf")))
        .bearer_auth(&staff_token)
        .send()
        .await
        .expect("pdf");
    assert_eq!(
        resp.status(),
        StatusCode::NOT_IMPLEMENTED,
        "PMS-936: staff caller clears the RequireBilling+RequireFinance gate and hits the 501 stub"
    );
}
