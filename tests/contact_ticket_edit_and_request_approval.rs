//! PMS-937: cap-gate + Company + reporter matrix for the two new
//! surfaces this ticket adds:
//!
//!   - `tickets:edit_own`         PATCH /api/v1/tickets/{id}
//!   - `tickets:request_approval` POST  /api/v1/tickets/{id}/approvals/request
//!
//! Shape rows per endpoint match the PMS-936 `portal_expanded_caps`
//! posture so a regression fires with a message that points at the
//! missing gate:
//!   1. contact WITH cap, own-reporter -> 2xx (row shape verified).
//!   2. contact WITH cap, different-reporter same-Company -> 404
//!      (leak-free: the contact learns nothing about a colleague's ticket).
//!   3. contact WITH cap, foreign Company -> 404 (leak-free).
//!   4. contact WITHOUT cap -> 403.
//!   5. contact editing tries to spoof status_id / priority_id /
//!      assignee_id: strip semantics; those fields do NOT land.
//!   6. staff bypasses the cap gate + regression against the existing
//!      staff surface.

mod common;

use reqwest::StatusCode;
use sqlx::PgPool;
use uuid::Uuid;

// ============================================================================
// Seeding helpers - lifted from tests/portal_expanded_caps.rs and
// tweaked so ticket rows carry an explicit reporter contact_id (which
// PMS-937's edit-own gate keys off).
// ============================================================================

async fn seed_contact_with_roles(
    app: &common::TestApp,
    pool: &PgPool,
    email_local: &str,
    role_names: &[&str],
) -> (Uuid, Uuid, String, String) {
    let tenant_id = common::DEFAULT_TENANT_ID;
    let email = format!("{email_local}@pms-937.example");
    let company_id = Uuid::new_v4();
    let slug = format!("p937-{}", &Uuid::new_v4().simple().to_string()[..12]);
    sqlx::query("INSERT INTO companies (id, tenant_id, name, portal_slug) VALUES ($1, $2, $3, $4)")
        .bind(company_id)
        .bind(tenant_id)
        .bind(format!("PMS-937 Co {email_local}"))
        .bind(&slug)
        .execute(pool)
        .await
        .expect("seed company");

    let contact_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO contacts (id, tenant_id, company_id, first_name, last_name, email) \
         VALUES ($1, $2, $3, 'PMS-937', 'Contact', $4)",
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

async fn seed_plain_contact(pool: &PgPool, tenant_id: Uuid, company_id: Uuid, email: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO contacts (id, tenant_id, company_id, first_name, last_name, email) \
         VALUES ($1, $2, $3, 'Plain', 'Contact', $4)",
    )
    .bind(id)
    .bind(tenant_id)
    .bind(company_id)
    .bind(email)
    .execute(pool)
    .await
    .expect("seed plain contact");
    id
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

/// Seed a ticket with an explicit reporter contact_id. PMS-937 keys
/// its edit-own gate off `tickets.contact_id`, so the tests must
/// exercise both the matching-contact and non-matching-contact
/// branches.
async fn seed_ticket_with_reporter(
    pool: &PgPool,
    tenant_id: Uuid,
    company_id: Uuid,
    reporter_contact_id: Option<Uuid>,
    admin_id: Uuid,
    label: &str,
) -> Uuid {
    let status_id = tenant_default_status(pool, tenant_id).await;
    let priority_id = tenant_default_priority(pool, tenant_id).await;
    let queue_id = tenant_default_queue(pool, tenant_id).await;
    let ticket_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO tickets (id, tenant_id, ticket_number, title, status_id, priority_id, \
         queue_id, source, company_id, contact_id, created_by_id) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, 'portal', $8, $9, $10)",
    )
    .bind(ticket_id)
    .bind(tenant_id)
    .bind(format!("P937-{}", &ticket_id.simple().to_string()[..8]))
    .bind(label)
    .bind(status_id)
    .bind(priority_id)
    .bind(queue_id)
    .bind(company_id)
    .bind(reporter_contact_id)
    .bind(admin_id)
    .execute(pool)
    .await
    .expect("seed ticket");
    ticket_id
}

// ============================================================================
// PATCH /api/v1/tickets/{id}
// ============================================================================

#[sqlx::test]
async fn contact_with_edit_own_can_edit_title_and_description_on_own_reported_ticket(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (own_company, contact_id, _e, token) =
        seed_contact_with_roles(&app, &pool, "edit-own-ok", &["Support Contact"]).await;
    let (admin_id, _e, _p) = common::seed_admin(&pool).await;
    let ticket_id = seed_ticket_with_reporter(
        &pool,
        common::DEFAULT_TENANT_ID,
        own_company,
        Some(contact_id),
        admin_id,
        "original title",
    )
    .await;

    let resp = app
        .client
        .patch(app.url(&format!("/api/v1/tickets/{ticket_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "title": "corrected title",
            "description": "adding details the MSP asked for",
        }))
        .send()
        .await
        .expect("patch");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "PMS-937: contact with tickets:edit_own must 200 on own-reported ticket"
    );
    let body: serde_json::Value = resp.json().await.expect("patch json");
    assert_eq!(body["title"].as_str(), Some("corrected title"));
    assert_eq!(
        body["description"].as_str(),
        Some("adding details the MSP asked for")
    );

    // Sanity-check the DB row so a bug in the response DTO cannot hide a
    // missing UPDATE.
    let (title, description): (String, Option<String>) =
        sqlx::query_as("SELECT title, description FROM tickets WHERE id = $1")
            .bind(ticket_id)
            .fetch_one(&pool)
            .await
            .expect("read back ticket");
    assert_eq!(title, "corrected title");
    assert_eq!(
        description.as_deref(),
        Some("adding details the MSP asked for")
    );
}

#[sqlx::test]
async fn contact_without_edit_own_returns_403(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    // Read-Only holds no mutation caps, and tickets:edit_own is not on
    // Billing Contact either - so Read-Only is the cleanest no-cap
    // seed here.
    let (own_company, contact_id, _e, token) =
        seed_contact_with_roles(&app, &pool, "edit-own-nocap", &["Read-Only"]).await;
    let (admin_id, _e, _p) = common::seed_admin(&pool).await;
    let ticket_id = seed_ticket_with_reporter(
        &pool,
        common::DEFAULT_TENANT_ID,
        own_company,
        Some(contact_id),
        admin_id,
        "nocap",
    )
    .await;

    let resp = app
        .client
        .patch(app.url(&format!("/api/v1/tickets/{ticket_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "title": "denied" }))
        .send()
        .await
        .expect("patch");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "PMS-937: contact without tickets:edit_own must 403"
    );
}

#[sqlx::test]
async fn contact_editing_a_different_contacts_ticket_same_company_returns_404(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (own_company, _self_contact, _e, token) =
        seed_contact_with_roles(&app, &pool, "edit-own-sibling", &["Support Contact"]).await;
    // A colleague at the same Company opens the ticket; the seeded
    // contact must not be able to touch it.
    let sibling_contact = seed_plain_contact(
        &pool,
        common::DEFAULT_TENANT_ID,
        own_company,
        "sibling@pms-937.example",
    )
    .await;
    let (admin_id, _e, _p) = common::seed_admin(&pool).await;
    let ticket_id = seed_ticket_with_reporter(
        &pool,
        common::DEFAULT_TENANT_ID,
        own_company,
        Some(sibling_contact),
        admin_id,
        "sibling's ticket",
    )
    .await;

    let resp = app
        .client
        .patch(app.url(&format!("/api/v1/tickets/{ticket_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "title": "hijack attempt" }))
        .send()
        .await
        .expect("patch");
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "PMS-937: editing a sibling's ticket (same Company, different reporter) must 404, not 403"
    );
}

#[sqlx::test]
async fn contact_editing_a_ticket_from_different_company_returns_404(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (_own_company, _contact_id, _e, token) =
        seed_contact_with_roles(&app, &pool, "edit-own-foreign", &["Support Contact"]).await;
    let other_company =
        seed_plain_company(&pool, common::DEFAULT_TENANT_ID, "edit-own-foreign-co").await;
    let foreign_contact = seed_plain_contact(
        &pool,
        common::DEFAULT_TENANT_ID,
        other_company,
        "foreign@pms-937.example",
    )
    .await;
    let (admin_id, _e, _p) = common::seed_admin(&pool).await;
    let ticket_id = seed_ticket_with_reporter(
        &pool,
        common::DEFAULT_TENANT_ID,
        other_company,
        Some(foreign_contact),
        admin_id,
        "foreign ticket",
    )
    .await;

    let resp = app
        .client
        .patch(app.url(&format!("/api/v1/tickets/{ticket_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "title": "hijack attempt" }))
        .send()
        .await
        .expect("patch");
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "PMS-937: cross-Company PATCH must 404, not 403"
    );
}

#[sqlx::test]
async fn contact_editing_strips_status_id_priority_id_assignee_id_from_body(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (own_company, contact_id, _e, token) =
        seed_contact_with_roles(&app, &pool, "edit-own-strip", &["Support Contact"]).await;
    let (admin_id, _e, _p) = common::seed_admin(&pool).await;
    let ticket_id = seed_ticket_with_reporter(
        &pool,
        common::DEFAULT_TENANT_ID,
        own_company,
        Some(contact_id),
        admin_id,
        "strip fields",
    )
    .await;

    // Snapshot the pre-PATCH row so the assertions below can compare
    // against the actual seeded values without needing to know the
    // tenant's default lookup ids.
    #[derive(sqlx::FromRow)]
    struct Snap {
        status_id: Uuid,
        priority_id: Uuid,
        assigned_to_id: Option<Uuid>,
    }
    let before: Snap =
        sqlx::query_as("SELECT status_id, priority_id, assigned_to_id FROM tickets WHERE id = $1")
            .bind(ticket_id)
            .fetch_one(&pool)
            .await
            .expect("read before");

    // Pick DIFFERENT lookup ids so a leak would surface as a real
    // divergence, not the coincidence of picking the same default
    // again. Any second status / priority row on the tenant is fine.
    let other_status: Uuid = sqlx::query_scalar(
        "SELECT id FROM ticket_statuses WHERE tenant_id = $1 AND id != $2 LIMIT 1",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(before.status_id)
    .fetch_one(&pool)
    .await
    .expect("other status");
    let other_priority: Uuid = sqlx::query_scalar(
        "SELECT id FROM ticket_priorities WHERE tenant_id = $1 AND id != $2 LIMIT 1",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(before.priority_id)
    .fetch_one(&pool)
    .await
    .expect("other priority");

    let resp = app
        .client
        .patch(app.url(&format!("/api/v1/tickets/{ticket_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "title": "just a title tweak",
            "status_id": other_status,
            "priority_id": other_priority,
            "assigned_to_id": admin_id,
            "company_id": Uuid::new_v4(),
        }))
        .send()
        .await
        .expect("patch");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "PMS-937: PATCH must succeed and silently strip non-title/description fields"
    );

    // Post-PATCH row: title changed, status/priority/assignee unchanged.
    let after: Snap =
        sqlx::query_as("SELECT status_id, priority_id, assigned_to_id FROM tickets WHERE id = $1")
            .bind(ticket_id)
            .fetch_one(&pool)
            .await
            .expect("read after");
    assert_eq!(
        after.status_id, before.status_id,
        "status_id must not change on a contact PATCH"
    );
    assert_eq!(
        after.priority_id, before.priority_id,
        "priority_id must not change on a contact PATCH"
    );
    assert_eq!(
        after.assigned_to_id, before.assigned_to_id,
        "assigned_to_id must not change on a contact PATCH"
    );
    let (title,): (String,) = sqlx::query_as("SELECT title FROM tickets WHERE id = $1")
        .bind(ticket_id)
        .fetch_one(&pool)
        .await
        .expect("title after");
    assert_eq!(title, "just a title tweak");
}

#[sqlx::test]
async fn staff_editing_still_accepts_all_editable_fields(pool: PgPool) {
    let (admin_id, admin_email, admin_password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let staff_token = common::login(&app, &admin_email, &admin_password).await;
    let plain_co = seed_plain_company(&pool, common::DEFAULT_TENANT_ID, "staff-patch-co").await;
    let ticket_id = seed_ticket_with_reporter(
        &pool,
        common::DEFAULT_TENANT_ID,
        plain_co,
        None,
        admin_id,
        "staff patch",
    )
    .await;
    let other_status: Uuid = sqlx::query_scalar(
        "SELECT id FROM ticket_statuses WHERE tenant_id = $1 AND is_default = FALSE LIMIT 1",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(&pool)
    .await
    .expect("non-default status");

    let resp = app
        .client
        .patch(app.url(&format!("/api/v1/tickets/{ticket_id}")))
        .bearer_auth(&staff_token)
        .json(&serde_json::json!({
            "title": "staff renamed",
            "status_id": other_status,
        }))
        .send()
        .await
        .expect("patch");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "PMS-937: staff PATCH accepts the full editable set (regression)"
    );
    let (title, status_id): (String, Uuid) =
        sqlx::query_as("SELECT title, status_id FROM tickets WHERE id = $1")
            .bind(ticket_id)
            .fetch_one(&pool)
            .await
            .expect("read back");
    assert_eq!(title, "staff renamed");
    assert_eq!(status_id, other_status, "staff PATCH still moves status");
}

// ============================================================================
// POST /api/v1/tickets/{id}/approvals/request
// ============================================================================

#[sqlx::test]
async fn contact_with_request_approval_creates_pending_approval_row(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (own_company, contact_id, _e, token) =
        seed_contact_with_roles(&app, &pool, "req-appr-ok", &["Support Contact"]).await;
    let (admin_id, _e, _p) = common::seed_admin(&pool).await;
    let ticket_id = seed_ticket_with_reporter(
        &pool,
        common::DEFAULT_TENANT_ID,
        own_company,
        Some(contact_id),
        admin_id,
        "please approve",
    )
    .await;

    let submitted_note = "Please sign off on the out-of-scope network cabling work.";
    let resp = app
        .client
        .post(app.url(&format!("/api/v1/tickets/{ticket_id}/approvals/request")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "note": submitted_note }))
        .send()
        .await
        .expect("request");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "PMS-937: contact with tickets:request_approval must 200 on own-Company ticket"
    );
    let body: serde_json::Value = resp.json().await.expect("json");
    let approval_id_str = body["id"].as_str().expect("id in response");
    let approval_id = Uuid::parse_str(approval_id_str).expect("parse id");
    assert_eq!(body["status"].as_str(), Some("pending"));

    // Row-shape assertion: `requested_by_contact_id` set to the caller,
    // `requested_by_id` NULL, `note` matches the submitted value, and
    // the `ticket_id` column carries the ticket (legacy phase-1 field).
    #[derive(sqlx::FromRow)]
    struct Row {
        requested_by_id: Option<Uuid>,
        requested_by_contact_id: Option<Uuid>,
        notes: Option<String>,
        status: String,
        ticket_id: Option<Uuid>,
    }
    let row: Row = sqlx::query_as(
        "SELECT requested_by_id, requested_by_contact_id, notes, status, ticket_id \
         FROM ticket_approvals WHERE id = $1",
    )
    .bind(approval_id)
    .fetch_one(&pool)
    .await
    .expect("read approval");
    assert!(
        row.requested_by_id.is_none(),
        "contact-plane row must leave requested_by_id NULL"
    );
    assert_eq!(
        row.requested_by_contact_id,
        Some(contact_id),
        "contact-plane row must stamp requested_by_contact_id"
    );
    assert_eq!(row.notes.as_deref(), Some(submitted_note));
    assert_eq!(row.status, "pending");
    assert_eq!(row.ticket_id, Some(ticket_id));
}

#[sqlx::test]
async fn contact_without_cap_returns_403(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    // Billing Contact holds no tickets:* caps at all - clean no-cap seed.
    let (own_company, contact_id, _e, token) =
        seed_contact_with_roles(&app, &pool, "req-appr-nocap", &["Billing Contact"]).await;
    let (admin_id, _e, _p) = common::seed_admin(&pool).await;
    let ticket_id = seed_ticket_with_reporter(
        &pool,
        common::DEFAULT_TENANT_ID,
        own_company,
        Some(contact_id),
        admin_id,
        "nocap",
    )
    .await;

    let resp = app
        .client
        .post(app.url(&format!("/api/v1/tickets/{ticket_id}/approvals/request")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "note": "please" }))
        .send()
        .await
        .expect("request");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "PMS-937: contact without tickets:request_approval must 403"
    );
}

#[sqlx::test]
async fn contact_from_different_company_returns_404(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (_own_company, _contact, _e, token) =
        seed_contact_with_roles(&app, &pool, "req-appr-foreign", &["Support Contact"]).await;
    let other_company =
        seed_plain_company(&pool, common::DEFAULT_TENANT_ID, "req-appr-foreign-co").await;
    let (admin_id, _e, _p) = common::seed_admin(&pool).await;
    let ticket_id = seed_ticket_with_reporter(
        &pool,
        common::DEFAULT_TENANT_ID,
        other_company,
        None,
        admin_id,
        "foreign approve",
    )
    .await;

    let resp = app
        .client
        .post(app.url(&format!("/api/v1/tickets/{ticket_id}/approvals/request")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "note": "hijack attempt" }))
        .send()
        .await
        .expect("request");
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "PMS-937: cross-Company approval-request must 404, not 403"
    );
}

#[sqlx::test]
async fn staff_request_approval_still_works(pool: PgPool) {
    let (admin_id, admin_email, admin_password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let staff_token = common::login(&app, &admin_email, &admin_password).await;
    let plain_co = seed_plain_company(&pool, common::DEFAULT_TENANT_ID, "staff-req-appr-co").await;
    let ticket_id = seed_ticket_with_reporter(
        &pool,
        common::DEFAULT_TENANT_ID,
        plain_co,
        None,
        admin_id,
        "staff request",
    )
    .await;

    // Existing staff surface (regression). PMS-937 leaves this path
    // untouched: the phase-1 `POST /tickets/{id}/approvals` endpoint
    // with `CreateApprovalRequest` still works exactly as before.
    let resp = app
        .client
        .post(app.url(&format!("/api/v1/tickets/{ticket_id}/approvals")))
        .bearer_auth(&staff_token)
        .json(&serde_json::json!({
            "approver_role": "admin",
            "notes": "existing staff surface",
        }))
        .send()
        .await
        .expect("staff request");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "PMS-937: existing staff `/approvals` surface must still work"
    );

    // New URL (`/approvals/request`) is dual-plane; hitting it as staff
    // routes to the shared insert path with `requested_by_id` set.
    let resp = app
        .client
        .post(app.url(&format!("/api/v1/tickets/{ticket_id}/approvals/request")))
        .bearer_auth(&staff_token)
        .json(&serde_json::json!({ "note": "staff-side shortcut" }))
        .send()
        .await
        .expect("staff shortcut");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "PMS-937: staff caller reaches /approvals/request the same way a contact does"
    );
    let body: serde_json::Value = resp.json().await.expect("json");
    let approval_id = Uuid::parse_str(body["id"].as_str().expect("id")).expect("parse id");
    let (requested_by_id, requested_by_contact_id): (Option<Uuid>, Option<Uuid>) = sqlx::query_as(
        "SELECT requested_by_id, requested_by_contact_id FROM ticket_approvals WHERE id = $1",
    )
    .bind(approval_id)
    .fetch_one(&pool)
    .await
    .expect("read row");
    assert_eq!(
        requested_by_id,
        Some(admin_id),
        "staff-plane shortcut must stamp requested_by_id"
    );
    assert!(
        requested_by_contact_id.is_none(),
        "staff-plane shortcut must leave requested_by_contact_id NULL"
    );
}
