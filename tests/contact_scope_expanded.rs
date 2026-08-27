//! PMS-935: extended scope-matrix suite covering the entities added
//! by the prompt 013 sweep - contracts, assets, projects - plus the
//! ticket-notes redaction, the new dashboard summary endpoint, and
//! the `PUT /contact/auth/me` profile self-edit. Shape matrix mirrors
//! `tests/contact_scope.rs` from the prompt 008 sweep: one row per
//! failure mode so a regression fires with a message that points at
//! the missing gate, not just "assertion left != right".

mod common;

use reqwest::StatusCode;
use sqlx::PgPool;
use uuid::Uuid;

/// Seed a Company + Contact + granted portal access under
/// [`common::DEFAULT_TENANT_ID`]. `role_names` picks which built-in
/// role(s) to assign the contact.
///
/// Returns `(company_id, contact_id, email, access_token)`.
async fn seed_contact_with_roles(
    app: &common::TestApp,
    pool: &PgPool,
    email_local: &str,
    role_names: &[&str],
) -> (Uuid, Uuid, String, String) {
    seed_contact_with_roles_in_tenant(
        app,
        pool,
        common::DEFAULT_TENANT_ID,
        email_local,
        role_names,
    )
    .await
}

async fn seed_contact_with_roles_in_tenant(
    app: &common::TestApp,
    pool: &PgPool,
    tenant_id: Uuid,
    email_local: &str,
    role_names: &[&str],
) -> (Uuid, Uuid, String, String) {
    let email = format!("{email_local}@contact-scope-expanded.example");
    let company_id = Uuid::new_v4();
    let slug = format!("cse-{}", &Uuid::new_v4().simple().to_string()[..12]);
    sqlx::query("INSERT INTO companies (id, tenant_id, name, portal_slug) VALUES ($1, $2, $3, $4)")
        .bind(company_id)
        .bind(tenant_id)
        .bind(format!("CSE Co {email_local}"))
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

/// Seed a contract row on the given (tenant, company). Returns its id.
async fn seed_contract(pool: &PgPool, tenant_id: Uuid, company_id: Uuid, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO contracts (id, tenant_id, name, company_id, contract_type, status, \
         start_date, billing_cycle) \
         VALUES ($1, $2, $3, $4, 'managed_services', 'active', CURRENT_DATE, 'monthly')",
    )
    .bind(id)
    .bind(tenant_id)
    .bind(name)
    .bind(company_id)
    .execute(pool)
    .await
    .expect("seed contract");
    id
}

/// Seed an asset row. Requires an asset_type_id; grabs the first one
/// in the tenant or seeds a fresh one.
async fn seed_asset(pool: &PgPool, tenant_id: Uuid, company_id: Uuid, name: &str) -> Uuid {
    let asset_type_id: Uuid = {
        // Try to reuse a seeded asset_type; else insert a fresh one.
        // `asset_types` has no `sort_order`; the seeded row order is
        // by name via migration 023's INSERT list.
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
                .bind("PMS-935 default")
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
    .bind(format!("AT-{}", &id.simple().to_string()[..8]))
    .bind(name)
    .bind(asset_type_id)
    .bind(company_id)
    .execute(pool)
    .await
    .expect("seed asset");
    id
}

/// Seed a project row.
async fn seed_project(pool: &PgPool, tenant_id: Uuid, company_id: Uuid, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO projects (id, tenant_id, name, company_id, project_type, status, start_date) \
         VALUES ($1, $2, $3, $4, 'internal', 'active', CURRENT_DATE)",
    )
    .bind(id)
    .bind(tenant_id)
    .bind(name)
    .bind(company_id)
    .execute(pool)
    .await
    .expect("seed project");
    id
}

// ============================================================================
// CONTRACTS - contact-plane sweep
// ============================================================================

#[sqlx::test]
async fn contracts_list_scoped_to_contact_company(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (own_company, _c, _e, token) =
        seed_contact_with_roles(&app, &pool, "ct-list", &["Read-Only"]).await;
    let other_company = seed_plain_company(&pool, common::DEFAULT_TENANT_ID, "ct-other-co").await;

    let _mine = seed_contract(&pool, common::DEFAULT_TENANT_ID, own_company, "mine").await;
    let _theirs = seed_contract(&pool, common::DEFAULT_TENANT_ID, other_company, "theirs").await;

    let resp = app
        .client
        .get(app.url("/api/v1/contracts"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "PMS-935: contact with contracts:read must 200 on /contracts"
    );
    let body: serde_json::Value = resp.json().await.expect("json");
    let items = body["data"].as_array().expect("data array");
    for row in items {
        assert_eq!(
            row["company_id"].as_str(),
            Some(own_company.to_string().as_str()),
            "PMS-935: /contracts for a contact must only return their Company's rows"
        );
    }
    assert!(
        !items.is_empty(),
        "PMS-935: expected the seeded MINE contract in the response"
    );
}

#[sqlx::test]
async fn contracts_get_foreign_company_returns_404(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (_own, _c, _e, token) =
        seed_contact_with_roles(&app, &pool, "ct-get-foreign", &["Read-Only"]).await;
    let other_company = seed_plain_company(&pool, common::DEFAULT_TENANT_ID, "ct-foreign-co").await;
    let foreign = seed_contract(&pool, common::DEFAULT_TENANT_ID, other_company, "foreign").await;

    let resp = app
        .client
        .get(app.url(&format!("/api/v1/contracts/{foreign}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("get");
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "PMS-935: cross-Company contract must 404, not 403 (no enumeration)"
    );
}

#[sqlx::test]
async fn contracts_list_without_cap_returns_403(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    // Support Contact does NOT hold contracts:read.
    let (_own, _c, _e, token) =
        seed_contact_with_roles(&app, &pool, "ct-nocap", &["Support Contact"]).await;
    let resp = app
        .client
        .get(app.url("/api/v1/contracts"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "PMS-935: contact without contracts:read must 403"
    );
}

#[sqlx::test]
async fn contracts_list_staff_bypass_returns_200(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let staff_token = common::login(&app, &email, &password).await;
    let resp = app
        .client
        .get(app.url("/api/v1/contracts"))
        .bearer_auth(&staff_token)
        .send()
        .await
        .expect("staff list");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "PMS-935: staff callers keep 200 on /contracts after the sweep"
    );
}

#[sqlx::test]
async fn contracts_cross_tenant_returns_404(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (_own, _c, _e, token) =
        seed_contact_with_roles(&app, &pool, "ct-cross-tenant", &["Read-Only"]).await;
    let (other_tenant, _admin, _e, _p) =
        common::seed_tenant_with_admin(&pool, "ct-other-tenant").await;
    let other_company = seed_plain_company(&pool, other_tenant, "ct-ot-co").await;
    let foreign = seed_contract(&pool, other_tenant, other_company, "foreign").await;
    let resp = app
        .client
        .get(app.url(&format!("/api/v1/contracts/{foreign}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("get cross tenant");
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "PMS-935: cross-tenant contract lookup MUST 404, never 200"
    );
}

// ============================================================================
// ASSETS - contact-plane sweep
// ============================================================================

#[sqlx::test]
async fn assets_list_scoped_to_contact_company(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (own_company, _c, _e, token) =
        seed_contact_with_roles(&app, &pool, "as-list", &["Read-Only"]).await;
    let other_company = seed_plain_company(&pool, common::DEFAULT_TENANT_ID, "as-other-co").await;
    let _mine = seed_asset(&pool, common::DEFAULT_TENANT_ID, own_company, "mine").await;
    let _theirs = seed_asset(&pool, common::DEFAULT_TENANT_ID, other_company, "theirs").await;

    let resp = app
        .client
        .get(app.url("/api/v1/assets"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "PMS-935: contact with assets:read must 200 on /assets"
    );
    let body: serde_json::Value = resp.json().await.expect("json");
    let items = body["data"].as_array().expect("data array");
    for row in items {
        assert_eq!(
            row["company_id"].as_str(),
            Some(own_company.to_string().as_str()),
            "PMS-935: /assets for a contact must only return their Company's rows"
        );
    }
    assert!(
        !items.is_empty(),
        "PMS-935: expected the seeded MINE asset in the response"
    );
}

#[sqlx::test]
async fn assets_get_foreign_company_returns_404(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (_own, _c, _e, token) =
        seed_contact_with_roles(&app, &pool, "as-get-foreign", &["Read-Only"]).await;
    let other_company = seed_plain_company(&pool, common::DEFAULT_TENANT_ID, "as-foreign-co").await;
    let foreign = seed_asset(&pool, common::DEFAULT_TENANT_ID, other_company, "foreign").await;
    let resp = app
        .client
        .get(app.url(&format!("/api/v1/assets/{foreign}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("get");
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "PMS-935: cross-Company asset must 404, not 403"
    );
}

#[sqlx::test]
async fn assets_list_without_cap_returns_403(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (_own, _c, _e, token) =
        seed_contact_with_roles(&app, &pool, "as-nocap", &["Billing Contact"]).await;
    let resp = app
        .client
        .get(app.url("/api/v1/assets"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "PMS-935: contact without assets:read must 403"
    );
}

#[sqlx::test]
async fn assets_list_staff_bypass_returns_200(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let staff_token = common::login(&app, &email, &password).await;
    let resp = app
        .client
        .get(app.url("/api/v1/assets"))
        .bearer_auth(&staff_token)
        .send()
        .await
        .expect("staff list");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "PMS-935: staff callers keep 200 on /assets"
    );
}

// ============================================================================
// PROJECTS - contact-plane sweep
// ============================================================================

#[sqlx::test]
async fn projects_list_scoped_to_contact_company(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (own_company, _c, _e, token) =
        seed_contact_with_roles(&app, &pool, "pr-list", &["Read-Only"]).await;
    let other_company = seed_plain_company(&pool, common::DEFAULT_TENANT_ID, "pr-other-co").await;
    let _mine = seed_project(&pool, common::DEFAULT_TENANT_ID, own_company, "mine").await;
    let _theirs = seed_project(&pool, common::DEFAULT_TENANT_ID, other_company, "theirs").await;

    let resp = app
        .client
        .get(app.url("/api/v1/projects"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "PMS-935: contact with projects:read must 200 on /projects"
    );
    let body: serde_json::Value = resp.json().await.expect("json");
    let items = body["data"].as_array().expect("data array");
    for row in items {
        assert_eq!(
            row["company_id"].as_str(),
            Some(own_company.to_string().as_str()),
            "PMS-935: /projects for a contact must only return their Company's rows"
        );
    }
    assert!(
        !items.is_empty(),
        "PMS-935: expected the seeded MINE project in the response"
    );
}

#[sqlx::test]
async fn projects_get_foreign_company_returns_404(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (_own, _c, _e, token) =
        seed_contact_with_roles(&app, &pool, "pr-get-foreign", &["Read-Only"]).await;
    let other_company = seed_plain_company(&pool, common::DEFAULT_TENANT_ID, "pr-foreign-co").await;
    let foreign = seed_project(&pool, common::DEFAULT_TENANT_ID, other_company, "foreign").await;
    let resp = app
        .client
        .get(app.url(&format!("/api/v1/projects/{foreign}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("get");
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "PMS-935: cross-Company project must 404, not 403"
    );
}

#[sqlx::test]
async fn projects_list_without_cap_returns_403(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (_own, _c, _e, token) =
        seed_contact_with_roles(&app, &pool, "pr-nocap", &["Billing Contact"]).await;
    let resp = app
        .client
        .get(app.url("/api/v1/projects"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "PMS-935: contact without projects:read must 403"
    );
}

#[sqlx::test]
async fn projects_list_staff_bypass_returns_200(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let staff_token = common::login(&app, &email, &password).await;
    let resp = app
        .client
        .get(app.url("/api/v1/projects"))
        .bearer_auth(&staff_token)
        .send()
        .await
        .expect("staff list");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "PMS-935: staff callers keep 200 on /projects"
    );
}

// ============================================================================
// TICKET NOTES - contact must see public notes only; staff sees the lot.
// ============================================================================

/// Seed a ticket for a specific Company plus one public note + one
/// internal note attributed to the admin. Returns the ticket id.
async fn seed_ticket_with_two_notes(
    pool: &PgPool,
    tenant_id: Uuid,
    company_id: Uuid,
    admin_id: Uuid,
) -> Uuid {
    let default_status: Uuid = sqlx::query_scalar(
        "SELECT id FROM ticket_statuses WHERE tenant_id = $1 AND is_default = TRUE LIMIT 1",
    )
    .bind(tenant_id)
    .fetch_one(pool)
    .await
    .expect("default status");
    let default_priority: Uuid = sqlx::query_scalar(
        "SELECT id FROM ticket_priorities WHERE tenant_id = $1 AND is_default = TRUE LIMIT 1",
    )
    .bind(tenant_id)
    .fetch_one(pool)
    .await
    .expect("default priority");
    let default_queue: Uuid = sqlx::query_scalar(
        "SELECT id FROM ticket_queues WHERE tenant_id = $1 AND is_default = TRUE LIMIT 1",
    )
    .bind(tenant_id)
    .fetch_one(pool)
    .await
    .expect("default queue");
    let ticket_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO tickets (id, tenant_id, ticket_number, title, status_id, priority_id, \
         queue_id, source, company_id, created_by_id) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, 'internal', $8, $9)",
    )
    .bind(ticket_id)
    .bind(tenant_id)
    .bind(format!("PMS935-{}", &ticket_id.simple().to_string()[..8]))
    .bind("note redaction ticket")
    .bind(default_status)
    .bind(default_priority)
    .bind(default_queue)
    .bind(company_id)
    .bind(admin_id)
    .execute(pool)
    .await
    .expect("seed ticket");
    // Two notes, one public, one internal.
    for (nt, content) in &[
        ("public", "customer-visible chatter"),
        ("internal", "back-channel agent discussion"),
    ] {
        sqlx::query(
            "INSERT INTO ticket_notes (id, tenant_id, ticket_id, note_type, content, \
             created_by_id) VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(Uuid::new_v4())
        .bind(tenant_id)
        .bind(ticket_id)
        .bind(*nt)
        .bind(*content)
        .bind(admin_id)
        .execute(pool)
        .await
        .expect("seed note");
    }
    ticket_id
}

#[sqlx::test]
async fn ticket_notes_staff_sees_internal_and_public(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let staff_token = common::login(&app, &email, &password).await;
    let company_id = seed_plain_company(&pool, common::DEFAULT_TENANT_ID, "notes-co").await;
    let ticket_id =
        seed_ticket_with_two_notes(&pool, common::DEFAULT_TENANT_ID, company_id, admin_id).await;

    let resp = app
        .client
        .get(app.url(&format!("/api/v1/tickets/{ticket_id}/notes")))
        .bearer_auth(&staff_token)
        .send()
        .await
        .expect("staff notes");
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("json");
    let notes = body["data"].as_array().expect("data array");
    let mut kinds: Vec<&str> = notes
        .iter()
        .map(|n| n["note_type"].as_str().unwrap_or_default())
        .collect();
    kinds.sort();
    assert_eq!(
        kinds,
        vec!["internal", "public"],
        "PMS-935: staff GET must return both internal and public notes"
    );
}

#[sqlx::test]
async fn ticket_notes_contact_sees_public_only(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (company_id, _c, _e, contact_token) =
        seed_contact_with_roles(&app, &pool, "notes-contact", &["Support Contact"]).await;
    // Admin sits in the same tenant so we can attribute the seeded
    // note without hitting a foreign-key wall on `created_by_id`.
    let (admin_id, _, _) = common::seed_admin(&pool).await;
    let ticket_id =
        seed_ticket_with_two_notes(&pool, common::DEFAULT_TENANT_ID, company_id, admin_id).await;

    let resp = app
        .client
        .get(app.url(&format!("/api/v1/tickets/{ticket_id}/notes")))
        .bearer_auth(&contact_token)
        .send()
        .await
        .expect("contact notes");
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("json");
    let notes = body["data"].as_array().expect("data array");
    let kinds: Vec<&str> = notes
        .iter()
        .map(|n| n["note_type"].as_str().unwrap_or_default())
        .collect();
    assert!(
        !kinds.iter().any(|k| *k == "internal"),
        "PMS-935: internal notes must NEVER reach a contact caller (got {kinds:?})"
    );
    assert!(
        kinds.iter().any(|k| *k == "public"),
        "PMS-935: contact GET must surface the public note (got {kinds:?})"
    );
}

// ============================================================================
// DASHBOARD SUMMARY - two-Company isolation.
// ============================================================================

/// Seed `n` open tickets on the given Company. Returns nothing;
/// intended for arranging the count-check tests.
async fn seed_open_tickets(
    pool: &PgPool,
    tenant_id: Uuid,
    company_id: Uuid,
    admin_id: Uuid,
    n: i64,
) {
    let default_status: Uuid = sqlx::query_scalar(
        "SELECT id FROM ticket_statuses \
         WHERE tenant_id = $1 AND is_closed = FALSE ORDER BY sort_order LIMIT 1",
    )
    .bind(tenant_id)
    .fetch_one(pool)
    .await
    .expect("open status");
    let default_priority: Uuid = sqlx::query_scalar(
        "SELECT id FROM ticket_priorities WHERE tenant_id = $1 AND is_default = TRUE LIMIT 1",
    )
    .bind(tenant_id)
    .fetch_one(pool)
    .await
    .expect("default priority");
    let default_queue: Uuid = sqlx::query_scalar(
        "SELECT id FROM ticket_queues WHERE tenant_id = $1 AND is_default = TRUE LIMIT 1",
    )
    .bind(tenant_id)
    .fetch_one(pool)
    .await
    .expect("default queue");
    for i in 0..n {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO tickets (id, tenant_id, ticket_number, title, status_id, priority_id, \
             queue_id, source, company_id, created_by_id) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, 'internal', $8, $9)",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(format!("DS-{}-{i}", &id.simple().to_string()[..6]))
        .bind(format!("dash ticket {i}"))
        .bind(default_status)
        .bind(default_priority)
        .bind(default_queue)
        .bind(company_id)
        .bind(admin_id)
        .execute(pool)
        .await
        .expect("seed open ticket");
    }
}

async fn seed_unpaid_invoices(pool: &PgPool, tenant_id: Uuid, company_id: Uuid, n: i64) {
    for i in 0..n {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO invoices (id, tenant_id, invoice_number, company_id, status, \
             invoice_date, due_date, subtotal, total, amount_paid, balance_due) \
             VALUES ($1, $2, $3, $4, 'sent', CURRENT_DATE, CURRENT_DATE + 30, \
             100, 100, 0, 100)",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(format!("DS-INV-{}-{i}", &id.simple().to_string()[..6]))
        .bind(company_id)
        .execute(pool)
        .await
        .expect("seed unpaid invoice");
    }
}

#[sqlx::test]
async fn dashboard_summary_two_company_isolation(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (admin_id, _, _) = common::seed_admin(&pool).await;
    let (company_a, _c_a, _e_a, token_a) =
        seed_contact_with_roles(&app, &pool, "dash-a", &["Read-Only"]).await;
    let (company_b, _c_b, _e_b, token_b) =
        seed_contact_with_roles(&app, &pool, "dash-b", &["Read-Only"]).await;

    seed_open_tickets(&pool, common::DEFAULT_TENANT_ID, company_a, admin_id, 5).await;
    seed_open_tickets(&pool, common::DEFAULT_TENANT_ID, company_b, admin_id, 3).await;
    seed_unpaid_invoices(&pool, common::DEFAULT_TENANT_ID, company_a, 2).await;

    let a: serde_json::Value = app
        .client
        .get(app.url("/api/v1/contact/dashboard/summary"))
        .bearer_auth(&token_a)
        .send()
        .await
        .expect("dash a")
        .json()
        .await
        .expect("json");
    let b: serde_json::Value = app
        .client
        .get(app.url("/api/v1/contact/dashboard/summary"))
        .bearer_auth(&token_b)
        .send()
        .await
        .expect("dash b")
        .json()
        .await
        .expect("json");

    assert_eq!(
        a["open_tickets"].as_i64(),
        Some(5),
        "PMS-935: contact of A must see 5 open tickets"
    );
    assert_eq!(
        a["unpaid_invoices"].as_i64(),
        Some(2),
        "PMS-935: contact of A must see 2 unpaid invoices"
    );
    assert_eq!(
        b["open_tickets"].as_i64(),
        Some(3),
        "PMS-935: contact of B must see 3 open tickets"
    );
    assert_eq!(
        b["unpaid_invoices"].as_i64(),
        Some(0),
        "PMS-935: contact of B must see 0 unpaid invoices"
    );
    // Sanity: recent_activity is present and honours the 10-item cap.
    let a_feed = a["recent_activity"].as_array().expect("recent_activity");
    assert!(
        a_feed.len() <= 10,
        "PMS-935: recent_activity must be capped at 10"
    );
}

#[sqlx::test]
async fn dashboard_summary_requires_contact_bearer(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let staff_token = common::login(&app, &email, &password).await;
    // Staff bearer must 401 - this is a contact-only endpoint.
    let resp = app
        .client
        .get(app.url("/api/v1/contact/dashboard/summary"))
        .bearer_auth(&staff_token)
        .send()
        .await
        .expect("staff dash");
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "PMS-935: staff bearer must 401 on the contact-only dashboard endpoint"
    );
}

// ============================================================================
// PROFILE SELF-EDIT - PUT /contact/auth/me
// ============================================================================

#[sqlx::test]
async fn contact_self_edit_persists_first_name(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    // Billing Contact + Support Contact both hold `settings:manage_own`
    // per the migration-142 seed; Read-Only does NOT.
    let (_company_id, _contact_id, _email, token) =
        seed_contact_with_roles(&app, &pool, "self-edit-ok", &["Billing Contact"]).await;

    let resp = app
        .client
        .put(app.url("/api/v1/contact/auth/me"))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "first_name": "Wanda" }))
        .send()
        .await
        .expect("put me");
    assert_eq!(resp.status(), StatusCode::OK, "PMS-935: happy path 200");
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(
        body["first_name"].as_str(),
        Some("Wanda"),
        "PMS-935: response must reflect the new first_name"
    );

    // GET /me must return the same value.
    let me: serde_json::Value = app
        .client
        .get(app.url("/api/v1/contact/auth/me"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("get me")
        .json()
        .await
        .expect("json");
    assert_eq!(
        me["first_name"].as_str(),
        Some("Wanda"),
        "PMS-935: /me must round-trip the update"
    );
}

#[sqlx::test]
async fn contact_self_edit_does_not_bleed_to_sibling_contact(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (company_id, _c_a, _e_a, token_a) =
        seed_contact_with_roles(&app, &pool, "self-a", &["Billing Contact"]).await;
    // Seed a second contact under the SAME Company. Reuses the Company
    // row so the two sit under the same portal_slug.
    let second_email = "self-b@contact-scope-expanded.example".to_string();
    let contact_b_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO contacts (id, tenant_id, company_id, first_name, last_name, email) \
         VALUES ($1, $2, $3, 'Original', 'Sibling', $4)",
    )
    .bind(contact_b_id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company_id)
    .bind(&second_email)
    .execute(&pool)
    .await
    .expect("seed sibling contact");

    // Grant + login as the sibling.
    let db = mokosh_server::Database::from_pool(pool.clone());
    let contact_svc = mokosh_server::modules::contacts::ContactService::new(db);
    let role_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM portal_roles WHERE tenant_id = $1 AND name = 'Billing Contact'",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(&pool)
    .await
    .expect("Billing Contact role");
    let outcome = contact_svc
        .grant_portal_access(
            mokosh_server::modules::auth::TenantId::from_trusted(common::DEFAULT_TENANT_ID),
            contact_b_id,
            &[role_id],
            &mokosh_server::modules::audit::AuditCtx::system(common::DEFAULT_TENANT_ID),
        )
        .await
        .expect("grant sibling");
    let prefix = format!("/portal/{}/set-password?token=", outcome.portal_slug);
    let token_txt = outcome
        .setup_link
        .split(&prefix)
        .nth(1)
        .expect("token")
        .to_string();
    let strong = "Kq7$mZ2n#PxR9wLf";
    app.client
        .post(app.url("/api/v1/contact/auth/set-password"))
        .json(&serde_json::json!({ "token": token_txt, "password": strong }))
        .send()
        .await
        .expect("set-password b");
    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/login"))
        .json(&serde_json::json!({
            "slug": outcome.portal_slug,
            "email": second_email,
            "password": strong,
        }))
        .send()
        .await
        .expect("login b");
    let body: serde_json::Value = resp.json().await.expect("login json");
    let token_b = body["access_token"].as_str().expect("access b").to_string();

    // Contact A renames to Wanda.
    let resp = app
        .client
        .put(app.url("/api/v1/contact/auth/me"))
        .bearer_auth(&token_a)
        .json(&serde_json::json!({ "first_name": "Wanda" }))
        .send()
        .await
        .expect("put a");
    assert_eq!(resp.status(), StatusCode::OK);

    // Contact B must see their OWN first_name, unchanged.
    let me_b: serde_json::Value = app
        .client
        .get(app.url("/api/v1/contact/auth/me"))
        .bearer_auth(&token_b)
        .send()
        .await
        .expect("get me b")
        .json()
        .await
        .expect("json");
    assert_eq!(
        me_b["first_name"].as_str(),
        Some("Original"),
        "PMS-935: /me for sibling must return their OWN row, unchanged by A's update"
    );
}

#[sqlx::test]
async fn contact_self_edit_without_cap_returns_403(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    // Read-Only role is the built-in one that deliberately does NOT
    // hold `settings:manage_own` (see migration 142 seed).
    let (_c, _cid, _e, token) =
        seed_contact_with_roles(&app, &pool, "self-nocap", &["Read-Only"]).await;
    let resp = app
        .client
        .put(app.url("/api/v1/contact/auth/me"))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "first_name": "Wanda" }))
        .send()
        .await
        .expect("put nocap");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "PMS-935: contact without settings:manage_own must 403 on PUT /me"
    );
}

// ============================================================================
// ContactMe DTO regression: company_id must round-trip on /me
// ============================================================================

#[sqlx::test]
async fn contact_me_carries_company_id(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (company_id, _c, _e, token) =
        seed_contact_with_roles(&app, &pool, "me-cid", &["Read-Only"]).await;
    let me: serde_json::Value = app
        .client
        .get(app.url("/api/v1/contact/auth/me"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("get me")
        .json()
        .await
        .expect("json");
    assert_eq!(
        me["company_id"].as_str(),
        Some(company_id.to_string().as_str()),
        "PMS-935: ContactMe.company_id must be populated so the SPA can \
         build scoped URLs without a round-trip"
    );
}
