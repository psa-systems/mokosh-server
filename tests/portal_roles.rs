//! mokosh-contact-login prompt 007: MSP-admin portal-role CRUD +
//! per-contact role assignment tests.
//!
//! Covers the /api/v1/portal-roles surface and the new
//! `PUT /api/v1/contacts/{id}/portal-roles` rewire endpoint.

mod common;

use reqwest::StatusCode;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

const BILLING: &str = "Billing Contact";
const SUPPORT: &str = "Support Contact";

async fn seed_company_row(pool: &PgPool, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(common::DEFAULT_TENANT_ID)
        .bind(name)
        .execute(pool)
        .await
        .expect("seed company");
    id
}

async fn seed_contact_row(pool: &PgPool, company_id: Uuid, email: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO contacts (id, tenant_id, company_id, first_name, last_name, email) \
         VALUES ($1, $2, $3, 'Test', 'Contact', $4)",
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company_id)
    .bind(email)
    .execute(pool)
    .await
    .expect("seed contact");
    id
}

async fn list_roles_summary(app: &common::TestApp, token: &str) -> Vec<serde_json::Value> {
    let resp = app
        .client
        .get(app.url("/api/v1/portal-roles"))
        .bearer_auth(token)
        .send()
        .await
        .expect("send list roles");
    assert!(
        resp.status().is_success(),
        "list should 2xx, got {}",
        resp.status()
    );
    resp.json().await.expect("list JSON")
}

async fn find_role_id(app: &common::TestApp, token: &str, name: &str) -> String {
    let roles = list_roles_summary(app, token).await;
    roles
        .iter()
        .find(|r| r["name"].as_str() == Some(name))
        .and_then(|r| r["id"].as_str())
        .unwrap_or_else(|| panic!("role `{name}` not found in list"))
        .to_string()
}

#[sqlx::test]
async fn crud_happy_path(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let created: serde_json::Value = app
        .client
        .post(app.url("/api/v1/portal-roles"))
        .bearer_auth(&token)
        .json(&json!({
            "name": "Consultant",
            "capabilities": ["tickets:read", "kb:read"],
        }))
        .send()
        .await
        .expect("create")
        .json()
        .await
        .expect("create JSON");
    let id = created["id"].as_str().expect("id");
    assert_eq!(created["name"], "Consultant");
    assert_eq!(created["is_builtin"], false);
    assert_eq!(created["capabilities"].as_array().unwrap().len(), 2);

    let got: serde_json::Value = app
        .client
        .get(app.url(&format!("/api/v1/portal-roles/{id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("get")
        .json()
        .await
        .expect("get JSON");
    assert_eq!(got["id"].as_str(), Some(id));
    assert_eq!(got["name"], "Consultant");

    let list = list_roles_summary(&app, &token).await;
    assert!(list
        .iter()
        .any(|r| r["name"].as_str() == Some("Consultant")));

    let renamed: serde_json::Value = app
        .client
        .put(app.url(&format!("/api/v1/portal-roles/{id}")))
        .bearer_auth(&token)
        .json(&json!({ "name": "Senior Consultant" }))
        .send()
        .await
        .expect("rename")
        .json()
        .await
        .expect("rename JSON");
    assert_eq!(renamed["name"], "Senior Consultant");
    assert_eq!(renamed["capabilities"].as_array().unwrap().len(), 2);

    let capped: serde_json::Value = app
        .client
        .put(app.url(&format!("/api/v1/portal-roles/{id}")))
        .bearer_auth(&token)
        .json(&json!({ "capabilities": ["tickets:read", "tickets:comment", "invoices:read"] }))
        .send()
        .await
        .expect("recap")
        .json()
        .await
        .expect("recap JSON");
    assert_eq!(capped["capabilities"].as_array().unwrap().len(), 3);

    let del = app
        .client
        .delete(app.url(&format!("/api/v1/portal-roles/{id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("delete");
    assert_eq!(del.status(), StatusCode::NO_CONTENT);

    let miss = app
        .client
        .get(app.url(&format!("/api/v1/portal-roles/{id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("get after delete");
    assert_eq!(miss.status(), StatusCode::NOT_FOUND);
}

#[sqlx::test]
async fn delete_blocked_when_assignments_exist(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let created: serde_json::Value = app
        .client
        .post(app.url("/api/v1/portal-roles"))
        .bearer_auth(&token)
        .json(&json!({ "name": "Field Tech", "capabilities": ["tickets:read"] }))
        .send()
        .await
        .expect("create")
        .json()
        .await
        .expect("create JSON");
    let role_id = created["id"].as_str().unwrap().to_string();

    let company_id = seed_company_row(&pool, "Delete-Block Co").await;
    let contact_id = seed_contact_row(&pool, company_id, "block@mcl.example").await;
    sqlx::query(
        "INSERT INTO contact_role_assignments (contact_id, role_id, tenant_id) \
         VALUES ($1, $2, $3)",
    )
    .bind(contact_id)
    .bind(Uuid::parse_str(&role_id).unwrap())
    .bind(common::DEFAULT_TENANT_ID)
    .execute(&pool)
    .await
    .expect("seed assignment");

    let resp = app
        .client
        .delete(app.url(&format!("/api/v1/portal-roles/{role_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("delete");
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[sqlx::test]
async fn delete_blocked_when_builtin(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let billing_id = find_role_id(&app, &token, BILLING).await;
    let resp = app
        .client
        .delete(app.url(&format!("/api/v1/portal-roles/{billing_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("delete builtin");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[sqlx::test]
async fn update_rejects_empty_capabilities(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let created: serde_json::Value = app
        .client
        .post(app.url("/api/v1/portal-roles"))
        .bearer_auth(&token)
        .json(&json!({ "name": "Analyst", "capabilities": ["tickets:read"] }))
        .send()
        .await
        .expect("create")
        .json()
        .await
        .expect("create JSON");
    let id = created["id"].as_str().unwrap();

    let resp = app
        .client
        .put(app.url(&format!("/api/v1/portal-roles/{id}")))
        .bearer_auth(&token)
        .json(&json!({ "capabilities": [] }))
        .send()
        .await
        .expect("empty caps");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[sqlx::test]
async fn update_builtin_rejects_capability_change_allows_rename(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let billing_id = find_role_id(&app, &token, BILLING).await;

    let caps = app
        .client
        .put(app.url(&format!("/api/v1/portal-roles/{billing_id}")))
        .bearer_auth(&token)
        .json(&json!({ "capabilities": ["invoices:read"] }))
        .send()
        .await
        .expect("cap change");
    assert_eq!(caps.status(), StatusCode::BAD_REQUEST);

    let rename = app
        .client
        .put(app.url(&format!("/api/v1/portal-roles/{billing_id}")))
        .bearer_auth(&token)
        .json(&json!({ "name": "Billing Primary" }))
        .send()
        .await
        .expect("rename builtin");
    assert!(
        rename.status().is_success(),
        "rename should 2xx, got {}",
        rename.status()
    );
    let body: serde_json::Value = rename.json().await.expect("json");
    assert_eq!(body["name"], "Billing Primary");
    assert_eq!(body["is_builtin"], true);
}

#[sqlx::test]
async fn create_rejects_unknown_capability(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let resp = app
        .client
        .post(app.url("/api/v1/portal-roles"))
        .bearer_auth(&token)
        .json(&json!({
            "name": "Bad Role",
            "capabilities": ["tickets:read", "billing:full_access"],
        }))
        .send()
        .await
        .expect("bad cap");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[sqlx::test]
async fn create_rejects_duplicate_name(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let first = app
        .client
        .post(app.url("/api/v1/portal-roles"))
        .bearer_auth(&token)
        .json(&json!({ "name": "Consultant", "capabilities": ["kb:read"] }))
        .send()
        .await
        .expect("first");
    assert!(
        first.status().is_success(),
        "first create should 2xx, got {}",
        first.status()
    );

    // Case-insensitive collision.
    let dup = app
        .client
        .post(app.url("/api/v1/portal-roles"))
        .bearer_auth(&token)
        .json(&json!({ "name": "consultant", "capabilities": ["tickets:read"] }))
        .send()
        .await
        .expect("dup");
    assert_eq!(dup.status(), StatusCode::CONFLICT);
}

#[sqlx::test]
async fn create_allows_same_name_across_tenants(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    // Home tenant: create "Consultant".
    let created = app
        .client
        .post(app.url("/api/v1/portal-roles"))
        .bearer_auth(&token)
        .json(&json!({ "name": "Consultant", "capabilities": ["kb:read"] }))
        .send()
        .await
        .expect("create home");
    assert!(created.status().is_success());

    // Seed a foreign tenant. Directly INSERT a portal_roles row with
    // the same name to prove UNIQUE (tenant_id, name) isolates across
    // tenants (we can't easily switch bearer tokens to hit the API as
    // that tenant, but the FK check + case-insensitive uniqueness
    // both key on tenant_id, so the SQL confirms the isolation).
    let foreign_tenant = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO tenants (id, name, slug, kind) VALUES ($1, 'Foreign', 'foreign', 'org')",
    )
    .bind(foreign_tenant)
    .execute(&pool)
    .await
    .expect("seed foreign tenant");
    let res = sqlx::query(
        "INSERT INTO portal_roles (id, tenant_id, name, capabilities, is_builtin) \
         VALUES ($1, $2, $3, ARRAY['tickets:read'], FALSE)",
    )
    .bind(Uuid::new_v4())
    .bind(foreign_tenant)
    .bind("Consultant")
    .execute(&pool)
    .await;
    assert!(res.is_ok(), "same name allowed across tenants: {res:?}");
}

#[sqlx::test]
async fn put_contact_portal_roles_rewires_and_replaces(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let billing = find_role_id(&app, &token, BILLING).await;
    let support = find_role_id(&app, &token, SUPPORT).await;

    let company_id = seed_company_row(&pool, "Rewire Co").await;
    let contact_id = seed_contact_row(&pool, company_id, "rewire@mcl.example").await;

    let put1 = app
        .client
        .put(app.url(&format!(
            "/api/v1/contacts/contacts/{contact_id}/portal-roles"
        )))
        .bearer_auth(&token)
        .json(&json!({ "role_ids": [billing] }))
        .send()
        .await
        .expect("put1");
    assert_eq!(put1.status(), StatusCode::NO_CONTENT);

    let after1: Vec<String> = sqlx::query_scalar(
        "SELECT pr.name FROM contact_role_assignments cra \
         JOIN portal_roles pr ON pr.id = cra.role_id \
         WHERE cra.contact_id = $1 ORDER BY pr.name",
    )
    .bind(contact_id)
    .fetch_all(&pool)
    .await
    .expect("read");
    assert_eq!(after1, vec![BILLING.to_string()]);

    let put2 = app
        .client
        .put(app.url(&format!(
            "/api/v1/contacts/contacts/{contact_id}/portal-roles"
        )))
        .bearer_auth(&token)
        .json(&json!({ "role_ids": [support] }))
        .send()
        .await
        .expect("put2");
    assert_eq!(put2.status(), StatusCode::NO_CONTENT);

    let after2: Vec<String> = sqlx::query_scalar(
        "SELECT pr.name FROM contact_role_assignments cra \
         JOIN portal_roles pr ON pr.id = cra.role_id \
         WHERE cra.contact_id = $1 ORDER BY pr.name",
    )
    .bind(contact_id)
    .fetch_all(&pool)
    .await
    .expect("read");
    assert_eq!(after2, vec![SUPPORT.to_string()]);

    // is_portal_user must NOT have been flipped by the PUT (no side effect).
    let is_portal_user: bool =
        sqlx::query_scalar("SELECT is_portal_user FROM contacts WHERE id = $1")
            .bind(contact_id)
            .fetch_one(&pool)
            .await
            .expect("read");
    assert!(!is_portal_user, "PUT must not touch is_portal_user");

    // No portal_setup_tokens either.
    let token_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM portal_setup_tokens WHERE contact_id = $1")
            .bind(contact_id)
            .fetch_one(&pool)
            .await
            .expect("count");
    assert_eq!(token_count, 0, "PUT must not mint setup tokens");
}

#[sqlx::test]
async fn put_contact_portal_roles_rejects_cross_tenant_role(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let foreign_tenant = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO tenants (id, name, slug, kind) VALUES ($1, 'Foreign', 'foreign', 'org')",
    )
    .bind(foreign_tenant)
    .execute(&pool)
    .await
    .expect("seed foreign tenant");
    let foreign_role = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO portal_roles (id, tenant_id, name, capabilities, is_builtin) \
         VALUES ($1, $2, 'Foreign', ARRAY['tickets:read'], FALSE)",
    )
    .bind(foreign_role)
    .bind(foreign_tenant)
    .execute(&pool)
    .await
    .expect("seed foreign role");

    let company_id = seed_company_row(&pool, "Cross-Tenant Co").await;
    let contact_id = seed_contact_row(&pool, company_id, "xt@mcl.example").await;

    let resp = app
        .client
        .put(app.url(&format!(
            "/api/v1/contacts/contacts/{contact_id}/portal-roles"
        )))
        .bearer_auth(&token)
        .json(&json!({ "role_ids": [foreign_role] }))
        .send()
        .await
        .expect("put foreign");
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[sqlx::test]
async fn capabilities_endpoint_returns_all_descriptors(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let resp = app
        .client
        .get(app.url("/api/v1/portal-roles/capabilities"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("caps");
    assert!(
        resp.status().is_success(),
        "caps should 2xx, got {}",
        resp.status()
    );
    let body: serde_json::Value = resp.json().await.expect("json");
    let caps = body["capabilities"].as_array().expect("capabilities array");
    assert!(
        caps.len() >= 16,
        "expected at least 16 capability descriptors, got {}",
        caps.len()
    );
    for cap in caps {
        assert!(
            !cap["label"].as_str().unwrap_or("").is_empty(),
            "empty label on {cap:?}"
        );
        assert!(
            !cap["group"].as_str().unwrap_or("").is_empty(),
            "empty group on {cap:?}"
        );
        assert!(
            !cap["key"].as_str().unwrap_or("").is_empty(),
            "empty key on {cap:?}"
        );
    }
}
