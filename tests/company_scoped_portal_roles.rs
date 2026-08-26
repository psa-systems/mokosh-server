//! PMS-929 (mokosh-contact-login prompt 012): Company-scoped portal
//! role CRUD + assignment scope-check tests.
//!
//! Covers the two shapes migration 148 unlocks:
//!   * tenant-wide roles (existing shape, `company_id IS NULL`)
//!   * Company-scoped roles (new: `company_id = <uuid>`)
//! and the write-side enforcement on
//! `PUT /api/v1/contacts/contacts/{id}/portal-roles` +
//! `POST /api/v1/contacts/contacts/{id}/grant-portal-access` that a
//! Company-scoped role never lands on a contact of a different Company.

mod common;

use reqwest::StatusCode;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

const BILLING: &str = "Billing Contact";

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

async fn find_builtin_role_id(pool: &PgPool, name: &str) -> Uuid {
    sqlx::query_scalar(
        "SELECT id FROM portal_roles \
         WHERE tenant_id = $1 AND company_id IS NULL AND name = $2",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(name)
    .fetch_one(pool)
    .await
    .expect("built-in role")
}

// ============================================================================
// Create + uniqueness
// ============================================================================

#[sqlx::test]
async fn create_tenant_wide_role_with_null_company_id_succeeds(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let resp = app
        .client
        .post(app.url("/api/v1/portal-roles"))
        .bearer_auth(&token)
        .json(&json!({
            "name": "Consultant",
            "capabilities": ["tickets:read", "kb:read"],
        }))
        .send()
        .await
        .expect("create tenant-wide");
    assert!(resp.status().is_success(), "got {}", resp.status());
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["name"], "Consultant");
    assert!(
        body["company_id"].is_null(),
        "tenant-wide row must carry null company_id"
    );
}

#[sqlx::test]
async fn create_company_scoped_role_with_company_id_succeeds(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let company_id = seed_company_row(&pool, "Scope Co").await;

    let resp = app
        .client
        .post(app.url(&format!(
            "/api/v1/contacts/companies/{company_id}/portal-roles"
        )))
        .bearer_auth(&token)
        .json(&json!({
            "name": "On-Site Tech",
            "capabilities": ["tickets:read", "tickets:comment"],
        }))
        .send()
        .await
        .expect("create scoped");
    assert!(resp.status().is_success(), "got {}", resp.status());
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["name"], "On-Site Tech");
    assert_eq!(
        body["company_id"]
            .as_str()
            .and_then(|s| Uuid::parse_str(s).ok()),
        Some(company_id)
    );
    assert_eq!(body["is_builtin"], false);
}

#[sqlx::test]
async fn tenant_wide_and_company_scoped_can_share_a_name(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    // Tenant-wide "Billing" already exists as a built-in. Create a
    // Company-scoped "Billing" under a specific Company; both should
    // coexist and both should appear in the union list for that
    // Company.
    let company_id = seed_company_row(&pool, "Share-Name Co").await;

    let scoped = app
        .client
        .post(app.url(&format!(
            "/api/v1/contacts/companies/{company_id}/portal-roles"
        )))
        .bearer_auth(&token)
        .json(&json!({ "name": BILLING, "capabilities": ["invoices:read"] }))
        .send()
        .await
        .expect("create scoped");
    assert!(scoped.status().is_success(), "got {}", scoped.status());

    let list_resp = app
        .client
        .get(app.url(&format!(
            "/api/v1/contacts/companies/{company_id}/portal-roles"
        )))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list scoped");
    assert!(list_resp.status().is_success());
    let rows: Vec<serde_json::Value> = list_resp.json().await.expect("list json");
    let billing_rows: Vec<&serde_json::Value> = rows
        .iter()
        .filter(|r| r["name"].as_str() == Some(BILLING))
        .collect();
    assert_eq!(
        billing_rows.len(),
        2,
        "tenant-wide + Company-scoped Billing coexist under this Company; got {rows:?}"
    );
}

#[sqlx::test]
async fn two_company_scoped_roles_same_name_different_companies_coexist(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let company_a = seed_company_row(&pool, "Different-Co A").await;
    let company_b = seed_company_row(&pool, "Different-Co B").await;

    for cid in [company_a, company_b] {
        let resp = app
            .client
            .post(app.url(&format!("/api/v1/contacts/companies/{cid}/portal-roles")))
            .bearer_auth(&token)
            .json(&json!({ "name": "Custom", "capabilities": ["tickets:read"] }))
            .send()
            .await
            .expect("create");
        assert!(resp.status().is_success(), "got {}", resp.status());
    }

    // Two rows exist server-side, one per Company.
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM portal_roles \
         WHERE tenant_id = $1 AND LOWER(name) = 'custom' AND company_id IS NOT NULL",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(count, 2);
}

#[sqlx::test]
async fn two_tenant_wide_roles_same_name_return_409(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let first = app
        .client
        .post(app.url("/api/v1/portal-roles"))
        .bearer_auth(&token)
        .json(&json!({ "name": "Analyst", "capabilities": ["tickets:read"] }))
        .send()
        .await
        .expect("first");
    assert!(first.status().is_success(), "got {}", first.status());

    let dup = app
        .client
        .post(app.url("/api/v1/portal-roles"))
        .bearer_auth(&token)
        .json(&json!({ "name": "analyst", "capabilities": ["kb:read"] }))
        .send()
        .await
        .expect("dup");
    assert_eq!(dup.status(), StatusCode::CONFLICT);
}

#[sqlx::test]
async fn two_company_scoped_roles_same_name_same_company_return_409(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let company_id = seed_company_row(&pool, "Same-Co").await;

    let first = app
        .client
        .post(app.url(&format!(
            "/api/v1/contacts/companies/{company_id}/portal-roles"
        )))
        .bearer_auth(&token)
        .json(&json!({ "name": "Consultant", "capabilities": ["kb:read"] }))
        .send()
        .await
        .expect("first");
    assert!(first.status().is_success(), "got {}", first.status());

    let dup = app
        .client
        .post(app.url(&format!(
            "/api/v1/contacts/companies/{company_id}/portal-roles"
        )))
        .bearer_auth(&token)
        .json(&json!({ "name": "CONSULTANT", "capabilities": ["tickets:read"] }))
        .send()
        .await
        .expect("dup");
    assert_eq!(dup.status(), StatusCode::CONFLICT);
}

// ============================================================================
// List semantics
// ============================================================================

#[sqlx::test]
async fn list_portal_roles_none_returns_tenant_wide_only(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let company_id = seed_company_row(&pool, "Hidden Co").await;

    // Create a scoped role under the Company.
    let scoped_create = app
        .client
        .post(app.url(&format!(
            "/api/v1/contacts/companies/{company_id}/portal-roles"
        )))
        .bearer_auth(&token)
        .json(&json!({ "name": "Scoped-Only", "capabilities": ["tickets:read"] }))
        .send()
        .await
        .expect("scoped create");
    assert!(scoped_create.status().is_success());

    // Top-level list without ?company_id must NOT include the scoped
    // row.
    let list_resp = app
        .client
        .get(app.url("/api/v1/portal-roles"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list");
    assert!(list_resp.status().is_success());
    let rows: Vec<serde_json::Value> = list_resp.json().await.expect("list json");
    assert!(
        rows.iter().all(|r| r["company_id"].is_null()),
        "tenant-wide list must not include scoped rows; got {rows:?}"
    );
    assert!(
        rows.iter()
            .all(|r| r["name"].as_str() != Some("Scoped-Only")),
        "scoped role leaked into tenant-wide list; got {rows:?}"
    );
}

#[sqlx::test]
async fn list_portal_roles_some_returns_union(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let company_id = seed_company_row(&pool, "Union Co").await;

    let scoped_create = app
        .client
        .post(app.url(&format!(
            "/api/v1/contacts/companies/{company_id}/portal-roles"
        )))
        .bearer_auth(&token)
        .json(&json!({ "name": "Field Tech", "capabilities": ["tickets:read"] }))
        .send()
        .await
        .expect("scoped create");
    assert!(scoped_create.status().is_success());

    let list_resp = app
        .client
        .get(app.url(&format!("/api/v1/portal-roles?company_id={company_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list");
    assert!(list_resp.status().is_success());
    let rows: Vec<serde_json::Value> = list_resp.json().await.expect("list json");

    // Tenant-wide built-ins (Billing/Support/Read-Only) must come first,
    // then Company-scoped (Field Tech). Order: is_builtin DESC, then
    // company_id NULLS FIRST, then name.
    assert!(
        rows.len() >= 4,
        "expected 3 builtins + scoped, got {rows:?}"
    );
    // First rows must be tenant-wide built-ins.
    assert_eq!(rows[0]["is_builtin"], true);
    // The scoped row must appear and it must sort AFTER every
    // tenant-wide row.
    let scoped_idx = rows
        .iter()
        .position(|r| r["name"].as_str() == Some("Field Tech"))
        .expect("Field Tech present");
    let tenant_wide_count = rows.iter().filter(|r| r["company_id"].is_null()).count();
    assert!(
        scoped_idx >= tenant_wide_count,
        "scoped role must sort after all tenant-wide rows; got {rows:?}"
    );
    // Nested list under the Company must match the union too.
    let nested_resp = app
        .client
        .get(app.url(&format!(
            "/api/v1/contacts/companies/{company_id}/portal-roles"
        )))
        .bearer_auth(&token)
        .send()
        .await
        .expect("nested list");
    assert!(nested_resp.status().is_success());
    let nested: Vec<serde_json::Value> = nested_resp.json().await.expect("nested json");
    assert_eq!(rows.len(), nested.len(), "two list endpoints must agree");
}

#[sqlx::test]
async fn get_scoped_role_from_wrong_company_returns_404(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let owner_company = seed_company_row(&pool, "Owner Co").await;
    let other_company = seed_company_row(&pool, "Other Co").await;

    let create = app
        .client
        .post(app.url(&format!(
            "/api/v1/contacts/companies/{owner_company}/portal-roles"
        )))
        .bearer_auth(&token)
        .json(&json!({ "name": "Scoped", "capabilities": ["kb:read"] }))
        .send()
        .await
        .expect("create");
    let created: serde_json::Value = create.json().await.expect("json");
    let role_id = created["id"].as_str().expect("role id");

    // GET through the OTHER Company's scoped surface must 404.
    let wrong_resp = app
        .client
        .get(app.url(&format!(
            "/api/v1/contacts/companies/{other_company}/portal-roles/{role_id}"
        )))
        .bearer_auth(&token)
        .send()
        .await
        .expect("wrong get");
    assert_eq!(wrong_resp.status(), StatusCode::NOT_FOUND);

    // A tenant-wide role also 404s through the scoped surface, because
    // this surface is deliberately Company-scoped-only.
    let billing_id = find_builtin_role_id(&pool, BILLING).await;
    let tw_resp = app
        .client
        .get(app.url(&format!(
            "/api/v1/contacts/companies/{owner_company}/portal-roles/{billing_id}"
        )))
        .bearer_auth(&token)
        .send()
        .await
        .expect("tw get");
    assert_eq!(tw_resp.status(), StatusCode::NOT_FOUND);
}

// ============================================================================
// Assignment scope enforcement
// ============================================================================

#[sqlx::test]
async fn replace_role_assignments_rejects_scoped_role_for_wrong_company_400(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let owner_company = seed_company_row(&pool, "Owner Co").await;
    let other_company = seed_company_row(&pool, "Other Co").await;

    let create = app
        .client
        .post(app.url(&format!(
            "/api/v1/contacts/companies/{owner_company}/portal-roles"
        )))
        .bearer_auth(&token)
        .json(&json!({ "name": "Only-Owner", "capabilities": ["kb:read"] }))
        .send()
        .await
        .expect("create");
    let created: serde_json::Value = create.json().await.expect("json");
    let role_id = created["id"].as_str().expect("role id");

    // Contact belongs to `other_company`; assigning `Only-Owner` to
    // it must 400 with the scope-mismatch message.
    let contact_id = seed_contact_row(&pool, other_company, "wrong@mcl.example").await;
    let resp = app
        .client
        .put(app.url(&format!(
            "/api/v1/contacts/contacts/{contact_id}/portal-roles"
        )))
        .bearer_auth(&token)
        .json(&json!({ "role_ids": [role_id] }))
        .send()
        .await
        .expect("put");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // No assignments landed.
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM contact_role_assignments WHERE contact_id = $1")
            .bind(contact_id)
            .fetch_one(&pool)
            .await
            .expect("count");
    assert_eq!(count, 0);
}

#[sqlx::test]
async fn grant_portal_access_rejects_scoped_role_for_wrong_company_400(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let owner_company = seed_company_row(&pool, "Owner Co").await;
    let other_company = seed_company_row(&pool, "Other Co").await;

    let create = app
        .client
        .post(app.url(&format!(
            "/api/v1/contacts/companies/{owner_company}/portal-roles"
        )))
        .bearer_auth(&token)
        .json(&json!({ "name": "Grant-Wrong", "capabilities": ["kb:read"] }))
        .send()
        .await
        .expect("create");
    let created: serde_json::Value = create.json().await.expect("json");
    let role_id = created["id"].as_str().expect("role id");

    let contact_id = seed_contact_row(&pool, other_company, "grant-wrong@mcl.example").await;

    let resp = app
        .client
        .post(app.url(&format!(
            "/api/v1/contacts/contacts/{contact_id}/grant-portal-access"
        )))
        .bearer_auth(&token)
        .json(&json!({ "role_ids": [role_id] }))
        .send()
        .await
        .expect("grant");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // is_portal_user should still be false after the failed grant.
    let is_pu: bool = sqlx::query_scalar("SELECT is_portal_user FROM contacts WHERE id = $1")
        .bind(contact_id)
        .fetch_one(&pool)
        .await
        .expect("is_pu");
    assert!(
        !is_pu,
        "grant tx must roll back the flag flip on scope reject"
    );
}

#[sqlx::test]
async fn delete_company_scoped_role_with_assignments_returns_409_with_count(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let company_id = seed_company_row(&pool, "Del-Block Co").await;

    let create = app
        .client
        .post(app.url(&format!(
            "/api/v1/contacts/companies/{company_id}/portal-roles"
        )))
        .bearer_auth(&token)
        .json(&json!({ "name": "In-Use", "capabilities": ["tickets:read"] }))
        .send()
        .await
        .expect("create");
    let created: serde_json::Value = create.json().await.expect("json");
    let role_id_str = created["id"].as_str().expect("role id").to_string();
    let role_id = Uuid::parse_str(&role_id_str).unwrap();

    let contact_id = seed_contact_row(&pool, company_id, "in-use@mcl.example").await;

    // Assign via the API so the scope check is exercised too.
    let put = app
        .client
        .put(app.url(&format!(
            "/api/v1/contacts/contacts/{contact_id}/portal-roles"
        )))
        .bearer_auth(&token)
        .json(&json!({ "role_ids": [role_id_str] }))
        .send()
        .await
        .expect("put");
    assert_eq!(put.status(), StatusCode::NO_CONTENT);
    let _ = role_id; // keep the parsed uuid available if the assertion below needs it later

    let del = app
        .client
        .delete(app.url(&format!(
            "/api/v1/contacts/companies/{company_id}/portal-roles/{role_id_str}"
        )))
        .bearer_auth(&token)
        .send()
        .await
        .expect("delete");
    assert_eq!(del.status(), StatusCode::CONFLICT);
    let body: serde_json::Value = del.json().await.expect("json");
    // Error message must surface the count so the operator sees the
    // number in the UI.
    let msg = body["error"]["message"]
        .as_str()
        .or_else(|| body["message"].as_str())
        .unwrap_or("");
    assert!(
        msg.contains('1'),
        "expected count in delete-block message; got {body:?}"
    );
}

// ============================================================================
// Post-migration + cross-tenant integrity
// ============================================================================

#[sqlx::test]
async fn built_in_roles_remain_tenant_wide_after_migration(pool: PgPool) {
    // No API involved; verify the seed rows stayed with company_id NULL
    // through migration 148.
    let all_null: bool = sqlx::query_scalar(
        "SELECT COALESCE(bool_and(company_id IS NULL), TRUE) \
         FROM portal_roles WHERE is_builtin = TRUE AND tenant_id = $1",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(&pool)
    .await
    .expect("bool_and");
    assert!(
        all_null,
        "built-in roles must stay tenant-wide after migration"
    );

    // And the count is still 3 (Billing / Support / Read-Only).
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM portal_roles WHERE is_builtin = TRUE AND tenant_id = $1",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(count, 3);
}

#[sqlx::test]
async fn cross_tenant_isolation_holds_on_company_scoped_roles(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    // Home tenant Company + scoped role.
    let home_company = seed_company_row(&pool, "Home Co").await;
    let created = app
        .client
        .post(app.url(&format!(
            "/api/v1/contacts/companies/{home_company}/portal-roles"
        )))
        .bearer_auth(&token)
        .json(&json!({ "name": "Home-Scoped", "capabilities": ["kb:read"] }))
        .send()
        .await
        .expect("create");
    assert!(created.status().is_success());

    // Seed a foreign tenant + Company at the SQL layer + a scoped role
    // under it, then verify that the home-tenant caller cannot see it.
    let foreign_tenant = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO tenants (id, name, slug, kind) VALUES ($1, 'Foreign', 'foreign', 'org')",
    )
    .bind(foreign_tenant)
    .execute(&pool)
    .await
    .expect("seed foreign tenant");
    let foreign_company = Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, 'Foreign Co')")
        .bind(foreign_company)
        .bind(foreign_tenant)
        .execute(&pool)
        .await
        .expect("seed foreign company");
    let foreign_role = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO portal_roles (id, tenant_id, company_id, name, capabilities, is_builtin) \
         VALUES ($1, $2, $3, 'Foreign-Scoped', ARRAY['tickets:read'], FALSE)",
    )
    .bind(foreign_role)
    .bind(foreign_tenant)
    .bind(foreign_company)
    .execute(&pool)
    .await
    .expect("seed foreign role");

    // From the home tenant, the scoped-role lookup under the foreign
    // Company must 404. (Foreign Company id has no rows under the
    // caller's tenant; the scoped-list handler passes the id straight
    // through, and `PortalRoleService::list_roles` filters on
    // `tenant_id = home`, so nothing scoped leaks.)
    let list = app
        .client
        .get(app.url(&format!(
            "/api/v1/contacts/companies/{foreign_company}/portal-roles"
        )))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list foreign");
    let rows: Vec<serde_json::Value> = list.json().await.expect("list json");
    assert!(
        rows.iter()
            .all(|r| r["name"].as_str() != Some("Foreign-Scoped")),
        "foreign-tenant scoped role must be invisible to home tenant; got {rows:?}"
    );
}

// ============================================================================
// Update semantics
// ============================================================================

#[sqlx::test]
async fn update_role_ignores_or_rejects_company_id_change(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let company_id = seed_company_row(&pool, "Update Co").await;

    let create = app
        .client
        .post(app.url(&format!(
            "/api/v1/contacts/companies/{company_id}/portal-roles"
        )))
        .bearer_auth(&token)
        .json(&json!({ "name": "Editable", "capabilities": ["kb:read"] }))
        .send()
        .await
        .expect("create");
    let created: serde_json::Value = create.json().await.expect("json");
    let role_id = created["id"].as_str().expect("role id");

    // Even if a body tries to carry `company_id`, the update DTO does
    // not deserialise it, so the value stays as-is. Rename to verify
    // the PUT went through and the scope did not move.
    let another_company = seed_company_row(&pool, "Not-The-Owner").await;
    let put = app
        .client
        .put(app.url(&format!(
            "/api/v1/contacts/companies/{company_id}/portal-roles/{role_id}"
        )))
        .bearer_auth(&token)
        .json(&json!({
            "name": "Renamed",
            "company_id": another_company,
        }))
        .send()
        .await
        .expect("put");
    assert!(put.status().is_success(), "put returned {}", put.status());

    let after: (Option<Uuid>, String) =
        sqlx::query_as("SELECT company_id, name FROM portal_roles WHERE id = $1")
            .bind(Uuid::parse_str(role_id).unwrap())
            .fetch_one(&pool)
            .await
            .expect("row");
    assert_eq!(after.0, Some(company_id), "company_id must stay unchanged");
    assert_eq!(after.1, "Renamed");
}

// ============================================================================
// Belt-and-braces on the nested create
// ============================================================================

#[sqlx::test]
async fn nested_post_body_company_id_must_equal_path_400(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let path_company = seed_company_row(&pool, "Path Co").await;
    let body_company = seed_company_row(&pool, "Body Co").await;

    let resp = app
        .client
        .post(app.url(&format!(
            "/api/v1/contacts/companies/{path_company}/portal-roles"
        )))
        .bearer_auth(&token)
        .json(&json!({
            "name": "Mismatched",
            "capabilities": ["kb:read"],
            "company_id": body_company,
        }))
        .send()
        .await
        .expect("nested post");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
