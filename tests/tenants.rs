//! Integration tests for the `tenants` module.
//!
//! Covers:
//! - PMS-124 F10 acceptance: list tenants returns the seeded default.
//! - PMS-21 AC5: module-config read happy path, module-config
//!   write-then-read persistence, cross-tenant access on module-config
//!   and `GET /tenants/:id` returns 403 for non-super-admin callers.

mod common;

use sqlx::PgPool;

use mokosh_server::modules::auth::AuthService;
use mokosh_server::modules::tenants::TenantService;
use mokosh_server::Database;

async fn user_tenant(pool: &PgPool, user_id: uuid::Uuid) -> uuid::Uuid {
    sqlx::query_scalar("SELECT tenant_id FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .expect("read user tenant")
}

#[sqlx::test]
async fn rehome_moves_default_tenant_user_to_org_tenant_once(pool: PgPool) {
    // PMS-243: a user mirrored into the default tenant is re-homed to their org
    // tenant on first org-claimed login; scoped to the default tenant and
    // idempotent.
    let (admin_id, _email, _password) = common::seed_admin(&pool).await;
    assert_eq!(user_tenant(&pool, admin_id).await, common::DEFAULT_TENANT_ID);

    let tenants = TenantService::new(Database::from_pool(pool.clone()));
    let org_tenant = tenants
        .ensure_tenant_for_bunyip_org("bunyip-org-rehome")
        .await
        .expect("provision org tenant");

    let auth = AuthService::new(Database::from_pool(pool.clone()), "test-secret".into(), vec![]);

    // First org-claimed login: the user moves out of the default tenant.
    let moved = auth
        .rehome_user_between_tenants(admin_id, common::DEFAULT_TENANT_ID, org_tenant)
        .await
        .expect("rehome");
    assert!(moved, "user re-homed on first sight");
    assert_eq!(user_tenant(&pool, admin_id).await, org_tenant);

    // Idempotent: already out of the default tenant, so nothing to move.
    let again = auth
        .rehome_user_between_tenants(admin_id, common::DEFAULT_TENANT_ID, org_tenant)
        .await
        .expect("rehome idempotent");
    assert!(!again, "no-op once re-homed");
    assert_eq!(user_tenant(&pool, admin_id).await, org_tenant);
}

#[sqlx::test]
async fn ensure_tenant_for_bunyip_org_provisions_then_is_idempotent(pool: PgPool) {
    // PMS-240: first login for an org provisions a dedicated tenant; subsequent
    // logins resolve the same one (no duplicate, no funnel into the default).
    let svc = TenantService::new(Database::from_pool(pool.clone()));

    let first = svc
        .ensure_tenant_for_bunyip_org("bunyip-org-abc")
        .await
        .expect("provision tenant");

    // A real, distinct tenant - not the shared default.
    assert_ne!(first, common::DEFAULT_TENANT_ID);

    let mapped: Option<uuid::Uuid> =
        sqlx::query_scalar("SELECT id FROM tenants WHERE bunyip_org_id = $1")
            .bind("bunyip-org-abc")
            .fetch_optional(&pool)
            .await
            .expect("read mapping");
    assert_eq!(mapped, Some(first), "org id maps to the provisioned tenant");

    // Default config copied so the tenant works out of the box (statuses are a
    // representative slice of `copy_default_config`).
    let status_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM ticket_statuses WHERE tenant_id = $1")
            .bind(first)
            .fetch_one(&pool)
            .await
            .expect("count statuses");
    assert!(status_count > 0, "default ticket statuses copied");

    // Second call resolves the same tenant; a different org gets a different one.
    let again = svc
        .ensure_tenant_for_bunyip_org("bunyip-org-abc")
        .await
        .expect("resolve tenant");
    assert_eq!(again, first, "idempotent for the same org");

    let other = svc
        .ensure_tenant_for_bunyip_org("bunyip-org-xyz")
        .await
        .expect("provision second org");
    assert_ne!(other, first, "distinct org gets a distinct tenant");

    let tenant_total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tenants")
        .fetch_one(&pool)
        .await
        .expect("count tenants");
    // default + two provisioned orgs.
    assert_eq!(tenant_total, 3, "no duplicate tenants provisioned");
}

#[sqlx::test]
async fn list_tenants_returns_default(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let resp = app
        .client
        .get(app.url("/api/v1/tenants"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send list tenants");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "list tenants should succeed for a super_admin"
    );

    let body: serde_json::Value = resp.json().await.expect("tenants list JSON");
    let items = body["data"].as_array().expect("tenants list has data");
    let default = items
        .iter()
        .find(|t| t["id"].as_str() == Some(&common::DEFAULT_TENANT_ID.to_string()))
        .expect("default tenant must be present in the list");
    assert_eq!(default["slug"].as_str(), Some("default"));
}

// ============================================================================
// PMS-21 AC5: module config + cross-tenant authz
// ============================================================================

/// `GET /tenants/{id}/modules/{module}` returns 200 with a default
/// `ModuleConfig` shape (`module_name`, `is_enabled`, `config`) for a
/// module that has no row yet. Pins the F5 read endpoint plus the
/// service's missing-row default-shaped fallback at
/// `service.rs:380-385`.
#[sqlx::test]
async fn module_config_read_returns_default(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let resp = app
        .client
        .get(app.url(&format!(
            "/api/v1/tenants/{}/modules/billing",
            common::DEFAULT_TENANT_ID
        )))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send get module config");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "module config GET should succeed for super_admin on own tenant"
    );

    let body: serde_json::Value = resp.json().await.expect("module config JSON");
    assert_eq!(body["module_name"].as_str(), Some("billing"));
    assert!(
        body["is_enabled"].is_boolean(),
        "is_enabled must be present"
    );
    assert!(body["config"].is_object(), "config must be a JSON object");
}

/// `PUT /tenants/{id}/modules/{module}` upserts the row and the
/// independent re-GET reflects the new state. Pins F5 write +
/// persistence at `service.rs:390-413`. Uses a fresh `test_module`
/// name so the migration-023 seed data (which may pre-populate rows
/// for known modules) cannot interfere.
#[sqlx::test]
async fn module_config_write_then_read_persists(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let put_resp = app
        .client
        .put(app.url(&format!(
            "/api/v1/tenants/{}/modules/test_module",
            common::DEFAULT_TENANT_ID
        )))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "is_enabled": true,
            "config": { "foo": "bar" },
        }))
        .send()
        .await
        .expect("send put module config");
    assert!(
        put_resp.status().is_success(),
        "module config PUT should 2xx, got {}",
        put_resp.status()
    );

    let get_resp = app
        .client
        .get(app.url(&format!(
            "/api/v1/tenants/{}/modules/test_module",
            common::DEFAULT_TENANT_ID
        )))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send re-get module config");
    assert_eq!(get_resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = get_resp.json().await.expect("re-get JSON");
    assert_eq!(body["module_name"].as_str(), Some("test_module"));
    assert_eq!(body["is_enabled"].as_bool(), Some(true));
    assert_eq!(body["config"]["foo"].as_str(), Some("bar"));
}

/// Module-config endpoints reject cross-tenant access by a non-super-
/// admin. Pins the authz checks at `routes.rs:186` (GET) and `:205`
/// (PUT). Super-admin is verified separately by the happy paths above.
#[sqlx::test]
async fn module_config_cross_tenant_returns_403(pool: PgPool) {
    let (_admin_id, _admin_email, _admin_password) = common::seed_admin(&pool).await;
    let (tenant_b_id, _b_user_id, _b_email, _b_password) =
        common::seed_tenant_with_admin(&pool, "pms21-tenant-b").await;
    // Tenant-A admin (not super_admin) - cannot reach tenant B.
    let (_tech_a_id, tech_a_email, tech_a_password) =
        common::seed_user(&pool, "tech-a@example.com", "admin").await;

    let app = common::boot(pool).await;
    let token = common::login(&app, &tech_a_email, &tech_a_password).await;

    let get_resp = app
        .client
        .get(app.url(&format!("/api/v1/tenants/{tenant_b_id}/modules/billing")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send cross-tenant get module config");
    assert_eq!(
        get_resp.status(),
        reqwest::StatusCode::FORBIDDEN,
        "tenant-A admin must not read tenant-B's module config"
    );

    let put_resp = app
        .client
        .put(app.url(&format!("/api/v1/tenants/{tenant_b_id}/modules/billing")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "is_enabled": true }))
        .send()
        .await
        .expect("send cross-tenant put module config");
    assert_eq!(
        put_resp.status(),
        reqwest::StatusCode::FORBIDDEN,
        "tenant-A admin must not write tenant-B's module config"
    );
}

/// `GET /tenants/{other_tenant_id}` returns 403 when the caller is a
/// non-super-admin authenticated under tenant A trying to read tenant
/// B. Pins the authz check at `routes.rs:92-100` (`get_tenant`).
#[sqlx::test]
async fn cross_tenant_get_tenant_returns_403(pool: PgPool) {
    let (_admin_id, _admin_email, _admin_password) = common::seed_admin(&pool).await;
    let (tenant_b_id, _b_user_id, _b_email, _b_password) =
        common::seed_tenant_with_admin(&pool, "pms21-tenant-b-get").await;
    let (_tech_id, tech_email, tech_password) =
        common::seed_user(&pool, "techguy-a@example.com", "technician").await;

    let app = common::boot(pool).await;
    let token = common::login(&app, &tech_email, &tech_password).await;

    let resp = app
        .client
        .get(app.url(&format!("/api/v1/tenants/{tenant_b_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send cross-tenant get tenant");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::FORBIDDEN,
        "tenant-A technician must not read tenant-B's record"
    );
}
