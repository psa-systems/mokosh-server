//! Integration tests for the `tenants` module.
//!
//! Covers:
//! - PMS-124 F10 acceptance: list tenants returns the seeded default.
//! - PMS-21 AC5: module-config read happy path, module-config
//!   write-then-read persistence, cross-tenant access on module-config
//!   and `GET /tenants/:id` returns 403 for non-super-admin callers.

mod common;

use sqlx::PgPool;

use mokosh_server::modules::audit::AuditCtx;
use mokosh_server::modules::auth::AuthService;
use mokosh_server::modules::tenants::{CreateTenantRequest, TenantService};
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
    assert_eq!(
        user_tenant(&pool, admin_id).await,
        common::DEFAULT_TENANT_ID
    );

    let tenants = TenantService::new(Database::from_pool(pool.clone()));
    let org_tenant = tenants
        .ensure_personal_tenant(uuid::Uuid::new_v4())
        .await
        .expect("provision target tenant");

    let auth = AuthService::new(
        Database::from_pool(pool.clone()),
        "test-secret".into(),
        vec![],
    );

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
async fn ensure_personal_tenant_provisions_then_is_idempotent(pool: PgPool) {
    // PMS-244: a brand-new SSO user with no invite gets their own personal
    // tenant; subsequent logins resolve the same one (no duplicate).
    let svc = TenantService::new(Database::from_pool(pool.clone()));
    let owner_a = uuid::Uuid::new_v4();
    let owner_b = uuid::Uuid::new_v4();

    let first = svc
        .ensure_personal_tenant(owner_a)
        .await
        .expect("provision tenant");

    // A real, distinct tenant - not the shared default.
    assert_ne!(first, common::DEFAULT_TENANT_ID);

    let mapped: Option<uuid::Uuid> =
        sqlx::query_scalar("SELECT id FROM tenants WHERE personal_owner_id = $1")
            .bind(owner_a)
            .fetch_optional(&pool)
            .await
            .expect("read mapping");
    assert_eq!(mapped, Some(first), "owner maps to the provisioned tenant");

    let kind: String = sqlx::query_scalar("SELECT kind FROM tenants WHERE id = $1")
        .bind(first)
        .fetch_one(&pool)
        .await
        .expect("read kind");
    assert_eq!(kind, "personal");

    // Default config copied so the tenant works out of the box (statuses are a
    // representative slice of `copy_default_config`).
    let status_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM ticket_statuses WHERE tenant_id = $1")
            .bind(first)
            .fetch_one(&pool)
            .await
            .expect("count statuses");
    assert!(status_count > 0, "default ticket statuses copied");

    // Second call resolves the same tenant; a different owner gets a different one.
    let again = svc
        .ensure_personal_tenant(owner_a)
        .await
        .expect("resolve tenant");
    assert_eq!(again, first, "idempotent for the same owner");

    let other = svc
        .ensure_personal_tenant(owner_b)
        .await
        .expect("provision second owner");
    assert_ne!(other, first, "distinct owner gets a distinct tenant");

    let tenant_total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tenants")
        .fetch_one(&pool)
        .await
        .expect("count tenants");
    // default + two provisioned personal tenants.
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

// PMS-260: `tenants::list_tenants` runs no SQL tenant filter (listing every
// tenant is its whole job); the only thing standing between a tenant-scoped
// caller and the full list is the route's SuperAdmin guard. Pin that guard: a
// non-super-admin must get 403, never the global tenant list.
#[sqlx::test]
async fn list_tenants_rejects_non_super_admin(pool: PgPool) {
    let (_admin_id, _admin_email, _admin_password) = common::seed_admin(&pool).await;
    // A second tenant exists, so an unscoped leak would be observable.
    let (_tenant_b_id, _b_uid, _b_email, _b_password) =
        common::seed_tenant_with_admin(&pool, "pms260-list-b").await;
    // A tenant-A admin (role `admin`, NOT super_admin).
    let (_tech_id, tech_email, tech_password) = common::seed_user(
        &pool,
        common::DEFAULT_TENANT_ID,
        "non-super@example.com",
        "admin",
    )
    .await;

    let app = common::boot(pool).await;
    let token = common::login(&app, &tech_email, &tech_password).await;

    let resp = app
        .client
        .get(app.url("/api/v1/tenants"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send list tenants as non-super-admin");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::FORBIDDEN,
        "a non-super-admin must not be able to list all tenants"
    );
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
    let (_tech_a_id, tech_a_email, tech_a_password) = common::seed_user(
        &pool,
        common::DEFAULT_TENANT_ID,
        "tech-a@example.com",
        "admin",
    )
    .await;

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
    let (_tech_id, tech_email, tech_password) = common::seed_user(
        &pool,
        common::DEFAULT_TENANT_ID,
        "techguy-a@example.com",
        "technician",
    )
    .await;

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

#[sqlx::test]
async fn ensure_default_config_seeds_off_psa_tenant_idempotently(pool: PgPool) {
    // PMS-288: a tenant provisioned off the PSA path (auth/SSO or manual) has no
    // lookup config and no per-tenant sequences, so ticket creation 500s.
    // ensure_default_config backfills both, idempotently.
    let svc = TenantService::new(Database::from_pool(pool.clone()));

    // A bare org tenant created WITHOUT copy_default_config / sequences.
    let tenant = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO tenants (id, name, slug, status, kind)
         VALUES ($1, 'Off-PSA', 'off-psa-288', 'active', 'org')",
    )
    .bind(tenant)
    .execute(&pool)
    .await
    .expect("insert bare tenant");

    let default_status = |p: PgPool| async move {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM ticket_statuses WHERE tenant_id = $1 AND is_default",
        )
        .bind(tenant)
        .fetch_one(&p)
        .await
        .expect("count default status")
    };
    let seq_rows = |p: PgPool| async move {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM ticket_sequences WHERE tenant_id = $1")
            .bind(tenant)
            .fetch_one(&p)
            .await
            .expect("count sequence rows")
    };

    assert_eq!(
        default_status(pool.clone()).await,
        0,
        "bare tenant: no default status"
    );
    assert_eq!(
        seq_rows(pool.clone()).await,
        0,
        "bare tenant: no sequence row"
    );

    svc.ensure_default_config(tenant).await.expect("seed");

    assert_eq!(
        default_status(pool.clone()).await,
        1,
        "seeded a default status"
    );
    assert_eq!(seq_rows(pool.clone()).await, 1, "seeded a ticket sequence");

    let statuses_after_first: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM ticket_statuses WHERE tenant_id = $1")
            .bind(tenant)
            .fetch_one(&pool)
            .await
            .expect("count statuses");

    // Idempotent: a second call adds no duplicate lookups or sequence rows.
    svc.ensure_default_config(tenant).await.expect("seed again");
    let statuses_after_second: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM ticket_statuses WHERE tenant_id = $1")
            .bind(tenant)
            .fetch_one(&pool)
            .await
            .expect("count statuses");
    assert_eq!(
        statuses_after_first, statuses_after_second,
        "second seed must not duplicate lookups"
    );
    assert_eq!(
        seq_rows(pool.clone()).await,
        1,
        "second seed must not duplicate the sequence row"
    );
}

#[sqlx::test]
async fn create_tenant_sets_org_kind(pool: PgPool) {
    // PMS-287: `create_tenant` must set the NOT-NULL `kind` column. Migration
    // 019_tenant_kind dropped the column default, so omitting it inserts NULL
    // and the INSERT fails with SQLSTATE 23502 (POST /api/v1/tenants 500s). This
    // is the org-create path, so kind must be 'org'. No existing test exercised
    // the create_tenant insert, which is why the missing column went unnoticed.
    let svc = TenantService::new(Database::from_pool(pool.clone()));
    let req = CreateTenantRequest {
        name: "PMS-287 Org".into(),
        slug: "pms287-org".into(),
        billing_email: None,
        billing_contact_name: None,
        subscription_plan: None,
        admin_email: "owner-pms287@example.test".into(),
        admin_first_name: "Owner".into(),
        admin_last_name: "Pms287".into(),
    };

    let tenant = svc
        .create_tenant(&req, &AuditCtx::system(common::DEFAULT_TENANT_ID))
        .await
        .expect("create_tenant must succeed (regression: missing NOT NULL kind)");

    let kind: String = sqlx::query_scalar("SELECT kind FROM tenants WHERE id = $1")
        .bind(tenant.id)
        .fetch_one(&pool)
        .await
        .expect("read kind");
    assert_eq!(kind, "org", "create_tenant provisions an org-kind tenant");
}
