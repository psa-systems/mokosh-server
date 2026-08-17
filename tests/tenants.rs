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
        .ensure_personal_tenant(uuid::Uuid::new_v4(), None, None)
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
        .ensure_personal_tenant(owner_a, None, None)
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
        .ensure_personal_tenant(owner_a, None, None)
        .await
        .expect("resolve tenant");
    assert_eq!(again, first, "idempotent for the same owner");

    let other = svc
        .ensure_personal_tenant(owner_b, None, None)
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

/// PMS-413: `create_tenant` also provisions an `internal` own-company named
/// after the tenant and points `tenants.own_company_id` at it.
#[sqlx::test]
async fn create_tenant_provisions_internal_own_company(pool: PgPool) {
    let svc = TenantService::new(Database::from_pool(pool.clone()));
    let req = CreateTenantRequest {
        name: "PMS-413 Org".into(),
        slug: "pms413-org".into(),
        billing_email: None,
        billing_contact_name: None,
        subscription_plan: None,
        admin_email: "owner-pms413@example.test".into(),
        admin_first_name: "Owner".into(),
        admin_last_name: "Pms413".into(),
    };

    let tenant = svc
        .create_tenant(&req, &AuditCtx::system(common::DEFAULT_TENANT_ID))
        .await
        .expect("create_tenant must succeed");

    let own_company_id: Option<uuid::Uuid> =
        sqlx::query_scalar("SELECT own_company_id FROM tenants WHERE id = $1")
            .bind(tenant.id)
            .fetch_one(&pool)
            .await
            .expect("read own_company_id");
    let own_company_id = own_company_id.expect("own_company_id is set after provisioning");

    let (name, company_type): (String, String) =
        sqlx::query_as("SELECT name, company_type FROM companies WHERE id = $1 AND tenant_id = $2")
            .bind(own_company_id)
            .bind(tenant.id)
            .fetch_one(&pool)
            .await
            .expect("own-company row exists");
    assert_eq!(company_type, "internal", "own-company is type internal");
    assert_eq!(name, "PMS-413 Org", "own-company is named after the tenant");
}

/// PMS-413: a tenant provisioned off the PSA create path (e.g. a manually
/// inserted org tenant a bunyip user lands in) gets an own-company when
/// `ensure_default_config` runs, and a second run is a no-op (one company).
#[sqlx::test]
async fn ensure_default_config_backfills_own_company_idempotently(pool: PgPool) {
    // A tenant inserted directly, bypassing create_tenant: no own_company yet.
    let (tenant_id, _user_id, _email, _password) =
        common::seed_tenant_with_admin(&pool, "pms413-backfill").await;

    let pre: Option<uuid::Uuid> =
        sqlx::query_scalar("SELECT own_company_id FROM tenants WHERE id = $1")
            .bind(tenant_id)
            .fetch_one(&pool)
            .await
            .expect("read own_company_id pre");
    assert!(
        pre.is_none(),
        "directly-seeded tenant starts with no own-company"
    );

    let svc = TenantService::new(Database::from_pool(pool.clone()));
    svc.ensure_default_config(tenant_id)
        .await
        .expect("first ensure_default_config");
    svc.ensure_default_config(tenant_id)
        .await
        .expect("second ensure_default_config (idempotent)");

    let own_company_id: Option<uuid::Uuid> =
        sqlx::query_scalar("SELECT own_company_id FROM tenants WHERE id = $1")
            .bind(tenant_id)
            .fetch_one(&pool)
            .await
            .expect("read own_company_id post");
    assert!(own_company_id.is_some(), "own-company set after backfill");

    let internal_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM companies WHERE tenant_id = $1 AND company_type = 'internal'",
    )
    .bind(tenant_id)
    .fetch_one(&pool)
    .await
    .expect("count internal companies");
    assert_eq!(
        internal_count, 1,
        "exactly one own-company, even after two runs"
    );
}

// ============================================================================
// PMS-751: the caller's own tenant, addressed without an id
// ============================================================================

/// The organization settings page could neither load nor save, because the SPA
/// built its URL from the `mokosh_tenant_id` id_token claim and bunyip only
/// mints that for a client configured with `tenant_claim_name`. Without it the
/// SPA carried the nil uuid and asked for a tenant that does not exist.
///
/// These routes take no id, so the page works whether or not that claim is ever
/// configured. Asserted end to end because the whole failure was that the id in
/// the URL was wrong, which no unit test on a service can see.
#[sqlx::test]
async fn current_reads_and_renames_the_callers_own_tenant(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let seeded: String = sqlx::query_scalar("SELECT name FROM tenants WHERE id = $1")
        .bind(common::DEFAULT_TENANT_ID)
        .fetch_one(&pool)
        .await
        .expect("seeded tenant name");

    let body: serde_json::Value = app
        .client
        .get(app.url("/api/v1/tenants/current"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send get current tenant")
        .json()
        .await
        .expect("current tenant JSON");
    assert_eq!(body["name"].as_str(), Some(seeded.as_str()));
    assert_eq!(
        body["id"].as_str(),
        Some(common::DEFAULT_TENANT_ID.to_string().as_str()),
        "`current` must resolve the caller's own tenant, not the first row it finds"
    );

    let resp = app
        .client
        .put(app.url("/api/v1/tenants/current"))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "name": "Acme IT" }))
        .send()
        .await
        .expect("send rename");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    // The name clients see in request-form and invitation email, so the write
    // is asserted against the column those read rather than the response body.
    let stored: String = sqlx::query_scalar("SELECT name FROM tenants WHERE id = $1")
        .bind(common::DEFAULT_TENANT_ID)
        .fetch_one(&pool)
        .await
        .expect("renamed tenant");
    assert_eq!(stored, "Acme IT");
}

/// `current` is not a uuid, and must never be parsed as one: a static segment
/// has to win over `/{tenant_id}` or the route would 400 on every call.
#[sqlx::test]
async fn current_is_not_mistaken_for_a_tenant_id(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let resp = app
        .client
        .get(app.url("/api/v1/tenants/current"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send get current tenant");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "a 400 here means `current` was routed into the uuid path param"
    );
}

/// Reading your own tenant needs only a session, but renaming it is tenant-wide
/// configuration: the name is the "from" on every email a client receives.
#[sqlx::test]
async fn a_non_admin_can_read_but_not_rename_their_tenant(pool: PgPool) {
    let (_tech_id, tech_email, tech_password) = common::seed_user(
        &pool,
        common::DEFAULT_TENANT_ID,
        "pms751-tech@example.com",
        "technician",
    )
    .await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &tech_email, &tech_password).await;

    let read = app
        .client
        .get(app.url("/api/v1/tenants/current"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send read");
    assert_eq!(read.status(), reqwest::StatusCode::OK);

    let write = app
        .client
        .put(app.url("/api/v1/tenants/current"))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "name": "Renamed by a technician" }))
        .send()
        .await
        .expect("send rename");
    assert_eq!(write.status(), reqwest::StatusCode::FORBIDDEN);

    let stored: String = sqlx::query_scalar("SELECT name FROM tenants WHERE id = $1")
        .bind(common::DEFAULT_TENANT_ID)
        .fetch_one(&pool)
        .await
        .expect("tenant name");
    assert_ne!(stored, "Renamed by a technician");
}

/// PMS-751: the new routes address the caller's own tenant and nothing else, so
/// a second tenant's row must be unreachable through them however the caller is
/// authenticated.
#[sqlx::test]
async fn current_cannot_reach_another_tenant(pool: PgPool) {
    let (other_tenant, _id, _email, _password) =
        common::seed_tenant_with_admin(&pool, "pms751-other").await;
    let (_tech_id, email, password) = common::seed_user(
        &pool,
        common::DEFAULT_TENANT_ID,
        "pms751-scoped@example.com",
        "admin",
    )
    .await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    app.client
        .put(app.url("/api/v1/tenants/current"))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "name": "Only mine" }))
        .send()
        .await
        .expect("send rename");

    let others: String = sqlx::query_scalar("SELECT name FROM tenants WHERE id = $1")
        .bind(other_tenant)
        .fetch_one(&pool)
        .await
        .expect("other tenant name");
    assert_ne!(
        others, "Only mine",
        "renaming via `current` must touch only the caller's tenant"
    );
}

// ============================================================================
// MAPPS-429: organisation contact + logo
// ============================================================================

/// The logo has to reach a client's browser AND a client's mail client, neither
/// of which has a session, so the read side is public. Asserted end to end
/// because the whole point is the hop from an authenticated upload to an
/// unauthenticated fetch.
#[sqlx::test]
async fn a_logo_is_uploaded_by_an_admin_and_served_to_anyone(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    // A one-pixel PNG. Real bytes rather than a stub, so the round trip proves
    // the file survived rather than that a string did.
    let png: &[u8] = &[
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44,
        0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F,
        0x15, 0xC4, 0x89,
    ];
    let part = reqwest::multipart::Part::bytes(png.to_vec())
        .file_name("logo.png")
        .mime_str("image/png")
        .expect("mime");
    let resp = app
        .client
        .put(app.url("/api/v1/tenants/current/logo"))
        .bearer_auth(&token)
        .multipart(reqwest::multipart::Form::new().part("file", part))
        .send()
        .await
        .expect("send upload");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("tenant JSON");
    let logo_url = body["branding"]["logo_url"]
        .as_str()
        .expect("branding carries the logo path")
        .to_string();
    assert!(
        logo_url.starts_with("/api/v1/public/"),
        "the stored path must be the public one, got {logo_url}"
    );

    // No bearer: this is the client, or their mail client.
    let served = app
        .client
        .get(app.url(&logo_url))
        .send()
        .await
        .expect("send public fetch");
    assert_eq!(served.status(), reqwest::StatusCode::OK);
    assert_eq!(
        served
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("image/png"),
        "the stored mime is what makes this renderable without sniffing"
    );
    assert_eq!(served.bytes().await.expect("bytes").as_ref(), png);

    // Deleting clears the pointer, and the public route stops answering.
    let deleted = app
        .client
        .delete(app.url("/api/v1/tenants/current/logo"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send delete");
    assert_eq!(deleted.status(), reqwest::StatusCode::OK);
    let after: serde_json::Value = deleted.json().await.expect("tenant JSON");
    assert!(after["branding"]["logo_url"].is_null());

    let gone = app
        .client
        .get(app.url(&logo_url))
        .send()
        .await
        .expect("send public fetch after delete");
    assert_eq!(gone.status(), reqwest::StatusCode::NOT_FOUND);
}

/// A logo is what every client sees on this tenant's forms and email, so it is
/// tenant-wide configuration, gated like the rename.
#[sqlx::test]
async fn a_non_admin_cannot_replace_the_logo(pool: PgPool) {
    let (_tech_id, email, password) = common::seed_user(
        &pool,
        common::DEFAULT_TENANT_ID,
        "mapps429-tech@example.com",
        "technician",
    )
    .await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let part = reqwest::multipart::Part::bytes(vec![1, 2, 3])
        .file_name("logo.png")
        .mime_str("image/png")
        .expect("mime");
    let resp = app
        .client
        .put(app.url("/api/v1/tenants/current/logo"))
        .bearer_auth(&token)
        .multipart(reqwest::multipart::Form::new().part("file", part))
        .send()
        .await
        .expect("send upload");
    assert_eq!(resp.status(), reqwest::StatusCode::FORBIDDEN);
}

/// An unsupported type is refused rather than stored and served back as
/// `octet-stream`, and SVG is refused specifically: it is a script-capable
/// document and this route serves it from the API origin to anonymous callers.
#[sqlx::test]
async fn an_unsupported_image_type_is_refused(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    for (mime, name) in [
        ("application/pdf", "logo.pdf"),
        ("image/svg+xml", "logo.svg"),
    ] {
        let part = reqwest::multipart::Part::bytes(b"not an image".to_vec())
            .file_name(name)
            .mime_str(mime)
            .expect("mime");
        let resp = app
            .client
            .put(app.url("/api/v1/tenants/current/logo"))
            .bearer_auth(&token)
            .multipart(reqwest::multipart::Form::new().part("file", part))
            .send()
            .await
            .expect("send upload");
        assert_eq!(
            resp.status(),
            reqwest::StatusCode::BAD_REQUEST,
            "{mime} must be refused"
        );
    }
}

/// PMS-758: `branding` is a JSONB document written by more than one caller.
///
/// The organisation settings page sends four contact keys; the logo upload
/// sends two of its own. A whole-document write meant saving the settings page
/// deleted `logo_mime`, so the public logo route answered 404 and every client
/// email rendered a broken image. Merging keeps what a caller did not mention,
/// and an explicit null still clears.
#[sqlx::test]
async fn a_partial_branding_write_keeps_the_keys_it_did_not_mention(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    // What the logo upload writes.
    let resp = app
        .client
        .put(app.url("/api/v1/tenants/current"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "branding": { "logo_url": "/api/v1/public/tenants/x/logo", "logo_mime": "image/png" }
        }))
        .send()
        .await
        .expect("send logo branding");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    // What the settings page writes: its own keys, and nothing about the logo.
    let after: serde_json::Value = app
        .client
        .put(app.url("/api/v1/tenants/current"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "branding": { "support_contact_name": "the service desk", "support_phone": "555-0100" }
        }))
        .send()
        .await
        .expect("send contact branding")
        .json()
        .await
        .expect("tenant JSON");

    assert_eq!(
        after["branding"]["logo_mime"].as_str(),
        Some("image/png"),
        "the settings page must not delete the content type the logo route needs"
    );
    assert_eq!(
        after["branding"]["logo_url"].as_str(),
        Some("/api/v1/public/tenants/x/logo")
    );
    assert_eq!(
        after["branding"]["support_contact_name"].as_str(),
        Some("the service desk")
    );

    // An explicit null still clears: that is how the settings page empties a
    // contact field, and why it sends nulls rather than omitting them.
    let cleared: serde_json::Value = app
        .client
        .put(app.url("/api/v1/tenants/current"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "branding": { "support_contact_name": null }
        }))
        .send()
        .await
        .expect("send clearing branding")
        .json()
        .await
        .expect("tenant JSON");
    assert!(cleared["branding"]["support_contact_name"].is_null());
    assert_eq!(
        cleared["branding"]["logo_mime"].as_str(),
        Some("image/png"),
        "clearing one key must not disturb another"
    );
}

/// PMS-776: the PATCH document is checked before it is merged.
///
/// These keys are read by a client, not by us: three of them compose the
/// contact sentence in a client's email and `logo_url` becomes an `<img src>`
/// in the same message, so a malformed value is one the MSP appears to have
/// published over its own SMTP identity.
#[sqlx::test]
async fn branding_a_client_will_read_is_validated_on_write(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    for (case, branding) in [
        (
            "an address that is not an address",
            serde_json::json!({ "support_email": "call us on 555-0100" }),
        ),
        (
            "a logo pointing outside the public route",
            serde_json::json!({ "logo_url": "https://evil.example/logo.png" }),
        ),
        (
            "a key no reader destructures",
            serde_json::json!({ "supprt_email": "help@acme.example" }),
        ),
        (
            "a colour that is not a colour",
            serde_json::json!({ "primary_color": "red" }),
        ),
        (
            "a phone number that is a sentence",
            serde_json::json!({ "support_phone": "call the service desk" }),
        ),
    ] {
        let resp = app
            .client
            .put(app.url("/api/v1/tenants/current"))
            .bearer_auth(&token)
            .json(&serde_json::json!({ "branding": branding }))
            .send()
            .await
            .expect("send branding");
        assert_eq!(
            resp.status(),
            reqwest::StatusCode::UNPROCESSABLE_ENTITY,
            "{case} must be refused, got {}",
            resp.status()
        );
    }

    // The values the settings page and the logo upload actually send still go
    // through untouched.
    let ok = app
        .client
        .put(app.url("/api/v1/tenants/current"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "branding": {
                "support_email": "help@acme.example",
                "support_phone": "+1 555-0100",
                "support_contact_name": "Dana",
                "primary_color": "#0066cc",
            }
        }))
        .send()
        .await
        .expect("send valid branding");
    assert_eq!(ok.status(), reqwest::StatusCode::OK);

    // Nothing was merged from the refused writes.
    let current: serde_json::Value = app
        .client
        .get(app.url("/api/v1/tenants/current"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send get current")
        .json()
        .await
        .expect("tenant JSON");
    assert_eq!(
        current["branding"]["support_email"].as_str(),
        Some("help@acme.example")
    );
    assert!(current["branding"]["logo_url"].is_null());
}

/// PMS-776: the two endpoints that write a branding value agree about it.
/// They still write to different stores (PMS-703 F18); what they no longer do
/// is disagree about which values are legal.
#[sqlx::test]
async fn the_settings_endpoint_validates_branding_like_the_tenants_endpoint(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    for (key, value, expected) in [
        ("support_email", "call us on 555-0100", false),
        ("support_email", "help@acme.example", true),
        ("logo_url", "https://evil.example/logo.png", false),
        ("secondary_color", "#00AA55", true),
        ("supprt_email", "help@acme.example", false),
    ] {
        let resp = app
            .client
            .put(app.url(&format!("/api/v1/settings/branding/{key}")))
            .bearer_auth(&token)
            .json(&serde_json::json!({ "value": value }))
            .send()
            .await
            .expect("send setting");
        assert_eq!(
            resp.status().is_success(),
            expected,
            "branding/{key} = {value} got {}",
            resp.status()
        );
    }
}

// ---------------------------------------------------------------------------
// PMS-761: the organisation identity every client-facing email renders
// ---------------------------------------------------------------------------

/// The identity in a client's email has to be the identity of the tenant that
/// owns the thing the email is about. `OrgIdentity::load` is the single reader
/// for all of them, so this is the one place that guarantee is checked.
#[sqlx::test]
async fn the_org_identity_loads_the_callers_own_tenant(pool: PgPool) {
    use mokosh_server::modules::auth::TenantId;
    use mokosh_server::modules::tenants::OrgIdentity;

    let db = Database::from_pool(pool.clone());
    let svc = TenantService::new(db.clone());

    let other = svc
        .create_tenant(
            &CreateTenantRequest {
                name: "Northwind MSP".into(),
                slug: "northwind-msp".into(),
                billing_email: None,
                billing_contact_name: None,
                subscription_plan: None,
                admin_email: "owner-pms761@example.test".into(),
                admin_first_name: "Owner".into(),
                admin_last_name: "Pms761".into(),
            },
            &AuditCtx::system(common::DEFAULT_TENANT_ID),
        )
        .await
        .expect("create_tenant must succeed");

    sqlx::query(
        r#"UPDATE tenants SET branding = '{"support_contact_name":"the service desk","support_phone":"555-0100"}'::jsonb WHERE id = $1"#,
    )
    .bind(other.id)
    .execute(&pool)
    .await
    .expect("set branding");

    let loaded = OrgIdentity::load(&db, TenantId::from_trusted(other.id))
        .await
        .expect("load the org identity");
    assert_eq!(loaded.name(), "Northwind MSP");
    assert_eq!(
        loaded.contact_line("Questions about this invoice?", None),
        "Questions about this invoice? Contact the service desk at Northwind MSP on 555-0100."
    );

    // The default tenant is a different organisation and reads as one, so a
    // caller that threads the wrong tenant_id produces a visibly wrong email
    // rather than a plausible one.
    let default = OrgIdentity::load(&db, TenantId::from_trusted(common::DEFAULT_TENANT_ID))
        .await
        .expect("load the default tenant identity");
    assert_ne!(default.name(), loaded.name());
    assert_eq!(default.contact_name(), None);
}

/// PMS-761: `dispatch` resolves rules by (tenant_id, event_type) and skips
/// silently when a tenant has none, so a client-facing template with no rule is
/// a message that is never sent. `ticket.note_added` was seeded for the default
/// tenant only and never copied, and `forms.request_link` had its template
/// copied but not its rule: both were silent for every tenant created here.
#[sqlx::test]
async fn a_new_tenant_can_actually_send_the_client_facing_email(pool: PgPool) {
    let svc = TenantService::new(Database::from_pool(pool.clone()));

    let tenant = svc
        .create_tenant(
            &CreateTenantRequest {
                name: "Fabrikam IT".into(),
                slug: "fabrikam-it".into(),
                billing_email: None,
                billing_contact_name: None,
                subscription_plan: None,
                admin_email: "owner-pms761b@example.test".into(),
                admin_first_name: "Owner".into(),
                admin_last_name: "Pms761b".into(),
            },
            &AuditCtx::system(common::DEFAULT_TENANT_ID),
        )
        .await
        .expect("create_tenant must succeed");

    for event in ["ticket.note_added", "forms.request_link"] {
        let usable: i64 = sqlx::query_scalar(
            r#"SELECT COUNT(*)
               FROM notification_rules r
               JOIN notification_templates t ON t.id = r.template_id AND t.tenant_id = r.tenant_id
               WHERE r.tenant_id = $1 AND r.event_type = $2 AND r.is_active"#,
        )
        .bind(tenant.id)
        .bind(event)
        .fetch_one(&pool)
        .await
        .expect("count usable rules");
        assert_eq!(
            usable, 1,
            "a new tenant needs an active {event} rule pointing at its own template, or the email is never sent",
        );
    }
}

/// Migration 104: the seeded ticket-note copy names the organisation. The keys
/// are supplied by `TicketsService::send_note_email`; an unresolved one would
/// reach the client as literal braces, so template and context are asserted
/// against each other here rather than trusted to stay in step.
#[sqlx::test]
async fn the_ticket_note_template_asks_for_the_organisation_identity(pool: PgPool) {
    let body: String = sqlx::query_scalar(
        "SELECT body_text FROM notification_templates \
         WHERE tenant_id = $1 AND event_type = 'ticket.note_added' AND channel_type = 'email'",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(&pool)
    .await
    .expect("the seeded ticket-note template exists");

    for key in ["{{org_name}}", "{{contact_line}}", "{{content}}"] {
        assert!(
            body.contains(key),
            "the ticket-note body must render {key}: {body}"
        );
    }
}
