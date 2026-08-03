//! PMS-692 regression: request-serving reads of RLS-covered tables resolve
//! through the tenant GUC, so they do NOT fail-closed to zero rows on the
//! unprivileged `NOBYPASSRLS` app role.
//!
//! `common::boot_rls` / `build_app_role_pool` wire the request-serving pool as a
//! freshly created `NOSUPERUSER NOBYPASSRLS` role (the production `mokosh_app`
//! posture), so these assertions actually exercise Row Level Security rather than
//! the superuser bypass the plain suite uses. Env-gated via `#[sqlx::test]` like
//! the rest of the integration suite.

mod common;

use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

use mokosh_server::modules::auth::AuthService;
use mokosh_server::Database;

/// Case B: global search reads five RLS-covered tables. Before PMS-692
/// `SearchService` held a bare app pool, so under the NOBYPASSRLS role every
/// scan fail-closed and `GET /search` returned an empty 200. It now runs the
/// scans inside a `begin_with_tenant` transaction, so a seeded row is found.
#[sqlx::test]
async fn search_returns_rows_through_the_nobypassrls_app_role(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;

    // A distinctively-named company under the admin's tenant, seeded as the
    // superuser (migrator) pool so setup is not itself RLS-bound.
    let needle = format!("Zephyr-{}", Uuid::new_v4().simple());
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, $3)")
        .bind(Uuid::new_v4())
        .bind(common::DEFAULT_TENANT_ID)
        .bind(&needle)
        .execute(&pool)
        .await
        .expect("seed searchable company");

    // Boot the app with the request-serving pool running as the unprivileged
    // NOBYPASSRLS role.
    let app = common::boot_rls(pool).await;
    let token = common::login(&app, &email, &password).await;

    let resp = app
        .client
        .get(app.url(&format!("/api/v1/search?q={needle}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send /search request");
    assert!(
        resp.status().is_success(),
        "search 2xx, got {}",
        resp.status()
    );
    let body: serde_json::Value = resp.json().await.expect("/search JSON");

    let companies = body["companies"].as_array().expect("companies array");
    assert!(
        !companies.is_empty(),
        "the seeded company must be found through the NOBYPASSRLS app role \
         (pre-PMS-692 this fail-closed to an empty 200): {body}"
    );
    assert!(
        companies
            .iter()
            .any(|c| c["label"].as_str() == Some(needle.as_str())),
        "the search hit must be the seeded company: {body}"
    );
}

/// Case E: `is_user_tombstoned` probes `users` by sub, tenant-unscoped, so it
/// runs on the migrator (BYPASSRLS) pool. On the app pool it always read
/// "not tombstoned", making the 410 ACCOUNT_DELETED branch dead code. This
/// asserts a soft-deleted row reads `true` through the NOBYPASSRLS-app Database.
#[sqlx::test]
async fn is_user_tombstoned_true_for_a_soft_deleted_user(pool: PgPool) {
    let (admin_id, _email, _password) = common::seed_admin(&pool).await;

    // Build a Database whose serving pool is the unprivileged NOBYPASSRLS role,
    // exactly like boot_rls, but drive the service directly.
    let app_pool = common::build_app_role_pool(&pool).await;
    let db = Database::from_pools(app_pool, pool.clone());
    let auth = Arc::new(AuthService::new(db, "test-secret".into(), vec![]));

    // Active user: not tombstoned.
    assert!(
        !auth
            .is_user_tombstoned(admin_id)
            .await
            .expect("probe active user"),
        "an active user must read as not tombstoned"
    );

    // Soft-delete it (as the superuser/migrator pool) and re-probe.
    sqlx::query("UPDATE users SET deleted_at = NOW() WHERE id = $1")
        .bind(admin_id)
        .execute(&pool)
        .await
        .expect("soft-delete the user");

    assert!(
        auth.is_user_tombstoned(admin_id)
            .await
            .expect("probe tombstoned user"),
        "a soft-deleted user must read as tombstoned through the NOBYPASSRLS app \
         Database (pre-PMS-692 this always read false, so the 410 branch was dead)"
    );
}
