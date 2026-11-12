//! PMS-1512: Microsoft 365 contact sync is gated by its own switch and
//! refreshed through its own OAuth client, on every call path that reads a
//! live connection (`assert_enabled`, `source` behind `sync_now`/`preview`).
//!
//! Before this fix, `source` and `access_token` had no `provider ==
//! "microsoft"` branch, so a Microsoft request fell through into Google's
//! `require_oauth_client()`/token endpoint, and `assert_enabled` read
//! `google_contacts_enabled` for a Microsoft request. Both bugs are proven
//! here without a real network call: with neither OAuth client configured on
//! the fixture, the OLD code's fallthrough would have failed with Google's
//! "not available" message (or succeeded wrongly if Google's switch was used);
//! the FIXED code fails with Microsoft's own message instead, which only
//! happens if the Microsoft branch was taken.

use crate::common;

use mokosh_server::db::Database;
use mokosh_server::modules::auth::TenantId;
use mokosh_server::modules::contact_sync::service::ContactSyncService;
use mokosh_server::secrets::DatabaseSecretProvider;
use mokosh_test::mokosh_test;
use sqlx::PgPool;
use std::sync::Arc;

async fn set_tenant_setting(pool: &PgPool, category: &str, key: &str, value: bool) {
    sqlx::query(
        "INSERT INTO tenant_settings (tenant_id, category, key, value) VALUES ($1, $2, $3, $4)",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(category)
    .bind(key)
    .bind(serde_json::json!(value))
    .execute(pool)
    .await
    .unwrap();
}

async fn service(pool: &PgPool) -> ContactSyncService {
    let app_pool = common::build_app_role_pool(pool).await;
    let db = Database::from_pools(app_pool, pool.clone());
    let secrets = Arc::new(DatabaseSecretProvider::new(db.clone(), [0u8; 32]));
    ContactSyncService::new(db, secrets, None, "https://app.msp.example".to_string())
}

/// `assert_enabled("microsoft")` reads its own switch, not Google's
/// (AC1/AC4): turning Google's off leaves Microsoft connectable, and turning
/// Microsoft's off blocks it with Microsoft's own wording.
#[mokosh_test]
async fn the_microsoft_switch_is_the_one_that_stops_a_microsoft_connect(pool: PgPool) {
    let svc = service(&pool).await;
    let (admin, _email, _password) = common::seed_admin(&pool).await;
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);

    set_tenant_setting(&pool, "integrations", "google_contacts_enabled", false).await;
    // Google's switch being off must not stop Microsoft: `assert_enabled`
    // passes, and the only reason this still errs is that no Microsoft OAuth
    // client is configured on this fixture at all (a different failure than
    // the switch).
    let err = svc
        .begin_microsoft_connect(tenant, admin)
        .await
        .expect_err("no Microsoft client is configured on this fixture")
        .to_string();
    assert!(
        err.contains("is not available on this deployment") && !err.contains("turned off"),
        "Google's switch must not gate Microsoft: {err}"
    );

    set_tenant_setting(&pool, "integrations", "microsoft_contacts_enabled", false).await;
    let err = svc
        .begin_microsoft_connect(tenant, admin)
        .await
        .expect_err("Microsoft's own switch is off")
        .to_string();
    assert!(
        err.contains("Microsoft 365 Contacts") && err.contains("turned off"),
        "{err}"
    );
}

/// `source` (behind `sync_now`/`preview`) resolves a Microsoft connection's
/// token through the Microsoft client, never Google's, and does not depend
/// on Google's client being configured at all (AC2/AC3).
#[mokosh_test]
async fn a_live_microsoft_connection_is_resolved_through_microsofts_own_client(pool: PgPool) {
    let svc = service(&pool).await;
    let (admin, _email, _password) = common::seed_admin(&pool).await;
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);

    svc.record_connection(
        tenant,
        admin,
        "microsoft",
        "person@contoso.example",
        "refresh-abc",
    )
    .await
    .expect("record a live microsoft connection");

    // Neither OAuth client is configured on this fixture. The pre-fix code
    // fell through to Google's `require_oauth_client()` here, which would
    // fail with Google's own "not available" message. The fix routes a
    // microsoft provider to `microsoft_access_token`/`require_microsoft_oauth_client`
    // instead, so the failure names Microsoft, never Google.
    let err = svc
        .preview(tenant, "microsoft", None)
        .await
        .expect_err("neither OAuth client is configured")
        .to_string();
    assert!(
        err.contains("Microsoft 365 Contacts is not available"),
        "expected Microsoft's own configuration error, got: {err}"
    );
    assert!(
        !err.contains("Google"),
        "a microsoft dispatch must never name Google's client: {err}"
    );

    let err = svc
        .sync_now(tenant, "microsoft")
        .await
        .expect_err("neither OAuth client is configured")
        .to_string();
    assert!(
        err.contains("Microsoft 365 Contacts is not available") && !err.contains("Google"),
        "{err}"
    );
}
