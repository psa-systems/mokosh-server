//! PMS-1212 (PSA-70 phase 2): the connect flow's gates and its state token.
//!
//! What a network cannot be asked in a test suite - Google's consent screen
//! and token endpoint - is left to PMS-1216's run against a real account. What
//! IS testable here is everything that decides whether the flow is safe:
//! who may start it, that the state parameter cannot be replayed or guessed,
//! and that a failed callback tells a browser nothing.

mod common;

use reqwest::StatusCode;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

/// The integration is unconfigured in the test environment (no
/// `GOOGLE_CONTACTS_CLIENT_ID`), which is itself the first thing worth
/// pinning: an operator who has not set the client gets told so, not a Google
/// error page.
#[sqlx::test]
async fn an_unconfigured_deployment_says_so_rather_than_offering_a_broken_connect(pool: PgPool) {
    let (_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let resp = app
        .client
        .post(app.url("/api/v1/integrations/contact-sync/google/authorize"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("authorize");
    assert_ne!(
        resp.status(),
        StatusCode::OK,
        "an unconfigured deployment must not hand out a consent URL"
    );
    let body = resp.text().await.unwrap_or_default();
    assert!(
        body.contains("not configured"),
        "the refusal should name the cause: {body}"
    );
}

/// Connecting a tenant's directory to its CRM is an administrator's act, the
/// same gate the RMM connection routes carry.
#[sqlx::test]
async fn a_non_admin_cannot_start_or_end_a_connection(pool: PgPool) {
    let (_admin, _email, _password) = common::seed_admin(&pool).await;
    let (_tech_id, tech_email, tech_password) = common::seed_user(
        &pool,
        common::DEFAULT_TENANT_ID,
        "tech@contact-sync.example",
        "technician",
    )
    .await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &tech_email, &tech_password).await;

    for path in [
        "/api/v1/integrations/contact-sync/google/authorize",
        "/api/v1/integrations/contact-sync/google/disconnect",
    ] {
        let resp = app
            .client
            .post(app.url(path))
            .bearer_auth(&token)
            .send()
            .await
            .expect("post");
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "{path} must be admin-gated"
        );
    }
}

/// Never connected reads as an offer, not an error.
#[sqlx::test]
async fn a_tenant_with_no_connection_reads_as_none(pool: PgPool) {
    let (_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let resp = app
        .client
        .get(app.url("/api/v1/integrations/contact-sync"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("get connection");
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.expect("json");
    assert!(
        body["connection"].is_null(),
        "no connection is null, not an error: {body}"
    );
    // PMS-1241: the card can tell never connected from turned off and from a
    // deployment with no Google client, without a second request.
    assert_eq!(body["enabled"], true, "unset means enabled: {body}");
    assert_eq!(
        body["configured"], false,
        "the test environment has no Google client: {body}"
    );
}

/// The callback is the one unauthenticated route here, so its refusals are
/// what keep it safe. A guessed state, a malformed one, a missing code and a
/// cancelled consent all end the same way: a redirect carrying a flag, never
/// a body, never the provider's words.
#[sqlx::test]
async fn every_bad_callback_redirects_and_tells_the_browser_nothing(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("client");

    let guessed = format!("{}.{}", Uuid::new_v4(), "not-the-secret");
    for query in [
        format!("?code=abc&state={guessed}"),
        "?code=abc&state=not-even-a-uuid".to_string(),
        "?state=missing-code".to_string(),
        "?error=access_denied".to_string(),
        String::new(),
    ] {
        let resp = client
            .get(app.url(&format!(
                "/api/v1/public/contact-sync/google/callback{query}"
            )))
            .send()
            .await
            .expect("callback");
        assert!(
            resp.status().is_redirection(),
            "{query:?} should redirect, got {}",
            resp.status()
        );
        let location = resp
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        assert!(
            location.contains("contact_sync=failed"),
            "{query:?} -> {location}"
        );
        let body = resp.text().await.unwrap_or_default();
        for leak in ["state", "code", "secret", "token"] {
            assert!(
                !body.contains(leak),
                "{query:?} leaked {leak} in the body: {body}"
            );
        }
    }
}

/// A state row is per tenant and RLS-scoped like everything else, so one
/// tenant's in-flight connect is invisible to another.
#[sqlx::test]
async fn state_rows_are_tenant_scoped(pool: PgPool) {
    let app = common::boot_rls(pool.clone()).await;
    let (other_tenant, _u, _e, _p) = common::seed_tenant_with_admin(&pool, "othersync").await;
    sqlx::query(
        "INSERT INTO contact_sync_oauth_states \
         (tenant_id, provider, started_by_user_id, state_hash, code_verifier, redirect_uri, expires_at) \
         SELECT $1, 'google', u.id, 'hash', 'verifier', 'https://example.test/cb', NOW() + INTERVAL '10 minutes' \
         FROM users u WHERE u.tenant_id = $1 LIMIT 1",
    )
    .bind(other_tenant)
    .execute(&app.pool)
    .await
    .expect("seed a foreign state row");

    let visible: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM contact_sync_oauth_states WHERE tenant_id = $1")
            .bind(common::DEFAULT_TENANT_ID)
            .fetch_one(&app.pool)
            .await
            .expect("count");
    assert_eq!(visible, 0, "another tenant's state row must be invisible");
}

/// PMS-1241: `reconnect_required` has a way out. Consenting again with the
/// SAME Google account replaces the stored grant on the existing connection -
/// its id, links, runs and selection all hang off that id - and clears the
/// failure state. A DIFFERENT account is refused, because every link names the
/// account it came from.
#[sqlx::test]
async fn reconnecting_the_same_account_keeps_the_connection(pool: PgPool) {
    use mokosh_server::db::Database;
    use mokosh_server::modules::auth::TenantId;
    use mokosh_server::modules::contact_sync::service::ConnectOutcome;
    use mokosh_server::modules::contact_sync::ContactSyncService;
    use mokosh_server::secrets::{DatabaseSecretProvider, SecretKey, SecretProvider};
    use std::sync::Arc;

    let (admin_id, _email, _password) = common::seed_admin(&pool).await;
    let db = Database::from_pool(pool.clone());
    let secrets: Arc<dyn SecretProvider> =
        Arc::new(DatabaseSecretProvider::new(db.clone(), [0u8; 32]));
    let service = ContactSyncService::new(
        db,
        secrets.clone(),
        None,
        "https://app.msp.example".to_string(),
    );
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);

    let ConnectOutcome::Connected(id) = service
        .record_connection(tenant, admin_id, "ops@msp.example", "grant-one")
        .await
        .expect("first connect")
    else {
        panic!("a first connect is a new connection");
    };
    sqlx::query(
        "UPDATE contact_sync_connections SET sync_status = 'reconnect_required', \
         last_error = 'Google has revoked this connection.', consecutive_failures = 4, \
         failure_notified_at = NOW() WHERE id = $1",
    )
    .bind(id)
    .execute(&pool)
    .await
    .unwrap();

    let again = service
        .record_connection(tenant, admin_id, "OPS@msp.example", "grant-two")
        .await
        .expect("reconnect");
    assert_eq!(
        again,
        ConnectOutcome::Reconnected(id),
        "the same connection"
    );
    let key = SecretKey::contact_sync(common::DEFAULT_TENANT_ID, "google", id);
    assert_eq!(
        secrets.get(&key).await.unwrap().as_deref(),
        Some("grant-two"),
        "the new grant replaced the revoked one"
    );
    let (status, error, failures, notified): (String, Option<String>, i32, bool) = sqlx::query_as(
        "SELECT sync_status, last_error, consecutive_failures, failure_notified_at IS NOT NULL \
         FROM contact_sync_connections WHERE id = $1",
    )
    .bind(id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        (status.as_str(), error, failures, notified),
        ("never", None, 0, false)
    );

    let other = service
        .record_connection(tenant, admin_id, "someone@else.example", "grant-three")
        .await
        .expect_err("a different account is refused");
    assert!(other.to_string().contains("ops@msp.example"), "{other}");
    assert_eq!(
        secrets.get(&key).await.unwrap().as_deref(),
        Some("grant-two"),
        "a refused account touches nothing"
    );
    let connections: i64 = sqlx::query_scalar("SELECT count(*) FROM contact_sync_connections")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(connections, 1);
}
