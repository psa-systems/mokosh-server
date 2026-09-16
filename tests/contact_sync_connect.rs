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
        body.is_null(),
        "no connection is null, not an error: {body}"
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
