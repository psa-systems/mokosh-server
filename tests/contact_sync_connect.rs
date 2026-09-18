//! PMS-1212 (PSA-70 phase 2): the connect flow's gates and its state token.
//!
//! What a network cannot be asked in a test suite - Google's consent screen
//! and token endpoint - is left to PMS-1216's run against a real account. What
//! IS testable here is everything that decides whether the flow is safe:
//! who may start it, that the state parameter cannot be replayed or guessed,
//! and that a failed callback tells a browser nothing.

mod common;

use reqwest::StatusCode;
use serde_json::{json, Value};
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

/// PMS-1264: the deployment's Google client set in the app, by an admin of
/// the system tenant. The secret goes to the secret provider and never comes
/// back; the connect flow uses the stored client; clearing it falls back to
/// env (unset here, so "not configured").
#[sqlx::test]
async fn the_google_client_is_set_in_the_app_and_the_secret_never_returns(pool: PgPool) {
    let (_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let client_path = "/api/v1/integrations/contact-sync/google/client";
    let put = |body: Value| {
        let app = &app;
        let token = &token;
        async move {
            let resp = app
                .client
                .put(app.url(client_path))
                .bearer_auth(token)
                .json(&body)
                .send()
                .await
                .expect("put client");
            let status = resp.status();
            (status, resp.json::<Value>().await.unwrap_or(Value::Null))
        }
    };
    let get = |path: &'static str| {
        let app = &app;
        let token = &token;
        async move {
            app.client
                .get(app.url(path))
                .bearer_auth(token)
                .send()
                .await
                .expect("get")
                .json::<Value>()
                .await
                .expect("json")
        }
    };

    let empty = get(client_path).await;
    assert_eq!(empty["source"], "none", "{empty}");
    assert_eq!(empty["secret_set"], false);
    assert_eq!(
        empty["redirect_uri"], "http://api.localhost/api/v1/public/contact-sync/google/callback",
        "the form shows what to register in the Google Cloud console"
    );
    let overview = get("/api/v1/integrations/contact-sync").await;
    assert_eq!(overview["client_editable"], true);
    assert_eq!(overview["configured"], false);

    let id = "1234-abc.apps.googleusercontent.com";
    let (status, _) = put(json!({ "client_id": id })).await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "an id needs its secret"
    );
    let (status, _) = put(json!({ "client_id": "not-a-client", "client_secret": "s3cret" })).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    let (status, saved) = put(json!({ "client_id": id, "client_secret": "GOCSPX-s3cret" })).await;
    assert_eq!(status, StatusCode::OK, "{saved}");
    assert_eq!(
        (
            saved["source"].as_str(),
            saved["client_id"].as_str(),
            saved["secret_set"].as_bool()
        ),
        (Some("database"), Some(id), Some(true))
    );
    assert!(
        !saved.to_string().contains("GOCSPX"),
        "the secret never returns: {saved}"
    );
    let stored_plain: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM tenant_settings WHERE value::text LIKE '%GOCSPX%'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(stored_plain, 0, "the secret is not a tenant setting");
    assert_eq!(
        get("/api/v1/integrations/contact-sync").await["configured"],
        true
    );

    // The connect flow now uses the stored client.
    let resp = app
        .client
        .post(app.url("/api/v1/integrations/contact-sync/google/authorize"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("authorize");
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["authorize_url"].as_str().unwrap().contains(id),
        "{body}"
    );

    // Keep the secret while renaming nothing; then clear back to env.
    let (status, kept) = put(json!({})).await;
    assert_eq!(
        (status, kept["source"].as_str()),
        (StatusCode::OK, Some("database"))
    );
    let (status, cleared) = put(json!({ "client_id": "" })).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(cleared["source"], "none", "{cleared}");
    assert_eq!(
        cleared["secret_set"], false,
        "clearing the id clears its secret"
    );
    assert_eq!(
        get("/api/v1/integrations/contact-sync").await["configured"],
        false
    );
    let audited: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_log WHERE new_values->>'event' = 'contact_sync.client_changed' \
         AND new_values::text NOT LIKE '%GOCSPX%'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(audited, 3, "every change is audited, without the secret");
}

/// An admin of any other organisation cannot read or swap the client every
/// tenant on the deployment connects through.
#[sqlx::test]
async fn only_the_system_tenant_configures_the_google_client(pool: PgPool) {
    let (_tenant, _user, email, password) =
        common::seed_tenant_with_admin(&pool, "customer-msp").await;
    let app = common::boot(pool.clone()).await;
    let login: Value = app
        .client
        .post(app.url("/api/v1/auth/login"))
        .json(&json!({ "email": email, "password": password, "tenant_slug": "customer-msp" }))
        .send()
        .await
        .expect("login")
        .json()
        .await
        .expect("login json");
    let token = login["access_token"]
        .as_str()
        .expect("an admin of the customer tenant signs in")
        .to_string();
    let path = "/api/v1/integrations/contact-sync/google/client";

    let get = app
        .client
        .get(app.url(path))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(get.status(), StatusCode::FORBIDDEN);
    let put = app
        .client
        .put(app.url(path))
        .bearer_auth(&token)
        .json(&json!({ "client_id": "1-x.apps.googleusercontent.com", "client_secret": "s" }))
        .send()
        .await
        .unwrap();
    assert_eq!(put.status(), StatusCode::FORBIDDEN);
    let overview: Value = app
        .client
        .get(app.url("/api/v1/integrations/contact-sync"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(overview["client_editable"], false);
}
