//! PMS-1310: the integrations framework, through the API.
//!
//! The unit tests in `modules::integrations::registry` and `::service` cover the
//! registry's shape and the subset rule as pure functions. What needs a database
//! and a booted app is everything those cannot show: that the row is confined to
//! its tenant, that a credential reaches the secrets provider and never the row,
//! that the refusal for a provider managed elsewhere is what an operator gets
//! back, and that the catalog a client renders agrees with what the server will
//! accept.

mod common;

use mokosh_test::mokosh_test;
use reqwest::StatusCode;
use serde_json::{json, Value};
use sqlx::PgPool;

/// Xero is managed by this subsystem (`ConnectionHome::Integrations`), so it is
/// the provider every write path is exercised through.
const MANAGED_HERE: &str = "xero";
/// Stripe's connection still lives in `payment_gateway_configs` until PMS-1312
/// moves it, so it is the provider every refusal is exercised through.
const MANAGED_ELSEWHERE: &str = "stripe";

async fn list(app: &common::TestApp, token: &str) -> Vec<Value> {
    let response = app
        .client
        .get(app.url("/api/v1/integrations"))
        .bearer_auth(token)
        .send()
        .await
        .expect("list integrations");
    assert_eq!(response.status(), StatusCode::OK);
    response.json().await.expect("list json")
}

fn entry<'a>(entries: &'a [Value], provider: &str) -> &'a Value {
    entries
        .iter()
        .find(|entry| entry["provider"] == provider)
        .unwrap_or_else(|| panic!("{provider} is not in the catalog"))
}

async fn connect(
    app: &common::TestApp,
    token: &str,
    provider: &str,
    body: Value,
) -> reqwest::Response {
    app.client
        .post(app.url(&format!("/api/v1/integrations/{provider}/connect")))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .expect("connect")
}

/// The second tenant in the isolation check, named once because its slug is
/// both the tenant label and the login's `tenant_slug`.
const OTHER_SLUG: &str = "other-msp";

/// Log in against a named tenant. `common::login` hardcodes `default`, which is
/// right for the seeded admin every other case uses and wrong for a second
/// tenant.
async fn login_to(app: &common::TestApp, email: &str, password: &str, slug: &str) -> String {
    let response = app
        .client
        .post(app.url("/api/v1/auth/login"))
        .json(&json!({ "email": email, "password": password, "tenant_slug": slug }))
        .send()
        .await
        .expect("login");
    assert_eq!(response.status(), StatusCode::OK, "login as {email}");
    let body: Value = response.json().await.expect("login json");
    body["access_token"]
        .as_str()
        .expect("access_token")
        .to_string()
}

async fn row_count(pool: &PgPool, provider: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM integrations WHERE provider = $1")
        .bind(provider)
        .fetch_one(pool)
        .await
        .expect("count integrations")
}

/// The page's job is to show what COULD be connected, so every provider in the
/// registry is listed on a tenant that has installed nothing, and each carries
/// the supported set the server will hold it to.
#[mokosh_test]
async fn the_catalog_lists_every_provider_before_anything_is_connected(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let entries = list(&app, &token).await;
    let providers: Vec<&str> = entries
        .iter()
        .map(|entry| entry["provider"].as_str().expect("provider"))
        .collect();
    assert_eq!(
        providers,
        vec![
            "stripe",
            "paypal",
            "quickbooks",
            "xero",
            "google",
            "microsoft"
        ],
        "the list is the registry, in its order"
    );

    let xero = entry(&entries, MANAGED_HERE);
    assert_eq!(xero["status"], "not_connected");
    assert_eq!(
        xero["enabled_capabilities"]
            .as_array()
            .expect("array")
            .len(),
        0,
        "nothing is delegated yet"
    );
    let supported: Vec<&str> = xero["supported_capabilities"]
        .as_array()
        .expect("array")
        .iter()
        .map(|c| c["key"].as_str().expect("key"))
        .collect();
    assert_eq!(supported, vec!["invoicing", "bills_and_expenses"]);
    assert!(
        xero["supported_capabilities"][0]["description"]
            .as_str()
            .expect("description")
            .contains("system of record"),
        "a capability says what handing it over MEANS: {}",
        xero["supported_capabilities"][0]
    );
    assert_eq!(
        xero["polling"]["default_minutes"], 15,
        "the poll default PMS-1310 settled on"
    );

    // Stripe is listed, but the page is told where it is actually configured
    // rather than being offered a Connect button that would 409.
    let stripe = entry(&entries, MANAGED_ELSEWHERE);
    assert_eq!(
        stripe["managed_elsewhere"]["table"],
        "payment_gateway_configs"
    );
    assert_eq!(stripe["managed_elsewhere"]["issue"], "PMS-1312");
    assert!(
        xero.get("managed_elsewhere").is_none(),
        "a provider managed here says nothing about being managed elsewhere: {xero}"
    );
}

/// Connecting stores the credential through the secrets provider and marks the
/// integration connected. Omitting `capabilities` delegates everything the
/// provider supports, because an operator who is asked nothing else expects the
/// integration to work.
#[mokosh_test]
async fn connecting_delegates_every_supported_capability_by_default(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let response = connect(
        &app,
        &token,
        MANAGED_HERE,
        json!({ "credential": "xero-refresh-token" }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.expect("connect json");
    assert_eq!(body["status"], "connected");
    assert_eq!(
        body["enabled_capabilities"],
        json!(["invoicing", "bills_and_expenses"]),
        "everything Xero supports, in the registry's order"
    );
    assert!(body["connected_at"].is_string());
}

/// The rule the whole subsystem exists for, through the API: a tenant cannot
/// hand a provider something the provider does not do, and the refusal says what
/// the provider does instead.
#[mokosh_test]
async fn a_capability_the_provider_does_not_support_is_refused(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let response = connect(
        &app,
        &token,
        MANAGED_HERE,
        json!({ "credential": "t", "capabilities": ["invoicing", "payments"] }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = response.json().await.expect("refusal json");
    let message = body["error"]["message"].as_str().unwrap_or_default();
    assert!(message.contains("payments"), "{message}");
    assert!(
        message.contains("invoicing"),
        "the refusal names what it DOES provide: {message}"
    );

    // Refused and not filtered: no row exists claiming the half that was legal.
    assert_eq!(
        row_count(&pool, MANAGED_HERE).await,
        0,
        "a rejected request writes nothing"
    );
}

/// The guard that keeps one connection in one place while PMS-1312 is
/// outstanding. A 409 rather than a 404, because Stripe exists and is listed;
/// what is wrong is that this is the wrong surface for it.
#[mokosh_test]
async fn a_provider_managed_elsewhere_cannot_be_connected_here(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let response = connect(
        &app,
        &token,
        MANAGED_ELSEWHERE,
        json!({ "credential": "sk_test_x" }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body: Value = response.json().await.expect("refusal json");
    let message = body["error"]["message"].as_str().unwrap_or_default();
    assert!(message.contains("Payment gateways"), "{message}");
    assert!(message.contains("PMS-1312"), "{message}");

    assert_eq!(
        row_count(&pool, MANAGED_ELSEWHERE).await,
        0,
        "no row is written for a provider whose home is elsewhere, so the two \
         tables cannot disagree"
    );
}

/// A credential is never on the row, never served back and never in the audit
/// trail. This is the property migration 251's header states and the one the
/// secrets provider exists for, so it is asserted against the stored bytes
/// rather than against what the service passed around.
#[mokosh_test]
async fn the_credential_is_nowhere_in_the_integration_row_or_its_audit_trail(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let credential = "xero-refresh-token-that-must-not-be-stored-here";
    let response = connect(
        &app,
        &token,
        MANAGED_HERE,
        json!({ "credential": credential, "config": { "tenant_realm": "abc" } }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.expect("connect json");
    assert!(
        !body.to_string().contains(credential),
        "the response carries the credential back: {body}"
    );

    let row: String = sqlx::query_scalar("SELECT to_jsonb(t)::text FROM integrations t")
        .fetch_one(&pool)
        .await
        .expect("the integrations row");
    assert!(
        !row.contains(credential),
        "the credential is on the row: {row}"
    );
    assert!(
        row.contains("tenant_realm"),
        "the non-secret config IS on the row: {row}"
    );

    let audit: String = sqlx::query_scalar(
        "SELECT COALESCE(string_agg(to_jsonb(t)::text, ' '), '') FROM audit_log t \
         WHERE entity_type = 'integrations'",
    )
    .fetch_one(&pool)
    .await
    .expect("the audit rows");
    assert!(
        !audit.contains(credential),
        "the credential is in the audit trail: {audit}"
    );
    assert!(
        audit.contains("\"action\": \"create\"") || audit.contains("\"action\":\"create\""),
        "connecting is audited: {audit}"
    );

    // It did reach the secrets provider, at the address PMS-1310 gives it.
    let stored: Option<String> =
        sqlx::query_scalar("SELECT name FROM secrets WHERE name LIKE 'INTEGRATION__%__XERO'")
            .fetch_optional(&pool)
            .await
            .expect("read the secrets table");
    assert!(
        stored.is_some(),
        "the credential did not reach the secrets provider"
    );
}

/// Suspending a delegation without discarding the credential is a real state, so
/// an empty capability set is accepted where a portal role's would be refused.
#[mokosh_test]
async fn a_delegation_can_be_narrowed_and_emptied_while_staying_connected(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    connect(&app, &token, MANAGED_HERE, json!({ "credential": "t" })).await;

    let narrow = app
        .client
        .put(app.url(&format!("/api/v1/integrations/{MANAGED_HERE}")))
        .bearer_auth(&token)
        .json(&json!({ "capabilities": ["invoicing"], "poll_interval_minutes": 30 }))
        .send()
        .await
        .expect("narrow the delegation");
    assert_eq!(narrow.status(), StatusCode::OK);
    let body: Value = narrow.json().await.expect("update json");
    assert_eq!(body["enabled_capabilities"], json!(["invoicing"]));
    assert_eq!(body["poll_interval_minutes"], 30);
    assert_eq!(body["status"], "connected");

    let emptied = app
        .client
        .put(app.url(&format!("/api/v1/integrations/{MANAGED_HERE}")))
        .bearer_auth(&token)
        .json(&json!({ "capabilities": [] }))
        .send()
        .await
        .expect("empty the delegation");
    assert_eq!(emptied.status(), StatusCode::OK);
    let body: Value = emptied.json().await.expect("update json");
    assert_eq!(body["enabled_capabilities"], json!([]));
    assert_eq!(
        body["status"], "connected",
        "delegating nothing is not disconnecting"
    );
    assert_eq!(
        body["poll_interval_minutes"], 30,
        "a field the request omitted keeps its value"
    );
}

/// Disconnecting keeps the row and deletes the credential. The row stays for the
/// `contact_sync_connections.disconnected_at` reason: the capability set the
/// tenant chose is worth keeping so reconnecting does not start from an empty
/// page, and the audit trail has to keep naming who connected it.
#[mokosh_test]
async fn disconnecting_keeps_the_row_and_deletes_the_credential(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    connect(
        &app,
        &token,
        MANAGED_HERE,
        json!({ "credential": "t", "capabilities": ["invoicing"] }),
    )
    .await;

    let response = app
        .client
        .post(app.url(&format!("/api/v1/integrations/{MANAGED_HERE}/disconnect")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("disconnect");
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.expect("disconnect json");
    assert_eq!(body["status"], "disconnected");
    assert_eq!(
        body["enabled_capabilities"],
        json!(["invoicing"]),
        "what the tenant chose survives the disconnect"
    );
    assert!(body["disconnected_at"].is_string());

    assert_eq!(row_count(&pool, MANAGED_HERE).await, 1, "the row is kept");
    let secrets: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM secrets WHERE name LIKE 'INTEGRATION__%'")
            .fetch_one(&pool)
            .await
            .expect("count secrets");
    assert_eq!(secrets, 0, "the credential is gone");

    // Reconnecting reuses the row rather than minting a second installation.
    let again = connect(&app, &token, MANAGED_HERE, json!({ "credential": "t2" })).await;
    assert_eq!(again.status(), StatusCode::OK);
    let body: Value = again.json().await.expect("reconnect json");
    assert_eq!(body["status"], "connected");
    assert!(
        body["disconnected_at"].is_null() || body.get("disconnected_at").is_none(),
        "reconnecting clears the disconnect: {body}"
    );
    assert_eq!(row_count(&pool, MANAGED_HERE).await, 1);
}

/// Configuring something that was never connected would mint a row claiming a
/// delegation nothing can act on, so it is a 404 pointing at connect.
#[mokosh_test]
async fn configuring_an_integration_that_was_never_connected_is_refused(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let response = app
        .client
        .put(app.url(&format!("/api/v1/integrations/{MANAGED_HERE}")))
        .bearer_auth(&token)
        .json(&json!({ "capabilities": ["invoicing"] }))
        .send()
        .await
        .expect("configure");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(row_count(&pool, MANAGED_HERE).await, 0);
}

/// A provider the registry has no entry for is a 404 naming the ones it does,
/// not a row with a provider nothing can serve.
#[mokosh_test]
async fn a_provider_the_registry_does_not_know_is_a_404(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let response = app
        .client
        .get(app.url("/api/v1/integrations/sage"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("unknown provider");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body: Value = response.json().await.expect("refusal json");
    let message = body["error"]["message"].as_str().unwrap_or_default();
    assert!(message.contains("xero"), "{message}");
}

/// Tenant scoping, through the app rather than through the policy alone: one
/// tenant's installation is invisible to the other, in both directions.
#[mokosh_test]
async fn one_tenants_integration_is_invisible_to_another(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    // `common::login` names the `default` slug, so the second tenant logs in
    // through its own, which is the shape PMS-728 requires of every local
    // password login.
    let (_other_tenant, _other_id, other_email, other_password) =
        common::seed_tenant_with_admin(&pool, OTHER_SLUG).await;

    // `boot_rls` and not `boot`: the default harness pool is the superuser,
    // which bypasses RLS however forced the policy is, so the isolation this
    // case is about would pass on the explicit `tenant_id` filter alone and
    // say nothing about the policy. This one runs the request path as the
    // unprivileged `mokosh_app` posture (PMS-285).
    let app = common::boot_rls(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let other_token = login_to(&app, &other_email, &other_password, OTHER_SLUG).await;

    connect(
        &app,
        &token,
        MANAGED_HERE,
        json!({ "credential": "ours", "capabilities": ["invoicing"] }),
    )
    .await;

    // The other tenant's catalog still shows Xero as available to connect.
    let theirs = list(&app, &other_token).await;
    let their_xero = entry(&theirs, MANAGED_HERE);
    assert_eq!(
        their_xero["status"], "not_connected",
        "the other tenant sees our installation: {their_xero}"
    );
    assert_eq!(their_xero["enabled_capabilities"], json!([]));

    // And disconnecting ours is not something they can do: there is nothing
    // there for them to disconnect.
    let response = app
        .client
        .post(app.url(&format!("/api/v1/integrations/{MANAGED_HERE}/disconnect")))
        .bearer_auth(&other_token)
        .send()
        .await
        .expect("disconnect across tenants");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // Ours is untouched.
    let ours = list(&app, &token).await;
    assert_eq!(entry(&ours, MANAGED_HERE)["status"], "connected");
}

/// The catalog a client renders has to agree with what the server will accept,
/// because the client does not hold its own copy of what a provider supports.
#[mokosh_test]
async fn every_capability_the_catalog_offers_is_one_the_server_accepts(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let catalog: Vec<Value> = app
        .client
        .get(app.url("/api/v1/integrations/capabilities"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("capability catalog")
        .json()
        .await
        .expect("catalog json");
    assert_eq!(catalog.len(), 5, "every capability in the vocabulary");
    for descriptor in &catalog {
        assert!(
            !descriptor["label"].as_str().unwrap_or_default().is_empty(),
            "a capability with no label cannot be rendered: {descriptor}"
        );
    }

    // And for the one provider this subsystem manages, everything its row says
    // it supports is accepted on a connect.
    let entries = list(&app, &token).await;
    let supported: Vec<String> = entry(&entries, MANAGED_HERE)["supported_capabilities"]
        .as_array()
        .expect("array")
        .iter()
        .map(|c| c["key"].as_str().expect("key").to_string())
        .collect();
    let response = connect(
        &app,
        &token,
        MANAGED_HERE,
        json!({ "credential": "t", "capabilities": supported }),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the catalog offered a capability the server refused"
    );
}
