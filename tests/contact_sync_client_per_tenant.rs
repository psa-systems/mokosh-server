//! PMS-1340: the Google OAuth client belongs to the tenant, not the deployment.
//!
//! PMS-1264 stored one client id and secret on the system tenant, so every
//! organisation on a deployment connected as the same Google application. That
//! shares three things a tenant should own: the consent screen a customer reads
//! (it names the application, which would be somebody else's MSP), the API quota
//! (one tenant's large sync throttles everyone), and the verification status.
//!
//! What this suite pins is the ladder - the tenant's own registration, else the
//! deprecated deployment-wide one, else operator env - and the isolation that
//! makes it worth having: one tenant's credential is invisible and unreachable
//! from another. Google itself is not in scope here (PMS-1216 covers a run
//! against a real account); what is in scope is which credential this deployment
//! would present, and who may change it.

mod common;

use mokosh_test::mokosh_test;
use reqwest::StatusCode;
use serde_json::{json, Value};
use sqlx::PgPool;

const CLIENT_PATH: &str = "/api/v1/integrations/contact-sync/google/client";

/// A syntactically valid Google client id, which the writer checks for.
fn client_id(label: &str) -> String {
    format!("{label}.apps.googleusercontent.com")
}

/// `common::login` hardcodes `tenant_slug: "default"`, which is the system
/// tenant, so a second tenant's admin signs in here with its own slug. The same
/// shape `tests/bunyip_principal_gate.rs` uses for the same reason.
async fn login_to(app: &common::TestApp, slug: &str, email: &str, password: &str) -> String {
    let resp = app
        .client
        .post(app.url("/api/v1/auth/login"))
        .json(&json!({
            "email": email,
            "password": password,
            "tenant_slug": slug,
        }))
        .send()
        .await
        .expect("send /auth/login request");
    assert!(
        resp.status().is_success(),
        "login for {slug} expected 2xx, got {}",
        resp.status()
    );
    let body: Value = resp.json().await.expect("login body");
    body["access_token"]
        .as_str()
        .expect("access_token")
        .to_string()
}

async fn get_client(app: &common::TestApp, token: &str) -> (StatusCode, Value) {
    let resp = app
        .client
        .get(app.url(CLIENT_PATH))
        .bearer_auth(token)
        .send()
        .await
        .expect("read the client settings");
    let status = resp.status();
    let body = resp.json().await.unwrap_or(Value::Null);
    (status, body)
}

async fn put_client(
    app: &common::TestApp,
    token: &str,
    id: Option<&str>,
    secret: Option<&str>,
) -> (StatusCode, String) {
    let mut body = serde_json::Map::new();
    if let Some(id) = id {
        body.insert("client_id".to_string(), json!(id));
    }
    if let Some(secret) = secret {
        body.insert("client_secret".to_string(), json!(secret));
    }
    let resp = app
        .client
        .put(app.url(CLIENT_PATH))
        .bearer_auth(token)
        .json(&Value::Object(body))
        .send()
        .await
        .expect("write the client settings");
    let status = resp.status();
    (status, resp.text().await.unwrap_or_default())
}

/// An admin sets their own tenant's client, and the view says the credential in
/// force is the tenant's own.
#[mokosh_test]
async fn an_admin_sets_their_own_tenants_client(pool: PgPool) {
    // A tenant of its own, NOT `seed_admin`'s: that helper lands in
    // `DEFAULT_TENANT_ID`, which is the system tenant, so a client written there
    // is the deployment-wide one and would read back as `deployment`.
    let (_tenant, _user, email, password) = common::seed_tenant_with_admin(&pool, "acme-msp").await;
    let app = common::boot(pool.clone()).await;
    let token = login_to(&app, "acme-msp", &email, &password).await;

    let (status, before) = get_client(&app, &token).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        before["source"], "none",
        "a tenant that has set nothing, on a deployment with no env client, has no client: {before}"
    );
    assert_eq!(before["secret_set"], json!(false));

    let (status, body) = put_client(
        &app,
        &token,
        Some(&client_id("acme")),
        Some("acme-client-secret"),
    )
    .await;
    assert!(status.is_success(), "setting the client: {status} {body}");

    let (_status, after) = get_client(&app, &token).await;
    assert_eq!(
        after["source"], "tenant",
        "the credential in force must be this tenant's own: {after}"
    );
    assert_eq!(after["client_id"], json!(client_id("acme")));
    assert_eq!(
        after["secret_set"],
        json!(true),
        "the form needs to know a secret is stored"
    );
    assert!(
        after.get("client_secret").is_none(),
        "the secret must never leave the server: {after}"
    );
}

/// The isolation that makes per-tenant credentials worth having: what one tenant
/// stores is neither visible nor usable to another, and each sees its own.
#[mokosh_test]
async fn one_tenants_client_is_invisible_to_another(pool: PgPool) {
    // Two ordinary tenants. Neither is the system tenant, so neither can be the
    // other's fallback: what this test is about is that they cannot see each
    // other at all.
    let (_first_tenant, _first_user, first_email, first_password) =
        common::seed_tenant_with_admin(&pool, "first-msp").await;
    let (_other_tenant, _other_user, other_email, other_password) =
        common::seed_tenant_with_admin(&pool, "other-msp").await;
    let app = common::boot(pool.clone()).await;
    let first = login_to(&app, "first-msp", &first_email, &first_password).await;
    let other = login_to(&app, "other-msp", &other_email, &other_password).await;

    let (status, body) = put_client(
        &app,
        &first,
        Some(&client_id("first")),
        Some("first-secret"),
    )
    .await;
    assert!(status.is_success(), "{status} {body}");

    let (_status, seen_by_other) = get_client(&app, &other).await;
    assert_eq!(
        seen_by_other["source"], "none",
        "the second tenant must not inherit the first tenant's registration: {seen_by_other}"
    );
    assert!(
        seen_by_other["client_id"].is_null(),
        "nor see its client id: {seen_by_other}"
    );

    // And the second tenant setting its own leaves the first alone.
    let (status, body) = put_client(
        &app,
        &other,
        Some(&client_id("second")),
        Some("second-secret"),
    )
    .await;
    assert!(status.is_success(), "{status} {body}");
    let (_status, first_view) = get_client(&app, &first).await;
    assert_eq!(first_view["client_id"], json!(client_id("first")));
    let (_status, other_view) = get_client(&app, &other).await;
    assert_eq!(other_view["client_id"], json!(client_id("second")));
}

/// The deprecated deployment-wide client (PMS-1264) still answers for a tenant
/// that has none of its own, so a deployment mid-migration keeps syncing, and
/// the view says which level answered so an operator can see who has moved.
#[mokosh_test]
async fn a_tenant_without_its_own_falls_back_to_the_deployment_client(pool: PgPool) {
    // `seed_admin` puts its admin in the DEFAULT tenant, which IS the system
    // tenant (`00000000-...-0001`), so this admin writes the deployment-wide
    // value through the ordinary route rather than by hand-seeding an encrypted
    // secret. The tenant reading it is a second one.
    let (_id, system_email, system_password) = common::seed_admin(&pool).await;
    let (_other_tenant, _other_user, email, password) =
        common::seed_tenant_with_admin(&pool, "reader-msp").await;
    let app = common::boot(pool.clone()).await;
    let system = common::login(&app, &system_email, &system_password).await;
    let token = login_to(&app, "reader-msp", &email, &password).await;

    let (status, body) = put_client(
        &app,
        &system,
        Some(&client_id("deployment")),
        Some("deployment-secret"),
    )
    .await;
    assert!(
        status.is_success(),
        "the system tenant's admin sets the deployment-wide client: {status} {body}"
    );

    let (_status, view) = get_client(&app, &token).await;
    assert_eq!(
        view["source"], "deployment",
        "a tenant with no client of its own reads the deployment's: {view}"
    );
    assert_eq!(view["client_id"], json!(client_id("deployment")));

    // Its own registration wins the moment it sets one.
    let (status, body) =
        put_client(&app, &token, Some(&client_id("own")), Some("own-secret")).await;
    assert!(status.is_success(), "{status} {body}");
    let (_status, view) = get_client(&app, &token).await;
    assert_eq!(view["source"], "tenant", "{view}");
    assert_eq!(view["client_id"], json!(client_id("own")));
}

/// An id with no secret beside it is half a client, and must not fall through to
/// the next level: connecting as somebody else's application because your own
/// secret is missing is the failure nobody would be able to place.
#[mokosh_test]
async fn an_id_without_a_secret_is_refused_rather_than_falling_through(pool: PgPool) {
    let (_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let (status, body) = put_client(&app, &token, Some(&client_id("half")), None).await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "an id with no secret must be refused at the write: {body}"
    );
    assert!(body.contains("client secret"), "{body}");

    let (_status, view) = get_client(&app, &token).await;
    assert_eq!(
        view["source"], "none",
        "nothing was stored, so nothing is in force: {view}"
    );
}

/// A technician cannot read or write the credential, and the refusal is the same
/// whichever way they try: this is admin authority over the organisation's own
/// integration, the way a payment gateway credential is.
#[mokosh_test]
async fn a_non_admin_cannot_read_or_write_the_client(pool: PgPool) {
    let (_id, _email, _password) = common::seed_admin(&pool).await;
    let (_tech, tech_email, tech_password) = common::seed_user(
        &pool,
        common::DEFAULT_TENANT_ID,
        "tech@per-tenant.example",
        "technician",
    )
    .await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &tech_email, &tech_password).await;

    let (status, _body) = get_client(&app, &token).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _body) = put_client(&app, &token, Some(&client_id("nope")), Some("nope")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// Clearing the id clears the secret with it, so a cleared credential cannot
/// leave a secret behind for the next id to be paired with by accident.
#[mokosh_test]
async fn clearing_the_id_clears_the_secret(pool: PgPool) {
    let (_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let (status, body) =
        put_client(&app, &token, Some(&client_id("temp")), Some("temp-secret")).await;
    assert!(status.is_success(), "{status} {body}");
    let (status, body) = put_client(&app, &token, Some(""), None).await;
    assert!(status.is_success(), "clearing: {status} {body}");

    let (_status, view) = get_client(&app, &token).await;
    assert_eq!(view["source"], "none", "{view}");
    assert_eq!(view["secret_set"], json!(false), "{view}");
}
