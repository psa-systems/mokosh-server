//! PMS-1444: the host's Google OAuth client, set from the product.
//!
//! The decisions are unit-tested in `settings::google_client`: the view carries
//! names and booleans, a blank or swapped pair is refused by field, and half a
//! pair is never reported as configured. What needs a database and a booted app
//! is everything those cannot reach.
//!
//! Above all the claim the page rests on. PMS-1430 resolved the client once in
//! `main` and handed each service a copy, so a value written after boot was
//! invisible until a restart. A Settings page whose effect waits for a deploy is
//! worse than the CLI, which at least says so. `the_write_takes_effect_without_a_restart`
//! is therefore the test this suite exists for: it writes through the API and
//! then asks a TENANT-facing read, on the same running app, whether the
//! deployment can connect.

mod common;

use mokosh_test::mokosh_test;
use reqwest::StatusCode;
use sqlx::PgPool;

const PATH: &str = "/api/v1/settings/google-contacts-client";
const OVERVIEW: &str = "/api/v1/integrations/contact-sync";

fn pair() -> serde_json::Value {
    serde_json::json!({
        "client_id": "pms1444.apps.googleusercontent.com",
        "client_secret": "GOCSPX-pms1444-secret",
    })
}

/// A write is live immediately: the tenant-facing card reports the deployment
/// as configured without the process being restarted.
///
/// Driven through the overview rather than through the settings read, because
/// the settings read would only prove the value reached the provider. What
/// PMS-1444 promises is that the OAuth flow a customer is about to use picks it
/// up, and `configured` on that card is `ContactSyncService::oauth_client()`,
/// which is the handle the write swaps.
#[mokosh_test]
async fn the_write_takes_effect_without_a_restart(pool: PgPool) {
    let (_id, email, password) = common::seed_admin(&pool).await;
    // Booted with NO client, which is the state of a deployment nobody has
    // configured yet.
    let app = common::boot(pool.clone()).await;
    let operator = common::login(&app, &email, &password).await;

    let before: serde_json::Value = app
        .client
        .get(app.url(OVERVIEW))
        .bearer_auth(&operator)
        .send()
        .await
        .expect("overview")
        .json()
        .await
        .expect("overview json");
    assert_eq!(
        before["configured"], false,
        "the fixture must start unconfigured or this proves nothing: {before}"
    );

    let response = app
        .client
        .put(app.url(PATH))
        .bearer_auth(&operator)
        .json(&pair())
        .send()
        .await
        .expect("write the client");
    assert_eq!(response.status(), StatusCode::OK);
    let view: serde_json::Value = response.json().await.expect("view json");
    assert_eq!(view["configured"], true, "{view}");
    assert_eq!(view["provider"], "database", "{view}");
    assert_eq!(
        view["restart_required"], false,
        "the handler swaps the live client, so it must not ask for a restart: {view}"
    );

    let after: serde_json::Value = app
        .client
        .get(app.url(OVERVIEW))
        .bearer_auth(&operator)
        .send()
        .await
        .expect("overview")
        .json()
        .await
        .expect("overview json");
    assert_eq!(
        after["configured"], true,
        "the same running process still reports the deployment as unconfigured, so the swap did \
         not reach the service a customer's Connect uses: {after}"
    );
}

/// Neither response carries either half, and neither does the stored shape a
/// tenant can read.
///
/// The id is checked as strictly as the secret. It is not confidential, but an
/// endpoint that returns it grows a page that displays it, and then a support
/// conversation about which Google project a string belongs to.
#[mokosh_test]
async fn no_response_carries_either_half(pool: PgPool) {
    let (_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let operator = common::login(&app, &email, &password).await;

    let write: serde_json::Value = app
        .client
        .put(app.url(PATH))
        .bearer_auth(&operator)
        .json(&pair())
        .send()
        .await
        .expect("write")
        .json()
        .await
        .expect("json");
    let read: serde_json::Value = app
        .client
        .get(app.url(PATH))
        .bearer_auth(&operator)
        .send()
        .await
        .expect("read")
        .json()
        .await
        .expect("json");
    let overview: serde_json::Value = app
        .client
        .get(app.url(OVERVIEW))
        .bearer_auth(&operator)
        .send()
        .await
        .expect("overview")
        .json()
        .await
        .expect("json");

    for (name, body) in [
        ("the write response", &write),
        ("the read response", &read),
        ("the tenant-facing overview", &overview),
    ] {
        let rendered = body.to_string();
        assert!(
            !rendered.contains("pms1444") && !rendered.contains("GOCSPX"),
            "{name} carries the Google client: {rendered}"
        );
    }

    // The pair is in the app-secret store, encrypted, and not in
    // `tenant_settings` where PMS-1430 and migration 258 took it from.
    let rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM app_secrets WHERE name IN \
         ('GOOGLE_CONTACTS_CLIENT_ID', 'GOOGLE_CONTACTS_CLIENT_SECRET')",
    )
    .fetch_one(&pool)
    .await
    .expect("count the app-secret rows");
    assert_eq!(rows, 2, "both halves should be stored as governed secrets");

    let leaked: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM tenant_settings WHERE value::text LIKE '%pms1444%' \
         OR value::text LIKE '%GOCSPX%'",
    )
    .fetch_one(&pool)
    .await
    .expect("scan tenant_settings");
    assert_eq!(
        leaked, 0,
        "the client is an application-tier secret, not a tenant setting"
    );

    let ciphertext: Vec<u8> =
        sqlx::query_scalar("SELECT ciphertext FROM app_secrets WHERE name = $1")
            .bind("GOOGLE_CONTACTS_CLIENT_SECRET")
            .fetch_one(&pool)
            .await
            .expect("the row exists");
    assert!(
        !String::from_utf8_lossy(&ciphertext).contains("GOCSPX"),
        "the secret is stored in the clear"
    );
}

/// Half a pair is refused, and nothing is written.
///
/// A host holding one half refuses to boot, so an endpoint that could store one
/// would be an endpoint for breaking the next restart. Asserted against the
/// store as well as the status, because a refusal that had already written the
/// first half would leave exactly that state.
#[mokosh_test]
async fn half_a_pair_is_refused_and_writes_nothing(pool: PgPool) {
    let (_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let operator = common::login(&app, &email, &password).await;

    for body in [
        serde_json::json!({ "client_id": "half.apps.googleusercontent.com", "client_secret": "" }),
        serde_json::json!({ "client_id": "", "client_secret": "GOCSPX-half" }),
        serde_json::json!({ "client_id": "   ", "client_secret": "   " }),
    ] {
        let status = app
            .client
            .put(app.url(PATH))
            .bearer_auth(&operator)
            .json(&body)
            .send()
            .await
            .expect("write")
            .status();
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "half a pair must be refused: {body}"
        );
    }

    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM app_secrets")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(rows, 0, "a refused write stored something");
}

/// A swapped pair is refused, naming the field rather than failing at Google.
///
/// Two long opaque strings in two boxes, and Google's answer to the swap is
/// `invalid_client`, which names neither. This is the one validation worth
/// having on this form.
#[mokosh_test]
async fn a_swapped_pair_is_refused_before_it_is_stored(pool: PgPool) {
    let (_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let operator = common::login(&app, &email, &password).await;

    let response = app
        .client
        .put(app.url(PATH))
        .bearer_auth(&operator)
        .json(&serde_json::json!({
            "client_id": "GOCSPX-in-the-wrong-box",
            "client_secret": "swapped.apps.googleusercontent.com",
        }))
        .send()
        .await
        .expect("write");
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body: serde_json::Value = response.json().await.expect("json");
    let rendered = body.to_string();
    assert!(
        rendered.contains("swapped"),
        "the refusal has to say what is wrong: {rendered}"
    );
    assert!(
        !rendered.contains("in-the-wrong-box"),
        "the value must not come back in the error: {rendered}"
    );

    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM app_secrets")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(rows, 0, "a refused write stored something");
}

/// Only the deployment's operator, on both routes.
///
/// An admin of a customer organisation is refused. This is the route that sets
/// which Google application every tenant on the deployment authenticates as, so
/// a tenant-admin gate would let one customer repoint every other customer's
/// consent screen at a project they control.
#[mokosh_test]
async fn only_the_deployment_operator_sets_the_client(pool: PgPool) {
    let (_id, email, password) = common::seed_admin(&pool).await;
    let (_tenant, _user, other_email, other_password) =
        common::seed_tenant_with_admin(&pool, "customer-msp").await;
    let app = common::boot(pool.clone()).await;
    let operator = common::login(&app, &email, &password).await;

    let login: serde_json::Value = app
        .client
        .post(app.url("/api/v1/auth/login"))
        .json(&serde_json::json!({
            "email": other_email,
            "password": other_password,
            "tenant_slug": "customer-msp",
        }))
        .send()
        .await
        .expect("login")
        .json()
        .await
        .expect("login json");
    let customer = login["access_token"]
        .as_str()
        .expect("the customer organisation's admin signs in")
        .to_string();

    for (method, body) in [
        (reqwest::Method::GET, None),
        (reqwest::Method::PUT, Some(pair())),
    ] {
        let mut request = app
            .client
            .request(method.clone(), app.url(PATH))
            .bearer_auth(&customer);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let status = request.send().await.expect("request").status();
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{method} {PATH} must refuse another organisation's admin"
        );
    }

    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM app_secrets")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(rows, 0, "the refused write stored something");

    // And the operator keeps the read.
    let status = app
        .client
        .get(app.url(PATH))
        .bearer_auth(&operator)
        .send()
        .await
        .expect("read")
        .status();
    assert_eq!(status, StatusCode::OK);
}

/// Replacing an existing client is recorded, and the audit row says a
/// configured client was replaced.
///
/// Google binds a refresh token to the client that issued it, so a new id
/// refuses every existing tenant grant with `invalid_grant` and each connection
/// is asked to reconnect. When somebody asks months later why every tenant
/// disconnected on one afternoon, this row is the answer, and it has to
/// distinguish a first-time write from a replacement.
#[mokosh_test]
async fn replacing_a_configured_client_is_audited_as_a_replacement(pool: PgPool) {
    let (_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let operator = common::login(&app, &email, &password).await;

    for _ in 0..2 {
        let status = app
            .client
            .put(app.url(PATH))
            .bearer_auth(&operator)
            .json(&pair())
            .send()
            .await
            .expect("write")
            .status();
        assert_eq!(status, StatusCode::OK);
    }

    let entries: Vec<serde_json::Value> = sqlx::query_scalar(
        "SELECT new_values FROM audit_log WHERE entity_type = 'app_secrets' ORDER BY timestamp",
    )
    .fetch_all(&pool)
    .await
    .expect("read the audit rows");
    assert_eq!(entries.len(), 2, "each write is recorded");
    assert_eq!(
        entries[0]["replaced_a_configured_client"], false,
        "the first write configured a deployment that had nothing: {}",
        entries[0]
    );
    assert_eq!(
        entries[1]["replaced_a_configured_client"], true,
        "the second replaced a working client, which is what invalidates every grant: {}",
        entries[1]
    );
    for entry in &entries {
        let rendered = entry.to_string();
        assert!(
            !rendered.contains("pms1444") && !rendered.contains("GOCSPX"),
            "the audit row carries the credential: {rendered}"
        );
    }
}
