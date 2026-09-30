//! PMS-1312: whether a payment provider is connected lives in `integrations`.
//!
//! The unit tests in `modules::integrations` cover the registry's shape and
//! `billing::service::retired_gateway_flag` covers the source rule that no
//! serving read consults the retired column. What needs a database and a booted
//! app is the thing those cannot show: that the two surfaces which set this one
//! fact agree, in both directions, and that what the payment path serves follows
//! from it.
//!
//! Each test drives real routes rather than the service, because the whole point
//! of the move is that an operator can connect a gateway from either page and
//! meet the same answer.

mod common;

use mokosh_test::mokosh_test;
use reqwest::StatusCode;
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

/// A Stripe credential blob that `StripeProvider::from_config` accepts, so a
/// gateway seeded with it is one the payment path can actually build. Nothing
/// here reaches the network.
fn stripe_config() -> Value {
    json!({ "secret_key": "sk_test_connection_home", "webhook_secret": "whsec_connection_home" })
}

async fn put_gateway(
    app: &common::TestApp,
    token: &str,
    provider: &str,
    is_active: bool,
    config: Option<Value>,
) -> reqwest::Response {
    let mut body = json!({
        "provider": provider,
        "is_active": is_active,
        "is_test_mode": true,
    });
    if let Some(config) = config {
        body["config"] = config;
    }
    app.client
        .put(app.url("/api/v1/payment-gateways"))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .expect("put gateway")
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

async fn disconnect(app: &common::TestApp, token: &str, provider: &str) -> reqwest::Response {
    app.client
        .post(app.url(&format!("/api/v1/integrations/{provider}/disconnect")))
        .bearer_auth(token)
        .send()
        .await
        .expect("disconnect")
}

async fn integration_status(app: &common::TestApp, token: &str, provider: &str) -> String {
    let response = app
        .client
        .get(app.url(&format!("/api/v1/integrations/{provider}")))
        .bearer_auth(token)
        .send()
        .await
        .expect("get integration");
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.expect("integration json");
    body["status"]
        .as_str()
        .expect("status is a string")
        .to_string()
}

/// What the payments settings page shows for this provider's switch.
async fn listed_is_active(app: &common::TestApp, token: &str, provider: &str) -> bool {
    let response = app
        .client
        .get(app.url("/api/v1/payment-gateways"))
        .bearer_auth(token)
        .send()
        .await
        .expect("list gateways");
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.expect("gateway list json");
    let items = body["data"].as_array().expect("a list of gateways");
    items
        .iter()
        .find(|row| row["provider"] == provider)
        .map(|row| row["is_active"].as_bool().unwrap_or(false))
        .unwrap_or(false)
}

/// The retired mirror, read straight out of the table. Nothing in the build reads
/// it; this asserts the rollback promise migration 256 makes.
async fn mirror(pool: &PgPool, provider: &str) -> Option<bool> {
    sqlx::query_scalar(
        "SELECT is_active FROM payment_gateway_configs WHERE tenant_id = $1 AND provider = $2",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(provider)
    .fetch_optional(pool)
    .await
    .expect("read the retired mirror")
    .flatten()
}

/// `gateway_ready` is the field the SPA renders the Pay Now button from, so it is
/// the end of the chain this issue changed: the readiness read resolves the
/// tenant's connected providers and builds each one.
async fn readiness_has_gateway(app: &common::TestApp, token: &str, invoice_id: Uuid) -> bool {
    let response = app
        .client
        .get(app.url(&format!("/api/v1/invoices/{invoice_id}/payment-readiness")))
        .bearer_auth(token)
        .send()
        .await
        .expect("readiness");
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.expect("readiness json");
    body["gateway_ready"]
        .as_bool()
        .unwrap_or_else(|| panic!("readiness says nothing about a gateway: {body}"))
}

async fn seed_sent_invoice(pool: &PgPool, company_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO invoices (id, tenant_id, invoice_number, company_id, status, \
         invoice_date, due_date, subtotal, total, amount_paid, balance_due, currency) \
         VALUES ($1, $2, $3, $4, 'sent', CURRENT_DATE, CURRENT_DATE + 30, 100, 100, 0, 100, 'USD')",
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(format!("PCH-INV-{}", &id.simple().to_string()[..8]))
    .bind(company_id)
    .execute(pool)
    .await
    .expect("seed sent invoice");
    id
}

/// The one fact, from both surfaces. Saving the gateway with `is_active: true`
/// is what an admin does today, and the integrations page has to report the same
/// thing without a second switch to flip.
#[mokosh_test]
async fn saving_an_active_gateway_connects_it_on_the_integrations_page(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    assert_eq!(
        integration_status(&app, &token, "stripe").await,
        "not_connected",
        "a tenant with no gateway has not connected Stripe"
    );

    let response = put_gateway(&app, &token, "stripe", true, Some(stripe_config())).await;
    assert_eq!(response.status(), StatusCode::OK);

    assert_eq!(
        integration_status(&app, &token, "stripe").await,
        "connected"
    );
    assert!(listed_is_active(&app, &token, "stripe").await);
    assert_eq!(
        mirror(&pool, "stripe").await,
        Some(true),
        "the retired mirror follows the fact, for a rolled-back image"
    );

    // And off again, through the same surface.
    let response = put_gateway(&app, &token, "stripe", false, None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        integration_status(&app, &token, "stripe").await,
        "disconnected",
        "switching a saved gateway off is the deliberate act, not `not_connected`"
    );
    assert!(!listed_is_active(&app, &token, "stripe").await);
    assert_eq!(mirror(&pool, "stripe").await, Some(false));
}

/// The other direction, which is the one the move exists for: connecting on the
/// integrations page is what decides whether a customer can pay.
#[mokosh_test]
async fn connecting_on_the_integrations_page_is_what_the_payment_path_serves(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    // Credentials saved, switch left off: the state an admin is in halfway
    // through setting Stripe up.
    let response = put_gateway(&app, &token, "stripe", false, Some(stripe_config())).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        listed_is_active(&app, &token, "stripe").await == false,
        "a saved-but-inactive gateway is still listed, and not as active"
    );

    let invoice_id = seed_sent_invoice(&pool, company_id).await;
    assert!(
        !readiness_has_gateway(&app, &token, invoice_id).await,
        "nothing is connected yet, so there is no Pay Now"
    );

    let response = connect(&app, &token, "stripe", json!({})).await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "connecting a configured gateway here is allowed now: {:?}",
        response.text().await
    );

    assert!(
        readiness_has_gateway(&app, &token, invoice_id).await,
        "the payment path reads the integrations row, so connecting there is enough"
    );
    assert!(
        listed_is_active(&app, &token, "stripe").await,
        "and the payments page shows the same fact rather than its own copy"
    );
    assert_eq!(mirror(&pool, "stripe").await, Some(true));

    // Disconnecting here stops the customer being asked to pay, and leaves the
    // credential so reconnecting does not mean finding the keys again.
    let response = disconnect(&app, &token, "stripe").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(!readiness_has_gateway(&app, &token, invoice_id).await);
    assert_eq!(mirror(&pool, "stripe").await, Some(false));

    let response = connect(&app, &token, "stripe", json!({})).await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the credential survived the disconnect, so a reconnect needs nothing"
    );
    assert!(readiness_has_gateway(&app, &token, invoice_id).await);
}

/// The three refusals, each for a state that would otherwise read as working.
#[mokosh_test]
async fn connecting_a_payment_gateway_refuses_the_states_that_would_lie(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    // 1. No gateway at all. The message has to name where one is created, or an
    //    operator is told no and not what to do.
    let response = connect(&app, &token, "stripe", json!({})).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = response.json().await.expect("refusal json");
    let message = body["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("Payment gateways"),
        "the refusal must say where to enter the credential: {message}"
    );

    // 2. A credential sent here would go to an address the payment path never
    //    reads, so it is refused rather than quietly stored.
    let response = put_gateway(&app, &token, "stripe", false, Some(stripe_config())).await;
    assert_eq!(response.status(), StatusCode::OK);
    let response = connect(
        &app,
        &token,
        "stripe",
        json!({ "credential": "sk_test_wrong" }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = response.json().await.expect("refusal json");
    let message = body["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("Payment gateways"),
        "the refusal must point at the surface that takes it: {message}"
    );
    assert_eq!(
        integration_status(&app, &token, "stripe").await,
        "not_connected",
        "a refused connect changes nothing"
    );

    // 3. A gateway row whose credential is in neither place: `config_encrypted`
    //    NULL says it moved to the secret provider, and nothing ever put it
    //    there. Seeded raw, because no route produces this state; a half-finished
    //    credential move does, which is what PMS-968 left behind. Connecting it
    //    would record a gateway that cannot charge.
    sqlx::query(
        "INSERT INTO payment_gateway_configs \
             (tenant_id, provider, is_test_mode, config_encrypted) \
         VALUES ($1, 'paypal', TRUE, NULL)",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .execute(&pool)
    .await
    .expect("seed a gateway with no credential");

    let response = connect(&app, &token, "paypal", json!({})).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = response.json().await.expect("refusal json");
    let message = body["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("no credential"),
        "the refusal must say what is missing: {message}"
    );
    assert_eq!(
        integration_status(&app, &token, "paypal").await,
        "not_connected"
    );
}

/// `authorize_net` is in the gateway table's CHECK and in no registry entry, so
/// saving one must not try to write an `integrations` row for it. Before the skip
/// was written this was a constraint violation on an ordinary save.
#[mokosh_test]
async fn saving_a_gateway_with_no_registry_entry_still_works(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let response = put_gateway(
        &app,
        &token,
        "authorize_net",
        false,
        Some(json!({ "api_login_id": "x", "transaction_key": "y" })),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "storing credentials for an unimplemented provider is allowed (PMS-966)"
    );

    let rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM integrations WHERE tenant_id = $1 AND provider = 'authorize_net'",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(&pool)
    .await
    .expect("count integrations rows");
    assert_eq!(
        rows, 0,
        "a provider the integrations CHECK refuses gets no row here"
    );
}
