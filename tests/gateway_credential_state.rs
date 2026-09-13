//! PMS-1181: a configured gateway says what it holds, and can be checked.
//!
//! The failure this closes is quiet by construction. Credentials are
//! write-only, so the settings page can show a badge and nothing else; the
//! first thing that exercises them is a customer's payment, and a wrong PayPal
//! webhook id survives the save, the readiness check and the checkout, showing
//! up only as a payment that never reaches the invoice. These tests assert the
//! two answers an admin could not get: which fields are stored, and whether
//! what is stored can be built into a working provider.

mod common;

use serde_json::Value;
use sqlx::PgPool;

/// The zero encryption key `common::boot_*` wires into the router.
const TEST_KEY: [u8; 32] = [0u8; 32];

/// Seed a gateway row holding `config` in the pre-PMS-968 encrypted column,
/// which is the state a deployment the credential mover has not finished is
/// in, and the one a test can produce without a secret provider.
async fn seed_gateway(pool: &PgPool, provider: &str, is_active: bool, config: Value) {
    let encrypted =
        mokosh_server::utils::crypto::encrypt(&config.to_string(), &TEST_KEY).unwrap();
    sqlx::query(
        "INSERT INTO payment_gateway_configs \
         (tenant_id, provider, is_active, is_test_mode, config_encrypted) \
         VALUES ($1, $2, $3, TRUE, $4)",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(provider)
    .bind(is_active)
    .bind(encrypted)
    .execute(pool)
    .await
    .expect("seed gateway");
}

/// A sent invoice with a balance, so readiness has something payable to answer
/// about.
async fn seed_sent_invoice(pool: &PgPool, company_id: uuid::Uuid) -> uuid::Uuid {
    let id = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO invoices (id, tenant_id, invoice_number, company_id, status, \
         invoice_date, due_date, subtotal, total, amount_paid, balance_due, currency) \
         VALUES ($1, $2, $3, $4, 'sent', CURRENT_DATE, CURRENT_DATE + 30, 100, 100, 0, 100, 'USD')",
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(format!("GCS-INV-{}", &id.simple().to_string()[..8]))
    .bind(company_id)
    .execute(pool)
    .await
    .expect("seed sent invoice");
    id
}

async fn list_gateways(app: &common::TestApp, token: &str) -> Value {
    let resp = app
        .client
        .get(app.url("/api/v1/payment-gateways"))
        .bearer_auth(token)
        .send()
        .await
        .expect("list gateways");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    resp.json().await.expect("json")
}

/// An identifier comes back whole and a secret comes back as a tail.
///
/// Whole is the point for the webhook id: comparing it against the one PayPal
/// prints beside the webhook is the check that catches a wrong one before a
/// customer's money does.
#[sqlx::test]
async fn a_stored_gateway_says_which_fields_it_holds(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    seed_gateway(
        &pool,
        "paypal",
        true,
        serde_json::json!({
            "client_id": "BAAL2TfRIpapPXfMSa6pMJZLjJxg",
            "client_secret": "EEynpmak2i66ZGeHZRjYGIY5eqiEUqCretLRDN",
            "webhook_id": "3WL54026PT222181E",
            "sandbox": true,
        }),
    )
    .await;

    let body = list_gateways(&app, &token).await;
    let fields = body["data"][0]["credentials"]
        .as_array()
        .expect("credentials")
        .clone();
    let by_key = |key: &str| -> Value {
        fields
            .iter()
            .find(|f| f["key"] == key)
            .unwrap_or_else(|| panic!("no {key} in {fields:?}"))
            .clone()
    };

    let webhook = by_key("webhook_id");
    assert_eq!(webhook["present"], Value::Bool(true));
    assert_eq!(webhook["secret"], Value::Bool(false));
    assert_eq!(
        webhook["value"], "3WL54026PT222181E",
        "an identifier is shown whole, so it can be compared against PayPal's"
    );

    let secret = by_key("client_secret");
    assert_eq!(secret["present"], Value::Bool(true));
    assert_eq!(secret["secret"], Value::Bool(true));
    assert_eq!(
        secret["value"], "LRDN",
        "a secret is shown as its last four characters and never in full"
    );
    let whole = "EEynpmak2i66ZGeHZRjYGIY5eqiEUqCretLRDN";
    assert!(
        !body.to_string().contains(whole),
        "the plaintext of a secret must never leave the server"
    );
}

/// A field that was never filled in reads as absent, which is what tells an
/// admin WHICH part of the form to fix.
#[sqlx::test]
async fn a_missing_field_reads_as_absent(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    seed_gateway(
        &pool,
        "paypal",
        true,
        serde_json::json!({"client_id": "cid", "client_secret": "sec", "sandbox": true}),
    )
    .await;

    let body = list_gateways(&app, &token).await;
    let webhook = body["data"][0]["credentials"]
        .as_array()
        .expect("credentials")
        .iter()
        .find(|f| f["key"] == "webhook_id")
        .expect("webhook_id field")
        .clone();
    assert_eq!(webhook["present"], Value::Bool(false));
    assert_eq!(webhook["value"], Value::Null);
    assert_eq!(
        body["data"][0]["configured"],
        Value::Bool(true),
        "the row still holds a credential blob; what changed is that its parts are visible"
    );
}

/// The check answers with the provider that could not be built, rather than
/// erroring, because that IS the answer to "does this configuration work".
#[sqlx::test]
async fn checking_an_incomplete_gateway_names_the_missing_field(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    seed_gateway(
        &pool,
        "paypal",
        true,
        serde_json::json!({"client_id": "cid", "client_secret": "sec", "sandbox": true}),
    )
    .await;

    let resp = app
        .client
        .post(app.url("/api/v1/payment-gateways/paypal/check"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("check gateway");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let checks: Value = resp.json().await.expect("json");
    let text = checks.to_string();
    assert!(
        text.contains("failed"),
        "an incomplete credential set must not report a pass: {text}"
    );
    assert!(
        text.contains("webhook_id"),
        "the check must name the field that is missing: {text}"
    );
}

/// Checking a provider the tenant has not configured is a 404 naming it, not a
/// pass and not a 500.
#[sqlx::test]
async fn checking_a_gateway_that_is_not_configured_is_a_404(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let resp = app
        .client
        .post(app.url("/api/v1/payment-gateways/stripe/check"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("check gateway");
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
}

/// The lie PMS-1181 closes: an active row whose credential cannot produce a
/// provider reported the invoice as ready to pay, so the customer met the
/// failure instead of the admin.
#[sqlx::test]
async fn an_unusable_credential_is_not_reported_as_ready(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    // The pre-MAPPS-759 blob: a shape no provider reads, which deserialised
    // into empty strings and counted as ready.
    seed_gateway(
        &pool,
        "stripe",
        true,
        serde_json::json!({"api_key": "sk_test_supersecret"}),
    )
    .await;

    let company_id = common::seed_company(&pool).await;
    let invoice_id = seed_sent_invoice(&pool, company_id).await;
    let resp = app
        .client
        .get(app.url(&format!(
            "/api/v1/invoices/{invoice_id}/payment-readiness"
        )))
        .bearer_auth(&token)
        .send()
        .await
        .expect("readiness");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: Value = resp.json().await.expect("json");
    assert_eq!(
        body["gateway_ready"],
        Value::Bool(false),
        "a credential nothing can build is not a gateway that can take a payment: {body}"
    );
}
