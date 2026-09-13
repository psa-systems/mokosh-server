//! PMS-1182: every inbound webhook delivery leaves a row, verified or refused.
//!
//! The failure this closes is the absence of evidence. A refused delivery used
//! to leave this process with no trace of having received anything, so "the
//! provider never called us", "we refused it" and "we took it and it matched
//! no invoice" were one symptom: the customer paid and the invoice is still
//! outstanding. That cost six real payments under PMS-1184, where the only
//! record anywhere was a row in PayPal's own dashboard saying 401.
//!
//! Driven through the real Stripe receiver over the NOBYPASSRLS app role, so
//! the signature verification runs for real and the rows are written and read
//! the way a deployment writes and reads them.

mod common;

use common::{boot_rls, dec, seed_company, DEFAULT_TENANT_ID};
use hmac::{Hmac, Mac};
use rust_decimal::Decimal;
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

const TEST_KEY: [u8; 32] = [0u8; 32];
const WEBHOOK_SECRET: &str = "whsec_delivery_record";

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sign(secret: &str, body: &[u8], t: i64) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(format!("{t}.").as_bytes());
    mac.update(body);
    format!("t={t},v1={}", hex_encode(&mac.finalize().into_bytes()))
}

async fn seed_sent_invoice(pool: &sqlx::PgPool, company_id: Uuid, total: Decimal) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO invoices (id, tenant_id, invoice_number, company_id, status, \
         invoice_date, due_date, subtotal, total, balance_due, currency, sent_at) \
         VALUES ($1, $2, $3, $4, 'sent', CURRENT_DATE, CURRENT_DATE, $5, $5, $5, 'USD', NOW())",
    )
    .bind(id)
    .bind(DEFAULT_TENANT_ID)
    .bind(format!("WD-{}", &id.simple().to_string()[..8]))
    .bind(company_id)
    .bind(total)
    .execute(pool)
    .await
    .expect("seed sent invoice");
    id
}

async fn seed_stripe_gateway(pool: &sqlx::PgPool) {
    let plaintext = serde_json::json!({
        "secret_key": "sk_test_unused_in_webhook_path",
        "webhook_secret": WEBHOOK_SECRET,
    })
    .to_string();
    let encrypted = mokosh_server::utils::crypto::encrypt(&plaintext, &TEST_KEY).unwrap();
    sqlx::query(
        "INSERT INTO payment_gateway_configs \
         (tenant_id, provider, is_active, is_test_mode, config_encrypted) \
         VALUES ($1, 'stripe', TRUE, TRUE, $2)",
    )
    .bind(DEFAULT_TENANT_ID)
    .bind(encrypted)
    .execute(pool)
    .await
    .expect("seed stripe gateway");
}

fn checkout_completed_event(invoice_id: Uuid, amount_total_minor: i64) -> String {
    serde_json::json!({
        "id": "evt_delivery_1",
        "type": "checkout.session.completed",
        "data": {"object": {
            "id": "cs_delivery_1",
            "payment_status": "paid",
            "payment_intent": "pi_delivery_1",
            "amount_total": amount_total_minor,
            "currency": "usd",
            "metadata": {
                "tenant_id": DEFAULT_TENANT_ID.to_string(),
                "invoice_id": invoice_id.to_string(),
            }
        }}
    })
    .to_string()
}

type DeliveryRow = (
    String,
    String,
    Option<String>,
    Option<String>,
    Option<Uuid>,
    Option<String>,
);

async fn deliveries(pool: &sqlx::PgPool) -> Vec<DeliveryRow> {
    sqlx::query_as(
        "SELECT provider, outcome, event_type, event_id, invoice_id, detail \
         FROM payment_webhook_deliveries WHERE tenant_id = $1 ORDER BY received_at",
    )
    .bind(DEFAULT_TENANT_ID)
    .fetch_all(pool)
    .await
    .expect("read deliveries")
}

/// An accepted payment records what arrived and what it settled, under the
/// provider's own names for the event, so an admin can line this up with the
/// same delivery in their provider's dashboard.
#[sqlx::test(migrations = "./migrations")]
async fn an_accepted_delivery_is_recorded_with_its_event_and_invoice(pool: sqlx::PgPool) {
    let app = boot_rls(pool).await;
    let company = seed_company(&app.pool).await;
    let invoice = seed_sent_invoice(&app.pool, company, dec("100.00")).await;
    seed_stripe_gateway(&app.pool).await;

    let body = checkout_completed_event(invoice, 10_000);
    let resp = app
        .client
        .post(app.url(&format!("/api/v1/stripe/webhooks/{DEFAULT_TENANT_ID}")))
        .header(
            "Stripe-Signature",
            sign(WEBHOOK_SECRET, body.as_bytes(), now_unix()),
        )
        .body(body)
        .send()
        .await
        .expect("post webhook");
    assert_eq!(resp.status(), 200);

    let rows = deliveries(&app.pool).await;
    assert_eq!(rows.len(), 1, "one delivery, one row: {rows:?}");
    let (provider, outcome, event_type, event_id, invoice_id, detail) = &rows[0];
    assert_eq!(provider, "stripe");
    assert_eq!(outcome, "accepted");
    assert_eq!(event_type.as_deref(), Some("checkout.session.completed"));
    assert_eq!(event_id.as_deref(), Some("evt_delivery_1"));
    assert_eq!(*invoice_id, Some(invoice));
    assert_eq!(detail.as_deref(), None);
}

/// The row that matters most. A delivery this deployment would not accept is
/// still an event that happened here, and the endpoint answers 401 exactly as
/// it did before.
#[sqlx::test(migrations = "./migrations")]
async fn a_refused_delivery_is_recorded_and_still_answers_401(pool: sqlx::PgPool) {
    let app = boot_rls(pool).await;
    let company = seed_company(&app.pool).await;
    let invoice = seed_sent_invoice(&app.pool, company, dec("100.00")).await;
    seed_stripe_gateway(&app.pool).await;

    let body = checkout_completed_event(invoice, 10_000);
    let resp = app
        .client
        .post(app.url(&format!("/api/v1/stripe/webhooks/{DEFAULT_TENANT_ID}")))
        .header(
            "Stripe-Signature",
            sign("whsec_the_wrong_secret", body.as_bytes(), now_unix()),
        )
        .body(body)
        .send()
        .await
        .expect("post webhook");
    assert_eq!(resp.status(), 401, "the refusal is unchanged");

    let rows = deliveries(&app.pool).await;
    assert_eq!(rows.len(), 1, "a refused delivery is still a delivery");
    let (_provider, outcome, event_type, event_id, invoice_id, detail) = &rows[0];
    assert_eq!(outcome, "refused");
    // Read off a body whose signature did not verify is exactly what must not
    // happen, so these stay empty however much the body claims.
    assert_eq!(event_type.as_deref(), None);
    assert_eq!(event_id.as_deref(), None);
    assert_eq!(*invoice_id, None);
    assert!(detail.is_some(), "a refusal says what it was");

    // And the invoice is untouched.
    let status: String = sqlx::query_scalar("SELECT status FROM invoices WHERE id = $1")
        .bind(invoice)
        .fetch_one(&app.pool)
        .await
        .expect("read invoice");
    assert_eq!(status, "sent");
}

/// A tenant with no gateway for the route's provider records nothing. The
/// endpoint is unauthenticated by construction, so anyone who learns the URL
/// could otherwise write history into any tenant id they can name.
#[sqlx::test(migrations = "./migrations")]
async fn a_delivery_to_a_tenant_with_no_gateway_records_nothing(pool: sqlx::PgPool) {
    let app = boot_rls(pool).await;
    let body = serde_json::json!({"id": "evt_x", "type": "checkout.session.completed"}).to_string();

    let resp = app
        .client
        .post(app.url(&format!("/api/v1/stripe/webhooks/{DEFAULT_TENANT_ID}")))
        .header(
            "Stripe-Signature",
            sign(WEBHOOK_SECRET, body.as_bytes(), now_unix()),
        )
        .body(body)
        .send()
        .await
        .expect("post webhook");
    assert_eq!(resp.status(), 401);
    assert!(
        deliveries(&app.pool).await.is_empty(),
        "no gateway, no row: the endpoint takes no credential"
    );
}

/// An event this build does not act on is a normal thing to receive, and reads
/// as its own outcome rather than as a payment that landed.
#[sqlx::test(migrations = "./migrations")]
async fn an_event_this_build_ignores_is_recorded_as_ignored(pool: sqlx::PgPool) {
    let app = boot_rls(pool).await;
    seed_stripe_gateway(&app.pool).await;
    let body = serde_json::json!({"id": "evt_ignored", "type": "customer.created"}).to_string();

    let resp = app
        .client
        .post(app.url(&format!("/api/v1/stripe/webhooks/{DEFAULT_TENANT_ID}")))
        .header(
            "Stripe-Signature",
            sign(WEBHOOK_SECRET, body.as_bytes(), now_unix()),
        )
        .body(body)
        .send()
        .await
        .expect("post webhook");
    assert_eq!(resp.status(), 200);

    let rows = deliveries(&app.pool).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].1, "ignored");
    assert_eq!(rows[0].3.as_deref(), Some("evt_ignored"));
}

/// The read an MSP actually makes, through the finance-gated route, over the
/// NOBYPASSRLS role so the tenant policy is doing the scoping.
#[sqlx::test(migrations = "./migrations")]
async fn the_deliveries_endpoint_serves_what_arrived(pool: sqlx::PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = boot_rls(pool).await;
    let token = common::login(&app, &email, &password).await;

    // Nothing has arrived yet, and the empty answer is the useful one: it is
    // what lets a client say "this provider has never called this endpoint".
    let resp = app
        .client
        .get(app.url("/api/v1/payment-gateways/webhook-deliveries"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list deliveries");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body.as_array().map(Vec::len), Some(0), "{body}");

    // One refused delivery later, it is on the list.
    seed_stripe_gateway(&app.pool).await;
    let event =
        serde_json::json!({"id": "evt_listed", "type": "checkout.session.completed"}).to_string();
    app.client
        .post(app.url(&format!("/api/v1/stripe/webhooks/{DEFAULT_TENANT_ID}")))
        .header(
            "Stripe-Signature",
            sign("whsec_wrong", event.as_bytes(), now_unix()),
        )
        .body(event)
        .send()
        .await
        .expect("post webhook");

    let resp = app
        .client
        .get(app.url("/api/v1/payment-gateways/webhook-deliveries?provider=stripe"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list deliveries");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body[0]["provider"], "stripe");
    assert_eq!(body[0]["outcome"], "refused");
    assert!(body[0]["detail"].is_string(), "{body}");

    // Narrowed to a provider that has delivered nothing, the answer is empty
    // rather than everything.
    let resp = app
        .client
        .get(app.url("/api/v1/payment-gateways/webhook-deliveries?provider=paypal"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list deliveries");
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body.as_array().map(Vec::len), Some(0), "{body}");
}
