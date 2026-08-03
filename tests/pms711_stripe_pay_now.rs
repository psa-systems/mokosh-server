//! PMS-711: Stripe "Pay Now" webhook reconciliation, end to end.
//!
//! Drives the real `POST /api/v1/stripe/webhooks/{tenant_id}` route through the
//! NOBYPASSRLS app role (`boot_rls`), signing each synthetic event with the
//! tenant's stored webhook secret so the platform signature verification runs
//! for real. Covers the four acceptance scenarios: a paid checkout marks the
//! invoice paid (and is idempotent on redelivery), a refund walks it back, an
//! abandoned/failed event is a no-op 200, and a bad signature is rejected 401
//! without touching the invoice.

mod common;

use common::{boot_rls, dec, seed_company, DEFAULT_TENANT_ID};
use hmac::{Hmac, Mac};
use rust_decimal::Decimal;
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// The zero encryption key `common::boot_*` wires into the router. The stored
/// gateway config must be encrypted with the same key the app decrypts with.
const TEST_KEY: [u8; 32] = [0u8; 32];
const WEBHOOK_SECRET: &str = "whsec_test_secret";

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Build a valid `Stripe-Signature` header (`t=<ts>,v1=<hmac>`) over `body`.
fn sign(secret: &str, body: &[u8], t: i64) -> String {
    let mut mac = <Hmac<Sha256>>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(t.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    format!("t={t},v1={}", hex_encode(&mac.finalize().into_bytes()))
}

/// Seed a `sent` invoice with the given balance; returns its id.
async fn seed_sent_invoice(pool: &sqlx::PgPool, company_id: Uuid, total: Decimal) -> Uuid {
    let id = Uuid::new_v4();
    let number = format!("INV-{}", &id.simple().to_string()[..8]);
    sqlx::query(
        r#"
        INSERT INTO invoices (
            id, tenant_id, invoice_number, company_id, status,
            invoice_date, due_date, subtotal, total, balance_due, currency, sent_at
        )
        VALUES ($1, $2, $3, $4, 'sent', CURRENT_DATE, CURRENT_DATE, $5, $5, $5, 'USD', NOW())
        "#,
    )
    .bind(id)
    .bind(DEFAULT_TENANT_ID)
    .bind(number)
    .bind(company_id)
    .bind(total)
    .execute(pool)
    .await
    .expect("seed sent invoice");
    id
}

/// Store an active Stripe gateway config for the default tenant, encrypted with
/// the same key the app uses.
async fn seed_stripe_gateway(pool: &sqlx::PgPool) {
    let plaintext = serde_json::json!({
        "secret_key": "sk_test_unused_in_webhook_path",
        "webhook_secret": WEBHOOK_SECRET,
    })
    .to_string();
    let encrypted = mokosh_server::utils::crypto::encrypt(&plaintext, &TEST_KEY).unwrap();
    sqlx::query(
        r#"
        INSERT INTO payment_gateway_configs
            (tenant_id, provider, is_active, is_test_mode, config_encrypted)
        VALUES ($1, 'stripe', TRUE, TRUE, $2)
        "#,
    )
    .bind(DEFAULT_TENANT_ID)
    .bind(encrypted)
    .execute(pool)
    .await
    .expect("seed stripe gateway");
}

fn checkout_completed_event(invoice_id: Uuid, amount_total_minor: i64) -> String {
    serde_json::json!({
        "id": "evt_1",
        "type": "checkout.session.completed",
        "data": {"object": {
            "id": "cs_test_1",
            "payment_status": "paid",
            "payment_intent": "pi_test_1",
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

async fn invoice_state(pool: &sqlx::PgPool, id: Uuid) -> (String, Decimal, Decimal) {
    sqlx::query_as("SELECT status, amount_paid, balance_due FROM invoices WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read invoice state")
}

#[sqlx::test(migrations = "./migrations")]
async fn paid_webhook_marks_invoice_paid_and_is_idempotent(pool: sqlx::PgPool) {
    let app = boot_rls(pool).await;
    let company = seed_company(&app.pool).await;
    let invoice = seed_sent_invoice(&app.pool, company, dec("100.00")).await;
    seed_stripe_gateway(&app.pool).await;

    let body = checkout_completed_event(invoice, 10_000);
    let url = app.url(&format!("/api/v1/stripe/webhooks/{DEFAULT_TENANT_ID}"));
    let sig = sign(WEBHOOK_SECRET, body.as_bytes(), now_unix());

    // First delivery: reconciles the payment.
    let resp = app
        .client
        .post(&url)
        .header("Stripe-Signature", &sig)
        .body(body.clone())
        .send()
        .await
        .expect("post webhook");
    assert_eq!(resp.status(), 200, "paid webhook should be accepted");

    let (status, amount_paid, balance_due) = invoice_state(&app.pool, invoice).await;
    assert_eq!(status, "paid");
    assert_eq!(amount_paid, dec("100.00"));
    assert_eq!(balance_due, dec("0.00"));

    // The payment row carries the currency + provider reference the AC requires.
    let (method, currency, gw): (String, Option<String>, Option<String>) = sqlx::query_as(
        "SELECT payment_method, currency, gateway_transaction_id FROM payments WHERE invoice_id = $1",
    )
    .bind(invoice)
    .fetch_one(&app.pool)
    .await
    .expect("payment row exists");
    assert_eq!(method, "credit_card");
    assert_eq!(currency.as_deref(), Some("USD"));
    assert_eq!(gw.as_deref(), Some("pi_test_1"));

    // Redelivery (Stripe retries until 2xx): still 200, still exactly one
    // payment, balances unchanged.
    let resp2 = app
        .client
        .post(&url)
        .header(
            "Stripe-Signature",
            &sign(WEBHOOK_SECRET, body.as_bytes(), now_unix()),
        )
        .body(body)
        .send()
        .await
        .expect("post webhook again");
    assert_eq!(resp2.status(), 200);
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM payments WHERE invoice_id = $1")
        .bind(invoice)
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(count, 1, "redelivered event must not double-record");
}

#[sqlx::test(migrations = "./migrations")]
async fn refund_webhook_walks_the_invoice_back_to_partially_paid(pool: sqlx::PgPool) {
    let app = boot_rls(pool).await;
    let company = seed_company(&app.pool).await;
    let invoice = seed_sent_invoice(&app.pool, company, dec("100.00")).await;
    seed_stripe_gateway(&app.pool).await;
    let url = app.url(&format!("/api/v1/stripe/webhooks/{DEFAULT_TENANT_ID}"));

    // Pay it in full first.
    let paid = checkout_completed_event(invoice, 10_000);
    app.client
        .post(&url)
        .header(
            "Stripe-Signature",
            &sign(WEBHOOK_SECRET, paid.as_bytes(), now_unix()),
        )
        .body(paid)
        .send()
        .await
        .expect("pay");

    // Refund $40 of the $100 charge.
    let refund = serde_json::json!({
        "id": "evt_2",
        "type": "charge.refunded",
        "data": {"object": {
            "id": "ch_test_1",
            "payment_intent": "pi_test_1",
            "currency": "usd",
            "refunds": {"data": [{"id": "re_test_1", "amount": 4_000}]}
        }}
    })
    .to_string();
    let resp = app
        .client
        .post(&url)
        .header(
            "Stripe-Signature",
            &sign(WEBHOOK_SECRET, refund.as_bytes(), now_unix()),
        )
        .body(refund)
        .send()
        .await
        .expect("post refund webhook");
    assert_eq!(resp.status(), 200);

    let (status, amount_paid, balance_due) = invoice_state(&app.pool, invoice).await;
    assert_eq!(
        status, "partially_paid",
        "a partial refund reopens the balance"
    );
    assert_eq!(amount_paid, dec("60.00"));
    assert_eq!(balance_due, dec("40.00"));

    let refund_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM payment_refunds WHERE invoice_id = $1")
            .bind(invoice)
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert_eq!(refund_count, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn abandoned_checkout_is_a_no_op(pool: sqlx::PgPool) {
    let app = boot_rls(pool).await;
    let company = seed_company(&app.pool).await;
    let invoice = seed_sent_invoice(&app.pool, company, dec("100.00")).await;
    seed_stripe_gateway(&app.pool).await;
    let url = app.url(&format!("/api/v1/stripe/webhooks/{DEFAULT_TENANT_ID}"));

    // An expired / abandoned session: recognised, but `payment_status` is not
    // `paid`, so it must not record anything - and must still 200 so Stripe
    // stops retrying.
    let body = serde_json::json!({
        "id": "evt_3",
        "type": "checkout.session.completed",
        "data": {"object": {
            "id": "cs_test_2",
            "payment_status": "unpaid",
            "payment_intent": "pi_test_2",
            "amount_total": 10_000,
            "currency": "usd",
            "metadata": {
                "tenant_id": DEFAULT_TENANT_ID.to_string(),
                "invoice_id": invoice.to_string(),
            }
        }}
    })
    .to_string();
    let resp = app
        .client
        .post(&url)
        .header(
            "Stripe-Signature",
            &sign(WEBHOOK_SECRET, body.as_bytes(), now_unix()),
        )
        .body(body)
        .send()
        .await
        .expect("post abandoned webhook");
    assert_eq!(resp.status(), 200);

    let (status, amount_paid, _) = invoice_state(&app.pool, invoice).await;
    assert_eq!(
        status, "sent",
        "an abandoned checkout must not change status"
    );
    assert_eq!(amount_paid, dec("0.00"));
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM payments WHERE invoice_id = $1")
        .bind(invoice)
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn bad_signature_is_rejected_and_changes_nothing(pool: sqlx::PgPool) {
    let app = boot_rls(pool).await;
    let company = seed_company(&app.pool).await;
    let invoice = seed_sent_invoice(&app.pool, company, dec("100.00")).await;
    seed_stripe_gateway(&app.pool).await;
    let url = app.url(&format!("/api/v1/stripe/webhooks/{DEFAULT_TENANT_ID}"));

    let body = checkout_completed_event(invoice, 10_000);
    // Sign with the WRONG secret.
    let resp = app
        .client
        .post(&url)
        .header(
            "Stripe-Signature",
            sign("whsec_wrong", body.as_bytes(), now_unix()),
        )
        .body(body)
        .send()
        .await
        .expect("post webhook with bad signature");
    assert_eq!(resp.status(), 401, "a bad signature must be rejected");

    let (status, amount_paid, _) = invoice_state(&app.pool, invoice).await;
    assert_eq!(status, "sent");
    assert_eq!(amount_paid, dec("0.00"));
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM payments WHERE invoice_id = $1")
        .bind(invoice)
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
}
