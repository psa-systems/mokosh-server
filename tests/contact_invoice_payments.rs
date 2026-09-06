//! PMS-1088: `GET /invoices/{id}/payments` on the contact plane. A
//! contact holding `invoices:read` sees the payments and refunds behind
//! its own Company's invoice, newest first, in the customer-safe subset
//! (no agent notes, no gateway ids, no provider payloads); a foreign
//! invoice is the unknown-id 404 even when it has payments; staff read
//! the same shape behind the billing and finance gates.

mod common;

use reqwest::StatusCode;
use rust_decimal::Decimal;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_company(pool: &PgPool, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(common::DEFAULT_TENANT_ID)
        .bind(name)
        .execute(pool)
        .await
        .expect("seed company");
    id
}

async fn seed_invoice(pool: &PgPool, company_id: Uuid, number: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO invoices \
            (id, tenant_id, invoice_number, company_id, status, invoice_date, due_date, \
             subtotal, total, amount_paid, balance_due, currency) \
         VALUES ($1, $2, $3, $4, 'sent', CURRENT_DATE, CURRENT_DATE + 30, 100, 100, 0, 100, 'EUR')",
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(number)
    .bind(company_id)
    .execute(pool)
    .await
    .expect("seed invoice");
    id
}

async fn seed_payment(
    pool: &PgPool,
    invoice_id: Uuid,
    company_id: Uuid,
    date: &str,
    amount: Decimal,
    method: &str,
    reference: Option<&str>,
) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO payments \
            (tenant_id, invoice_id, company_id, payment_date, amount, payment_method, \
             reference_number, gateway_transaction_id, gateway_response, notes) \
         VALUES ($1, $2, $3, $4::DATE, $5, $6, $7, $8, '{\"raw\": true}'::jsonb, \
                 'internal: bounced, retry Friday') \
         RETURNING id",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(invoice_id)
    .bind(company_id)
    .bind(date)
    .bind(amount)
    .bind(method)
    .bind(reference)
    .bind(format!("pi_{}", Uuid::new_v4().simple()))
    .fetch_one(pool)
    .await
    .expect("seed payment")
}

async fn seed_refund(pool: &PgPool, payment_id: Uuid, invoice_id: Uuid, amount: Decimal) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO payment_refunds \
            (tenant_id, payment_id, invoice_id, amount, provider, provider_reference, gateway_response) \
         VALUES ($1, $2, $3, $4, 'stripe', $5, '{\"raw\": true}'::jsonb) RETURNING id",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(payment_id)
    .bind(invoice_id)
    .bind(amount)
    .bind(format!("re_{}", Uuid::new_v4().simple()))
    .fetch_one(pool)
    .await
    .expect("seed refund")
}

async fn ledger(app: &common::TestApp, token: &str, invoice: Uuid) -> (StatusCode, Value) {
    let resp = app
        .client
        .get(app.url(&format!("/api/v1/invoices/{invoice}/payments")))
        .bearer_auth(token)
        .send()
        .await
        .expect("ledger");
    let status = resp.status();
    let body = resp.json().await.unwrap_or(Value::Null);
    (status, body)
}

// Two payments and a refund, newest first, the safe subset, the sums;
// an invoice with nothing paid answers the same shape empty.
#[sqlx::test]
async fn a_contact_reads_the_ledger_of_its_own_invoice(pool: PgPool) {
    let (_, email, password) = common::seed_admin(&pool).await;
    let company = seed_company(&pool, "Ledger Co").await;
    let me =
        common::seed_portal_contact(&pool, company, "me@example.com", &["Billing Contact"]).await;
    let invoice = seed_invoice(&pool, company, "INV-500").await;
    let empty = seed_invoice(&pool, company, "INV-501").await;
    let first = seed_payment(
        &pool,
        invoice,
        company,
        "2026-07-01",
        Decimal::new(4000, 2),
        "check",
        Some("CHK-100"),
    )
    .await;
    seed_payment(
        &pool,
        invoice,
        company,
        "2026-08-05",
        Decimal::new(6000, 2),
        "credit_card",
        None,
    )
    .await;
    seed_refund(&pool, first, invoice, Decimal::new(1500, 2)).await;
    let app = common::boot(pool.clone()).await;
    let token = common::contact_token(&app, &me).await;

    let (status, body) = ledger(&app, &token, invoice).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["invoice_id"], invoice.to_string());
    assert_eq!(body["currency"], "EUR");
    let payments = body["payments"].as_array().unwrap();
    assert_eq!(payments.len(), 2);
    assert_eq!(payments[0]["payment_date"], "2026-08-05");
    assert_eq!(payments[1]["payment_date"], "2026-07-01");
    assert_eq!(payments[1]["reference_number"], "CHK-100");
    assert!(payments[0].get("reference_number").is_none());
    assert_eq!(payments[1]["payment_method"], "check");
    for row in payments {
        for hidden in [
            "notes",
            "gateway_transaction_id",
            "gateway_response",
            "company_id",
        ] {
            assert!(row.get(hidden).is_none(), "{hidden} leaked: {row}");
        }
    }
    let refunds = body["refunds"].as_array().unwrap();
    assert_eq!(refunds.len(), 1);
    assert_eq!(refunds[0]["payment_id"], first.to_string());
    for hidden in ["provider", "provider_reference", "gateway_response"] {
        assert!(refunds[0].get(hidden).is_none(), "{hidden} leaked");
    }
    assert_eq!(
        common::dec(body["total_paid"].as_str().unwrap()),
        Decimal::new(10000, 2)
    );
    assert_eq!(
        common::dec(body["total_refunded"].as_str().unwrap()),
        Decimal::new(1500, 2)
    );

    let (status, body) = ledger(&app, &token, empty).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["payments"].as_array().unwrap().is_empty());
    assert!(body["refunds"].as_array().unwrap().is_empty());
    assert_eq!(
        common::dec(body["total_paid"].as_str().unwrap()),
        Decimal::ZERO
    );

    // Staff read the same shape.
    let staff = common::login(&app, &email, &password).await;
    let (status, body) = ledger(&app, &staff, invoice).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["payments"].as_array().unwrap().len(), 2);
    assert!(body["payments"][0].get("notes").is_none());
}

// A foreign invoice with payments is the unknown-id 404; without
// invoices:read it is 403; anonymous is 401.
#[sqlx::test]
async fn a_foreign_invoice_is_404_and_the_gate_holds(pool: PgPool) {
    let _ = common::seed_admin(&pool).await;
    let mine = seed_company(&pool, "Mine Co").await;
    let other = seed_company(&pool, "Other Co").await;
    let me = common::seed_portal_contact(&pool, mine, "me@example.com", &["Read-Only"]).await;
    let support =
        common::seed_portal_contact(&pool, mine, "sup@example.com", &["Support Contact"]).await;
    let own = seed_invoice(&pool, mine, "INV-1").await;
    let stolen = seed_invoice(&pool, other, "INV-STOLEN").await;
    seed_payment(
        &pool,
        stolen,
        other,
        "2026-08-01",
        Decimal::new(9999, 2),
        "wire",
        None,
    )
    .await;
    let app = common::boot(pool.clone()).await;
    let token = common::contact_token(&app, &me).await;

    let (status, unknown_body) = ledger(&app, &token, Uuid::new_v4()).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, foreign_body) = ledger(&app, &token, stolen).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(foreign_body, unknown_body);
    let (status, _) = ledger(&app, &token, own).await;
    assert_eq!(status, StatusCode::OK);

    // Support Contact holds no invoices:read.
    let support_token = common::contact_token(&app, &support).await;
    let (status, _) = ledger(&app, &support_token, own).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let anon = app
        .client
        .get(app.url(&format!("/api/v1/invoices/{own}/payments")))
        .send()
        .await
        .unwrap();
    assert_eq!(anon.status(), StatusCode::UNAUTHORIZED);
}
