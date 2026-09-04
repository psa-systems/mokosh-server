//! PMS-729 phase 2 §7 slice A / I11: `/portal/invoices/{id}/payments` HTTP
//! tests. Pins the wire shape, the newest-first ordering, the safe
//! subset (no `notes`, no `gateway_response`), and the cross-company
//! 404 posture.

mod common;

use rust_decimal::Decimal;
use sqlx::PgPool;
use uuid::Uuid;

const PORTAL_PASSWORD: &str = "portal-password-12345";

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

async fn seed_portal_contact(pool: &PgPool, company_id: Uuid, email: &str) -> Uuid {
    let hash = mokosh_server::utils::crypto::hash_password(PORTAL_PASSWORD).expect("hash password");
    let id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO contacts (
            id, tenant_id, company_id, first_name, last_name, email,
            is_portal_user, portal_password_hash
        )
        VALUES ($1, $2, $3, 'Port', 'Al', $4, TRUE, $5)
        "#,
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company_id)
    .bind(email)
    .bind(&hash)
    .execute(pool)
    .await
    .expect("seed portal contact");
    id
}

async fn login(app: &common::TestApp, email: &str) -> String {
    let resp = app
        .client
        .post(app.url("/api/v1/portal/auth/login"))
        .json(&serde_json::json!({
            "tenant_slug": "default",
            "email": email,
            "password": PORTAL_PASSWORD,
        }))
        .send()
        .await
        .expect("login");
    assert!(resp.status().is_success());
    let body: serde_json::Value = resp.json().await.expect("login body");
    body["access_token"].as_str().unwrap().to_string()
}

async fn seed_invoice(pool: &PgPool, company_id: Uuid, number: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO invoices
            (id, tenant_id, invoice_number, company_id, status,
             invoice_date, due_date, subtotal, total, amount_paid, balance_due, currency)
        VALUES ($1, $2, $3, $4, 'sent', CURRENT_DATE, CURRENT_DATE + 30,
                100, 100, 0, 100, 'USD')
        "#,
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

#[allow(clippy::too_many_arguments)]
async fn seed_payment(
    pool: &PgPool,
    invoice_id: Uuid,
    company_id: Uuid,
    date: &str,
    amount: Decimal,
    method: &str,
    reference: Option<&str>,
    notes: Option<&str>,
) {
    sqlx::query(
        r#"
        INSERT INTO payments
            (id, tenant_id, invoice_id, company_id, payment_date, amount,
             payment_method, reference_number, notes)
        VALUES ($1, $2, $3, $4, $5::DATE, $6, $7, $8, $9)
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(common::DEFAULT_TENANT_ID)
    .bind(invoice_id)
    .bind(company_id)
    .bind(date)
    .bind(amount)
    .bind(method)
    .bind(reference)
    .bind(notes)
    .execute(pool)
    .await
    .expect("seed payment");
}

// -- tests ------------------------------------------------------------------

/// Two payments, newest-first, safe subset in the wire shape.
#[sqlx::test]
async fn payments_endpoint_returns_ledger_newest_first(pool: PgPool) {
    let _ = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let company = seed_company(&pool, "Ledger Co").await;
    let _c = seed_portal_contact(&pool, company, "ledger@example.com").await;
    let invoice = seed_invoice(&pool, company, "INV-500").await;

    seed_payment(
        &pool,
        invoice,
        company,
        "2026-07-01",
        Decimal::new(4000, 2),
        "check",
        Some("CHK-100"),
        Some("internal: bounced, resent"),
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
        Some("internal: manual capture"),
    )
    .await;

    let token = login(&app, "ledger@example.com").await;
    let resp = app
        .client
        .get(app.url(&format!("/api/v1/portal/invoices/{invoice}/payments")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send payments");
    assert!(resp.status().is_success(), "status: {}", resp.status());
    let body: serde_json::Value = resp.json().await.unwrap();
    let payments = body["payments"].as_array().expect("payments array");
    assert_eq!(payments.len(), 2, "expected 2 payments: {body}");
    assert_eq!(body["total"].as_i64().unwrap(), 2);

    // Newest first.
    assert_eq!(payments[0]["payment_date"].as_str().unwrap(), "2026-08-05");
    assert_eq!(payments[1]["payment_date"].as_str().unwrap(), "2026-07-01");
    // Safe subset: internal `notes` and `gateway_response` never
    // surface, even though the seed rows carry them.
    for row in payments {
        assert!(row.get("notes").is_none(), "notes leaked: {row}");
        assert!(row.get("gateway_response").is_none(), "gw leaked: {row}");
    }
    // Reference number is surfaced when present, dropped when null.
    assert_eq!(payments[1]["reference_number"].as_str().unwrap(), "CHK-100");
    assert!(payments[0].get("reference_number").is_none());
}

/// Empty ledger renders the same shape with `total: 0`, no 404.
#[sqlx::test]
async fn payments_endpoint_renders_empty_when_no_payments(pool: PgPool) {
    let _ = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let company = seed_company(&pool, "Empty Ledger Co").await;
    let _c = seed_portal_contact(&pool, company, "no-pay@example.com").await;
    let invoice = seed_invoice(&pool, company, "INV-501").await;

    let token = login(&app, "no-pay@example.com").await;
    let resp = app
        .client
        .get(app.url(&format!("/api/v1/portal/invoices/{invoice}/payments")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send");
    assert!(resp.status().is_success());
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["total"].as_i64().unwrap(), 0);
    assert!(body["payments"].as_array().unwrap().is_empty());
}

/// Cross-company invoice id returns 404, not 403. Payments for that
/// invoice never surface even if they exist.
#[sqlx::test]
async fn payments_endpoint_returns_404_for_cross_company_invoice(pool: PgPool) {
    let _ = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let mine = seed_company(&pool, "Mine Co").await;
    let other = seed_company(&pool, "Other Co").await;
    let _c = seed_portal_contact(&pool, mine, "me@example.com").await;
    let stolen = seed_invoice(&pool, other, "INV-STOLEN").await;
    // Seed a payment so we know the read would return >0 if scoping were broken.
    seed_payment(
        &pool,
        stolen,
        other,
        "2026-08-01",
        Decimal::new(9999, 2),
        "wire",
        None,
        None,
    )
    .await;

    let token = login(&app, "me@example.com").await;
    let resp = app
        .client
        .get(app.url(&format!("/api/v1/portal/invoices/{stolen}/payments")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
}

/// Missing bearer: 401.
#[sqlx::test]
async fn payments_endpoint_requires_a_portal_session(pool: PgPool) {
    let _ = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let resp = app
        .client
        .get(app.url(&format!(
            "/api/v1/portal/invoices/{}/payments",
            Uuid::new_v4()
        )))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}
