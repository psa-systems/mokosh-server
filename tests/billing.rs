//! Integration tests for the PMS-33 (Billing) core working component:
//! generating an invoice from a company's billable time entries.
//!
//! Covers:
//! - `POST /api/v1/invoices/from-time-entries` happy path: a draft
//!   invoice is created with a gapless number, one `time_entry` line per
//!   eligible entry, the subtotal/total equal the sum of the entries'
//!   amounts, and the source entries flip to `billing_status = 'billed'`
//!   with `invoice_id` set (proven via an independent DB read).
//! - Recording a payment against that invoice (via the existing
//!   `POST /api/v1/payments`) transitions the invoice status.
//!
//! Money columns are bound as `Decimal` values (the dev `sqlx` feature
//! set enables `rust_decimal`, PMS-199). Assertions read money back
//! through the JSON API, where it is serialised by the service layer.

mod common;

use sqlx::PgPool;
use sqlx::Row;
use uuid::Uuid;

/// Seed a billable work type under the default tenant; returns its id.
/// `time_entries.work_type_id` is `NOT NULL REFERENCES work_types(id)`,
/// so each seeded entry needs a real work type to point at.
async fn seed_work_type(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO work_types (id, tenant_id, name, default_billable, default_rate)
        VALUES ($1, $2, 'Billing Test Work', TRUE, 150.00)
        "#,
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .execute(pool)
    .await
    .expect("seed test work type");
    id
}

/// Seed one billable, unbilled time entry directly. The money columns
/// are bound as `Decimal` values (parsed from the string literals via
/// [`common::dec`]) rather than interpolated as SQL literals. Returns
/// the new entry id.
async fn seed_time_entry(
    pool: &PgPool,
    user_id: Uuid,
    company_id: Uuid,
    work_type_id: Uuid,
    duration_minutes: i32,
    hourly_rate: &str,
    total_amount: &str,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO time_entries (
            id, tenant_id, user_id, date, duration_minutes, work_type_id,
            company_id, is_billable, billing_status, invoice_id,
            hourly_rate, total_amount
        )
        VALUES ($1, $2, $3, CURRENT_DATE, $4, $5,
                $6, TRUE, 'ready_to_bill', NULL,
                $7, $8)
        "#,
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(user_id)
    .bind(duration_minutes)
    .bind(work_type_id)
    .bind(company_id)
    .bind(common::dec(hourly_rate))
    .bind(common::dec(total_amount))
    .execute(pool)
    .await
    .expect("seed test time entry");
    id
}

#[sqlx::test]
async fn generate_invoice_from_time_entries(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let work_type_id = seed_work_type(&pool).await;

    // Two billable entries: 60 min @ $150 = $150, 90 min @ $200 = $300.
    let entry_a = seed_time_entry(
        &pool,
        admin_id,
        company_id,
        work_type_id,
        60,
        "150.00",
        "150.00",
    )
    .await;
    let entry_b = seed_time_entry(
        &pool,
        admin_id,
        company_id,
        work_type_id,
        90,
        "200.00",
        "300.00",
    )
    .await;

    // A non-billable entry that must NOT be swept in (negative control).
    let ignored_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO time_entries (
            id, tenant_id, user_id, date, duration_minutes, work_type_id,
            company_id, is_billable, billing_status, invoice_id,
            hourly_rate, total_amount
        )
        VALUES ($1, $2, $3, CURRENT_DATE, 30, $4, $5,
                FALSE, 'not_billed', NULL, 100.00, 50.00)
        "#,
    )
    .bind(ignored_id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(admin_id)
    .bind(work_type_id)
    .bind(company_id)
    .execute(&pool)
    .await
    .expect("seed ignored non-billable entry");

    // PMS-144: a BILLABLE but unapproved entry (billing_status='not_billed')
    // must NOT be swept in - billing now consumes only 'ready_to_bill', which
    // timesheet approval produces. This is the approval gate's negative control.
    let unapproved_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO time_entries (
            id, tenant_id, user_id, date, duration_minutes, work_type_id,
            company_id, is_billable, billing_status, invoice_id,
            hourly_rate, total_amount
        )
        VALUES ($1, $2, $3, CURRENT_DATE, 45, $4, $5,
                TRUE, 'not_billed', NULL, 120.00, 90.00)
        "#,
    )
    .bind(unapproved_id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(admin_id)
    .bind(work_type_id)
    .bind(company_id)
    .execute(&pool)
    .await
    .expect("seed billable-but-unapproved entry");

    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    // Generate the invoice from the company's eligible entries.
    let resp = app
        .client
        .post(app.url("/api/v1/invoices/from-time-entries"))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "company_id": company_id }))
        .send()
        .await
        .expect("send generate-invoice request");
    assert!(
        resp.status().is_success(),
        "generate invoice should 2xx, got {}",
        resp.status()
    );
    let invoice: serde_json::Value = resp.json().await.expect("invoice JSON");

    // Gapless number: first invoice for this tenant -> INV-000001.
    assert_eq!(
        invoice["invoice_number"].as_str(),
        Some("INV-000001"),
        "first invoice should get the gapless INV-000001 number"
    );
    assert_eq!(invoice["status"].as_str(), Some("draft"));
    assert_eq!(
        invoice["company_id"].as_str(),
        Some(company_id.to_string().as_str())
    );

    // One time_entry line per eligible entry (the non-billable entry is
    // excluded).
    let lines = invoice["lines"]
        .as_array()
        .expect("invoice has lines array");
    assert_eq!(lines.len(), 2, "one line per eligible billable entry");
    assert!(
        lines
            .iter()
            .all(|l| l["line_type"].as_str() == Some("time_entry")),
        "every generated line is a time_entry line"
    );

    // Subtotal / total == sum of entry amounts (150 + 300 = 450).
    let total: f64 = invoice["total"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .or_else(|| invoice["total"].as_f64())
        .expect("invoice total is numeric");
    assert!(
        (total - 450.0).abs() < 0.001,
        "total should be 450, got {total}"
    );
    let subtotal: f64 = invoice["subtotal"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .or_else(|| invoice["subtotal"].as_f64())
        .expect("invoice subtotal is numeric");
    assert!(
        (subtotal - 450.0).abs() < 0.001,
        "subtotal should be 450, got {subtotal}"
    );

    let invoice_id = invoice["id"].as_str().expect("invoice has id").to_string();

    // The source entries are now billed and linked, proven via an
    // independent DB read (not just the API response).
    for entry_id in [entry_a, entry_b] {
        let row = sqlx::query("SELECT billing_status, invoice_id FROM time_entries WHERE id = $1")
            .bind(entry_id)
            .fetch_one(&app.pool)
            .await
            .expect("read back time entry");
        let status: String = row.get("billing_status");
        let linked: Option<Uuid> = row.get("invoice_id");
        assert_eq!(status, "billed", "entry {entry_id} should be billed");
        assert_eq!(
            linked.map(|u| u.to_string()),
            Some(invoice_id.clone()),
            "entry {entry_id} should link to the new invoice"
        );
    }

    // The non-billable entry must be untouched.
    let ignored = sqlx::query("SELECT billing_status, invoice_id FROM time_entries WHERE id = $1")
        .bind(ignored_id)
        .fetch_one(&app.pool)
        .await
        .expect("read back ignored entry");
    let ignored_status: String = ignored.get("billing_status");
    let ignored_link: Option<Uuid> = ignored.get("invoice_id");
    assert_eq!(
        ignored_status, "not_billed",
        "non-billable entry stays unbilled"
    );
    assert!(ignored_link.is_none(), "non-billable entry stays unlinked");

    // PMS-144: the billable-but-unapproved entry must also be untouched -
    // proof the approval gate holds (only ready_to_bill is invoiceable).
    let unapproved =
        sqlx::query("SELECT billing_status, invoice_id FROM time_entries WHERE id = $1")
            .bind(unapproved_id)
            .fetch_one(&app.pool)
            .await
            .expect("read back unapproved entry");
    let unapproved_status: String = unapproved.get("billing_status");
    let unapproved_link: Option<Uuid> = unapproved.get("invoice_id");
    assert_eq!(
        unapproved_status, "not_billed",
        "billable-but-unapproved entry must stay unbilled (approval gate)"
    );
    assert!(
        unapproved_link.is_none(),
        "billable-but-unapproved entry stays unlinked"
    );
}

#[sqlx::test]
async fn payment_against_generated_invoice_transitions_status(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let work_type_id = seed_work_type(&pool).await;

    // One billable entry: 60 min @ $150 = $150 total.
    seed_time_entry(
        &pool,
        admin_id,
        company_id,
        work_type_id,
        60,
        "150.00",
        "150.00",
    )
    .await;

    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let resp = app
        .client
        .post(app.url("/api/v1/invoices/from-time-entries"))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "company_id": company_id }))
        .send()
        .await
        .expect("send generate-invoice request");
    assert!(
        resp.status().is_success(),
        "generate should 2xx, got {}",
        resp.status()
    );
    let invoice: serde_json::Value = resp.json().await.expect("invoice JSON");
    let invoice_id = invoice["id"].as_str().expect("invoice id").to_string();

    // Record a full payment via the existing payments endpoint.
    let pay_resp = app
        .client
        .post(app.url("/api/v1/payments"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "invoice_id": invoice_id,
            "company_id": company_id,
            "payment_date": chrono::Utc::now().date_naive().to_string(),
            "amount": "150.00",
            "payment_method": "check",
        }))
        .send()
        .await
        .expect("send record-payment request");
    assert!(
        pay_resp.status().is_success(),
        "record payment should 2xx, got {}",
        pay_resp.status()
    );

    // The invoice should now be fully paid (balance zero, status 'paid').
    let get_resp = app
        .client
        .get(app.url(&format!("/api/v1/invoices/{invoice_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send get-invoice request");
    assert_eq!(get_resp.status(), reqwest::StatusCode::OK);
    let got: serde_json::Value = get_resp.json().await.expect("get invoice JSON");
    assert_eq!(
        got["status"].as_str(),
        Some("paid"),
        "a full payment should move the invoice to 'paid'"
    );
    let balance: f64 = got["balance_due"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .or_else(|| got["balance_due"].as_f64())
        .expect("balance_due numeric");
    assert!(
        balance.abs() < 0.001,
        "balance_due should be zero, got {balance}"
    );
}

// PMS-186: invoice and payment responses carry the company's display name
// so the client never has to surface a raw company_id UUID.
#[sqlx::test]
async fn billing_responses_carry_company_name(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await; // seeded as "Acme Co"
    let work_type_id = seed_work_type(&pool).await;
    seed_time_entry(
        &pool,
        admin_id,
        company_id,
        work_type_id,
        60,
        "150.00",
        "150.00",
    )
    .await;

    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let invoice: serde_json::Value = app
        .client
        .post(app.url("/api/v1/invoices/from-time-entries"))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "company_id": company_id }))
        .send()
        .await
        .expect("generate invoice")
        .json()
        .await
        .expect("invoice JSON");
    let invoice_id = invoice["id"].as_str().expect("invoice id").to_string();

    // --- Invoice list carries company_name ---
    let list: serde_json::Value = app
        .client
        .get(app.url("/api/v1/invoices"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list invoices")
        .json()
        .await
        .expect("invoices JSON");
    assert_eq!(
        list["data"][0]["company_name"].as_str(),
        Some("Acme Co"),
        "invoice list rows carry the company name"
    );

    // --- Invoice detail carries company_name ---
    let detail: serde_json::Value = app
        .client
        .get(app.url(&format!("/api/v1/invoices/{invoice_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("get invoice")
        .json()
        .await
        .expect("invoice detail JSON");
    assert_eq!(
        detail["company_name"].as_str(),
        Some("Acme Co"),
        "invoice detail carries the company name"
    );

    // --- Payment create + list carry company_name ---
    let payment: serde_json::Value = app
        .client
        .post(app.url("/api/v1/payments"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "invoice_id": invoice_id,
            "company_id": company_id,
            "payment_date": chrono::Utc::now().date_naive().to_string(),
            "amount": "150.00",
            "payment_method": "check",
        }))
        .send()
        .await
        .expect("record payment")
        .json()
        .await
        .expect("payment JSON");
    assert_eq!(
        payment["company_name"].as_str(),
        Some("Acme Co"),
        "the create-payment response carries the company name"
    );
    assert_eq!(
        payment["invoice_number"].as_str(),
        invoice["invoice_number"].as_str(),
        "the create-payment response carries the linked invoice number"
    );

    let payments: serde_json::Value = app
        .client
        .get(app.url("/api/v1/payments"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list payments")
        .json()
        .await
        .expect("payments JSON");
    assert_eq!(
        payments["data"][0]["company_name"].as_str(),
        Some("Acme Co"),
        "payment list rows carry the company name"
    );
    assert_eq!(
        payments["data"][0]["invoice_number"].as_str(),
        invoice["invoice_number"].as_str(),
        "payment list rows carry the linked invoice number"
    );
}

// ============================================================================
// PMS-333: payment_terms lookup + invoice FK.
// ============================================================================

/// Find a payment term id by name from `GET /payment-terms`.
async fn term_id(app: &common::TestApp, token: &str, name: &str) -> String {
    let body: serde_json::Value = app
        .client
        .get(app.url("/api/v1/payment-terms"))
        .bearer_auth(token)
        .send()
        .await
        .expect("list payment terms")
        .json()
        .await
        .expect("payment terms JSON");
    body["data"]
        .as_array()
        .expect("data array")
        .iter()
        .find(|t| t["name"].as_str() == Some(name))
        .unwrap_or_else(|| panic!("seeded term {name} present"))["id"]
        .as_str()
        .expect("term id")
        .to_string()
}

/// Migration 050 seeds Net 30 (PMS-934 renamed it from `net30`) as the single
/// default per tenant; setting a new
/// default clears the prior one.
#[sqlx::test]
async fn payment_terms_seeded_and_single_default(pool: PgPool) {
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;

    let list: serde_json::Value = app
        .client
        .get(app.url("/api/v1/payment-terms"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list")
        .json()
        .await
        .expect("JSON");
    let rows = list["data"].as_array().expect("data");
    // PMS-934: the seeded names are readable now. `name` is the display field
    // and the invoice dropdown renders it verbatim, so the seed no longer puts
    // an identifier there.
    let net30 = rows
        .iter()
        .find(|t| t["name"].as_str() == Some("Net 30"))
        .expect("Net 30 seeded");
    assert_eq!(
        net30["is_default"].as_bool(),
        Some(true),
        "net30 is the seeded default"
    );
    assert_eq!(
        rows.iter()
            .filter(|t| t["is_default"].as_bool() == Some(true))
            .count(),
        1,
        "exactly one default per tenant"
    );

    // Create a new default; the prior default (net30) must clear.
    let created: serde_json::Value = app
        .client
        .post(app.url("/api/v1/payment-terms"))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "name": "net90", "is_default": true, "sort_order": 9 }))
        .send()
        .await
        .expect("create term")
        .json()
        .await
        .expect("term JSON");
    assert_eq!(created["is_default"].as_bool(), Some(true));

    // net30 is no longer the default.
    let relist: serde_json::Value = app
        .client
        .get(app.url("/api/v1/payment-terms"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("relist")
        .json()
        .await
        .expect("JSON");
    let n30 = relist["data"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"].as_str() == Some("Net 30"))
        .expect("Net 30 row");
    assert_eq!(
        n30["is_default"].as_bool(),
        Some(false),
        "prior default cleared when a new default is set"
    );
    assert_eq!(
        relist["data"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|t| t["is_default"].as_bool() == Some(true))
            .count(),
        1,
        "still exactly one default after the switch"
    );
}

/// An invoice references a payment term by FK; the response carries
/// payment_term_id + payment_term_name, and a rename of the term is reflected
/// on the invoice (rename-safe FK). Deleting a referenced term is a 409.
#[sqlx::test]
async fn invoice_payment_term_link_rename_and_delete_guard(pool: PgPool) {
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;

    let net30 = term_id(&app, &token, "Net 30").await;

    let invoice: serde_json::Value = app
        .client
        .post(app.url("/api/v1/invoices"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "company_id": company_id,
            "invoice_date": "2026-06-15",
            "due_date": "2026-07-15",
            "payment_term_id": net30,
            "lines": [{ "line_type": "service", "description": "Work", "quantity": "1", "unit_price": "100" }],
        }))
        .send()
        .await
        .expect("create invoice")
        .json()
        .await
        .expect("invoice JSON");
    let invoice_id = invoice["id"].as_str().expect("invoice id").to_string();
    assert_eq!(invoice["payment_term_id"].as_str(), Some(net30.as_str()));
    assert_eq!(invoice["payment_term_name"].as_str(), Some("Net 30"));

    // Rename the term; the invoice's joined name follows (FK, not a copy).
    let put = app
        .client
        .put(app.url(&format!("/api/v1/payment-terms/{net30}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "name": "net-30-renamed" }))
        .send()
        .await
        .expect("rename term");
    assert!(put.status().is_success(), "rename: {}", put.status());

    let reread: serde_json::Value = app
        .client
        .get(app.url(&format!("/api/v1/invoices/{invoice_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("get invoice")
        .json()
        .await
        .expect("invoice JSON");
    assert_eq!(
        reread["payment_term_name"].as_str(),
        Some("net-30-renamed"),
        "a renamed term is reflected on the invoice"
    );

    // Deleting a term still referenced by an invoice is a 409, not a 500.
    let del = app
        .client
        .delete(app.url(&format!("/api/v1/payment-terms/{net30}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("delete referenced term");
    assert_eq!(
        del.status(),
        reqwest::StatusCode::CONFLICT,
        "deleting a referenced payment term is a 409"
    );
}

/// A payment_term_id from another tenant is rejected with a 400, never linked
/// across tenants (the FK alone would pass since FK checks bypass RLS).
#[sqlx::test]
async fn invoice_rejects_cross_tenant_payment_term(pool: PgPool) {
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;

    // A payment term owned by a different tenant.
    let (other_tenant, _, _, _) = common::seed_tenant_with_admin(&pool, "pt-other").await;
    let foreign_term = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO payment_terms (id, tenant_id, name, is_default) VALUES ($1, $2, 'foreign', FALSE)",
    )
    .bind(foreign_term)
    .bind(other_tenant)
    .execute(&pool)
    .await
    .expect("seed foreign term");

    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;

    let resp = app
        .client
        .post(app.url("/api/v1/invoices"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "company_id": company_id,
            "invoice_date": "2026-06-15",
            "due_date": "2026-07-15",
            "payment_term_id": foreign_term,
            "lines": [{ "line_type": "service", "description": "Work", "quantity": "1", "unit_price": "100" }],
        }))
        .send()
        .await
        .expect("create invoice with foreign term");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "a cross-tenant payment_term_id is rejected with 400"
    );
}

/// PMS-342: the payment-gateway secret is write-only. The upsert response and
/// the `GET /payment-gateways` list must never echo the decrypted credential;
/// they expose only non-secret metadata plus `configured`. Updating a gateway
/// without re-sending `config` preserves the stored secret.
#[sqlx::test]
async fn payment_gateway_secret_is_write_only(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    const SECRET: &str = "sk_live_supersecret_PMS342";

    // 1. Create a gateway carrying a secret in its config blob.
    let resp = app
        .client
        .put(app.url("/api/v1/payment-gateways"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "provider": "stripe",
            "is_active": true,
            "is_test_mode": false,
            "config": { "api_key": SECRET },
        }))
        .send()
        .await
        .expect("upsert payment gateway");
    assert!(
        resp.status().is_success(),
        "create gateway should 2xx, got {}",
        resp.status()
    );
    let body = resp.text().await.expect("upsert body");
    assert!(
        !body.contains(SECRET),
        "upsert response must not echo the plaintext secret, got {body}"
    );
    let created: serde_json::Value = serde_json::from_str(&body).expect("upsert JSON");
    assert!(
        created.get("config").is_none(),
        "response must not carry a `config` field, got {created}"
    );
    assert_eq!(
        created["configured"].as_bool(),
        Some(true),
        "a stored gateway reports configured = true"
    );

    // PMS-968: the credential is in the secret store now, not in the row. The
    // column being NULL is what says so, and the ciphertext lives in `secrets`
    // under the key the row's own (tenant_id, provider) gives.
    let column: Option<String> = sqlx::query_scalar(
        "SELECT config_encrypted FROM payment_gateway_configs WHERE provider = 'stripe'",
    )
    .fetch_one(&app.pool)
    .await
    .expect("read gateway column");
    assert!(
        column.is_none(),
        "a credential written through the API lives in the secret store, not the row"
    );

    // Capture the stored secret, to prove a metadata-only update leaves it
    // untouched. Still ciphertext at rest: the database backend encrypts with
    // the same host key the column used to.
    let secret_before: String = sqlx::query_scalar(
        "SELECT value_encrypted FROM secrets WHERE name LIKE 'PAYMENT_GATEWAY%'",
    )
    .fetch_one(&app.pool)
    .await
    .expect("read stored secret");
    assert!(
        !secret_before.contains(SECRET),
        "the stored secret must be ciphertext, not the plaintext"
    );

    // 2. `GET /payment-gateways` exposes metadata but never the secret.
    let resp = app
        .client
        .get(app.url("/api/v1/payment-gateways"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list payment gateways");
    assert!(resp.status().is_success(), "list gateways should 2xx");
    let body = resp.text().await.expect("list body");
    assert!(
        !body.contains(SECRET),
        "list response must not contain the plaintext secret, got {body}"
    );
    let list: serde_json::Value = serde_json::from_str(&body).expect("list JSON");
    let gw = &list["data"][0];
    assert!(
        gw.get("config").is_none(),
        "list item must not carry a `config` field, got {gw}"
    );
    assert_eq!(gw["provider"].as_str(), Some("stripe"));
    assert_eq!(gw["is_active"].as_bool(), Some(true));
    assert_eq!(gw["is_test_mode"].as_bool(), Some(false));
    assert_eq!(
        gw["configured"].as_bool(),
        Some(true),
        "list conveys that a secret is configured"
    );

    // 3. Update metadata only (no `config`): the stored secret is preserved.
    let resp = app
        .client
        .put(app.url("/api/v1/payment-gateways"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "provider": "stripe",
            "is_active": false,
            "is_test_mode": true,
        }))
        .send()
        .await
        .expect("update gateway without config");
    assert!(
        resp.status().is_success(),
        "config-less update should 2xx, got {}",
        resp.status()
    );

    let (is_active_after, is_test_after): (bool, bool) = sqlx::query_as(
        "SELECT is_active, is_test_mode \
         FROM payment_gateway_configs WHERE provider = 'stripe'",
    )
    .fetch_one(&app.pool)
    .await
    .expect("read gateway after metadata update");
    let secret_after: String = sqlx::query_scalar(
        "SELECT value_encrypted FROM secrets WHERE name LIKE 'PAYMENT_GATEWAY%'",
    )
    .fetch_one(&app.pool)
    .await
    .expect("read stored secret after metadata update");
    assert_eq!(
        secret_after, secret_before,
        "a config-less update must preserve the stored secret, wherever it lives"
    );
    assert!(
        !is_active_after,
        "metadata update applied is_active = false"
    );
    assert!(is_test_after, "metadata update applied is_test_mode = true");

    // 4. First-time create with no config is rejected (nothing to preserve).
    let resp = app
        .client
        .put(app.url("/api/v1/payment-gateways"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "provider": "paypal",
            "is_active": true,
            "is_test_mode": true,
        }))
        .send()
        .await
        .expect("create gateway without config");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "creating a new gateway without a config is a 400"
    );
}

// ============================================================================
// PMS-695: concurrent payments against one invoice must not lose an update.
// `create_payment` locks the invoice row before inserting, and both the
// create and delete paths derive `amount_paid` from `SUM(payments.amount)`.
// ============================================================================

/// Seed a `sent` invoice with the given total and no payments; returns its id.
async fn seed_sent_invoice(pool: &PgPool, company_id: Uuid, total: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO invoices (
            id, tenant_id, invoice_number, company_id, status,
            invoice_date, due_date, subtotal, total, amount_paid, balance_due
        )
        VALUES ($1, $2, $3, $4, 'sent',
                CURRENT_DATE, CURRENT_DATE + 30, $5, $5, 0, $5)
        "#,
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(format!("PMS695-{}", &id.simple().to_string()[..8]))
    .bind(company_id)
    .bind(common::dec(total))
    .execute(pool)
    .await
    .expect("seed test invoice");
    id
}

/// POST a payment of `amount` against `invoice_id`.
async fn post_payment(
    app: &common::TestApp,
    token: &str,
    invoice_id: Uuid,
    company_id: Uuid,
    amount: &str,
) -> reqwest::Response {
    app.client
        .post(app.url("/api/v1/payments"))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "invoice_id": invoice_id,
            "company_id": company_id,
            "payment_date": chrono::Utc::now().date_naive().to_string(),
            "amount": amount,
            "payment_method": "check",
        }))
        .send()
        .await
        .expect("send record-payment request")
}

/// Read the invoice's stored payment state straight from the DB.
async fn invoice_state(pool: &PgPool, invoice_id: Uuid) -> (String, String, String) {
    let row = sqlx::query(
        "SELECT amount_paid::text, balance_due::text, status FROM invoices WHERE id = $1",
    )
    .bind(invoice_id)
    .fetch_one(pool)
    .await
    .expect("read invoice state");
    (row.get(0), row.get(1), row.get(2))
}

/// Fire two payments at one invoice with the read-modify-write window held
/// open, and return both responses.
///
/// Simply firing two requests is not enough to reproduce the lost update: a
/// handler finishes in well under the time the second request needs to reach
/// the server, so the two never overlap. Instead a third transaction takes the
/// invoice row lock first, both requests are sent and park against it, and the
/// lock is only released once both are in flight. Pre-PMS-695 both requests get
/// their unlocked `SELECT total, amount_paid` in before either `UPDATE
/// invoices` can proceed, which is exactly the failing interleaving. Post-fix
/// they queue on the `FOR UPDATE` lock instead and serialise.
async fn race_two_payments(
    pool: &PgPool,
    app: &common::TestApp,
    token: &str,
    invoice_id: Uuid,
    company_id: Uuid,
    amount_a: &str,
    amount_b: &str,
) -> (reqwest::Response, reqwest::Response) {
    let mut blocker = pool.begin().await.expect("open blocking transaction");
    sqlx::query("SELECT id FROM invoices WHERE id = $1 FOR UPDATE")
        .bind(invoice_id)
        .execute(&mut *blocker)
        .await
        .expect("take the invoice row lock");

    let (a, b, ()) = tokio::join!(
        post_payment(app, token, invoice_id, company_id, amount_a),
        post_payment(app, token, invoice_id, company_id, amount_b),
        async {
            // Long enough for both handlers to reach the invoice row and park.
            tokio::time::sleep(std::time::Duration::from_millis(750)).await;
            blocker
                .rollback()
                .await
                .expect("release the invoice row lock");
        },
    );
    (a, b)
}

/// Sum of the invoice's payment rows, as the ledger sees it.
async fn payments_sum(pool: &PgPool, invoice_id: Uuid) -> String {
    sqlx::query_scalar("SELECT COALESCE(SUM(amount), 0)::text FROM payments WHERE invoice_id = $1")
        .bind(invoice_id)
        .fetch_one(pool)
        .await
        .expect("sum payments")
}

/// Two concurrent partial payments that together settle the invoice: both
/// must land and the invoice must end fully paid. Before PMS-695 the two
/// requests both read `amount_paid = 0` and the later write discarded the
/// earlier one, leaving `amount_paid = 600.00` against `1000.00` of payments.
#[sqlx::test]
async fn concurrent_partial_payments_both_land(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let invoice_id = seed_sent_invoice(&pool, company_id, "1000.00").await;

    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let (a, b) = race_two_payments(
        &pool, &app, &token, invoice_id, company_id, "400.00", "600.00",
    )
    .await;
    assert!(a.status().is_success(), "400.00 payment: {}", a.status());
    assert!(b.status().is_success(), "600.00 payment: {}", b.status());

    let (paid, balance, status) = invoice_state(&pool, invoice_id).await;
    assert_eq!(paid, "1000.00", "amount_paid is the sum of both payments");
    assert_eq!(balance, "0.00", "balance_due is settled");
    assert_eq!(status, "paid", "a fully settled invoice is 'paid'");
    assert_eq!(
        payments_sum(&pool, invoice_id).await,
        paid,
        "amount_paid always equals SUM(payments.amount)"
    );
}

/// Two concurrent payments that each fit the balance alone but overshoot it
/// together: exactly one wins, the loser is rejected with a 400, and the
/// invoice is never overpaid.
#[sqlx::test]
async fn concurrent_overpayment_is_rejected(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let invoice_id = seed_sent_invoice(&pool, company_id, "1000.00").await;

    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let (a, b) = race_two_payments(
        &pool, &app, &token, invoice_id, company_id, "700.00", "700.00",
    )
    .await;
    let statuses = [a.status(), b.status()];
    assert_eq!(
        statuses.iter().filter(|s| s.is_success()).count(),
        1,
        "exactly one of the two 700.00 payments succeeds, got {statuses:?}"
    );
    assert_eq!(
        statuses
            .iter()
            .filter(|s| **s == reqwest::StatusCode::BAD_REQUEST)
            .count(),
        1,
        "the loser is rejected as an overpayment, got {statuses:?}"
    );

    let (paid, balance, status) = invoice_state(&pool, invoice_id).await;
    assert_eq!(paid, "700.00", "only the winning payment is applied");
    assert_eq!(balance, "300.00", "balance_due never goes negative");
    assert_eq!(status, "partially_paid");
    assert_eq!(
        payments_sum(&pool, invoice_id).await,
        paid,
        "the rejected payment left no row behind"
    );
}

/// Deleting one of two payments recomputes the invoice from the surviving
/// rows rather than subtracting the deleted amount from a stale snapshot.
#[sqlx::test]
async fn deleting_a_payment_recomputes_from_remaining(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let invoice_id = seed_sent_invoice(&pool, company_id, "1000.00").await;

    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let first: serde_json::Value = post_payment(&app, &token, invoice_id, company_id, "500.00")
        .await
        .json()
        .await
        .expect("first payment JSON");
    let first_id = first["id"].as_str().expect("payment id").to_string();
    let second = post_payment(&app, &token, invoice_id, company_id, "500.00").await;
    assert!(second.status().is_success(), "second payment should 2xx");

    let (paid, _, status) = invoice_state(&pool, invoice_id).await;
    assert_eq!(paid, "1000.00");
    assert_eq!(status, "paid");

    let del = app
        .client
        .delete(app.url(&format!("/api/v1/payments/{first_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("delete payment");
    assert!(
        del.status().is_success(),
        "delete payment should 2xx, got {}",
        del.status()
    );

    let (paid, balance, status) = invoice_state(&pool, invoice_id).await;
    assert_eq!(
        paid, "500.00",
        "amount_paid falls back to the surviving row"
    );
    assert_eq!(balance, "500.00");
    assert_eq!(status, "partially_paid");
    assert_eq!(
        payments_sum(&pool, invoice_id).await,
        paid,
        "amount_paid always equals SUM(payments.amount)"
    );
}

// =====================================================================// PMS-993: the billing contact is the invoice recipient
// ============================================================================

/// AC2: a create that names no recipient inherits the company's billing
/// contact, so a draft carries who it is for from the moment it exists.
#[sqlx::test]
async fn invoice_inherits_the_company_billing_contact(pool: PgPool) {
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let contact_id = common::seed_billing_contact(&pool, company_id).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;

    let invoice: serde_json::Value = app
        .client
        .post(app.url("/api/v1/invoices"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "company_id": company_id,
            "invoice_date": "2026-06-15",
            "due_date": "2026-07-15",
            "lines": [{ "line_type": "service", "description": "Work", "quantity": "1", "unit_price": "100" }],
        }))
        .send()
        .await
        .expect("create invoice")
        .json()
        .await
        .expect("invoice JSON");
    assert_eq!(
        invoice["billing_contact_id"].as_str(),
        Some(contact_id.to_string().as_str()),
        "an omitted recipient resolves to the company's billing contact"
    );
}

/// AC2 negative: a recipient from another company (or another tenant) is a
/// 400, not a silent cross-account link. FK checks bypass RLS, so nothing else
/// was stopping it.
#[sqlx::test]
async fn invoice_rejects_a_billing_contact_from_another_company(pool: PgPool) {
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let other_company = common::seed_company_named(&pool, "Globex").await;
    let stranger = common::seed_billing_contact(&pool, other_company).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;

    let resp = app
        .client
        .post(app.url("/api/v1/invoices"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "company_id": company_id,
            "billing_contact_id": stranger,
            "invoice_date": "2026-06-15",
            "due_date": "2026-07-15",
            "lines": [{ "line_type": "service", "description": "Work", "quantity": "1", "unit_price": "100" }],
        }))
        .send()
        .await
        .expect("create invoice with a stranger");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "a billing contact outside the company is rejected"
    );
}

/// AC4: a company with no billing contact cannot have an invoice sent, and the
/// refusal leaves nothing behind - no `sent_at`, no frozen issuer, no issued
/// document. Those are what a partially-applied send would strand.
#[sqlx::test]
async fn sending_without_a_billing_contact_is_refused(pool: PgPool) {
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    // The pool is read again at the end to prove the row never moved off draft,
    // so `boot` gets a clone rather than ownership.
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &pw).await;

    let invoice: serde_json::Value = app
        .client
        .post(app.url("/api/v1/invoices"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "company_id": company_id,
            "invoice_date": "2026-06-15",
            "due_date": "2026-07-15",
            "lines": [{ "line_type": "service", "description": "Work", "quantity": "1", "unit_price": "100" }],
        }))
        .send()
        .await
        .expect("create invoice")
        .json()
        .await
        .expect("invoice JSON");
    assert!(
        invoice["billing_contact_id"].is_null(),
        "no billing contact to inherit"
    );
    let invoice_id = Uuid::parse_str(invoice["id"].as_str().expect("id")).expect("uuid");

    let resp = app
        .client
        .put(app.url(&format!("/api/v1/invoices/{invoice_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "status": "sent" }))
        .send()
        .await
        .expect("send invoice");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::CONFLICT,
        "sending to nobody is a 409"
    );

    let row = sqlx::query(
        "SELECT status, sent_at, issuer_snapshot FROM invoices \
         WHERE tenant_id = $1 AND id = $2",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(invoice_id)
    .fetch_one(&pool)
    .await
    .expect("read invoice back");
    assert_eq!(row.get::<String, _>("status"), "draft", "still a draft");
    assert!(
        row.get::<Option<chrono::DateTime<chrono::Utc>>, _>("sent_at")
            .is_none(),
        "a refused send stamps no sent_at"
    );
    assert!(
        row.get::<Option<serde_json::Value>, _>("issuer_snapshot")
            .is_none(),
        "a refused send freezes no issuer"
    );
    // PMS-959 stores the issued document as a `files` ledger row, not a table
    // of its own (see `billing::documents::store_issued`).
    let documents: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM files \
         WHERE tenant_id = $1 AND entity_id = $2 AND entity_type = 'invoice_document'",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(invoice_id)
    .fetch_one(&pool)
    .await
    .expect("count issued documents");
    assert_eq!(documents, 0, "a refused send writes no issued document");
}

/// AC2 + AC4: the send PERSISTS the recipient it resolved. Resolving only to
/// decide the 409 would leave the column NULL, and the pay-now mail reads that
/// column, so the invoice would go out addressed to nobody.
#[sqlx::test]
async fn sending_persists_the_resolved_billing_contact(pool: PgPool) {
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &pw).await;

    // Created BEFORE the company has a billing contact, so the draft stores
    // NULL and only the send can fill it in.
    let invoice: serde_json::Value = app
        .client
        .post(app.url("/api/v1/invoices"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "company_id": company_id,
            "invoice_date": "2026-06-15",
            "due_date": "2026-07-15",
            "lines": [{ "line_type": "service", "description": "Work", "quantity": "1", "unit_price": "100" }],
        }))
        .send()
        .await
        .expect("create invoice")
        .json()
        .await
        .expect("invoice JSON");
    let invoice_id = Uuid::parse_str(invoice["id"].as_str().expect("id")).expect("uuid");
    assert!(invoice["billing_contact_id"].is_null());

    let contact_id = common::seed_billing_contact(&pool, company_id).await;
    let sent: serde_json::Value = app
        .client
        .put(app.url(&format!("/api/v1/invoices/{invoice_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "status": "sent" }))
        .send()
        .await
        .expect("send invoice")
        .json()
        .await
        .expect("sent JSON");
    assert_eq!(sent["status"].as_str(), Some("sent"));

    let stored: Option<Uuid> = sqlx::query_scalar(
        "SELECT billing_contact_id FROM invoices WHERE tenant_id = $1 AND id = $2",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(invoice_id)
    .fetch_one(&pool)
    .await
    .expect("read recipient back");
    assert_eq!(
        stored,
        Some(contact_id),
        "the send writes the recipient it resolved, it does not only check it"
    );
}

/// PMS-1004: a generated line describes the work, not the row.
///
/// `Time entry {uuid}` was the description of every line the builder wrote,
/// and it reached the API, the page and the PDF a customer receives. The
/// line now names the date, the work type, the ticket and the notes.
#[sqlx::test]
async fn a_generated_line_describes_the_work_not_the_row(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let work_type_id = seed_work_type(&pool).await;
    let (ticket_id, _note_id) = common::seed_ticket_and_note(&pool, admin_id, company_id).await;
    let ticket_number: String =
        sqlx::query_scalar("SELECT ticket_number FROM tickets WHERE id = $1")
            .bind(ticket_id)
            .fetch_one(&pool)
            .await
            .expect("ticket number");

    let with_ticket = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO time_entries (
            id, tenant_id, user_id, date, duration_minutes, work_type_id,
            company_id, ticket_id, notes, is_billable, billing_status,
            hourly_rate, total_amount
        )
        VALUES ($1, $2, $3, '2026-08-27', 60, $4, $5, $6,
                'Rebooted the print spooler' || E'\n' || 'second line stays off the invoice',
                TRUE, 'ready_to_bill', 150.00, 150.00)
        "#,
    )
    .bind(with_ticket)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(admin_id)
    .bind(work_type_id)
    .bind(company_id)
    .bind(ticket_id)
    .execute(&pool)
    .await
    .expect("seed entry with a ticket");
    let bare = seed_time_entry(
        &pool,
        admin_id,
        company_id,
        work_type_id,
        30,
        "150.00",
        "75.00",
    )
    .await;

    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;
    let resp = app
        .client
        .post(app.url("/api/v1/invoices/from-time-entries"))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "company_id": company_id }))
        .send()
        .await
        .expect("generate invoice");
    assert!(resp.status().is_success(), "{}", resp.status());
    let invoice: serde_json::Value = resp.json().await.expect("invoice JSON");
    let lines = invoice["lines"].as_array().expect("lines");
    assert_eq!(lines.len(), 2);

    let descriptions: Vec<&str> = lines
        .iter()
        .map(|l| l["description"].as_str().expect("description"))
        .collect();
    assert_eq!(
        descriptions[0],
        format!("2026-08-27 Billing Test Work: {ticket_number} Attachment ticket - Rebooted the print spooler"),
        "the dated entry sorts first and names its ticket and notes"
    );
    assert!(
        descriptions[1].ends_with(" Billing Test Work"),
        "an entry with no ticket and no notes is its date and work type: {}",
        descriptions[1]
    );
    for (line, id) in descriptions.iter().zip([with_ticket, bare]) {
        assert!(!line.contains(&id.to_string()), "no UUID on a line: {line}");
        assert!(!line.contains("Time entry"), "{line}");
    }
}
