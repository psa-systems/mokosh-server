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

/// Migration 050 seeds net30 as the single default per tenant; setting a new
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
    let net30 = rows
        .iter()
        .find(|t| t["name"].as_str() == Some("net30"))
        .expect("net30 seeded");
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
        .find(|t| t["name"].as_str() == Some("net30"))
        .expect("net30 row");
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

    let net30 = term_id(&app, &token, "net30").await;

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
    assert_eq!(invoice["payment_term_name"].as_str(), Some("net30"));

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
