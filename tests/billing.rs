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
//! Money columns are written with SQL numeric literals rather than bound
//! `Decimal`s because the dev-dependency `sqlx` feature set used by the
//! integration-test binaries does not enable `rust_decimal`. Assertions
//! read money back through the JSON API, where it is serialised by the
//! service layer.

mod common;

use sqlx::PgPool;
use sqlx::Row;
use uuid::Uuid;

/// Seed a company under the default tenant; returns its id.
async fn seed_company(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO companies (id, tenant_id, name)
        VALUES ($1, $2, 'Acme Co')
        "#,
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .execute(pool)
    .await
    .expect("seed test company");
    id
}

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

/// Seed one billable, unbilled time entry directly. `duration_minutes`
/// and the money columns are interpolated as SQL literals (see the
/// module note on the missing `rust_decimal` dev feature). Returns the
/// new entry id.
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
    let sql = format!(
        r#"
        INSERT INTO time_entries (
            id, tenant_id, user_id, date, duration_minutes, work_type_id,
            company_id, is_billable, billing_status, invoice_id,
            hourly_rate, total_amount
        )
        VALUES ($1, $2, $3, CURRENT_DATE, {duration_minutes}, $4,
                $5, TRUE, 'ready_to_bill', NULL,
                {hourly_rate}, {total_amount})
        "#
    );
    sqlx::query(&sql)
        .bind(id)
        .bind(common::DEFAULT_TENANT_ID)
        .bind(user_id)
        .bind(work_type_id)
        .bind(company_id)
        .execute(pool)
        .await
        .expect("seed test time entry");
    id
}

#[sqlx::test]
async fn generate_invoice_from_time_entries(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = seed_company(&pool).await;
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
    let company_id = seed_company(&pool).await;
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
