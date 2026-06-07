//! Integration tests for the reports module (PMS-93 / PMS-146).
//!
//! Asserts the registry endpoint lists the report types, that each
//! aggregate reflects seeded data, that CSV export works, and that a
//! report is tenant-scoped (one tenant's data never appears in another's
//! report).

mod common;

use sqlx::PgPool;
use uuid::Uuid;

async fn seed_company(pool: &PgPool, tenant_id: Uuid, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(tenant_id)
        .bind(name)
        .execute(pool)
        .await
        .expect("seed company");
    id
}

/// Seed an invoice with an integer `total` (and equal balance due). The
/// total is inlined into the numeric column to avoid a Decimal bind.
async fn seed_invoice(pool: &PgPool, tenant_id: Uuid, company_id: Uuid, number: &str, total: i64) {
    let q = format!(
        r#"INSERT INTO invoices
           (id, tenant_id, invoice_number, company_id, invoice_date, due_date,
            status, total, amount_paid, balance_due)
           VALUES ($1, $2, $3, $4, '2026-01-01', '2026-01-31', 'sent', {total}, 0, {total})"#
    );
    sqlx::query(&q)
        .bind(Uuid::new_v4())
        .bind(tenant_id)
        .bind(number)
        .bind(company_id)
        .execute(pool)
        .await
        .expect("seed invoice");
}

// AC1 + AC2 + AC3 + AC4 + AC6: registry lists types; the dashboard,
// tickets, time, and billing aggregates reflect seeded data; CSV export
// works.
#[sqlx::test]
async fn reports_registry_and_aggregates(pool: PgPool) {
    let (admin_id, email, pw) = common::seed_admin(&pool).await;
    let company = seed_company(&pool, common::DEFAULT_TENANT_ID, "Acme Co").await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;

    // --- Registry (AC1) ---
    let registry: serde_json::Value = app
        .client
        .get(app.url("/api/v1/reports"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list reports")
        .json()
        .await
        .expect("registry JSON");
    let keys: Vec<&str> = registry
        .as_array()
        .expect("registry is an array")
        .iter()
        .filter_map(|r| r["key"].as_str())
        .collect();
    for expected in ["dashboard", "tickets", "time", "billing"] {
        assert!(keys.contains(&expected), "registry lists '{expected}'");
    }
    // The billing report advertises its company_id parameter.
    let billing = registry
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["key"] == "billing")
        .unwrap();
    assert!(
        billing["parameters"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["name"] == "company_id"),
        "billing report advertises company_id"
    );

    // Seed a ticket so the ticket aggregates have something to count.
    let ticket = app
        .client
        .post(app.url("/api/v1/tickets"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "title": "Printer down",
            "company_id": company,
            "description": "PCL errors",
            "custom_fields": {},
        }))
        .send()
        .await
        .expect("create ticket");
    assert!(ticket.status().is_success(), "create ticket should 2xx");

    // Seed a time entry (120 min) for the time report.
    let work_types: serde_json::Value = app
        .client
        .get(app.url("/api/v1/work-types"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("work types")
        .json()
        .await
        .expect("work types JSON");
    let work_type_id = work_types["data"][0]["id"].as_str().unwrap().to_string();
    let date = chrono::Utc::now().date_naive().to_string();
    let te = app
        .client
        .post(app.url("/api/v1/time-entries"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "user_id": admin_id,
            "date": date,
            "duration_minutes": 120,
            "work_type_id": work_type_id,
            "company_id": company,
            "is_billable": true,
        }))
        .send()
        .await
        .expect("create time entry");
    assert!(te.status().is_success(), "create time entry should 2xx");

    // Seed an invoice for the billing report.
    seed_invoice(
        &app.pool,
        common::DEFAULT_TENANT_ID,
        company,
        "INV-0001",
        1000,
    )
    .await;

    // --- Dashboard aggregate (AC3) ---
    let dash: serde_json::Value = app
        .client
        .get(app.url("/api/v1/reports/dashboard"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("dashboard report")
        .json()
        .await
        .expect("dashboard JSON");
    let open: i64 = dash["open_by_priority"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|b| b["count"].as_i64())
        .sum();
    assert_eq!(open, 1, "dashboard counts the one open ticket");

    // --- Tickets aggregate ---
    let tickets_rep: serde_json::Value = app
        .client
        .get(app.url("/api/v1/reports/tickets"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("tickets report")
        .json()
        .await
        .expect("tickets JSON");
    let opened: i64 = tickets_rep["opened_by_status"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|b| b["count"].as_i64())
        .sum();
    assert_eq!(opened, 1, "tickets report counts the opened ticket");

    // --- Time aggregate ---
    let time_rep: serde_json::Value = app
        .client
        .get(app.url("/api/v1/reports/time"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("time report")
        .json()
        .await
        .expect("time JSON");
    let minutes: i64 = time_rep["minutes_by_user"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|u| u["count"].as_i64())
        .sum();
    assert_eq!(minutes, 120, "time report sums the logged minutes");

    // --- Billing aggregate (manager: the seeded super_admin satisfies it) ---
    let billing_rep: serde_json::Value = app
        .client
        .get(app.url("/api/v1/reports/billing"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("billing report")
        .json()
        .await
        .expect("billing JSON");
    let invoiced = dec(&billing_rep["invoiced"]);
    assert!(
        (invoiced - 1000.0).abs() < 0.01,
        "billing report sums the invoiced total (got {invoiced})"
    );

    // --- CSV export (AC4) ---
    let export = app
        .client
        .get(app.url("/api/v1/reports/tickets/export?format=csv"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("csv export");
    assert!(export.status().is_success(), "csv export should 2xx");
    let body = export.text().await.expect("csv body");
    assert!(!body.trim().is_empty(), "csv export returns content");
}

// AC5: a report is tenant-scoped - another tenant's invoices never appear
// in this tenant's billing report.
#[sqlx::test]
async fn billing_report_is_tenant_scoped(pool: PgPool) {
    let (_admin_id, email, pw) = common::seed_admin(&pool).await;
    let company_a = seed_company(&pool, common::DEFAULT_TENANT_ID, "Tenant A Co").await;
    seed_invoice(&pool, common::DEFAULT_TENANT_ID, company_a, "INV-A", 1000).await;

    // A second tenant with its own (larger) invoice.
    let (tenant_b, _b_uid, _b_email, _b_pw) =
        common::seed_tenant_with_admin(&pool, "tenant-b").await;
    let company_b = seed_company(&pool, tenant_b, "Tenant B Co").await;
    seed_invoice(&pool, tenant_b, company_b, "INV-B", 5000).await;

    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;

    let billing: serde_json::Value = app
        .client
        .get(app.url("/api/v1/reports/billing"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("billing report")
        .json()
        .await
        .expect("billing JSON");
    let invoiced = dec(&billing["invoiced"]);
    assert!(
        (invoiced - 1000.0).abs() < 0.01,
        "tenant A sees only its own $1000 invoice, not tenant B's $5000 (got {invoiced})"
    );
}

/// Read a `Decimal`-ish JSON value (number or string) as f64.
fn dec(v: &serde_json::Value) -> f64 {
    v.as_f64()
        .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        .unwrap_or(f64::NAN)
}
