//! Integration tests for the reports module (PMS-93 / PMS-146).
//!
//! Asserts the registry endpoint lists the report types, that each
//! aggregate reflects seeded data, that CSV export works, and that a
//! report is tenant-scoped (one tenant's data never appears in another's
//! report).

mod common;

use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

use mokosh_server::modules::auth::TenantId;
use mokosh_server::modules::reports::ReportsService;
use mokosh_server::Database;

/// Seed an open ticket under `tenant_id`. The classification lookups
/// (status/priority/queue) are pulled from the default tenant - the only
/// tenant the seed migration provisions them for - and referenced by id;
/// the ticket FKs do not enforce same-tenant lookups, so this lets a test
/// plant tickets in a second tenant without duplicating the whole lookup set.
/// The chosen status is open (`is_closed = false`) so the dashboard's
/// open-ticket aggregates count it.
async fn seed_open_ticket(
    pool: &PgPool,
    tenant_id: Uuid,
    company_id: Uuid,
    created_by: Uuid,
    number: &str,
) {
    let status_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM ticket_statuses WHERE tenant_id = $1 AND is_closed = FALSE LIMIT 1",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(pool)
    .await
    .expect("an open ticket status");
    let priority_id: Uuid =
        sqlx::query_scalar("SELECT id FROM ticket_priorities WHERE tenant_id = $1 LIMIT 1")
            .bind(common::DEFAULT_TENANT_ID)
            .fetch_one(pool)
            .await
            .expect("a ticket priority");
    let queue_id: Uuid =
        sqlx::query_scalar("SELECT id FROM ticket_queues WHERE tenant_id = $1 LIMIT 1")
            .bind(common::DEFAULT_TENANT_ID)
            .fetch_one(pool)
            .await
            .expect("a ticket queue");

    sqlx::query(
        r#"INSERT INTO tickets
           (id, tenant_id, ticket_number, title, status_id, priority_id,
            queue_id, company_id, created_by_id)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"#,
    )
    .bind(Uuid::new_v4())
    .bind(tenant_id)
    .bind(number)
    .bind("Seed ticket")
    .bind(status_id)
    .bind(priority_id)
    .bind(queue_id)
    .bind(company_id)
    .bind(created_by)
    .execute(pool)
    .await
    .expect("seed open ticket");
}

/// Seed an open ticket with an explicit `created_at` instant. Same lookup
/// strategy as [`seed_open_ticket`]; used to plant a ticket at a UTC moment
/// that falls on a different calendar day depending on the viewer's timezone
/// (PMS-360).
async fn seed_open_ticket_at(
    pool: &PgPool,
    tenant_id: Uuid,
    company_id: Uuid,
    created_by: Uuid,
    number: &str,
    created_at: chrono::DateTime<chrono::Utc>,
) {
    let status_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM ticket_statuses WHERE tenant_id = $1 AND is_closed = FALSE LIMIT 1",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(pool)
    .await
    .expect("an open ticket status");
    let priority_id: Uuid =
        sqlx::query_scalar("SELECT id FROM ticket_priorities WHERE tenant_id = $1 LIMIT 1")
            .bind(common::DEFAULT_TENANT_ID)
            .fetch_one(pool)
            .await
            .expect("a ticket priority");
    let queue_id: Uuid =
        sqlx::query_scalar("SELECT id FROM ticket_queues WHERE tenant_id = $1 LIMIT 1")
            .bind(common::DEFAULT_TENANT_ID)
            .fetch_one(pool)
            .await
            .expect("a ticket queue");

    sqlx::query(
        r#"INSERT INTO tickets
           (id, tenant_id, ticket_number, title, status_id, priority_id,
            queue_id, company_id, created_by_id, created_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)"#,
    )
    .bind(Uuid::new_v4())
    .bind(tenant_id)
    .bind(number)
    .bind("Seed ticket")
    .bind(status_id)
    .bind(priority_id)
    .bind(queue_id)
    .bind(company_id)
    .bind(created_by)
    .bind(created_at)
    .execute(pool)
    .await
    .expect("seed open ticket at instant");
}

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

// PMS-260: the dashboard aggregates (open-by-priority, ticket trend) are
// tenant-scoped - a second tenant's tickets never inflate this tenant's
// counts. Aggregates leak counts even when rows are hidden, so this pins
// the COUNT(*) scoping directly at the service layer.
#[sqlx::test]
async fn dashboard_is_tenant_scoped(pool: PgPool) {
    let tenant_a = common::DEFAULT_TENANT_ID;
    let (admin_a, _email, _pw) = common::seed_admin(&pool).await;
    let company_a = seed_company(&pool, tenant_a, "Tenant A Co").await;
    // Two open tickets in the caller's tenant.
    seed_open_ticket(&pool, tenant_a, company_a, admin_a, "A-1").await;
    seed_open_ticket(&pool, tenant_a, company_a, admin_a, "A-2").await;

    // A second tenant with three open tickets of its own.
    let (tenant_b, user_b, _b_email, _b_pw) =
        common::seed_tenant_with_admin(&pool, "pms260-dash-b").await;
    let company_b = seed_company(&pool, tenant_b, "Tenant B Co").await;
    for n in 0..3 {
        seed_open_ticket(&pool, tenant_b, company_b, user_b, &format!("B-{n}")).await;
    }

    let reports = ReportsService::new(Database::from_pool(pool.clone()));
    let dash = reports
        .dashboard(TenantId::from_trusted(tenant_a), None, "UTC")
        .await
        .expect("dashboard");

    let open: i64 = dash.open_by_priority.iter().map(|b| b.count).sum();
    assert_eq!(
        open, 2,
        "open_by_priority counts only the caller's two tickets, not tenant B's three"
    );
    let trend: i64 = dash.ticket_trend_30d.iter().map(|d| d.count).sum();
    assert_eq!(
        trend, 2,
        "ticket_trend_30d counts only the caller's two tickets, not tenant B's three"
    );
}

/// PMS-360: the 30-day ticket trend buckets `created_at` by the active user's
/// timezone, not UTC. A ticket created at 03:00 UTC is still the previous
/// evening in America/Los_Angeles, so an LA viewer must see it on the prior
/// day while a UTC viewer sees it on the UTC day. Same instant, two day
/// buckets, exactly as the source-of-truth helper computes.
#[sqlx::test]
async fn dashboard_trend_buckets_in_user_timezone(pool: PgPool) {
    let (tenant, admin, _email, _pw) =
        common::seed_tenant_with_admin(&pool, "pms360-trend-tz").await;
    let company = seed_company(&pool, tenant, "TZ Co").await;

    // 03:00 UTC today: late yesterday evening in Los Angeles (UTC-7/-8).
    let created = chrono::Utc::now()
        .date_naive()
        .and_hms_opt(3, 0, 0)
        .unwrap()
        .and_utc();
    seed_open_ticket_at(&pool, tenant, company, admin, "TZ-1", created).await;

    let utc_day = mokosh_types::datetime::user_local_date(created, "UTC");
    let la_day = mokosh_types::datetime::user_local_date(created, "America/Los_Angeles");
    assert_ne!(
        utc_day, la_day,
        "03:00 UTC straddles the day boundary for Los Angeles"
    );

    let reports = ReportsService::new(Database::from_pool(pool.clone()));

    let utc_dash = reports
        .dashboard(TenantId::from_trusted(tenant), None, "UTC")
        .await
        .expect("utc dashboard");
    let utc_days: Vec<_> = utc_dash.ticket_trend_30d.iter().map(|d| d.date).collect();
    assert_eq!(
        utc_days,
        vec![utc_day],
        "UTC viewer buckets the ticket on the UTC day"
    );

    let la_dash = reports
        .dashboard(TenantId::from_trusted(tenant), None, "America/Los_Angeles")
        .await
        .expect("la dashboard");
    let la_days: Vec<_> = la_dash.ticket_trend_30d.iter().map(|d| d.date).collect();
    assert_eq!(
        la_days,
        vec![la_day],
        "Los Angeles viewer buckets the same ticket on the prior local day"
    );
}

/// Read a `Decimal`-ish JSON value (number or string) as f64.
fn dec(v: &serde_json::Value) -> f64 {
    v.as_f64()
        .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        .unwrap_or(f64::NAN)
}

// --- PMS-179 project + client report seed helpers ---------------------------

/// Seed a project. Numeric/date columns are inlined (not bound) so we don't
/// pull in a Decimal bind; `target_end_sql` is a raw SQL date expression
/// (e.g. `CURRENT_DATE - INTERVAL '1 day'` or `NULL`).
async fn seed_project(
    pool: &PgPool,
    tenant_id: Uuid,
    name: &str,
    status: &str,
    budget_hours: i64,
    budget_amount: i64,
    target_end_sql: &str,
) -> Uuid {
    let id = Uuid::new_v4();
    let q = format!(
        r#"INSERT INTO projects
           (id, tenant_id, name, status, budget_hours, budget_amount, target_end_date)
           VALUES ($1, $2, $3, $4, {budget_hours}, {budget_amount}, {target_end_sql})"#
    );
    sqlx::query(&q)
        .bind(id)
        .bind(tenant_id)
        .bind(name)
        .bind(status)
        .execute(pool)
        .await
        .expect("seed project");
    id
}

/// First seeded task status matching the wanted completion flag (the seed
/// migration provisions a "Done"-style completed status and several open
/// ones for the default tenant).
async fn task_status_id(pool: &PgPool, tenant_id: Uuid, completed: bool) -> Uuid {
    sqlx::query_scalar(
        "SELECT id FROM task_statuses WHERE tenant_id = $1 AND is_completed = $2 LIMIT 1",
    )
    .bind(tenant_id)
    .bind(completed)
    .fetch_one(pool)
    .await
    .expect("a seeded task status")
}

async fn seed_task(pool: &PgPool, tenant_id: Uuid, project_id: Uuid, status_id: Uuid, title: &str) {
    sqlx::query(
        "INSERT INTO tasks (id, tenant_id, project_id, title, status_id) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(Uuid::new_v4())
    .bind(tenant_id)
    .bind(project_id)
    .bind(title)
    .bind(status_id)
    .execute(pool)
    .await
    .expect("seed task");
}

/// Seed a project-linked time entry. `minutes` and `amount` are inlined to
/// avoid a Decimal bind; `work_type_id` is fetched from the seeded set.
async fn seed_project_time_entry(
    pool: &PgPool,
    tenant_id: Uuid,
    user_id: Uuid,
    company_id: Uuid,
    project_id: Uuid,
    minutes: i64,
    amount: i64,
) {
    let work_type_id: Uuid =
        sqlx::query_scalar("SELECT id FROM work_types WHERE tenant_id = $1 LIMIT 1")
            .bind(tenant_id)
            .fetch_one(pool)
            .await
            .expect("a seeded work type");
    let q = format!(
        r#"INSERT INTO time_entries
           (id, tenant_id, user_id, date, duration_minutes, work_type_id,
            company_id, project_id, total_amount)
           VALUES ($1, $2, $3, CURRENT_DATE, {minutes}, $4, $5, $6, {amount})"#
    );
    sqlx::query(&q)
        .bind(Uuid::new_v4())
        .bind(tenant_id)
        .bind(user_id)
        .bind(work_type_id)
        .bind(company_id)
        .bind(project_id)
        .execute(pool)
        .await
        .expect("seed project time entry");
}

async fn asset_type_id(pool: &PgPool, tenant_id: Uuid) -> Uuid {
    sqlx::query_scalar("SELECT id FROM asset_types WHERE tenant_id = $1 LIMIT 1")
        .bind(tenant_id)
        .fetch_one(pool)
        .await
        .expect("a seeded asset type")
}

/// Create an asset type for a tenant that has none (the seed migration only
/// provisions lookup rows for the default tenant).
async fn seed_asset_type(pool: &PgPool, tenant_id: Uuid, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO asset_types (id, tenant_id, name) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(tenant_id)
        .bind(name)
        .execute(pool)
        .await
        .expect("seed asset type");
    id
}

/// Seed an asset. `warranty_sql` is a raw SQL date expression
/// (e.g. `CURRENT_DATE + INTERVAL '30 days'` or `NULL`).
async fn seed_asset(
    pool: &PgPool,
    tenant_id: Uuid,
    company_id: Uuid,
    type_id: Uuid,
    name: &str,
    status: &str,
    warranty_sql: &str,
) {
    let q = format!(
        r#"INSERT INTO assets
           (id, tenant_id, name, asset_type_id, company_id, status, warranty_expiry)
           VALUES ($1, $2, $3, $4, $5, $6, {warranty_sql})"#
    );
    sqlx::query(&q)
        .bind(Uuid::new_v4())
        .bind(tenant_id)
        .bind(name)
        .bind(type_id)
        .bind(company_id)
        .bind(status)
        .execute(pool)
        .await
        .expect("seed asset");
}

/// Seed a contract. `end_sql` is a raw SQL date expression (or `NULL`).
async fn seed_contract(
    pool: &PgPool,
    tenant_id: Uuid,
    company_id: Uuid,
    name: &str,
    status: &str,
    end_sql: &str,
) {
    let q = format!(
        r#"INSERT INTO contracts
           (id, tenant_id, name, company_id, contract_type, status, start_date, end_date)
           VALUES ($1, $2, $3, $4, 'managed_services', $5, '2026-01-01', {end_sql})"#
    );
    sqlx::query(&q)
        .bind(Uuid::new_v4())
        .bind(tenant_id)
        .bind(name)
        .bind(company_id)
        .bind(status)
        .execute(pool)
        .await
        .expect("seed contract");
}

/// Set a company's status (seed_company defaults to 'active').
async fn set_company_status(pool: &PgPool, company_id: Uuid, status: &str) {
    sqlx::query("UPDATE companies SET status = $1 WHERE id = $2")
        .bind(status)
        .bind(company_id)
        .execute(pool)
        .await
        .expect("set company status");
}

// PMS-179: projects report reflects seeded delivery data; appears in the
// registry; CSV export works.
#[sqlx::test]
async fn projects_report_aggregates(pool: PgPool) {
    let tenant = common::DEFAULT_TENANT_ID;
    let (admin_id, email, pw) = common::seed_admin(&pool).await;
    let company = seed_company(&pool, tenant, "Acme Co").await;

    // One active, overdue project: budget 10h / $1000.
    let project = seed_project(
        &pool,
        tenant,
        "Migration",
        "active",
        10,
        1000,
        "CURRENT_DATE - INTERVAL '1 day'",
    )
    .await;
    // A second, on-track planning project so by_status has two buckets.
    seed_project(
        &pool,
        tenant,
        "Onboarding",
        "planning",
        5,
        500,
        "CURRENT_DATE + INTERVAL '30 days'",
    )
    .await;

    // Two tasks: one completed, one open.
    let done = task_status_id(&pool, tenant, true).await;
    let open = task_status_id(&pool, tenant, false).await;
    seed_task(&pool, tenant, project, done, "Cutover").await;
    seed_task(&pool, tenant, project, open, "Validation").await;

    // 90 minutes / $150 of project-linked time -> 1.5 actual hours.
    seed_project_time_entry(&pool, tenant, admin_id, company, project, 90, 150).await;

    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;

    // Registry advertises the projects report.
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
        .unwrap()
        .iter()
        .filter_map(|r| r["key"].as_str())
        .collect();
    assert!(keys.contains(&"projects"), "registry lists 'projects'");
    assert!(keys.contains(&"clients"), "registry lists 'clients'");

    let rep: serde_json::Value = app
        .client
        .get(app.url("/api/v1/reports/projects"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("projects report")
        .json()
        .await
        .expect("projects JSON");

    let by_status = rep["by_status"].as_array().unwrap();
    let count_for = |label: &str| -> i64 {
        by_status
            .iter()
            .find(|b| b["label"] == label)
            .and_then(|b| b["count"].as_i64())
            .unwrap_or(0)
    };
    assert_eq!(count_for("active"), 1, "one active project");
    assert_eq!(count_for("planning"), 1, "one planning project");
    // PMS-366: every canonical state is countable even at zero, so a tenant
    // with no Cancelled/On-Hold/Completed projects still renders those tiles.
    for state in ["planning", "active", "on_hold", "completed", "cancelled"] {
        assert!(
            by_status.iter().any(|b| b["label"] == state),
            "by_status always includes the '{state}' bucket"
        );
    }
    // Buckets sum to the total project rows (2 seeded here).
    let sum: i64 = by_status.iter().filter_map(|b| b["count"].as_i64()).sum();
    assert_eq!(sum, 2, "status buckets sum to total project rows");
    assert!(
        (dec(&rep["budget_hours"]) - 15.0).abs() < 0.01,
        "budget hours sum 10 + 5"
    );
    assert!(
        (dec(&rep["budget_amount"]) - 1500.0).abs() < 0.01,
        "budget amount sum 1000 + 500"
    );
    assert!(
        (dec(&rep["actual_hours"]) - 1.5).abs() < 0.01,
        "90 logged minutes -> 1.5 hours"
    );
    assert!(
        (dec(&rep["actual_amount"]) - 150.0).abs() < 0.01,
        "actual amount 150"
    );
    assert_eq!(rep["tasks_total"].as_i64().unwrap(), 2, "two tasks");
    assert_eq!(
        rep["tasks_completed"].as_i64().unwrap(),
        1,
        "one completed task"
    );
    assert_eq!(rep["overdue"].as_i64().unwrap(), 1, "one overdue project");

    // CSV export.
    let export = app
        .client
        .get(app.url("/api/v1/reports/projects/export?format=csv"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("csv export");
    assert!(export.status().is_success(), "projects csv export 2xx");
    assert!(
        !export.text().await.unwrap().trim().is_empty(),
        "projects csv has content"
    );
}

// PMS-179: clients report reflects seeded CMDB / contract data; CSV works.
#[sqlx::test]
async fn clients_report_aggregates(pool: PgPool) {
    let tenant = common::DEFAULT_TENANT_ID;
    let (_admin_id, email, pw) = common::seed_admin(&pool).await;

    let company_a = seed_company(&pool, tenant, "Active Co").await;
    let company_b = seed_company(&pool, tenant, "Inactive Co").await;
    set_company_status(&pool, company_b, "inactive").await;

    let at = asset_type_id(&pool, tenant).await;
    // One asset with a warranty expiring inside 90 days, one with none.
    seed_asset(
        &pool,
        tenant,
        company_a,
        at,
        "Server-1",
        "active",
        "CURRENT_DATE + INTERVAL '30 days'",
    )
    .await;
    seed_asset(&pool, tenant, company_a, at, "Laptop-1", "active", "NULL").await;

    // One contract renewing inside 90 days, one well beyond.
    seed_contract(
        &pool,
        tenant,
        company_a,
        "MSP Agreement",
        "active",
        "CURRENT_DATE + INTERVAL '30 days'",
    )
    .await;
    seed_contract(
        &pool,
        tenant,
        company_a,
        "Long Term",
        "active",
        "CURRENT_DATE + INTERVAL '300 days'",
    )
    .await;

    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;

    let rep: serde_json::Value = app
        .client
        .get(app.url("/api/v1/reports/clients"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("clients report")
        .json()
        .await
        .expect("clients JSON");

    assert_eq!(rep["companies_total"].as_i64().unwrap(), 2, "two companies");
    assert_eq!(
        rep["companies_active"].as_i64().unwrap(),
        1,
        "one active company"
    );
    assert_eq!(rep["assets_total"].as_i64().unwrap(), 2, "two assets");
    let by_type: i64 = rep["assets_by_type"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|b| b["count"].as_i64())
        .sum();
    assert_eq!(by_type, 2, "assets_by_type sums to all assets");
    // PMS-366: every canonical asset state is countable even at zero, and the
    // buckets still sum to the asset total.
    let assets_by_status = rep["assets_by_status"].as_array().unwrap();
    for state in ["active", "inactive", "retired", "in_repair", "in_stock"] {
        assert!(
            assets_by_status.iter().any(|b| b["label"] == state),
            "assets_by_status always includes the '{state}' bucket"
        );
    }
    let by_status_sum: i64 = assets_by_status
        .iter()
        .filter_map(|b| b["count"].as_i64())
        .sum();
    assert_eq!(by_status_sum, 2, "assets_by_status sums to all assets");
    assert_eq!(
        rep["warranty_expiring_90d"].as_i64().unwrap(),
        1,
        "one warranty expiring within 90 days"
    );
    assert_eq!(
        rep["contracts_active"].as_i64().unwrap(),
        2,
        "two active contracts"
    );
    assert_eq!(
        rep["contracts_renewing_90d"].as_i64().unwrap(),
        1,
        "one contract renewing within 90 days"
    );

    let export = app
        .client
        .get(app.url("/api/v1/reports/clients/export?format=csv"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("csv export");
    assert!(export.status().is_success(), "clients csv export 2xx");
    assert!(
        !export.text().await.unwrap().trim().is_empty(),
        "clients csv has content"
    );
}

// PMS-179 (AC5): the clients report is tenant-scoped - a second tenant's
// assets never leak into this tenant's counts.
#[sqlx::test]
async fn clients_report_is_tenant_scoped(pool: PgPool) {
    let tenant_a = common::DEFAULT_TENANT_ID;
    let (_admin_id, email, pw) = common::seed_admin(&pool).await;
    let company_a = seed_company(&pool, tenant_a, "Tenant A Co").await;
    let at_a = asset_type_id(&pool, tenant_a).await;
    seed_asset(&pool, tenant_a, company_a, at_a, "A-1", "active", "NULL").await;

    // Tenant B with three assets of its own.
    let (tenant_b, _b_uid, _b_email, _b_pw) =
        common::seed_tenant_with_admin(&pool, "tenant-b").await;
    let company_b = seed_company(&pool, tenant_b, "Tenant B Co").await;
    let at_b = seed_asset_type(&pool, tenant_b, "Workstation").await;
    for n in 0..3 {
        seed_asset(
            &pool,
            tenant_b,
            company_b,
            at_b,
            &format!("B-{n}"),
            "active",
            "NULL",
        )
        .await;
    }

    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;

    let rep: serde_json::Value = app
        .client
        .get(app.url("/api/v1/reports/clients"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("clients report")
        .json()
        .await
        .expect("clients JSON");
    assert_eq!(
        rep["assets_total"].as_i64().unwrap(),
        1,
        "tenant A sees only its own asset, not tenant B's three"
    );
}

// --- PMS-180 custom report builder ------------------------------------------

/// POST a custom-report spec and return the HTTP status code.
async fn custom_post_status(app: &common::TestApp, token: &str, body: serde_json::Value) -> u16 {
    app.client
        .post(app.url("/api/v1/reports/custom"))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .expect("custom post")
        .status()
        .as_u16()
}

// The builder runs a whitelisted aggregate, advertises its catalog, and
// exports CSV.
#[sqlx::test]
async fn custom_report_runs_and_exports(pool: PgPool) {
    let tenant = common::DEFAULT_TENANT_ID;
    let (_admin_id, email, pw) = common::seed_admin(&pool).await;
    let company = seed_company(&pool, tenant, "Acme Co").await;
    let at = asset_type_id(&pool, tenant).await;
    seed_asset(&pool, tenant, company, at, "Srv-1", "active", "NULL").await;
    seed_asset(&pool, tenant, company, at, "Srv-2", "active", "NULL").await;
    seed_asset(&pool, tenant, company, at, "Old-1", "retired", "NULL").await;

    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;

    // --- Schema advertises the assets source with status / count ---
    let schema: serde_json::Value = app
        .client
        .get(app.url("/api/v1/reports/custom/schema"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("schema")
        .json()
        .await
        .expect("schema JSON");
    let assets_src = schema
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["key"] == "assets")
        .expect("assets source in schema");
    assert!(
        assets_src["dimensions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["key"] == "status"),
        "assets source advertises a status dimension"
    );
    assert!(
        assets_src["measures"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m["key"] == "count"),
        "assets source advertises a count measure"
    );

    // --- Run: assets grouped by status, counted ---
    let res = app
        .client
        .post(app.url("/api/v1/reports/custom"))
        .bearer_auth(&token)
        .json(&json!({ "source": "assets", "dimensions": ["status"], "measures": ["count"] }))
        .send()
        .await
        .expect("custom run");
    assert!(res.status().is_success(), "custom run should 2xx");
    let body: serde_json::Value = res.json().await.expect("custom JSON");
    assert_eq!(body["columns"], json!(["Status", "Count"]));
    let rows = body["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 2, "two status groups (active, retired)");
    let active = rows
        .iter()
        .find(|r| r[0] == "active")
        .expect("an active row");
    assert_eq!(active[1], "2", "two active assets");
    assert_eq!(body["totals"]["Count"], "3", "totals sum across groups");

    // --- CSV export ---
    let csv = app
        .client
        .post(app.url("/api/v1/reports/custom"))
        .bearer_auth(&token)
        .json(&json!({ "source": "assets", "measures": ["count"], "format": "csv" }))
        .send()
        .await
        .expect("csv run");
    assert!(csv.status().is_success(), "csv run should 2xx");
    let ct = csv
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(ct.contains("text/csv"), "csv content type (got {ct})");
    assert!(
        !csv.text().await.unwrap().trim().is_empty(),
        "csv body has content"
    );
}

// Unknown / malicious source, dimension, measure, or an empty measure list
// are rejected with 400 before any SQL is built.
#[sqlx::test]
async fn custom_report_rejects_unknown_fields(pool: PgPool) {
    let (_admin_id, email, pw) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;

    assert_eq!(
        custom_post_status(
            &app,
            &token,
            json!({ "source": "bogus", "measures": ["count"] })
        )
        .await,
        400,
        "unknown source rejected"
    );
    // An injection-style dimension name is just an unknown key -> 400, never
    // interpolated into SQL.
    assert_eq!(
        custom_post_status(
            &app,
            &token,
            json!({ "source": "tickets", "dimensions": ["status; DROP TABLE tickets"], "measures": ["count"] })
        )
        .await,
        400,
        "unknown / malicious dimension rejected"
    );
    assert_eq!(
        custom_post_status(
            &app,
            &token,
            json!({ "source": "tickets", "measures": ["evil"] })
        )
        .await,
        400,
        "unknown measure rejected"
    );
    assert_eq!(
        custom_post_status(
            &app,
            &token,
            json!({ "source": "tickets", "dimensions": ["status"], "measures": [] })
        )
        .await,
        400,
        "a report with no measure is rejected"
    );
    // A fully valid request still succeeds.
    assert_eq!(
        custom_post_status(
            &app,
            &token,
            json!({ "source": "tickets", "measures": ["count"] })
        )
        .await,
        200,
        "a valid spec succeeds"
    );
}

// A custom report is tenant-scoped: a second tenant's assets never reach
// this tenant's counts.
#[sqlx::test]
async fn custom_report_is_tenant_scoped(pool: PgPool) {
    let tenant_a = common::DEFAULT_TENANT_ID;
    let (_admin_id, email, pw) = common::seed_admin(&pool).await;
    let company_a = seed_company(&pool, tenant_a, "Tenant A Co").await;
    let at_a = asset_type_id(&pool, tenant_a).await;
    seed_asset(&pool, tenant_a, company_a, at_a, "A-1", "active", "NULL").await;

    let (tenant_b, _b_uid, _b_email, _b_pw) =
        common::seed_tenant_with_admin(&pool, "tenant-b").await;
    let company_b = seed_company(&pool, tenant_b, "Tenant B Co").await;
    let at_b = seed_asset_type(&pool, tenant_b, "Workstation").await;
    for n in 0..3 {
        seed_asset(
            &pool,
            tenant_b,
            company_b,
            at_b,
            &format!("B-{n}"),
            "active",
            "NULL",
        )
        .await;
    }

    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;

    let body: serde_json::Value = app
        .client
        .post(app.url("/api/v1/reports/custom"))
        .bearer_auth(&token)
        .json(&json!({ "source": "assets", "measures": ["count"] }))
        .send()
        .await
        .expect("custom run")
        .json()
        .await
        .expect("custom JSON");
    assert_eq!(
        body["totals"]["Count"], "1",
        "tenant A counts only its own asset, not tenant B's three"
    );
}
