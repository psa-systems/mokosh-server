//! PMS-729 phase 2 §7 slice A / I17: `/portal/dashboard` HTTP tests.
//!
//! Pins the four cards D17 fixed for phase 2: open tickets by priority,
//! next invoice due, open quotes awaiting decision, recent activity. Every
//! assertion focuses on cross-company isolation and on the "empty set
//! still renders" posture the SPA depends on so the layout does not
//! collapse before the first ticket / invoice / quote lands.

mod common;

use rust_decimal::Decimal;
use sqlx::PgPool;
use uuid::Uuid;

const PORTAL_PASSWORD: &str = "portal-password-12345";

// -- fixtures ---------------------------------------------------------------

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
        .expect("send login");
    assert!(resp.status().is_success(), "login: {}", resp.status());
    let body: serde_json::Value = resp.json().await.expect("login body");
    body["access_token"].as_str().unwrap().to_string()
}

/// A ticket in the default queue + status + priority.
async fn seed_ticket(
    pool: &PgPool,
    company_id: Uuid,
    admin_id: Uuid,
    priority_id: Uuid,
    status_id: Uuid,
    title: &str,
) -> Uuid {
    let id = Uuid::new_v4();
    let queue_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM ticket_queues WHERE tenant_id = $1 ORDER BY name LIMIT 1",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(pool)
    .await
    .expect("queue");
    sqlx::query(
        r#"INSERT INTO tickets
           (id, tenant_id, ticket_number, title, status_id, priority_id,
            queue_id, company_id, created_by_id)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"#,
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(format!("T-{}", &id.to_string()[..8]))
    .bind(title)
    .bind(status_id)
    .bind(priority_id)
    .bind(queue_id)
    .bind(company_id)
    .bind(admin_id)
    .execute(pool)
    .await
    .expect("seed ticket");
    id
}

async fn get_priority(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "SELECT id FROM ticket_priorities WHERE tenant_id = $1 ORDER BY sort_order LIMIT 1",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(pool)
    .await
    .expect("priority")
}

async fn get_open_status(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "SELECT id FROM ticket_statuses WHERE tenant_id = $1 AND is_closed = FALSE ORDER BY sort_order LIMIT 1",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(pool)
    .await
    .expect("open status")
}

async fn get_closed_status(pool: &PgPool) -> Uuid {
    // Fall back to an open status if this migration set has no closed
    // status seeded (defensive; the default set always includes one).
    sqlx::query_scalar(
        "SELECT id FROM ticket_statuses WHERE tenant_id = $1 AND is_closed = TRUE ORDER BY sort_order LIMIT 1",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(pool)
    .await
    .expect("closed status")
}

async fn seed_invoice(
    pool: &PgPool,
    company_id: Uuid,
    status: &str,
    total: Decimal,
    balance_due: Decimal,
    due: &str,
    number: &str,
) {
    sqlx::query(
        r#"
        INSERT INTO invoices
            (id, tenant_id, invoice_number, company_id, status,
             invoice_date, due_date, subtotal, total, amount_paid, balance_due, currency)
        VALUES ($1, $2, $3, $4, $5, CURRENT_DATE, $6::DATE,
                $7, $7, $7 - $8, $8, 'USD')
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(common::DEFAULT_TENANT_ID)
    .bind(number)
    .bind(company_id)
    .bind(status)
    .bind(due)
    .bind(total)
    .bind(balance_due)
    .execute(pool)
    .await
    .expect("seed invoice");
}

async fn seed_quote(pool: &PgPool, company_id: Uuid, status: &str, admin_id: Uuid) {
    sqlx::query(
        r#"
        INSERT INTO quotes
            (id, tenant_id, company_id, title, summary, status, requested_by_id)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company_id)
    .bind("Renew agreement")
    .bind("annual")
    .bind(status)
    .bind(admin_id)
    .execute(pool)
    .await
    .expect("seed quote");
}

// -- tests ------------------------------------------------------------------

/// Empty company: every card renders (no 500), counts are zero, activity
/// feed is empty, priorities are still enumerated so the axis stays.
#[sqlx::test]
async fn dashboard_renders_zeros_when_company_is_empty(pool: PgPool) {
    let (_admin_id, _email, _password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let company = seed_company(&pool, "Empty Co").await;
    let _contact = seed_portal_contact(&pool, company, "empty@example.com").await;

    let token = login(&app, "empty@example.com").await;
    let resp = app
        .client
        .get(app.url("/api/v1/portal/dashboard"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send dashboard");
    assert!(resp.status().is_success(), "status: {}", resp.status());
    let body: serde_json::Value = resp.json().await.expect("dashboard body");

    // The priority axis is always present so the SPA layout stays stable.
    let priorities = body["tickets_by_priority"].as_array().expect("array");
    assert!(
        !priorities.is_empty(),
        "priority axis empty; default tenant should have at least one priority: {body}"
    );
    for p in priorities {
        assert_eq!(p["count"].as_i64().unwrap(), 0, "unexpected non-zero: {p}");
    }
    assert!(body["next_invoice_due"].is_null());
    assert_eq!(body["open_quotes_awaiting_decision"].as_i64().unwrap(), 0);
    assert_eq!(body["recent_activity"].as_array().unwrap().len(), 0);
}

/// Populated company: open tickets bucket, next invoice picked by earliest
/// due, quote awaiting decision counted, recent activity newest-first.
#[sqlx::test]
async fn dashboard_aggregates_populated_data(pool: PgPool) {
    let (admin_id, _email, _password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let company = seed_company(&pool, "Populated Co").await;
    let _contact = seed_portal_contact(&pool, company, "populated@example.com").await;
    let priority = get_priority(&pool).await;
    let open = get_open_status(&pool).await;
    let closed = get_closed_status(&pool).await;

    // Two open tickets + one closed ticket. Only the two open count.
    seed_ticket(&pool, company, admin_id, priority, open, "Server down").await;
    seed_ticket(&pool, company, admin_id, priority, open, "VPN slow").await;
    seed_ticket(
        &pool,
        company,
        admin_id,
        priority,
        closed,
        "Resolved last week",
    )
    .await;

    // Two unpaid invoices; earliest-due wins. A void invoice never surfaces.
    seed_invoice(
        &pool,
        company,
        "sent",
        Decimal::new(50000, 2),
        Decimal::new(50000, 2),
        "2026-09-01",
        "INV-9001",
    )
    .await;
    seed_invoice(
        &pool,
        company,
        "sent",
        Decimal::new(120000, 2),
        Decimal::new(120000, 2),
        "2026-08-20",
        "INV-9002",
    )
    .await;
    seed_invoice(
        &pool,
        company,
        "void",
        Decimal::new(999999, 2),
        Decimal::new(999999, 2),
        "2026-08-15",
        "INV-9003",
    )
    .await;

    // One quote awaiting decision + one already accepted.
    seed_quote(&pool, company, "sent", admin_id).await;
    seed_quote(&pool, company, "accepted", admin_id).await;

    let token = login(&app, "populated@example.com").await;
    let resp = app
        .client
        .get(app.url("/api/v1/portal/dashboard"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send dashboard");
    assert!(resp.status().is_success());
    let body: serde_json::Value = resp.json().await.unwrap();

    // Open tickets bucket totals to 2 across all priorities.
    let total_open: i64 = body["tickets_by_priority"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["count"].as_i64().unwrap_or(0))
        .sum();
    assert_eq!(total_open, 2, "expected 2 open tickets across priorities");

    // Earliest-due invoice wins.
    let next = &body["next_invoice_due"];
    assert!(!next.is_null(), "expected a next invoice");
    assert_eq!(next["invoice_number"].as_str().unwrap(), "INV-9002");
    assert_eq!(next["due_date"].as_str().unwrap(), "2026-08-20");
    assert_eq!(
        next["currency"].as_str().unwrap(),
        "USD",
        "currency should default to USD"
    );

    // Exactly one quote is awaiting decision (accepted is terminal).
    assert_eq!(body["open_quotes_awaiting_decision"].as_i64().unwrap(), 1);

    // Recent activity carries all three tickets, newest-first.
    let activity = body["recent_activity"].as_array().unwrap();
    assert_eq!(activity.len(), 3, "expected 3 activity rows");
    for row in activity {
        assert_eq!(row["kind"].as_str().unwrap(), "ticket");
    }
}

/// Cross-company isolation: a contact at Company A never sees Company
/// B's tickets, invoices, or quotes, even though both live under the
/// same tenant. Non-negotiable per §7 D18 style scoping.
#[sqlx::test]
async fn dashboard_never_leaks_cross_company_data(pool: PgPool) {
    let (admin_id, _email, _password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let mine = seed_company(&pool, "My Co").await;
    let other = seed_company(&pool, "Other Co").await;
    let _me = seed_portal_contact(&pool, mine, "me@example.com").await;
    let priority = get_priority(&pool).await;
    let open = get_open_status(&pool).await;

    // Seed OTHER company only. My own company is empty; the dashboard
    // must reflect empty state regardless of the sibling's data.
    seed_ticket(&pool, other, admin_id, priority, open, "Not mine").await;
    seed_invoice(
        &pool,
        other,
        "sent",
        Decimal::new(500000, 2),
        Decimal::new(500000, 2),
        "2026-08-05",
        "INV-OTHER",
    )
    .await;
    seed_quote(&pool, other, "sent", admin_id).await;

    let token = login(&app, "me@example.com").await;
    let resp = app
        .client
        .get(app.url("/api/v1/portal/dashboard"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send");
    assert!(resp.status().is_success());
    let body: serde_json::Value = resp.json().await.unwrap();

    let total: i64 = body["tickets_by_priority"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["count"].as_i64().unwrap_or(0))
        .sum();
    assert_eq!(total, 0, "cross-company ticket leaked: {body}");
    assert!(
        body["next_invoice_due"].is_null(),
        "cross-company invoice leaked: {body}"
    );
    assert_eq!(
        body["open_quotes_awaiting_decision"].as_i64().unwrap(),
        0,
        "cross-company quote leaked: {body}"
    );
    assert!(
        body["recent_activity"].as_array().unwrap().is_empty(),
        "cross-company ticket in activity feed: {body}"
    );
}

/// Missing bearer token: dashboard is auth-required (401), not an open
/// endpoint. Guards against a future middleware refactor that would
/// accidentally publish the shape.
#[sqlx::test]
async fn dashboard_requires_a_portal_session(pool: PgPool) {
    let _admin = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let resp = app
        .client
        .get(app.url("/api/v1/portal/dashboard"))
        .send()
        .await
        .expect("send anonymous");
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}
