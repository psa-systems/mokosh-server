//! PMS-729 phase 2 §7 slice A / I17: the contact dashboard HTTP tests,
//! on the contact plane since PMS-1025 (ported in PMS-1031).
//!
//! `GET /contact/dashboard/summary` answers four counts (open tickets,
//! unpaid invoices, quotes awaiting decision, active contracts) and a
//! recent-activity feed, each gated on the caller's capabilities
//! (MAPPS-705). The retired portal's shape (open tickets bucketed by
//! priority, the next invoice due) is gone with it; what these tests
//! keep is the posture the SPA depends on: cross-company isolation, and
//! an empty company still rendering so the layout does not collapse
//! before the first ticket / invoice / quote lands.

mod common;

use rust_decimal::Decimal;
use sqlx::PgPool;
use uuid::Uuid;

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

/// A contact holding every read capability, so every tile counts.
async fn seed_reader(pool: &PgPool, company_id: Uuid, email: &str) -> common::PortalContact {
    common::seed_portal_contact(pool, company_id, email, &["Read-Only"]).await
}

async fn summary(app: &common::TestApp, token: &str) -> serde_json::Value {
    let resp = app
        .client
        .get(app.url("/api/v1/contact/dashboard/summary"))
        .bearer_auth(token)
        .send()
        .await
        .expect("send dashboard");
    let status = resp.status();
    let text = resp.text().await.expect("dashboard body");
    assert_eq!(status, reqwest::StatusCode::OK, "dashboard: {text}");
    serde_json::from_str(&text).expect("dashboard JSON")
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

/// Empty company: the summary renders (no 500), every count is zero and
/// the activity feed is empty.
#[sqlx::test]
async fn dashboard_renders_zeros_when_company_is_empty(pool: PgPool) {
    let (_admin_id, _email, _password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let company = seed_company(&pool, "Empty Co").await;
    let contact = seed_reader(&pool, company, "empty@example.com").await;
    let token = common::contact_token(&app, &contact).await;

    let body = summary(&app, &token).await;
    for tile in [
        "open_tickets",
        "unpaid_invoices",
        "active_quotes",
        "active_contracts",
    ] {
        assert_eq!(body[tile].as_i64(), Some(0), "{tile} on an empty company: {body}");
    }
    assert_eq!(body["recent_activity"].as_array().unwrap().len(), 0);
}

/// Populated company: only open tickets count, a void invoice is not
/// unpaid, an accepted quote is no longer awaiting a decision, and the
/// activity feed carries the rows.
#[sqlx::test]
async fn dashboard_aggregates_populated_data(pool: PgPool) {
    let (admin_id, _email, _password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let company = seed_company(&pool, "Populated Co").await;
    let contact = seed_reader(&pool, company, "populated@example.com").await;
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

    // Two unpaid invoices. A void invoice never surfaces.
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

    let token = common::contact_token(&app, &contact).await;
    let body = summary(&app, &token).await;

    assert_eq!(body["open_tickets"].as_i64(), Some(2), "{body}");
    assert_eq!(body["unpaid_invoices"].as_i64(), Some(2), "{body}");
    assert_eq!(body["active_quotes"].as_i64(), Some(1), "{body}");
    assert_eq!(body["active_contracts"].as_i64(), Some(0), "{body}");

    // Recent activity carries the tickets, the invoices and the quotes,
    // each row naming its kind.
    let activity = body["recent_activity"].as_array().unwrap();
    let kinds = |kind: &str| activity.iter().filter(|r| r["kind"] == kind).count();
    assert_eq!(kinds("ticket"), 3, "{body}");
    assert_eq!(kinds("invoice"), 3, "{body}");
    assert_eq!(kinds("quote"), 2, "{body}");
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
    let me = seed_reader(&pool, mine, "me@example.com").await;
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

    let token = common::contact_token(&app, &me).await;
    let body = summary(&app, &token).await;
    assert_eq!(body["open_tickets"].as_i64(), Some(0), "cross-company ticket leaked: {body}");
    assert_eq!(body["unpaid_invoices"].as_i64(), Some(0), "cross-company invoice leaked: {body}");
    assert_eq!(body["active_quotes"].as_i64(), Some(0), "cross-company quote leaked: {body}");
    assert!(
        body["recent_activity"].as_array().unwrap().is_empty(),
        "cross-company row in activity feed: {body}"
    );
}

/// Missing bearer token: the summary is auth-required (401), not an open
/// endpoint. Guards against a future middleware refactor that would
/// accidentally publish the shape.
#[sqlx::test]
async fn dashboard_requires_a_portal_session(pool: PgPool) {
    let _admin = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let resp = app
        .client
        .get(app.url("/api/v1/contact/dashboard/summary"))
        .send()
        .await
        .expect("send anonymous");
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}
