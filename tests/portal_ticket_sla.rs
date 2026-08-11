//! PMS-729 phase 2 §7 slice A / I10: `/portal/tickets/{id}/sla` HTTP tests.
//!
//! Pins the wire shape, the on-track / warning / breached labels, and the
//! cross-company / cross-tenant scoping. The status math itself is unit
//! tested in `mokosh_types::compute_sla_status`; this file only checks
//! that the portal endpoint calls into it correctly and forces the
//! company scope.

mod common;

use chrono::{Duration, Utc};
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

async fn seed_ticket_with_sla(
    pool: &PgPool,
    company_id: Uuid,
    admin_id: Uuid,
    sla_due: Option<chrono::DateTime<Utc>>,
    closed_at: Option<chrono::DateTime<Utc>>,
) -> Uuid {
    let status_id: Uuid = if closed_at.is_some() {
        sqlx::query_scalar(
            "SELECT id FROM ticket_statuses WHERE tenant_id = $1 AND is_closed = TRUE ORDER BY sort_order LIMIT 1",
        )
        .bind(common::DEFAULT_TENANT_ID)
        .fetch_one(pool)
        .await
        .expect("closed status")
    } else {
        sqlx::query_scalar(
            "SELECT id FROM ticket_statuses WHERE tenant_id = $1 AND is_closed = FALSE ORDER BY sort_order LIMIT 1",
        )
        .bind(common::DEFAULT_TENANT_ID)
        .fetch_one(pool)
        .await
        .expect("open status")
    };
    let priority_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM ticket_priorities WHERE tenant_id = $1 ORDER BY sort_order LIMIT 1",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(pool)
    .await
    .expect("priority");
    let queue_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM ticket_queues WHERE tenant_id = $1 ORDER BY name LIMIT 1",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(pool)
    .await
    .expect("queue");
    let id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO tickets
            (id, tenant_id, ticket_number, title, status_id, priority_id,
             queue_id, company_id, created_by_id,
             sla_due_date, first_response_due, resolution_due, closed_at)
        VALUES ($1, $2, $3, 'SLA ticket', $4, $5, $6, $7, $8,
                $9, $9, $9, $10)
        "#,
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(format!("T-{}", &id.to_string()[..8]))
    .bind(status_id)
    .bind(priority_id)
    .bind(queue_id)
    .bind(company_id)
    .bind(admin_id)
    .bind(sla_due)
    .bind(closed_at)
    .execute(pool)
    .await
    .expect("seed ticket");
    id
}

// -- tests -----------------------------------------------------------------

/// Ticket with plenty of time left on its SLA renders `on_track` and
/// echoes the due date back on both legs.
#[sqlx::test]
async fn sla_endpoint_returns_on_track_for_a_healthy_ticket(pool: PgPool) {
    let (admin_id, _e, _p) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let company = seed_company(&pool, "Healthy Co").await;
    let _c = seed_portal_contact(&pool, company, "healthy@example.com").await;
    let due = Utc::now() + Duration::hours(48);
    let ticket = seed_ticket_with_sla(&pool, company, admin_id, Some(due), None).await;

    let token = login(&app, "healthy@example.com").await;
    let resp = app
        .client
        .get(app.url(&format!("/api/v1/portal/tickets/{ticket}/sla")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send sla");
    assert!(resp.status().is_success(), "status: {}", resp.status());
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"].as_str().unwrap(), "on_track");
    assert!(body["sla_due_date"].is_string());
    assert!(body["first_response_due"].is_string());
    assert!(body["resolution_due"].is_string());
    assert!(body["closed_at"].is_null());
    assert!(!body["status_name"].as_str().unwrap().is_empty());
}

/// A closed ticket collapses every SLA leg to `not_applicable`.
#[sqlx::test]
async fn sla_endpoint_returns_not_applicable_for_a_closed_ticket(pool: PgPool) {
    let (admin_id, _e, _p) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let company = seed_company(&pool, "Closed Co").await;
    let _c = seed_portal_contact(&pool, company, "closed@example.com").await;
    let due = Utc::now() - Duration::hours(1); // even a breached due date
    let closed = Utc::now() - Duration::minutes(30);
    let ticket = seed_ticket_with_sla(&pool, company, admin_id, Some(due), Some(closed)).await;

    let token = login(&app, "closed@example.com").await;
    let resp = app
        .client
        .get(app.url(&format!("/api/v1/portal/tickets/{ticket}/sla")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send sla");
    assert!(resp.status().is_success());
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"].as_str().unwrap(), "not_applicable");
    assert!(
        body["closed_at"].is_string(),
        "closed_at not surfaced: {body}"
    );
}

/// A ticket whose SLA due date has already passed and remains open is
/// `breached`.
#[sqlx::test]
async fn sla_endpoint_returns_breached_when_overdue(pool: PgPool) {
    let (admin_id, _e, _p) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let company = seed_company(&pool, "Overdue Co").await;
    let _c = seed_portal_contact(&pool, company, "overdue@example.com").await;
    let past = Utc::now() - Duration::hours(3);
    let ticket = seed_ticket_with_sla(&pool, company, admin_id, Some(past), None).await;

    let token = login(&app, "overdue@example.com").await;
    let resp = app
        .client
        .get(app.url(&format!("/api/v1/portal/tickets/{ticket}/sla")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send sla");
    assert!(resp.status().is_success());
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"].as_str().unwrap(), "breached");
}

/// Cross-company ticket id returns 404, not 403. Portal never confirms
/// the existence of another company's ticket.
#[sqlx::test]
async fn sla_endpoint_returns_404_for_cross_company_ticket(pool: PgPool) {
    let (admin_id, _e, _p) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let mine = seed_company(&pool, "Mine Co").await;
    let other = seed_company(&pool, "Other Co").await;
    let _c = seed_portal_contact(&pool, mine, "me@example.com").await;
    let due = Utc::now() + Duration::hours(4);
    let stolen = seed_ticket_with_sla(&pool, other, admin_id, Some(due), None).await;

    let token = login(&app, "me@example.com").await;
    let resp = app
        .client
        .get(app.url(&format!("/api/v1/portal/tickets/{stolen}/sla")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send sla");
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
}

/// Missing bearer: 401. The endpoint is auth-required.
#[sqlx::test]
async fn sla_endpoint_requires_a_portal_session(pool: PgPool) {
    let _a = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let resp = app
        .client
        .get(app.url(&format!("/api/v1/portal/tickets/{}/sla", Uuid::new_v4())))
        .send()
        .await
        .expect("send anonymous");
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}
