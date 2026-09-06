//! PMS-1087: `GET /tickets/{id}/sla` on the contact plane. A contact
//! holding `tickets:read` sees the SLA targets and state of its own
//! Company's ticket; a foreign ticket is a 404 like an unknown id; the
//! state is `compute_sla_status` over the same clock the list badge
//! uses. The status math is unit tested in `mokosh_types`; this suite
//! pins the wire shape, the scoping and the gate.

mod common;

use chrono::{DateTime, Duration, Utc};
use reqwest::StatusCode;
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

async fn seed_ticket_with_sla(
    pool: &PgPool,
    company_id: Uuid,
    admin_id: Uuid,
    sla_due: Option<DateTime<Utc>>,
    closed_at: Option<DateTime<Utc>>,
) -> Uuid {
    let status_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM ticket_statuses WHERE tenant_id = $1 AND is_closed = $2 \
         ORDER BY sort_order LIMIT 1",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(closed_at.is_some())
    .fetch_one(pool)
    .await
    .expect("status");
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
        "INSERT INTO tickets \
            (id, tenant_id, ticket_number, title, status_id, priority_id, \
             queue_id, company_id, created_by_id, \
             sla_due_date, first_response_due, resolution_due, closed_at) \
         VALUES ($1, $2, $3, 'SLA ticket', $4, $5, $6, $7, $8, $9, $9, $9, $10)",
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

async fn sla(app: &common::TestApp, token: &str, ticket: Uuid) -> (StatusCode, Value) {
    let resp = app
        .client
        .get(app.url(&format!("/api/v1/tickets/{ticket}/sla")))
        .bearer_auth(token)
        .send()
        .await
        .expect("sla");
    let status = resp.status();
    let body = resp.json().await.unwrap_or(Value::Null);
    (status, body)
}

// A healthy ticket is on_track with both legs' targets echoed; a
// closed one collapses to not_applicable; an overdue open one is
// breached. Staff read the same shape.
#[sqlx::test]
async fn a_contact_sees_the_state_of_its_own_ticket(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company = seed_company(&pool, "Healthy Co").await;
    let me = common::seed_portal_contact(&pool, company, "me@example.com", &["Read-Only"]).await;
    let healthy = seed_ticket_with_sla(
        &pool,
        company,
        admin_id,
        Some(Utc::now() + Duration::hours(48)),
        None,
    )
    .await;
    let closed = seed_ticket_with_sla(
        &pool,
        company,
        admin_id,
        Some(Utc::now() - Duration::hours(1)),
        Some(Utc::now() - Duration::minutes(30)),
    )
    .await;
    let overdue = seed_ticket_with_sla(
        &pool,
        company,
        admin_id,
        Some(Utc::now() - Duration::hours(3)),
        None,
    )
    .await;
    let none = seed_ticket_with_sla(&pool, company, admin_id, None, None).await;
    let app = common::boot(pool.clone()).await;
    let token = common::contact_token(&app, &me).await;

    let (status, body) = sla(&app, &token, healthy).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "on_track");
    assert!(body["sla_due_date"].is_string());
    assert!(body["first_response_due"].is_string());
    assert!(body["resolution_due"].is_string());
    assert!(body["first_response_at"].is_null());
    assert!(body["closed_at"].is_null());
    assert!(!body["status_name"].as_str().unwrap().is_empty());
    // Nothing internal rides along.
    for hidden in [
        "sla_id",
        "sla_policy_id",
        "policy",
        "escalation",
        "business_hours",
    ] {
        assert!(body.get(hidden).is_none(), "{hidden} leaked: {body}");
    }

    let (_, body) = sla(&app, &token, closed).await;
    assert_eq!(body["status"], "not_applicable");
    assert!(body["closed_at"].is_string());

    let (_, body) = sla(&app, &token, overdue).await;
    assert_eq!(body["status"], "breached");

    let (_, body) = sla(&app, &token, none).await;
    assert_eq!(body["status"], "not_applicable");
    assert!(body["sla_due_date"].is_null());

    // Staff: the same shape for any ticket of the tenant.
    let staff = common::login(&app, &email, &password).await;
    let (status, body) = sla(&app, &staff, overdue).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "breached");
}

// Another Company's ticket and an unknown id are the same 404; a
// contact without tickets:read is 403; anonymous is 401.
#[sqlx::test]
async fn a_foreign_ticket_is_404_and_the_gate_holds(pool: PgPool) {
    let (admin_id, _, _) = common::seed_admin(&pool).await;
    let mine = seed_company(&pool, "Mine Co").await;
    let other = seed_company(&pool, "Other Co").await;
    let me = common::seed_portal_contact(&pool, mine, "me@example.com", &["Support Contact"]).await;
    let bare = common::seed_portal_contact(&pool, mine, "bare@example.com", &[]).await;
    let own = seed_ticket_with_sla(
        &pool,
        mine,
        admin_id,
        Some(Utc::now() + Duration::hours(4)),
        None,
    )
    .await;
    let stolen = seed_ticket_with_sla(
        &pool,
        other,
        admin_id,
        Some(Utc::now() + Duration::hours(4)),
        None,
    )
    .await;
    let app = common::boot(pool.clone()).await;
    let token = common::contact_token(&app, &me).await;

    let (status, unknown_body) = sla(&app, &token, Uuid::new_v4()).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, foreign_body) = sla(&app, &token, stolen).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(
        foreign_body, unknown_body,
        "a foreign ticket must be indistinguishable from an unknown id"
    );
    let (status, _) = sla(&app, &token, own).await;
    assert_eq!(status, StatusCode::OK);

    let bare_token = common::contact_token(&app, &bare).await;
    let (status, _) = sla(&app, &bare_token, own).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let anon = app
        .client
        .get(app.url(&format!("/api/v1/tickets/{own}/sla")))
        .send()
        .await
        .unwrap();
    assert_eq!(anon.status(), StatusCode::UNAUTHORIZED);
}
