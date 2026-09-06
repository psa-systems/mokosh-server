//! PMS-1083: a contact's notifications inbox on the contact plane.
//!
//! Two halves. The dispatcher writes an `in_app` row against
//! `notifications.contact_id` for a `recipient_contact_id` in the
//! context or a `contacts` entry on the rule, honouring the contact's
//! preferences (the write MAPPS-656 recorded as dropped). And the same
//! `GET /notifications` and `POST /notifications/{id}/read` the staff
//! SPA calls serve a contact holding `notifications:read` its own rows
//! only: a sibling's and a staff user's never appear, and a foreign id
//! on mark-read is a 404.

mod common;

use std::sync::Arc;

use mokosh_server::modules::notifications::{DispatcherWorker, NotificationsService};
use mokosh_server::utils::email::LogMailer;
use mokosh_server::Database;
use reqwest::StatusCode;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

const EVENT: &str = "test.contact_ping";

/// `(contact_id, user_id, body, entity_type, entity_id)` off a row.
type WrittenRow = (
    Option<Uuid>,
    Option<Uuid>,
    String,
    Option<String>,
    Option<Uuid>,
);

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

/// An `in_app` template and a rule on [`EVENT`] with the given
/// rule-level contact recipients.
async fn seed_in_app_rule(pool: &PgPool, rule_contacts: &[Uuid]) {
    let template_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO notification_templates \
         (id, tenant_id, name, event_type, channel_type, subject, body_text, is_active) \
         VALUES ($1, $2, 'Contact In-App', $3, 'in_app', 'Hello', 'Body {{note}}', TRUE)",
    )
    .bind(template_id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(EVENT)
    .execute(pool)
    .await
    .expect("seed template");
    let recipients = serde_json::json!({
        "user_ids": [],
        "emails": [],
        "contacts": rule_contacts.iter().map(|c| c.to_string()).collect::<Vec<_>>(),
    });
    sqlx::query(
        "INSERT INTO notification_rules \
         (id, tenant_id, name, event_type, channels, recipients, template_id, is_active) \
         VALUES ($1, $2, 'Contact In-App Rule', $3, ARRAY['in_app']::VARCHAR(20)[], $4, $5, TRUE)",
    )
    .bind(Uuid::new_v4())
    .bind(common::DEFAULT_TENANT_ID)
    .bind(EVENT)
    .bind(recipients)
    .bind(template_id)
    .execute(pool)
    .await
    .expect("seed rule");
}

fn service(pool: &PgPool) -> NotificationsService {
    NotificationsService::with_encryption_key(Database::from_pool(pool.clone()), [0u8; 32])
}

async fn dispatch(pool: &PgPool, ctx: Value) -> u64 {
    service(pool)
        .dispatch(
            mokosh_server::modules::auth::TenantId::from_trusted(common::DEFAULT_TENANT_ID),
            EVENT,
            &ctx,
        )
        .await
        .expect("dispatch")
}

async fn seed_inbox_row(pool: &PgPool, owner: (&str, Uuid), subject: &str, read: bool) -> Uuid {
    let (column, id) = owner;
    let sql = format!(
        "INSERT INTO notifications \
         (tenant_id, {column}, channel_type, subject, body, status, read_at) \
         VALUES ($1, $2, 'in_app', $3, 'body', 'sent', CASE WHEN $4 THEN NOW() ELSE NULL END) \
         RETURNING id"
    );
    sqlx::query_scalar(&sql)
        .bind(common::DEFAULT_TENANT_ID)
        .bind(id)
        .bind(subject)
        .bind(read)
        .fetch_one(pool)
        .await
        .expect("seed notification")
}

async fn inbox(app: &common::TestApp, token: &str) -> Value {
    let resp = app
        .client
        .get(app.url("/api/v1/notifications?per_page=50"))
        .bearer_auth(token)
        .send()
        .await
        .expect("list");
    let status = resp.status();
    let text = resp.text().await.unwrap();
    assert_eq!(status, StatusCode::OK, "{text}");
    serde_json::from_str(&text).unwrap()
}

fn subjects(body: &Value) -> Vec<String> {
    let mut v: Vec<String> = body["data"]
        .as_array()
        .expect("data")
        .iter()
        .map(|r| r["subject"].as_str().unwrap_or("").to_string())
        .collect();
    v.sort();
    v
}

async fn mark_read(app: &common::TestApp, token: &str, id: Uuid) -> StatusCode {
    app.client
        .post(app.url(&format!("/api/v1/notifications/{id}/read")))
        .bearer_auth(token)
        .send()
        .await
        .expect("mark read")
        .status()
}

// The dispatcher writes the contact's in_app row: once for a contact
// named both in the context and on the rule, none for one who opted
// out, and the entity ref from the context lands on the row.
#[sqlx::test]
async fn a_dispatch_writes_the_contacts_inbox_row(pool: PgPool) {
    let _ = common::seed_admin(&pool).await;
    let company = seed_company(&pool, "Dispatch Co").await;
    let me =
        common::seed_portal_contact(&pool, company, "me@example.com", &["Support Contact"]).await;
    let on_rule =
        common::seed_portal_contact(&pool, company, "rule@example.com", &["Read-Only"]).await;
    let opted_out =
        common::seed_portal_contact(&pool, company, "out@example.com", &["Read-Only"]).await;
    seed_in_app_rule(&pool, &[me.id, on_rule.id, opted_out.id]).await;
    sqlx::query(
        "INSERT INTO contact_notification_preferences \
         (tenant_id, contact_id, event_type, is_enabled, channel_types) \
         VALUES ($1, $2, $3, FALSE, ARRAY[]::VARCHAR(20)[])",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(opted_out.id)
    .bind(EVENT)
    .execute(&pool)
    .await
    .unwrap();
    let ticket_id = Uuid::new_v4();

    // `me` is on the rule AND in the context: one row, not two.
    let fanout = dispatch(
        &pool,
        serde_json::json!({
            "recipient_contact_id": me.id.to_string(),
            "note": "welcome",
            "entity_type": "ticket",
            "entity_id": ticket_id.to_string(),
        }),
    )
    .await;
    assert_eq!(
        fanout, 2,
        "me and the rule contact; the opted-out one is skipped"
    );

    let rows: Vec<WrittenRow> = sqlx::query_as(
        "SELECT contact_id, user_id, body, entity_type, entity_id FROM notifications \
             WHERE tenant_id = $1 AND channel_type = 'in_app' ORDER BY created_at",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(rows.len(), 2, "{rows:?}");
    let mut who: Vec<Uuid> = rows.iter().map(|r| r.0.unwrap()).collect();
    who.sort();
    let mut expected = vec![me.id, on_rule.id];
    expected.sort();
    assert_eq!(who, expected);
    for row in &rows {
        assert!(row.1.is_none(), "a contact row carries no user_id");
        assert_eq!(row.2, "Body welcome");
        assert_eq!(row.3.as_deref(), Some("ticket"));
        assert_eq!(row.4, Some(ticket_id));
    }

    // The inbox shows it, with the deep link.
    let app = common::boot(pool.clone()).await;
    let token = common::contact_token(&app, &me).await;
    let body = inbox(&app, &token).await;
    assert_eq!(subjects(&body), vec!["Hello"]);
    assert_eq!(body["data"][0]["entity_type"], "ticket");
    assert_eq!(body["data"][0]["entity_id"], ticket_id.to_string());
    assert!(body["data"][0]["read_at"].is_null());
}

// The list is the caller's rows only, and mark-read is idempotent on
// its own row and a 404 on anyone else's.
#[sqlx::test]
async fn the_inbox_is_the_callers_rows_only(pool: PgPool) {
    let (staff_id, staff_email, staff_password) = common::seed_admin(&pool).await;
    let company = seed_company(&pool, "Inbox Co").await;
    let me =
        common::seed_portal_contact(&pool, company, "me@example.com", &["Support Contact"]).await;
    let sibling =
        common::seed_portal_contact(&pool, company, "sib@example.com", &["Support Contact"]).await;
    let mine = seed_inbox_row(&pool, ("contact_id", me.id), "Ticket updated", false).await;
    let _mine_read = seed_inbox_row(&pool, ("contact_id", me.id), "Invoice reminder", true).await;
    let theirs = seed_inbox_row(&pool, ("contact_id", sibling.id), "Not mine", false).await;
    let staffs = seed_inbox_row(&pool, ("user_id", staff_id), "Staff only", false).await;

    let app = common::boot(pool.clone()).await;
    let token = common::contact_token(&app, &me).await;
    let body = inbox(&app, &token).await;
    assert_eq!(subjects(&body), vec!["Invoice reminder", "Ticket updated"]);
    assert_eq!(body["meta"]["total"].as_u64(), Some(2));

    // Staff keep their own inbox, which has none of the contact rows.
    let staff = common::login(&app, &staff_email, &staff_password).await;
    let staff_body = inbox(&app, &staff).await;
    assert_eq!(subjects(&staff_body), vec!["Staff only"]);

    // Mark-read: own row 200 twice, a sibling's and a staff row 404.
    assert_eq!(mark_read(&app, &token, mine).await, StatusCode::OK);
    assert_eq!(mark_read(&app, &token, mine).await, StatusCode::OK);
    assert_eq!(mark_read(&app, &token, theirs).await, StatusCode::NOT_FOUND);
    assert_eq!(mark_read(&app, &token, staffs).await, StatusCode::NOT_FOUND);
    assert_eq!(
        mark_read(&app, &token, Uuid::new_v4()).await,
        StatusCode::NOT_FOUND
    );
    let after = inbox(&app, &token).await;
    assert!(after["data"]
        .as_array()
        .unwrap()
        .iter()
        .all(|r| !r["read_at"].is_null()));
    // The sibling's row is untouched.
    let sibling_read: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT read_at FROM notifications WHERE id = $1")
            .bind(theirs)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(sibling_read.is_none());
    // And staff cannot mark a contact's row either.
    assert_eq!(mark_read(&app, &staff, mine).await, StatusCode::NOT_FOUND);
}

// Without `notifications:read` both routes are 403; anonymous is 401.
#[sqlx::test]
async fn without_notifications_read_the_routes_are_403(pool: PgPool) {
    let _ = common::seed_admin(&pool).await;
    let company = seed_company(&pool, "Cap Co").await;
    let bare = common::seed_portal_contact(&pool, company, "bare@example.com", &[]).await;
    let row = seed_inbox_row(&pool, ("contact_id", bare.id), "Unreachable", false).await;
    let app = common::boot(pool.clone()).await;
    let token = common::contact_token(&app, &bare).await;

    let list = app
        .client
        .get(app.url("/api/v1/notifications"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(list.status(), StatusCode::FORBIDDEN);
    assert_eq!(mark_read(&app, &token, row).await, StatusCode::FORBIDDEN);

    let anon = app
        .client
        .get(app.url("/api/v1/notifications"))
        .send()
        .await
        .unwrap();
    assert_eq!(anon.status(), StatusCode::UNAUTHORIZED);
    let anon_mark = app
        .client
        .post(app.url(&format!("/api/v1/notifications/{row}/read")))
        .send()
        .await
        .unwrap();
    assert_eq!(anon_mark.status(), StatusCode::UNAUTHORIZED);
}

// The worker delivers a contact's in_app row (status flips to sent)
// instead of failing it for having no user_id.
#[sqlx::test]
async fn the_worker_delivers_a_contact_in_app_row(pool: PgPool) {
    let _ = common::seed_admin(&pool).await;
    let company = seed_company(&pool, "Worker Co").await;
    let me =
        common::seed_portal_contact(&pool, company, "me@example.com", &["Support Contact"]).await;
    seed_in_app_rule(&pool, &[]).await;
    assert_eq!(
        dispatch(
            &pool,
            serde_json::json!({ "recipient_contact_id": me.id.to_string(), "note": "x" })
        )
        .await,
        1
    );
    let worker = DispatcherWorker::new(Database::from_pool(pool.clone()), Arc::new(LogMailer));
    let stats = worker.run_tick(10).await.expect("worker tick");
    assert_eq!(stats.examined, 1);
    assert_eq!(stats.sent, 1);
    assert_eq!(stats.failed, 0);
    let status: String = sqlx::query_scalar(
        "SELECT status FROM notifications WHERE contact_id = $1 AND channel_type = 'in_app'",
    )
    .bind(me.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(status, "sent");
}
