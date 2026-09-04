//! PMS-729 phase 2 §7 slice B / I12: `/portal/notifications` HTTP tests.
//!
//! Pins the contact-scoped inbox (no cross-contact leak inside the
//! same tenant), the mark-read flow (contact-scoped + idempotent), and
//! the dispatcher-side plumbing (`recipient_contact_id` in the context
//! writes an `in_app` row against `contact_id`, not `user_id`).

mod common;

use mokosh_server::modules::notifications::NotificationsService;
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

async fn seed_inbox_row(
    pool: &PgPool,
    contact_id: Uuid,
    subject: &str,
    body: &str,
    read: bool,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO notifications
            (id, tenant_id, contact_id, channel_type, subject, body, status, read_at)
        VALUES ($1, $2, $3, 'in_app', $4, $5, 'sent', CASE WHEN $6 THEN NOW() ELSE NULL END)
        "#,
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(contact_id)
    .bind(subject)
    .bind(body)
    .bind(read)
    .execute(pool)
    .await
    .expect("seed notification");
    id
}

// -- tests -----------------------------------------------------------------

#[sqlx::test]
async fn inbox_returns_only_the_callers_rows_with_unread_count(pool: PgPool) {
    let _ = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let company = seed_company(&pool, "Inbox Co").await;
    let me = seed_portal_contact(&pool, company, "me@example.com").await;
    let sibling = seed_portal_contact(&pool, company, "sibling@example.com").await;

    let _mine1 = seed_inbox_row(&pool, me, "Ticket updated", "Body A", false).await;
    let _mine2 = seed_inbox_row(&pool, me, "Invoice reminder", "Body B", true).await;
    let _theirs = seed_inbox_row(&pool, sibling, "Not mine", "Body C", false).await;

    let token = login(&app, "me@example.com").await;
    let resp = app
        .client
        .get(app.url("/api/v1/portal/notifications"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list");
    assert!(resp.status().is_success());
    let body: serde_json::Value = resp.json().await.unwrap();
    let rows = body["notifications"].as_array().unwrap();
    assert_eq!(rows.len(), 2, "expected 2 own rows: {body}");
    // Newest first: seeding order was A then B; B was read but timestamp is later.
    // Both rows just have to be in the response; ordering is by created_at DESC.
    let subjects: Vec<&str> = rows
        .iter()
        .map(|r| r["subject"].as_str().unwrap())
        .collect();
    assert!(subjects.contains(&"Ticket updated"));
    assert!(subjects.contains(&"Invoice reminder"));
    assert!(
        !subjects.contains(&"Not mine"),
        "sibling row leaked: {body}"
    );
    assert_eq!(body["unread_count"].as_i64().unwrap(), 1);
}

#[sqlx::test]
async fn mark_read_flips_read_at_and_is_idempotent(pool: PgPool) {
    let _ = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let company = seed_company(&pool, "Mark Co").await;
    let me = seed_portal_contact(&pool, company, "mark@example.com").await;
    let id = seed_inbox_row(&pool, me, "Unread", "body", false).await;

    let token = login(&app, "mark@example.com").await;
    // First mark-read: 204.
    let resp = app
        .client
        .put(app.url(&format!("/api/v1/portal/notifications/{id}/read")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("mark read");
    assert_eq!(resp.status(), reqwest::StatusCode::NO_CONTENT);
    // Re-mark: also 204 (idempotent), not 409 / 404.
    let resp = app
        .client
        .put(app.url(&format!("/api/v1/portal/notifications/{id}/read")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("mark read again");
    assert_eq!(resp.status(), reqwest::StatusCode::NO_CONTENT);

    // Unread count now zero.
    let resp = app
        .client
        .get(app.url("/api/v1/portal/notifications"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["unread_count"].as_i64().unwrap(), 0);
}

#[sqlx::test]
async fn mark_read_returns_404_for_cross_contact_id(pool: PgPool) {
    let _ = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let company = seed_company(&pool, "Cross Co").await;
    let me = seed_portal_contact(&pool, company, "me@example.com").await;
    let sibling = seed_portal_contact(&pool, company, "sibling@example.com").await;
    let stolen = seed_inbox_row(&pool, sibling, "Not mine", "body", false).await;
    let _ = me;

    let token = login(&app, "me@example.com").await;
    let resp = app
        .client
        .put(app.url(&format!("/api/v1/portal/notifications/{stolen}/read")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("mark read");
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
}

/// The dispatcher's `recipient_contact_id` context key writes an
/// `in_app` row against `contact_id`, and the inbox picks it up on
/// the next GET.
#[sqlx::test]
async fn dispatch_recipient_contact_id_writes_a_portal_inbox_row(pool: PgPool) {
    let _ = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let company = seed_company(&pool, "Dispatch Co").await;
    let me = seed_portal_contact(&pool, company, "disp@example.com").await;

    // Seed an in_app template + rule so the dispatcher has something
    // renderable to fire.
    let template_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO notification_templates
            (id, tenant_id, name, event_type, channel_type, subject, body_text, is_active)
        VALUES ($1, $2, 'Portal In-App', 'test.portal_ping', 'in_app', 'Hello', 'Body {{note}}', TRUE)
        "#,
    )
    .bind(template_id)
    .bind(common::DEFAULT_TENANT_ID)
    .execute(&pool)
    .await
    .expect("seed template");
    sqlx::query(
        r#"
        INSERT INTO notification_rules
            (id, tenant_id, name, event_type, channels, recipients, template_id, is_active)
        VALUES ($1, $2, 'Portal In-App Rule', 'test.portal_ping',
                ARRAY['in_app']::VARCHAR(20)[],
                '{"user_ids": [], "emails": [], "contacts": []}'::jsonb, $3, TRUE)
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(common::DEFAULT_TENANT_ID)
    .bind(template_id)
    .execute(&pool)
    .await
    .expect("seed rule");

    let service = NotificationsService::with_encryption_key(
        mokosh_server::Database::from_pool(pool.clone()),
        [0u8; 32],
    );
    let ctx = serde_json::json!({
        "recipient_contact_id": me.to_string(),
        "note": "welcome",
    });
    let fanout = service
        .dispatch(
            mokosh_server::modules::auth::TenantId::from_trusted(common::DEFAULT_TENANT_ID),
            "test.portal_ping",
            &ctx,
        )
        .await
        .expect("dispatch");
    assert!(fanout >= 1, "expected at least one dispatched row");

    let token = login(&app, "disp@example.com").await;
    let resp = app
        .client
        .get(app.url("/api/v1/portal/notifications"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list");
    let body: serde_json::Value = resp.json().await.unwrap();
    let rows = body["notifications"].as_array().unwrap();
    assert_eq!(rows.len(), 1, "expected 1 inbox row: {body}");
    assert_eq!(rows[0]["subject"].as_str().unwrap(), "Hello");
    assert_eq!(rows[0]["body"].as_str().unwrap(), "Body welcome");
    assert_eq!(body["unread_count"].as_i64().unwrap(), 1);
}

#[sqlx::test]
async fn inbox_endpoints_require_a_portal_session(pool: PgPool) {
    let _ = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let list = app
        .client
        .get(app.url("/api/v1/portal/notifications"))
        .send()
        .await
        .expect("list");
    assert_eq!(list.status(), reqwest::StatusCode::UNAUTHORIZED);
    let mark = app
        .client
        .put(app.url(&format!(
            "/api/v1/portal/notifications/{}/read",
            Uuid::new_v4()
        )))
        .send()
        .await
        .expect("mark");
    assert_eq!(mark.status(), reqwest::StatusCode::UNAUTHORIZED);
}
