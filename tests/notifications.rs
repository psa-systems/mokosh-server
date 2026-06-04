//! Integration test for the notifications module (PMS-92).
//!
//! Covers the gaps the PMS-85 story verification surfaced:
//!   * `user_notification_preferences` actually suppresses channels at
//!     dispatch time (not just CRUD-stored).
//!   * `notifications.status` is bound explicitly on insert (no silent
//!     reliance on the column default).
//!   * The dispatcher worker drains pending rows, flips status to
//!     `sent`, and stamps `sent_at`.
//!   * The in-app inbox surfaces the row and `mark-read` clears it.
//!   * `notification_channels.config_encrypted` is actual ciphertext,
//!     not the plaintext config that was POSTed (zero-key regression
//!     guard).

mod common;

use std::sync::Arc;

use mokosh_server::modules::notifications::DispatcherWorker;
use mokosh_server::utils::email::LogMailer;
use mokosh_server::Database;
use sqlx::PgPool;
use uuid::Uuid;

#[sqlx::test]
async fn dispatch_respects_preferences_and_worker_marks_sent(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let tenant_id = common::DEFAULT_TENANT_ID;
    let event_type = "test.preference_enforcement";

    // Seed one template + one rule that targets two channels (email,
    // in_app) so the preference enforcement decides which one runs.
    let template_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO notification_templates
            (id, tenant_id, name, event_type, channel_type, subject, body_text, body_html, is_active)
        VALUES ($1, $2, 'Preference Test - Email', $3, 'email', $4, $5, NULL, TRUE)
        "#,
    )
    .bind(template_id)
    .bind(tenant_id)
    .bind(event_type)
    .bind("Hello {{display_name}}")
    .bind("Body for {{display_name}} at {{link}}")
    .execute(&pool)
    .await
    .expect("seed template");

    sqlx::query(
        r#"
        INSERT INTO notification_rules
            (id, tenant_id, name, event_type, channels, recipients, template_id, is_active)
        VALUES ($1, $2, 'Preference Test Rule', $3, ARRAY['email', 'in_app']::VARCHAR(20)[],
                '{"user_ids": [], "emails": []}'::jsonb, $4, TRUE)
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(tenant_id)
    .bind(event_type)
    .bind(template_id)
    .execute(&pool)
    .await
    .expect("seed rule");

    // Admin opts INTO in_app and OUT of email for this event. The
    // dispatcher must skip the email fanout for this user.
    let pref_resp = app
        .client
        .put(app.url("/api/v1/me/notification-preferences"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "event_type": event_type,
            "channel_types": ["in_app"],
            "is_enabled": true,
        }))
        .send()
        .await
        .expect("send pref upsert");
    assert!(
        pref_resp.status().is_success(),
        "pref upsert should 2xx, got {}",
        pref_resp.status(),
    );

    // Drive dispatch via the admin endpoint. recipient_user_id in
    // context targets the admin we just seeded; the rule itself
    // carries no recipients.
    let dispatch_resp = app
        .client
        .post(app.url("/api/v1/notifications/dispatch"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "event_type": event_type,
            "context": {
                "recipient_user_id": admin_id.to_string(),
                "display_name": "Test Admin",
                "link": "https://example.test/welcome",
            },
        }))
        .send()
        .await
        .expect("send dispatch");
    let dispatch_status = dispatch_resp.status();
    let dispatch_text = dispatch_resp.text().await.expect("dispatch body");
    assert!(
        dispatch_status.is_success(),
        "dispatch should 2xx, got {dispatch_status} body={dispatch_text}",
    );

    // Exactly one row: the in_app fan-out. The email fan-out for this
    // user is suppressed by the preference; the rule has no standalone
    // emails so no recipient-only row gets written either.
    type NotifRow = (
        Uuid,
        String,
        Option<String>,
        Option<chrono::DateTime<chrono::Utc>>,
    );
    let rows: Vec<NotifRow> = sqlx::query_as(
        r#"
        SELECT id, channel_type, status, sent_at
        FROM notifications
        WHERE tenant_id = $1 AND template_id = $2
        ORDER BY channel_type
        "#,
    )
    .bind(tenant_id)
    .bind(template_id)
    .fetch_all(&pool)
    .await
    .expect("query notifications");

    assert_eq!(
        rows.len(),
        1,
        "expected exactly one notification row (in_app only), got {rows:?}",
    );
    let (notif_id, channel, status, sent_at) = rows.into_iter().next().unwrap();
    assert_eq!(
        channel, "in_app",
        "preference enforcement let email through"
    );
    assert_eq!(
        status.as_deref(),
        Some("pending"),
        "status must be bound explicitly to 'pending'",
    );
    assert!(sent_at.is_none(), "sent_at must be null before worker runs");

    // Render check: `{{display_name}}` resolved from the context.
    let (subject, body): (Option<String>, String) =
        sqlx::query_as("SELECT subject, body FROM notifications WHERE id = $1")
            .bind(notif_id)
            .fetch_one(&pool)
            .await
            .expect("fetch rendered row");
    assert_eq!(subject.as_deref(), Some("Hello Test Admin"));
    assert!(
        body.contains("Body for Test Admin at https://example.test/welcome"),
        "template placeholders should resolve from context, got: {body}",
    );

    // One worker tick should drain the row. in_app delivery is a
    // database flip; the LogMailer never enters the picture.
    let worker = DispatcherWorker::new(Database::from_pool(pool.clone()), Arc::new(LogMailer));
    let stats = worker.run_tick(10).await.expect("worker tick");
    assert_eq!(stats.examined, 1, "tick should examine the one pending row");
    assert_eq!(stats.sent, 1, "in_app row should be marked sent");
    assert_eq!(stats.retried, 0);
    assert_eq!(stats.failed, 0);

    let (status, sent_at): (Option<String>, Option<chrono::DateTime<chrono::Utc>>) =
        sqlx::query_as("SELECT status, sent_at FROM notifications WHERE id = $1")
            .bind(notif_id)
            .fetch_one(&pool)
            .await
            .expect("re-fetch row");
    assert_eq!(
        status.as_deref(),
        Some("sent"),
        "worker should flip status to sent",
    );
    assert!(sent_at.is_some(), "worker should stamp sent_at");

    // GET /api/v1/notifications returns the in-app row.
    let inbox_resp = app
        .client
        .get(app.url("/api/v1/notifications"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send inbox");
    assert_eq!(inbox_resp.status(), reqwest::StatusCode::OK);
    let inbox: serde_json::Value = inbox_resp.json().await.expect("inbox JSON");
    let items = inbox.as_array().expect("inbox returns an array");
    assert!(
        items
            .iter()
            .any(|i| i["id"].as_str() == Some(&notif_id.to_string())),
        "inbox should contain the dispatched notification",
    );

    // POST /api/v1/notifications/{id}/read flips read_at.
    let mark_resp = app
        .client
        .post(app.url(&format!("/api/v1/notifications/{notif_id}/read")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send mark-read");
    assert!(
        mark_resp.status().is_success(),
        "mark-read should 2xx, got {}",
        mark_resp.status(),
    );
    let read_at: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT read_at FROM notifications WHERE id = $1")
            .bind(notif_id)
            .fetch_one(&pool)
            .await
            .expect("re-fetch read_at");
    assert!(read_at.is_some(), "mark-read should stamp read_at");
}

#[sqlx::test]
async fn channel_config_is_encrypted_at_rest(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let tenant_id = common::DEFAULT_TENANT_ID;

    // Distinctive plaintext we can grep for in the persisted bytes.
    // If `config_encrypted` is stored verbatim (zero-key regression),
    // this exact substring will appear.
    let secret_marker = "PMS92-not-encrypted-canary-token";
    let create_resp = app
        .client
        .post(app.url("/api/v1/notification-channels"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "channel_type": "email",
            "name": "Encryption Smoke",
            "config": {"smtp_host": secret_marker},
            "is_active": true,
            "is_default": false,
        }))
        .send()
        .await
        .expect("send create channel");
    assert!(
        create_resp.status().is_success(),
        "create channel should 2xx, got {}",
        create_resp.status(),
    );

    let stored: String = sqlx::query_scalar(
        "SELECT config_encrypted FROM notification_channels WHERE tenant_id = $1",
    )
    .bind(tenant_id)
    .fetch_one(&pool)
    .await
    .expect("fetch ciphertext");

    assert!(
        !stored.contains(secret_marker),
        "config_encrypted should be ciphertext, but contained the plaintext marker: {stored}",
    );
}
