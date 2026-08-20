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
//!   * Every migration-seeded template stores real newlines and only
//!     flat placeholders (PMS-702 regression guard).
//!   * A rule with no template writes no `notifications` row, and the
//!     rules endpoint rejects a template-less rule (PMS-701).
//!   * An authored `body_html` reaches the mailer as the HTML alternative,
//!     and a NULL one still sends single-part plain text (PMS-700).
//!   * The seeded transactional greetings read correctly with and without a
//!     recipient name (PMS-774).
//!   * `POST /notifications/preview` renders exactly what `dispatch` would
//!     send, writes nothing, and stays inside the caller's tenant (PMS-808).

mod common;

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use mokosh_server::modules::notifications::{render_template, DispatcherWorker};
use mokosh_server::utils::email::{salutation, LogMailer, Mailer};
use mokosh_server::utils::error::AppResult;
use mokosh_server::Database;
use sqlx::PgPool;
use uuid::Uuid;

/// One captured send, so a test can assert the message shape the dispatcher
/// asked for.
#[derive(Clone)]
struct SentMail {
    to: String,
    text: String,
    html: Option<String>,
}

/// Records every send the worker performs.
#[derive(Default)]
struct CapturingMailer {
    sent: Mutex<Vec<SentMail>>,
}

#[async_trait]
impl Mailer for CapturingMailer {
    async fn send_multipart(
        &self,
        to: &str,
        _subject: &str,
        text: &str,
        html: Option<&str>,
    ) -> AppResult<()> {
        self.sent.lock().unwrap().push(SentMail {
            to: to.to_string(),
            text: text.to_string(),
            html: html.map(str::to_string),
        });
        Ok(())
    }
}

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
    let items = inbox["data"]
        .as_array()
        .expect("inbox returns a paginated data array");
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

/// PMS-701: a rule with no template used to dispatch a row with a
/// synthetic subject and the serialized dispatch context as its body.
/// Such a rule must now write nothing at all, and the API must refuse to
/// create one.
#[sqlx::test]
async fn rule_without_template_dispatches_nothing_and_cannot_be_created(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let tenant_id = common::DEFAULT_TENANT_ID;
    let event_type = "test.template_less_rule";

    // Legacy shape: a rule row with a NULL template_id (PMS-386-era rules
    // predate templates, so this state exists in the wild).
    sqlx::query(
        r#"
        INSERT INTO notification_rules
            (id, tenant_id, name, event_type, channels, recipients, template_id, is_active)
        VALUES ($1, $2, 'Template-less Rule', $3, ARRAY['email', 'in_app']::VARCHAR(20)[],
                '{"user_ids": [], "emails": ["ops@example.test"]}'::jsonb, NULL, TRUE)
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(tenant_id)
    .bind(event_type)
    .execute(&pool)
    .await
    .expect("seed template-less rule");

    let dispatch_resp = app
        .client
        .post(app.url("/api/v1/notifications/dispatch"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "event_type": event_type,
            "context": {
                "recipient_user_id": admin_id.to_string(),
                "recipient_email": "victim@example.test",
                "reset_token": "super-secret-value",
            },
        }))
        .send()
        .await
        .expect("send dispatch");
    assert!(
        dispatch_resp.status().is_success(),
        "dispatch should 2xx, got {}",
        dispatch_resp.status(),
    );

    let rows: Vec<(Option<String>, String)> = sqlx::query_as(
        "SELECT subject, body FROM notifications WHERE tenant_id = $1 AND template_id IS NULL",
    )
    .bind(tenant_id)
    .fetch_all(&pool)
    .await
    .expect("query notifications");
    assert!(
        rows.is_empty(),
        "a rule with no template must insert no notifications row, got {rows:?}",
    );

    // The write path is closed too: no template_id -> 422.
    let create_resp = app
        .client
        .post(app.url("/api/v1/notification-rules"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "name": "No Template Rule",
            "event_type": event_type,
            "channels": ["email"],
            "recipients": {"emails": ["ops@example.test"]},
            "is_active": true,
        }))
        .send()
        .await
        .expect("send create rule");
    assert_eq!(
        create_resp.status(),
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "creating a rule without template_id must be a validation error",
    );
    let body: serde_json::Value = create_resp.json().await.expect("error JSON");
    assert!(
        serde_json::to_string(&body)
            .expect("serialise error body")
            .contains("template_id"),
        "validation error should name template_id, got {body}",
    );

    let created: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM notification_rules WHERE tenant_id = $1 AND name = 'No Template Rule'")
            .bind(tenant_id)
            .fetch_one(&pool)
            .await
            .expect("count rules");
    assert_eq!(created, 0, "rejected rule must not be persisted");
}

/// Every placeholder key in `text`, i.e. the contents of each `{{...}}`.
fn placeholder_keys(text: &str) -> Vec<&str> {
    let mut keys = Vec::new();
    let mut rest = text;
    while let Some(open) = rest.find("{{") {
        rest = &rest[open + 2..];
        let Some(close) = rest.find("}}") else {
            break;
        };
        keys.push(rest[..close].trim());
        rest = &rest[close + 2..];
    }
    keys
}

/// PMS-702: migration 023 seeded its templates with plain single-quoted
/// literals (so `\n` was stored as backslash + n and the mail arrived as
/// one long line) and dotted placeholders that `render_template`'s flat
/// `context.get` can never resolve. Migration 096 rewrites those rows;
/// this asserts no seeded template ever regresses to either shape.
#[sqlx::test]
async fn seeded_templates_have_real_newlines_and_flat_placeholders(pool: PgPool) {
    // (name, subject, body_text, body_html)
    type TemplateRow = (String, Option<String>, Option<String>, Option<String>);
    let rows: Vec<TemplateRow> =
        sqlx::query_as("SELECT name, subject, body_text, body_html FROM notification_templates")
            .fetch_all(&pool)
            .await
            .expect("fetch seeded templates");

    assert!(!rows.is_empty(), "migrations should seed some templates");

    for (name, subject, body_text, body_html) in rows {
        for (column, value) in [
            ("subject", subject),
            ("body_text", body_text),
            ("body_html", body_html),
        ] {
            let Some(value) = value else {
                continue;
            };
            assert!(
                !value.contains("\\n"),
                "template {name}.{column} stores a literal backslash-n: use an E'...' literal so \
                 the newline is real: {value}",
            );
            for key in placeholder_keys(&value) {
                assert!(
                    !key.contains('.'),
                    "template {name}.{column} has dotted placeholder {{{{{key}}}}}: \
                     render_template resolves flat context keys only",
                );
            }
        }
    }
}

/// PMS-774: every transactional message opens the same way, and reads
/// correctly when the recipient's name is not known.
///
/// Migration 106 moved the greeting word into `forms.request_link` and
/// `auth.welcome` and left the name in the data. Rendering the seeded bodies
/// with the blank-name salutation is what proves the pair is in step: a
/// template that kept its own "Hello" would render "Hello Hello," and one that
/// still asked for `{{display_name}}` alone would open on a bare comma.
#[sqlx::test]
async fn the_seeded_greetings_read_correctly_without_a_name(pool: PgPool) {
    type BodyRow = (String, Option<String>, Option<String>);
    for event_type in ["forms.request_link", "auth.welcome"] {
        let rows: Vec<BodyRow> = sqlx::query_as(
            "SELECT name, body_text, body_html FROM notification_templates \
             WHERE event_type = $1 AND channel_type = 'email'",
        )
        .bind(event_type)
        .fetch_all(&pool)
        .await
        .expect("fetch the seeded template");

        assert!(!rows.is_empty(), "{event_type} must be seeded");

        for (name, body_text, body_html) in rows {
            for (column, body) in [("body_text", body_text), ("body_html", body_html)] {
                let Some(body) = body else { continue };
                assert!(
                    body.contains("{{salutation}},"),
                    "{name}.{column} must open from the shared helper: {body}",
                );

                // The composers supply both keys on every send, so render with
                // both: the blank name is the case the greeting has to carry.
                let context = serde_json::json!({
                    "salutation": salutation(""),
                    "display_name": "",
                });
                let (rendered, _) = render_template(&body, &context);
                assert!(
                    rendered.contains("Hello,"),
                    "{name}.{column} must greet an unnamed recipient as \"Hello,\": {rendered}",
                );
                assert!(
                    !rendered.contains("Hello ,") && !rendered.contains(">,<"),
                    "{name}.{column} left a stray space or comma: {rendered}",
                );

                let (named, _) = render_template(
                    &body,
                    &serde_json::json!({
                        "salutation": salutation("David"),
                        "display_name": "David",
                    }),
                );
                assert!(
                    named.contains("Hello David,"),
                    "{name}.{column} must greet a named recipient once, by name: {named}",
                );
            }
        }
    }
}

/// PMS-700: `dispatch` selected `body_html` but never read it, and `deliver`
/// only ever called the plain-text send, so every authored HTML body was
/// dropped. The rendered HTML must now ride the `notifications` row and reach
/// the mailer as the HTML alternative; a template with a NULL `body_html`
/// must still produce a single-part plain-text send.
#[sqlx::test]
async fn dispatch_carries_rendered_body_html_to_the_mailer(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let tenant_id = common::DEFAULT_TENANT_ID;

    // Two events: one template carries HTML, the other leaves it NULL.
    let html_event = "test.body_html_present";
    let text_event = "test.body_html_absent";
    for (event_type, name, body_html) in [
        (
            html_event,
            "HTML Template",
            Some("<html><body><p>Hi {{display_name}}: <a href=\"{{link}}\">open</a></p></body></html>"),
        ),
        (text_event, "Text Template", None),
    ] {
        let template_id = Uuid::new_v4();
        sqlx::query(
            r#"
            INSERT INTO notification_templates
                (id, tenant_id, name, event_type, channel_type, subject, body_text, body_html, is_active)
            VALUES ($1, $2, $3, $4, 'email', $5, $6, $7, TRUE)
            "#,
        )
        .bind(template_id)
        .bind(tenant_id)
        .bind(name)
        .bind(event_type)
        .bind("Hello {{display_name}}")
        .bind("Plain body for {{display_name}} at {{link}}")
        .bind(body_html)
        .execute(&pool)
        .await
        .expect("seed template");

        sqlx::query(
            r#"
            INSERT INTO notification_rules
                (id, tenant_id, name, event_type, channels, recipients, template_id, is_active)
            VALUES ($1, $2, $3, $4, ARRAY['email']::VARCHAR(20)[],
                    '{"user_ids": [], "emails": []}'::jsonb, $5, TRUE)
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(tenant_id)
        .bind(format!("{name} Rule"))
        .bind(event_type)
        .bind(template_id)
        .execute(&pool)
        .await
        .expect("seed rule");
    }

    for (event_type, recipient) in [
        (html_event, "html@example.test"),
        (text_event, "text@example.test"),
    ] {
        let resp = app
            .client
            .post(app.url("/api/v1/notifications/dispatch"))
            .bearer_auth(&token)
            .json(&serde_json::json!({
                "event_type": event_type,
                "context": {
                    "recipient_email": recipient,
                    "display_name": "Test Admin",
                    "link": "https://example.test/welcome",
                },
            }))
            .send()
            .await
            .expect("send dispatch");
        assert!(
            resp.status().is_success(),
            "dispatch of {event_type} should 2xx, got {}",
            resp.status(),
        );
    }

    // The rendered HTML is persisted on the queue row (not re-resolved from
    // the template at delivery time), with placeholders already substituted.
    let queued_html: Option<String> = sqlx::query_scalar(
        "SELECT body_html FROM notifications WHERE tenant_id = $1 AND recipient = 'html@example.test'",
    )
    .bind(tenant_id)
    .fetch_one(&pool)
    .await
    .expect("fetch queued html row");
    let queued_html = queued_html.expect("dispatch must persist the rendered body_html");
    assert!(
        queued_html.contains("Hi Test Admin")
            && queued_html.contains("https://example.test/welcome"),
        "body_html placeholders should resolve from context, got: {queued_html}",
    );

    let queued_text_html: Option<String> = sqlx::query_scalar(
        "SELECT body_html FROM notifications WHERE tenant_id = $1 AND recipient = 'text@example.test'",
    )
    .bind(tenant_id)
    .fetch_one(&pool)
    .await
    .expect("fetch queued text row");
    assert!(
        queued_text_html.is_none(),
        "a template with no body_html must leave the row's body_html NULL",
    );

    // Drain both rows and inspect what the worker handed the mailer.
    let mailer = Arc::new(CapturingMailer::default());
    let worker = DispatcherWorker::new(Database::from_pool(pool.clone()), mailer.clone());
    let stats = worker.run_tick(10).await.expect("worker tick");
    assert_eq!(stats.sent, 2, "both email rows should send: {stats:?}");

    let sent = mailer.sent.lock().unwrap().clone();
    let html_send = sent
        .iter()
        .find(|m| m.to == "html@example.test")
        .expect("html recipient was mailed");
    assert_eq!(
        html_send.html.as_deref(),
        Some(queued_html.as_str()),
        "the rendered HTML must be handed to the mailer as the HTML alternative",
    );
    assert!(
        html_send.text.contains("Plain body for Test Admin"),
        "the plain-text part must still be the fallback, got: {}",
        html_send.text,
    );

    let text_send = sent
        .iter()
        .find(|m| m.to == "text@example.test")
        .expect("text recipient was mailed");
    assert!(
        text_send.html.is_none(),
        "a NULL body_html must stay a single-part plain-text send, got: {:?}",
        text_send.html,
    );
}

/// Seed one email template + one active rule for `event_type` under
/// `tenant_id`, shaped like the request-form link the SPA previews
/// (PMS-808): the company name comes from the context, the link only
/// exists at send time. Returns the template id.
async fn seed_preview_rule(pool: &PgPool, tenant_id: Uuid, event_type: &str) -> Uuid {
    let template_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO notification_templates
            (id, tenant_id, name, event_type, channel_type, subject, body_text, body_html, is_active)
        VALUES ($1, $2, 'Preview Template', $3, 'email', $4, $5, $6, TRUE)
        "#,
    )
    .bind(template_id)
    .bind(tenant_id)
    .bind(event_type)
    .bind("A form to fill in for {{company_name}}")
    .bind("Open {{link}} to fill in the form for {{company_name}}.")
    .bind("<p>Open <a href=\"{{link}}\">the form</a> for {{company_name}}.</p>")
    .execute(pool)
    .await
    .expect("seed preview template");

    sqlx::query(
        r#"
        INSERT INTO notification_rules
            (id, tenant_id, name, event_type, channels, recipients, template_id, is_active)
        VALUES ($1, $2, 'Request form link', $3, ARRAY['email']::VARCHAR(20)[],
                '{"user_ids": [], "emails": []}'::jsonb, $4, TRUE)
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(tenant_id)
    .bind(event_type)
    .bind(template_id)
    .execute(pool)
    .await
    .expect("seed preview rule");

    template_id
}

async fn preview(
    app: &common::TestApp,
    token: &str,
    body: serde_json::Value,
) -> Vec<serde_json::Value> {
    let resp = app
        .client
        .post(app.url("/api/v1/notifications/preview"))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .expect("send preview");
    let status = resp.status();
    let text = resp.text().await.expect("preview body");
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "preview should 200, got {status} body={text}",
    );
    serde_json::from_str::<serde_json::Value>(&text)
        .expect("preview JSON")
        .as_array()
        .expect("preview returns an array")
        .clone()
}

/// PMS-808: the preview must be what `dispatch` renders, not a second
/// copy of the rendering that can drift from it, and asking for it must
/// leave the queue exactly as it was.
#[sqlx::test]
async fn preview_renders_what_dispatch_sends_and_queues_nothing(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let tenant_id = common::DEFAULT_TENANT_ID;
    let event_type = "test.preview_matches_dispatch";
    let template_id = seed_preview_rule(&pool, tenant_id, event_type).await;

    // `link` is deliberately absent: it is minted when the mail is sent.
    let request = serde_json::json!({
        "event_type": event_type,
        "context": {
            "recipient_email": "preview@example.test",
            "company_name": "Dental Arts Practice",
        },
    });

    // Scoped to this test's own template and recipient: the tenant-wide
    // table also carries whatever the first-visit demo seed dispatches,
    // which is not synchronous with this request.
    let queued_before: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM notifications \
         WHERE tenant_id = $1 AND (template_id = $2 OR recipient = 'preview@example.test')",
    )
    .bind(tenant_id)
    .bind(template_id)
    .fetch_one(&pool)
    .await
    .expect("count queue before");
    assert_eq!(queued_before, 0, "fixture starts with an empty queue");

    let entries = preview(&app, &token, request.clone()).await;
    assert_eq!(entries.len(), 1, "one rule fires: {entries:?}");
    let entry = &entries[0];

    assert_eq!(entry["rule_name"], "Request form link");
    assert_eq!(entry["channel"], "email");
    assert_eq!(
        entry["recipients"],
        serde_json::json!(["preview@example.test"]),
        "recipients come from the rule logic, not from anything the caller can address",
    );
    assert_eq!(
        entry["subject"], "A form to fill in for Dental Arts Practice",
        "the context keys that ARE present must render",
    );
    assert_eq!(
        entry["unresolved"],
        serde_json::json!(["link"]),
        "a send-time value must be named, not fabricated: {entry}",
    );
    assert!(
        entry["body_text"]
            .as_str()
            .expect("body_text is a string")
            .contains("Open {{link}} to fill in the form for Dental Arts Practice."),
        "an unresolved placeholder stays literal in the body: {entry}",
    );
    assert!(
        entry["body_html"]
            .as_str()
            .expect("body_html is a string")
            .contains("href=\"{{link}}\""),
        "the HTML alternative renders the same way: {entry}",
    );

    // Nothing was queued, and nothing was audited, by asking.
    let queued_after: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM notifications \
         WHERE tenant_id = $1 AND (template_id = $2 OR recipient = 'preview@example.test')",
    )
    .bind(tenant_id)
    .bind(template_id)
    .fetch_one(&pool)
    .await
    .expect("count queue after");
    assert_eq!(
        queued_after, queued_before,
        "preview must not write a notifications row",
    );
    let audited: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_log WHERE tenant_id = $1 AND entity_type LIKE 'notification%'",
    )
    .bind(tenant_id)
    .fetch_one(&pool)
    .await
    .expect("count audit rows");
    assert_eq!(audited, 0, "preview must not write an audit entry");

    // The same event and context, actually dispatched, must render
    // identically: one function does the rendering for both paths.
    let dispatch_resp = app
        .client
        .post(app.url("/api/v1/notifications/dispatch"))
        .bearer_auth(&token)
        .json(&request)
        .send()
        .await
        .expect("send dispatch");
    assert!(
        dispatch_resp.status().is_success(),
        "dispatch should 2xx, got {}",
        dispatch_resp.status(),
    );

    let (subject, body, body_html): (Option<String>, String, Option<String>) = sqlx::query_as(
        "SELECT subject, body, body_html FROM notifications \
         WHERE tenant_id = $1 AND template_id = $2",
    )
    .bind(tenant_id)
    .bind(template_id)
    .fetch_one(&pool)
    .await
    .expect("fetch the dispatched row");

    assert_eq!(
        entry["subject"].as_str(),
        subject.as_deref(),
        "preview subject must equal the dispatched subject",
    );
    assert_eq!(
        entry["body_text"].as_str(),
        Some(body.as_str()),
        "preview body_text must equal the dispatched body",
    );
    assert_eq!(
        entry["body_html"].as_str(),
        body_html.as_deref(),
        "preview body_html must equal the dispatched body_html",
    );
}

/// PMS-808: no active rule means no email would be sent at all, which is
/// a real answer an operator wants before clicking Send, not an error.
#[sqlx::test]
async fn preview_of_an_event_with_no_rule_is_an_empty_array(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let entries = preview(
        &app,
        &token,
        serde_json::json!({
            "event_type": "test.no_rule_matches_this",
            "context": {"company_name": "Dental Arts Practice"},
        }),
    )
    .await;
    assert!(
        entries.is_empty(),
        "expected an empty array, got {entries:?}"
    );
}

/// PMS-808: the preview reads templates and rules through
/// `begin_with_tenant` like every other template read, so it cannot show
/// one tenant what another tenant's mail says.
#[sqlx::test]
async fn preview_cannot_read_another_tenants_templates(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let own_token = common::login(&app, &email, &password).await;
    let event_type = "test.preview_tenant_scope";
    seed_preview_rule(&pool, common::DEFAULT_TENANT_ID, event_type).await;

    let (other_tenant, _other_id, other_email, other_password) =
        common::seed_tenant_with_admin(&pool, "preview-other").await;
    let other_resp = app
        .client
        .post(app.url("/api/v1/auth/login"))
        .json(&serde_json::json!({
            "email": other_email,
            "password": other_password,
            "tenant_id": other_tenant,
        }))
        .send()
        .await
        .expect("send other-tenant login");
    assert!(
        other_resp.status().is_success(),
        "other-tenant login should 2xx, got {}",
        other_resp.status(),
    );
    let other_token = other_resp
        .json::<serde_json::Value>()
        .await
        .expect("login JSON")["access_token"]
        .as_str()
        .expect("login response has access_token")
        .to_string();

    let request = serde_json::json!({
        "event_type": event_type,
        "context": {
            "recipient_email": "preview@example.test",
            "company_name": "Dental Arts Practice",
        },
    });

    // The owning tenant sees its own template...
    let own = preview(&app, &own_token, request.clone()).await;
    assert_eq!(own.len(), 1, "the owning tenant sees its rule: {own:?}");

    // ...and the other tenant sees nothing at all for the same event.
    let other = preview(&app, &other_token, request).await;
    assert!(
        other.is_empty(),
        "a tenant must not preview another tenant's templates, got {other:?}",
    );
}
