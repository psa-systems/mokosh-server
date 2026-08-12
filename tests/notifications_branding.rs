//! PMS-729 phase 2 §6 slice 5: branded outbound emails.
//!
//! Verifies the dispatcher enriches every render context with the
//! tenant's identity (`msp_name`, `msp_logo_url`, `msp_primary_color`,
//! `msp_support_email`) and that the migration-006-updated default
//! `auth.password_reset` template uses those placeholders so a
//! password-reset email arrives with the MSP's brand on the subject,
//! logo in the header, and support email in the footer.
//!
//! Migration-immutable posture: this test does NOT touch the migrated
//! rows; it seeds a branded tenant and asserts the pre-existing
//! `auth.password_reset` template renders correctly for that tenant.

mod common;

use mokosh_server::modules::notifications::NotificationsService;
use sqlx::PgPool;
use uuid::Uuid;

/// Assert the branding placeholders are substituted with the
/// tenant's actual values and land in the queued row's subject /
/// body / body_html.
#[sqlx::test]
async fn dispatch_injects_tenant_branding_into_render_context(pool: PgPool) {
    // Seed a fresh tenant with full branding so we do not clobber the
    // default tenant that every other test relies on.
    let tenant_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO tenants (id, name, slug, status, kind, branding)
        VALUES ($1, $2, $3, 'active', 'org', $4)
        "#,
    )
    .bind(tenant_id)
    .bind("Acme MSP")
    .bind("acme-branding-test")
    .bind(serde_json::json!({
        "logo_url": "https://cdn.example/acme-logo.svg",
        "primary_color": "#2563eb",
        "support_email": "help@acme.example"
    }))
    .execute(&pool)
    .await
    .expect("seed branded tenant");

    // Clone the default `auth.password_reset` template + rule into the
    // fresh tenant so the dispatcher can find something to fire (the
    // seeded templates from migration 021/106 live under the default
    // tenant only). Read the migrated bodies directly so the test does
    // not have to re-declare them (also proves the migration UPDATE
    // actually landed the branded copy).
    let (tpl_id, subject, body_text, body_html): (Uuid, Option<String>, String, Option<String>) =
        sqlx::query_as(
            r#"SELECT id, subject, body_text, body_html
           FROM notification_templates
           WHERE tenant_id = '00000000-0000-0000-0000-000000000001'
             AND event_type = 'auth.password_reset'
             AND channel_type = 'email'"#,
        )
        .fetch_one(&pool)
        .await
        .expect("default password-reset template exists");

    // Sanity check: the migration 110 UPDATE landed.
    assert!(
        subject.as_deref().unwrap_or("").contains("{{msp_name}}"),
        "migration 110 did not rewrite the subject: {subject:?}"
    );
    assert!(
        body_text.contains("{{msp_name}}"),
        "migration 110 did not rewrite the plain-text body: {body_text}"
    );
    assert!(
        body_html
            .as_deref()
            .unwrap_or("")
            .contains("{{msp_primary_color}}"),
        "migration 110 did not rewrite the html body: {body_html:?}"
    );

    let new_tpl = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO notification_templates
            (id, tenant_id, name, event_type, channel_type, subject, body_text, body_html, is_active)
        VALUES ($1, $2, 'Password Reset - Email', 'auth.password_reset', 'email', $3, $4, $5, TRUE)
        "#,
    )
    .bind(new_tpl)
    .bind(tenant_id)
    .bind(&subject)
    .bind(&body_text)
    .bind(&body_html)
    .execute(&pool)
    .await
    .expect("clone template under branded tenant");
    // Prevent unused warning while keeping the reads explicit above.
    let _ = tpl_id;

    sqlx::query(
        r#"
        INSERT INTO notification_rules
            (id, tenant_id, name, event_type, channels, recipients, template_id, is_active)
        VALUES ($1, $2, 'Password Reset', 'auth.password_reset',
                ARRAY['email']::VARCHAR(20)[],
                '{"user_ids": [], "emails": []}'::jsonb, $3, TRUE)
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(tenant_id)
    .bind(new_tpl)
    .execute(&pool)
    .await
    .expect("seed rule");

    // Fire the dispatcher. Empty context should still render the
    // subject / body with the injected branding.
    let service = NotificationsService::with_encryption_key(
        mokosh_server::Database::from_pool(pool.clone()),
        [0u8; 32],
    );
    let ctx = serde_json::json!({
        "recipient_email": "customer@example.com",
        "reset_link": "https://acme.example/reset?token=abc",
    });
    let fanout = service
        .dispatch(
            mokosh_server::modules::auth::TenantId::from_trusted(tenant_id),
            "auth.password_reset",
            &ctx,
        )
        .await
        .expect("dispatch");
    assert!(fanout >= 1, "expected at least one dispatched row");

    // Read the queued notification row back and assert every branding
    // placeholder has been resolved to the tenant's actual value.
    let (queued_subject, queued_body, queued_html): (Option<String>, String, Option<String>) =
        sqlx::query_as(
            r#"SELECT subject, body, body_html
               FROM notifications
               WHERE tenant_id = $1
                 AND template_id = $2
               ORDER BY created_at DESC
               LIMIT 1"#,
        )
        .bind(tenant_id)
        .bind(new_tpl)
        .fetch_one(&pool)
        .await
        .expect("read queued notification");

    let subject = queued_subject.expect("subject rendered");
    assert!(
        subject.contains("Acme MSP"),
        "subject missing MSP name: {subject}"
    );
    assert!(
        !subject.contains("{{"),
        "subject has unresolved placeholder: {subject}"
    );

    assert!(
        queued_body.contains("Acme MSP"),
        "plain body missing MSP name: {queued_body}"
    );
    assert!(
        queued_body.contains("help@acme.example"),
        "plain body missing support email: {queued_body}"
    );
    assert!(
        queued_body.contains("https://acme.example/reset?token=abc"),
        "plain body missing reset link: {queued_body}"
    );
    assert!(
        !queued_body.contains("{{"),
        "plain body has unresolved placeholder: {queued_body}"
    );

    let html = queued_html.expect("html rendered");
    assert!(
        html.contains("https://cdn.example/acme-logo.svg"),
        "html missing logo: {html}"
    );
    assert!(
        html.contains("#2563eb"),
        "html missing primary color: {html}"
    );
    assert!(
        html.contains("help@acme.example"),
        "html missing support email: {html}"
    );
    assert!(
        !html.contains("{{"),
        "html has unresolved placeholder: {html}"
    );
}

/// A tenant with an empty `branding` blob should still render (empty
/// strings for the missing branding fields), never a literal
/// `{{msp_logo_url}}` in the recipient's inbox.
#[sqlx::test]
async fn dispatch_renders_cleanly_when_branding_absent(pool: PgPool) {
    let tenant_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO tenants (id, name, slug, status, kind, branding)
        VALUES ($1, 'Bare MSP', 'bare-msp-test', 'active', 'org', '{}'::jsonb)
        "#,
    )
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("seed bare tenant");

    let tpl_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO notification_templates
            (id, tenant_id, name, event_type, channel_type, subject, body_text, body_html, is_active)
        VALUES ($1, $2, 'Bare Test - Email', 'test.branding_defaults', 'email',
                '{{msp_name}} says hi',
                'name={{msp_name}}, logo={{msp_logo_url}}, color={{msp_primary_color}}, help={{msp_support_email}}',
                NULL, TRUE)
        "#,
    )
    .bind(tpl_id)
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("seed template");

    sqlx::query(
        r#"
        INSERT INTO notification_rules
            (id, tenant_id, name, event_type, channels, recipients, template_id, is_active)
        VALUES ($1, $2, 'Bare Test Rule', 'test.branding_defaults',
                ARRAY['email']::VARCHAR(20)[],
                '{"user_ids": [], "emails": []}'::jsonb, $3, TRUE)
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(tenant_id)
    .bind(tpl_id)
    .execute(&pool)
    .await
    .expect("seed rule");

    let service = NotificationsService::with_encryption_key(
        mokosh_server::Database::from_pool(pool.clone()),
        [0u8; 32],
    );
    let ctx = serde_json::json!({"recipient_email": "one@example.com"});
    let _ = service
        .dispatch(
            mokosh_server::modules::auth::TenantId::from_trusted(tenant_id),
            "test.branding_defaults",
            &ctx,
        )
        .await
        .expect("dispatch");

    let (subject, body): (Option<String>, String) = sqlx::query_as(
        r#"SELECT subject, body
           FROM notifications
           WHERE tenant_id = $1 AND template_id = $2
           ORDER BY created_at DESC LIMIT 1"#,
    )
    .bind(tenant_id)
    .bind(tpl_id)
    .fetch_one(&pool)
    .await
    .expect("read row");

    let subject = subject.expect("subject rendered");
    assert_eq!(subject, "Bare MSP says hi", "unexpected: {subject}");
    // Body renders `""` for every unset branding key; no `{{...}}`
    // leaks through.
    assert_eq!(
        body, "name=Bare MSP, logo=, color=, help=",
        "unexpected body: {body}"
    );
}

/// Caller-supplied context keys win over the auto-injected branding
/// defaults, so a specific dispatch can override the tenant identity
/// (e.g. an integration test asserting a specific string).
#[sqlx::test]
async fn caller_context_overrides_branding_defaults(pool: PgPool) {
    let tenant_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO tenants (id, name, slug, status, kind, branding)
        VALUES ($1, 'Real MSP', 'override-test', 'active', 'org',
                '{"logo_url": "https://cdn/logo.svg"}'::jsonb)
        "#,
    )
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("seed tenant");

    let tpl_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO notification_templates
            (id, tenant_id, name, event_type, channel_type, subject, body_text, body_html, is_active)
        VALUES ($1, $2, 'Override Test - Email', 'test.branding_override', 'email',
                '{{msp_name}}', 'body: {{msp_name}}', NULL, TRUE)
        "#,
    )
    .bind(tpl_id)
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("seed template");

    sqlx::query(
        r#"
        INSERT INTO notification_rules
            (id, tenant_id, name, event_type, channels, recipients, template_id, is_active)
        VALUES ($1, $2, 'Override Test Rule', 'test.branding_override',
                ARRAY['email']::VARCHAR(20)[],
                '{"user_ids": [], "emails": []}'::jsonb, $3, TRUE)
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(tenant_id)
    .bind(tpl_id)
    .execute(&pool)
    .await
    .expect("seed rule");

    let service = NotificationsService::with_encryption_key(
        mokosh_server::Database::from_pool(pool.clone()),
        [0u8; 32],
    );
    let ctx = serde_json::json!({
        "recipient_email": "x@example.com",
        "msp_name": "Explicit override wins",
    });
    let _ = service
        .dispatch(
            mokosh_server::modules::auth::TenantId::from_trusted(tenant_id),
            "test.branding_override",
            &ctx,
        )
        .await
        .expect("dispatch");

    let (_, body): (Option<String>, String) = sqlx::query_as(
        r#"SELECT subject, body FROM notifications
           WHERE tenant_id = $1 AND template_id = $2
           ORDER BY created_at DESC LIMIT 1"#,
    )
    .bind(tenant_id)
    .bind(tpl_id)
    .fetch_one(&pool)
    .await
    .expect("read row");

    assert_eq!(body, "body: Explicit override wins", "unexpected: {body}");
}
