//! PMS-729 phase 2 §6 slice 5: branded outbound emails.
//!
//! Verifies the dispatcher enriches every render context with the
//! tenant's identity (`msp_name`, `msp_logo_url`, `msp_primary_color`,
//! `msp_support_email`) and that the branded default
//! `auth.password_reset` template uses those placeholders so a
//! password-reset email arrives with the MSP's brand on the subject,
//! logo in the header, and support email in the footer.
//!
//! Migration-immutable posture: no test here touches the migrated rows.
//! Each seeds a branded tenant and a template of its own carrying the four
//! placeholders, then asserts what the dispatcher rendered.
//!
//! PMS-1139: the first test used to borrow the migrated `auth.password_reset`
//! copy and assert what that copy SAYS before dispatching it. That is a
//! different question from whether the dispatcher injects branding, and it is
//! the question migration 139 lost and PMS-1140 has still to settle, so it
//! stood red on `main` and reddened every pull request's integration run.
//! `a_seeded_template_carries_the_branding_placeholders` below keeps the half
//! that is worth pinning, pointed at the template where the answer is settled.

mod common;

use mokosh_server::modules::notifications::NotificationsService;
use sqlx::PgPool;
use uuid::Uuid;

/// PMS-1139: at least one template the migrations seed really does carry the
/// branding placeholders, so the four values the dispatcher injects are not
/// merely available to a template somebody writes by hand.
///
/// `ticket.note_added` is the one asserted on, and deliberately so. Migration
/// 139 rebranded four seeded templates and landed on two of them; this is one
/// of the two, and no later migration contests it. The other two are
/// `auth.password_reset` and `auth.welcome`, whose copy is the open question
/// in PMS-1140, so asserting on either would make this test the place a
/// product decision is enforced.
#[sqlx::test]
async fn a_seeded_template_carries_the_branding_placeholders(pool: PgPool) {
    let subject: Option<String> = sqlx::query_scalar(
        r#"SELECT subject FROM notification_templates
           WHERE tenant_id = '00000000-0000-0000-0000-000000000001'
             AND event_type = 'ticket.note_added'
             AND channel_type = 'email'"#,
    )
    .fetch_one(&pool)
    .await
    .expect("default ticket.note_added template exists");

    assert!(
        subject.as_deref().unwrap_or("").contains("{{msp_name}}"),
        "migration 139's branding is gone from ticket.note_added: {subject:?}"
    );
}

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

    // PMS-1139: the template is this test's own, carrying all four
    // placeholders, the way the two tests below already seed theirs. It used
    // to be a copy of the migrated `auth.password_reset` row, which tied a
    // dispatcher test to what that row's copy happens to say; see the module
    // doc. What is asserted after the dispatch is unchanged.
    let new_tpl = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO notification_templates
            (id, tenant_id, name, event_type, channel_type, subject, body_text, body_html, is_active)
        VALUES ($1, $2, 'Password Reset - Email', 'auth.password_reset', 'email',
                '{{msp_name}} - Reset your password',
                E'{{msp_name}} received a request to reset your password.\n\nUse the link below within 24 hours to set a new password.\n\n{{reset_link}}\n\n-- \nSent on behalf of {{msp_name}}. Questions? Reply to {{msp_support_email}}.\n',
                '<!doctype html><html><body><div style="border-bottom:3px solid {{msp_primary_color}};"><img src="{{msp_logo_url}}" alt="{{msp_name}}"></div><p>{{msp_name}} received a request to reset your password.</p><p><a href="{{reset_link}}">{{reset_link}}</a></p><p>Questions? Reply to {{msp_support_email}}.</p></body></html>',
                TRUE)
        "#,
    )
    .bind(new_tpl)
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("seed template under branded tenant");

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
