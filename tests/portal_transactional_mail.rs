//! PMS-1140: the two transactional mails that used to serve two audiences
//! from one template.
//!
//! `auth.password_reset` and `auth.welcome` are staff-side and keep the
//! `{{app_name}}` copy migration 116 gave them (PMS-789). The portal halves
//! are their own events, seeded and backfilled by migration 206:
//! `auth.portal_password_reset` for a customer resetting their portal
//! password, which names the MSP the way every other portal-only template
//! does, and `auth.portal_welcome` for the MSP admin a tenant provisions,
//! which is the only template carrying `{{client_portal_url}}`.
//!
//! What is asserted here is the RENDERED mail, read back off the queued
//! `notifications` row, not what a template says. The defects this closes
//! were all invisible at the template: `render_template` is a flat `{{key}}`
//! replacer that emits an unsupplied key verbatim, so a template can be
//! perfect and the mail still ship a literal `{{salutation}},`.

mod common;

use mokosh_server::modules::audit::AuditCtx;
use mokosh_server::modules::auth::TenantId;
use mokosh_server::modules::notifications::NotificationsService;
use mokosh_server::modules::tenants::{CreateTenantRequest, TenantService};
use mokosh_server::Database;
use sqlx::PgPool;
use uuid::Uuid;

/// The newest queued notification for a tenant, as it would be sent.
async fn latest_mail(pool: &PgPool, tenant_id: Uuid) -> (Option<String>, String, Option<String>) {
    sqlx::query_as(
        r#"SELECT subject, body, body_html FROM notifications
           WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 1"#,
    )
    .bind(tenant_id)
    .fetch_one(pool)
    .await
    .expect("a notification was queued")
}

/// Create a tenant, give it the portal admin contact the retired create-time
/// provisioner used to write, and re-issue the welcome. Returns the tenant id.
async fn provision(svc: &TenantService, name: &str, slug: &str, first: &str, last: &str) -> Uuid {
    let tenant = svc
        .create_tenant(
            &CreateTenantRequest {
                name: name.into(),
                slug: slug.into(),
                billing_email: None,
                billing_contact_name: None,
                subscription_plan: None,
                admin_email: format!("admin@{slug}.example"),
                admin_first_name: first.into(),
                admin_last_name: last.into(),
                branding: None,
            },
            &AuditCtx::system(common::DEFAULT_TENANT_ID),
        )
        .await
        .expect("create_tenant");

    svc.insert_portal_admin_contact(tenant.id, &format!("admin@{slug}.example"), first, last)
        .await
        .expect("insert the portal admin contact");

    svc.resend_admin_welcome(
        TenantId::from_trusted(tenant.id),
        &AuditCtx::system(tenant.id),
    )
    .await
    .expect("re-issue the admin welcome");

    tenant.id
}

/// A customer resetting their portal password is told whose portal it is.
/// Before this the mail said "Reset your {{app_name}} password", naming a
/// product the customer has never heard of instead of the MSP they hired.
#[sqlx::test]
async fn the_portal_password_reset_names_the_msp_and_never_the_product(pool: PgPool) {
    sqlx::query("UPDATE tenants SET name = 'Niceguy IT' WHERE id = $1")
        .bind(common::DEFAULT_TENANT_ID)
        .execute(&pool)
        .await
        .expect("name the tenant");

    let company = Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, 'Acme Co')")
        .bind(company)
        .bind(common::DEFAULT_TENANT_ID)
        .execute(&pool)
        .await
        .expect("seed company");
    let contact = common::seed_portal_contact(&pool, company, "customer@acme.example", &[]).await;

    let app = common::boot(pool.clone()).await;
    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/forgot-password"))
        .json(&serde_json::json!({ "slug": contact.slug, "email": contact.email }))
        .send()
        .await
        .expect("send forgot-password");
    assert_eq!(resp.status(), reqwest::StatusCode::NO_CONTENT);

    let (subject, body, html) = latest_mail(&pool, common::DEFAULT_TENANT_ID).await;
    let subject = subject.expect("subject rendered");
    assert!(
        subject.contains("Niceguy IT"),
        "the customer is told whose portal this is: {subject}"
    );
    assert!(body.contains("Niceguy IT"), "and so does the body: {body}");
    assert!(
        body.contains("/reset-password?token="),
        "the reset link survived the split: {body}"
    );

    // The product name must not reach a customer. `Mokosh` is the default
    // app name, so its absence is the check that this mail is not the staff
    // template wearing a new event name.
    for rendered in [&subject, &body, html.as_ref().expect("html rendered")] {
        assert!(
            !rendered.contains("Mokosh"),
            "the product name reached a customer: {rendered}"
        );
        assert!(
            !rendered.contains("{{"),
            "unresolved placeholder in a customer's inbox: {rendered}"
        );
    }
}

/// The staff mail is untouched by the split: it still names the deployment,
/// which is PMS-789's decision and the thing migration 204 restored.
#[sqlx::test]
async fn the_staff_password_reset_still_names_the_deployment(pool: PgPool) {
    let subject: Option<String> = sqlx::query_scalar(
        r#"SELECT subject FROM notification_templates
           WHERE tenant_id = $1 AND event_type = 'auth.password_reset'
             AND channel_type = 'email'"#,
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(&pool)
    .await
    .expect("staff template exists");
    assert_eq!(
        subject.as_deref(),
        Some("Reset your {{app_name}} password"),
        "PMS-789's copy is what the staff mail keeps"
    );
}

/// The MSP admin's welcome mail, which reaches an inbox through
/// `resend_admin_welcome`: the create-time provisioner is retired pending
/// the MAPPS-656/657 restoration decision, so the re-issue path is the live
/// one and `insert_portal_admin_contact` is `pub` for exactly this reason.
///
/// Two defects are pinned here, both of which were shipping: the mail opened
/// with a literal `{{salutation}},` because this path supplies `display_name`
/// and the shared template asked for `salutation`, and it never named the
/// portal, because migration 152 was the only thing that would have
/// referenced `client_portal_url` and its guard matched zero rows.
#[sqlx::test]
async fn the_admin_welcome_greets_the_admin_and_names_their_portal(pool: PgPool) {
    let notifications =
        NotificationsService::with_encryption_key(Database::from_pool(pool.clone()), [0u8; 32]);
    let svc = TenantService::new(Database::from_pool(pool.clone()))
        .with_dispatcher(notifications, "http://spa.test:4301".into());

    let tenant = provision(&svc, "Fabrikam IT", "fabrikam-pms1140", "Ada", "Admin").await;

    let (subject, body, html) = latest_mail(&pool, tenant).await;
    let subject = subject.expect("subject rendered");
    let html = html.expect("html rendered");

    assert!(
        body.starts_with("Hello Ada Admin,"),
        "the admin is greeted by name, not with a placeholder: {body}"
    );
    assert!(
        body.contains("invite your clients to their portal at"),
        "and told where their portal is, which migration 152 never managed: {body}"
    );
    assert!(
        html.contains("invite your clients to their portal"),
        "the html says it too: {html}"
    );
    assert!(
        body.contains("/portal/set-password?token="),
        "the setup link survived the split: {body}"
    );
    for rendered in [&subject, &body, &html] {
        assert!(
            !rendered.contains("{{"),
            "unresolved placeholder in the admin's inbox: {rendered}"
        );
        assert!(
            !rendered.contains("{%"),
            "the renderer has no conditionals, so one would ship verbatim: {rendered}"
        );
    }
}

/// The greeting with nothing to greet. PMS-774's rule is that a missing name
/// reads "Hello" rather than "Hello ,", and the fix for the placeholder had
/// to adopt that rule rather than interpolate a bare name.
#[sqlx::test]
async fn the_admin_welcome_reads_correctly_with_no_name_on_file(pool: PgPool) {
    let notifications =
        NotificationsService::with_encryption_key(Database::from_pool(pool.clone()), [0u8; 32]);
    let svc = TenantService::new(Database::from_pool(pool.clone()))
        .with_dispatcher(notifications, "http://spa.test:4301".into());

    let tenant = provision(&svc, "Contoso IT", "contoso-pms1140", "  ", "").await;

    let (_, body, _) = latest_mail(&pool, tenant).await;
    assert!(
        body.starts_with("Hello,"),
        "a missing name reads 'Hello,' and never 'Hello ,': {body}"
    );
}

/// A tenant provisioned from now on can send both mails. `dispatch` iterates
/// RULES, so a template copied without its rule is a message that is never
/// sent (PMS-761), and the welcome above is how this very call reaches the
/// admin it just created.
#[sqlx::test]
async fn a_new_tenant_can_send_both_portal_mails(pool: PgPool) {
    let svc = TenantService::new(Database::from_pool(pool.clone()));
    let tenant = svc
        .create_tenant(
            &CreateTenantRequest {
                name: "Northwind IT".into(),
                slug: "northwind-pms1140".into(),
                billing_email: None,
                billing_contact_name: None,
                subscription_plan: None,
                admin_email: "owner@northwind.example".into(),
                admin_first_name: "Nora".into(),
                admin_last_name: "North".into(),
                branding: None,
            },
            &AuditCtx::system(common::DEFAULT_TENANT_ID),
        )
        .await
        .expect("create_tenant");

    for event in ["auth.portal_password_reset", "auth.portal_welcome"] {
        let usable: i64 = sqlx::query_scalar(
            r#"SELECT COUNT(*) FROM notification_rules r
               JOIN notification_templates t
                 ON t.id = r.template_id AND t.tenant_id = r.tenant_id
               WHERE r.tenant_id = $1 AND r.event_type = $2 AND r.is_active"#,
        )
        .bind(tenant.id)
        .bind(event)
        .fetch_one(&pool)
        .await
        .expect("count usable rules");
        assert_eq!(
            usable, 1,
            "a new tenant needs an active {event} rule pointing at its own template, or the mail is never sent",
        );
    }
}

/// A tenant that existed before migration 206 got both by backfill. Without
/// it, switching the dispatch sites over would have stopped the mail for
/// every tenant already provisioned, silently: `dispatch` finds no rule,
/// sends nothing and reports success.
#[sqlx::test]
async fn a_tenant_that_predates_the_migration_was_backfilled(pool: PgPool) {
    // The default tenant is migration 023's and predates 206 by definition.
    for event in ["auth.portal_password_reset", "auth.portal_welcome"] {
        let usable: i64 = sqlx::query_scalar(
            r#"SELECT COUNT(*) FROM notification_rules r
               JOIN notification_templates t
                 ON t.id = r.template_id AND t.tenant_id = r.tenant_id
               WHERE r.tenant_id = $1 AND r.event_type = $2 AND r.is_active"#,
        )
        .bind(common::DEFAULT_TENANT_ID)
        .bind(event)
        .fetch_one(&pool)
        .await
        .expect("count usable rules");
        assert_eq!(usable, 1, "{event} must be usable on a pre-206 tenant");
    }
}

/// The dispatcher is what decides which template renders, so the two portal
/// events must not resolve to the staff copy. Cheap, and it is the assertion
/// that would have caught the original defect the day it landed.
#[sqlx::test]
async fn the_two_planes_render_from_different_templates(pool: PgPool) {
    let service =
        NotificationsService::with_encryption_key(Database::from_pool(pool.clone()), [0u8; 32]);
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);

    let staff = service
        .preview(
            tenant,
            "auth.password_reset",
            &serde_json::json!({ "reset_link": "https://example.test/r" }),
        )
        .await
        .expect("preview staff reset");
    let portal = service
        .preview(
            tenant,
            "auth.portal_password_reset",
            &serde_json::json!({ "reset_link": "https://example.test/r" }),
        )
        .await
        .expect("preview portal reset");

    let staff_subject = staff
        .first()
        .expect("a staff rule fires")
        .subject
        .clone()
        .unwrap_or_default();
    let portal_subject = portal
        .first()
        .expect("a portal rule fires")
        .subject
        .clone()
        .unwrap_or_default();
    assert_ne!(
        staff_subject, portal_subject,
        "the two planes must not collapse back onto one template"
    );
}
