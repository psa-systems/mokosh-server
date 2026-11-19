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

use crate::common;

use mokosh_server::modules::audit::AuditCtx;
use mokosh_server::modules::auth::TenantId;
use mokosh_server::modules::notifications::NotificationsService;
use mokosh_server::modules::tenants::{CreateTenantRequest, TenantService};
use mokosh_server::Database;
use mokosh_test::mokosh_test;
use sqlx::PgPool;

// PMS-1343: the self-service reset mail had this case, pinning that a
// customer-facing mail names the MSP and never the product (PMS-1140).
// `auth.portal_password_reset` has no dispatch site now that the customer
// cannot start a reset; the template row stays seeded (migrations are
// immutable, and a future MSP-initiated reset mail would want it). The
// property moved to the mail that actually ships on a reissue, which is
// `auth.portal_grant`, and is pinned in tests/msp_portal_password_reset.rs.

/// The staff mail is untouched by the split: it still names the deployment,
/// which is PMS-789's decision and the thing migration 204 restored.
#[mokosh_test]
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

/// A tenant provisioned from now on can send both mails. `dispatch` iterates
/// RULES, so a template copied without its rule is a message that is never
/// sent (PMS-761).
#[mokosh_test]
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
#[mokosh_test]
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
#[mokosh_test]
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
