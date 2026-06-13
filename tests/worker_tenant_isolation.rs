//! PMS-261 regression: a cross-tenant background worker's per-tenant unit of
//! work is confined to the tenant it is processing.
//!
//! The notifications dispatcher ([`NotificationsService::dispatch`]) is the
//! shared fan-out behind the calendar-reminder and SLA-sweep workers: each
//! worker enumerates tenants, then calls `dispatch(TenantId::from_trusted(t),
//! ..)` per tenant. This test seeds a matching rule + template under BOTH
//! tenant A and tenant B for the same event, then drives the dispatcher for
//! tenant A only. It asserts the worker neither READS tenant B's rule (only
//! tenant A's rule fires) nor WRITES a notification row under tenant B, and
//! that tenant A's row resolves against tenant A's own template (exercising the
//! tenant-scoped template lookup the audit added in `service.rs`).

mod common;

use mokosh_server::modules::auth::TenantId;
use mokosh_server::modules::notifications::NotificationsService;
use mokosh_server::Database;
use sqlx::PgPool;
use uuid::Uuid;

/// Seed one `email`-channel rule plus its template for `tenant_id`, with the
/// recipient carried on the rule itself (no context recipient needed at
/// dispatch). Returns the template id so the caller can pin which tenant's
/// template a dispatched row resolved against.
async fn seed_rule_and_template(
    pool: &PgPool,
    tenant_id: Uuid,
    event_type: &str,
    subject: &str,
    recipient_email: &str,
) -> Uuid {
    let template_id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO notification_templates
            (id, tenant_id, name, event_type, channel_type, subject, body_text, body_html, is_active)
           VALUES ($1, $2, $3, $4, 'email', $5, 'probe body', NULL, TRUE)"#,
    )
    .bind(template_id)
    .bind(tenant_id)
    .bind(format!("tmpl-{subject}"))
    .bind(event_type)
    .bind(subject)
    .execute(pool)
    .await
    .expect("seed template");

    sqlx::query(
        r#"INSERT INTO notification_rules
            (id, tenant_id, name, event_type, channels, recipients, template_id, is_active)
           VALUES ($1, $2, $3, $4, ARRAY['email']::VARCHAR(20)[], $5, $6, TRUE)"#,
    )
    .bind(Uuid::new_v4())
    .bind(tenant_id)
    .bind(format!("rule-{subject}"))
    .bind(event_type)
    .bind(serde_json::json!({ "user_ids": [], "emails": [recipient_email] }))
    .bind(template_id)
    .execute(pool)
    .await
    .expect("seed rule");

    template_id
}

#[sqlx::test]
async fn worker_dispatch_is_tenant_confined(pool: PgPool) {
    // Tenant A is the default tenant the seed migration inserts; tenant B is a
    // second, fully distinct tenant.
    let tenant_a = common::DEFAULT_TENANT_ID;
    let (tenant_b, _b_uid, _b_email, _b_pw) =
        common::seed_tenant_with_admin(&pool, "pms261-tenant-b").await;
    let event_type = "worker.iso_probe";

    let template_a = seed_rule_and_template(
        &pool,
        tenant_a,
        event_type,
        "TENANT_A_SUBJECT",
        "a-recipient@example.test",
    )
    .await;
    let _template_b = seed_rule_and_template(
        &pool,
        tenant_b,
        event_type,
        "TENANT_B_SUBJECT",
        "b-recipient@example.test",
    )
    .await;

    let svc =
        NotificationsService::with_encryption_key(Database::from_pool(pool.clone()), [0u8; 32]);

    // The worker processes tenant A. `from_trusted` mirrors the worker call
    // sites (calendar/worker.rs, sla/worker.rs), which read the tenant id off a
    // DB-projected row.
    let fanout = svc
        .dispatch(
            TenantId::from_trusted(tenant_a),
            event_type,
            &serde_json::json!({}),
        )
        .await
        .expect("dispatch for tenant A");

    // Read confinement: exactly tenant A's single email rule fired. If the
    // worker had read tenant B's rule too, fanout would be 2.
    assert_eq!(
        fanout, 1,
        "dispatch for tenant A must fire only tenant A's rule, got fanout={fanout}",
    );

    // Write confinement: nothing was written under tenant B.
    let b_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM notifications WHERE tenant_id = $1")
            .bind(tenant_b)
            .fetch_one(&pool)
            .await
            .expect("count tenant B notifications");
    assert_eq!(
        b_count, 0,
        "a worker processing tenant A must not write tenant B rows",
    );

    // Tenant A got exactly one row, resolved against tenant A's own template and
    // recipient - proving the tenant-scoped template lookup resolved correctly.
    let a_rows: Vec<(Option<String>, Option<String>, Option<Uuid>)> = sqlx::query_as(
        "SELECT subject, recipient, template_id FROM notifications WHERE tenant_id = $1",
    )
    .bind(tenant_a)
    .fetch_all(&pool)
    .await
    .expect("query tenant A notifications");
    assert_eq!(
        a_rows.len(),
        1,
        "tenant A should have exactly one notification, got {a_rows:?}",
    );
    let (subject, recipient, template_id) = a_rows.into_iter().next().unwrap();
    assert_eq!(subject.as_deref(), Some("TENANT_A_SUBJECT"));
    assert_eq!(recipient.as_deref(), Some("a-recipient@example.test"));
    assert_eq!(
        template_id,
        Some(template_a),
        "row must reference tenant A's template, not tenant B's",
    );

    // Belt-and-suspenders: tenant B's recipient never appears anywhere.
    let leaked: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM notifications WHERE recipient = 'b-recipient@example.test'",
    )
    .fetch_one(&pool)
    .await
    .expect("count leaked recipients");
    assert_eq!(leaked, 0, "tenant B's recipient must never appear");
}
