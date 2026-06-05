//! Integration test: backfill default worker notification rules into
//! pre-existing tenants (feat/notifications-seed-existing-tenants).
//!
//! Background: new tenants get the in-app worker templates + rules for
//! event_type ('appointment.reminder', 'sla.at_risk', 'sla.breached')
//! from TenantService::copy_default_config
//! (src/modules/tenants/service.rs, lines 458-502). Tenants created
//! before that seeding landed lack those rows, so the SLA sweep and
//! appointment-reminder workers never auto-deliver for them. Migration
//! 030_backfill_notification_rules.sql backfills the same rows for every
//! existing tenant that is missing them, idempotently.
//!
//! Why the SQL is duplicated here: `#[sqlx::test]` applies ALL migrations
//! (including 030) before the test body runs, so re-asserting the
//! migration against a fresh tenant created inside the test requires
//! re-running the backfill statements. The two statements below are a
//! verbatim copy of migration 030's two INSERTs; if the migration
//! changes, update this fixture to match. The test creates a tenant with
//! NO notification rules (mirroring a pre-seeding tenant), runs the
//! backfill, and asserts:
//!   * the tenant gains exactly the three default worker rules, each
//!     linked to its own copied template by (event_type, channel_type);
//!   * running the backfill a second time is a no-op (no duplicate
//!     templates or rules).

mod common;

use sqlx::PgPool;
use uuid::Uuid;

const DEFAULT_TENANT: Uuid = Uuid::from_u128(1);

/// The three worker event types a new tenant (and therefore the backfill)
/// seeds. Mirrors the IN (...) filter in migration 030 and
/// copy_default_config.
const WORKER_EVENTS: [&str; 3] = ["appointment.reminder", "sla.at_risk", "sla.breached"];

/// Run the backfill statements from migration 030 against the live pool.
/// Verbatim copy of the migration's two INSERTs, wrapped in a DO block so
/// the local `default_tenant` constant matches the migration's shape.
async fn run_backfill(pool: &PgPool) {
    sqlx::query(
        r#"
        DO $$
        DECLARE
            default_tenant CONSTANT uuid := '00000000-0000-0000-0000-000000000001';
        BEGIN
            INSERT INTO notification_templates
                (tenant_id, name, event_type, channel_type, subject, body_text, body_html, is_active)
            SELECT t.id, src.name, src.event_type, src.channel_type,
                   src.subject, src.body_text, src.body_html, src.is_active
            FROM tenants t
            CROSS JOIN notification_templates src
            WHERE src.tenant_id = default_tenant
              AND src.event_type IN ('appointment.reminder', 'sla.at_risk', 'sla.breached')
              AND t.id <> default_tenant
              AND NOT EXISTS (
                  SELECT 1
                  FROM notification_templates existing
                  WHERE existing.tenant_id = t.id
                    AND existing.event_type = src.event_type
                    AND existing.channel_type = src.channel_type
              );

            INSERT INTO notification_rules
                (tenant_id, name, event_type, channels, recipients, template_id, is_active)
            SELECT t.id, r.name, r.event_type, r.channels, r.recipients, nt.id, r.is_active
            FROM tenants t
            CROSS JOIN notification_rules r
            JOIN notification_templates ot
              ON ot.id = r.template_id AND ot.tenant_id = default_tenant
            JOIN notification_templates nt
              ON nt.tenant_id = t.id
             AND nt.event_type = ot.event_type
             AND nt.channel_type = ot.channel_type
            WHERE r.tenant_id = default_tenant
              AND r.event_type IN ('appointment.reminder', 'sla.at_risk', 'sla.breached')
              AND t.id <> default_tenant
              AND NOT EXISTS (
                  SELECT 1
                  FROM notification_rules existing
                  WHERE existing.tenant_id = t.id
                    AND existing.event_type = r.event_type
                    AND existing.template_id = nt.id
              );
        END $$;
        "#,
    )
    .execute(pool)
    .await
    .expect("run backfill");
}

async fn active_rule_count(pool: &PgPool, tenant_id: Uuid) -> i64 {
    sqlx::query_scalar(
        r#"SELECT COUNT(*)
           FROM notification_rules
           WHERE tenant_id = $1
             AND event_type = ANY($2)
             AND is_active = TRUE"#,
    )
    .bind(tenant_id)
    .bind(&WORKER_EVENTS[..])
    .fetch_one(pool)
    .await
    .expect("count worker rules")
}

async fn template_count(pool: &PgPool, tenant_id: Uuid) -> i64 {
    sqlx::query_scalar(
        r#"SELECT COUNT(*)
           FROM notification_templates
           WHERE tenant_id = $1
             AND event_type = ANY($2)"#,
    )
    .bind(tenant_id)
    .bind(&WORKER_EVENTS[..])
    .fetch_one(pool)
    .await
    .expect("count worker templates")
}

#[sqlx::test]
async fn backfills_missing_rules_then_is_idempotent(pool: PgPool) {
    // A pre-seeding tenant: bare tenant row, NO notification rules or
    // templates. seed_tenant_with_admin inserts only the tenants row (+
    // admin), so it has none of the worker rows.
    let (tenant_id, _admin_id, _email, _password) =
        common::seed_tenant_with_admin(&pool, "backfill-co").await;

    // Sanity: the new tenant starts with none of the worker rows.
    assert_eq!(
        active_rule_count(&pool, tenant_id).await,
        0,
        "fresh tenant must start with no worker notification rules",
    );
    assert_eq!(
        template_count(&pool, tenant_id).await,
        0,
        "fresh tenant must start with no worker notification templates",
    );

    // First backfill: tenant gains exactly the three default worker
    // rules + their three templates.
    run_backfill(&pool).await;

    assert_eq!(
        template_count(&pool, tenant_id).await,
        3,
        "backfill must copy the three worker templates",
    );
    assert_eq!(
        active_rule_count(&pool, tenant_id).await,
        3,
        "backfill must copy the three worker rules",
    );

    // The copied rule set matches the default tenant's worker rule set,
    // event-for-event.
    let mut got: Vec<String> = sqlx::query_scalar(
        r#"SELECT event_type FROM notification_rules
           WHERE tenant_id = $1 AND event_type = ANY($2) ORDER BY event_type"#,
    )
    .bind(tenant_id)
    .bind(&WORKER_EVENTS[..])
    .fetch_all(&pool)
    .await
    .expect("list backfilled rule events");
    got.sort();
    let mut want: Vec<String> = WORKER_EVENTS.iter().map(|s| s.to_string()).collect();
    want.sort();
    assert_eq!(
        got, want,
        "backfilled events must match the worker event set"
    );

    // Every backfilled rule's template_id points at a template owned by
    // the SAME tenant with a matching (event_type, channel_type) - i.e.
    // the re-link worked and no rule leaks across tenants.
    let mislinked: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)
           FROM notification_rules r
           LEFT JOIN notification_templates t
             ON t.id = r.template_id
            AND t.tenant_id = r.tenant_id
            AND t.event_type = r.event_type
           WHERE r.tenant_id = $1
             AND r.event_type = ANY($2)
             AND t.id IS NULL"#,
    )
    .bind(tenant_id)
    .bind(&WORKER_EVENTS[..])
    .fetch_one(&pool)
    .await
    .expect("count mislinked rules");
    assert_eq!(
        mislinked, 0,
        "every backfilled rule must link to its own tenant's matching template",
    );

    // Second backfill: idempotent no-op. Counts unchanged.
    run_backfill(&pool).await;

    assert_eq!(
        template_count(&pool, tenant_id).await,
        3,
        "second backfill must not duplicate templates",
    );
    assert_eq!(
        active_rule_count(&pool, tenant_id).await,
        3,
        "second backfill must not duplicate rules",
    );

    // The default tenant itself is excluded as a target (it is the
    // source), so the backfill never adds duplicate worker rows to it.
    // Migration 027/028 seeded exactly one rule per worker event there.
    assert_eq!(
        active_rule_count(&pool, DEFAULT_TENANT).await,
        3,
        "default tenant keeps exactly its seeded worker rules",
    );
}
