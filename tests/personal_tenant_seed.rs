//! PMS-259: per-personal-tenant lookup seeding + the system-shared class.
//!
//! Drives `TenantService::ensure_personal_tenant` directly against a per-test
//! database (mirroring `tests/contracts.rs`). A freshly provisioned personal
//! tenant must start with the full default set of editable lookups copied from
//! the migration-023 default tenant, isolated from every other tenant, and the
//! copy must be idempotent. A second test exercises the reserved system-shared
//! read-only class mechanism from migration 039.

mod common;

use mokosh_server::modules::tenants::TenantService;
use mokosh_server::Database;
use sqlx::PgPool;
use uuid::Uuid;

async fn count(pool: &PgPool, table: &str, tenant: Uuid) -> i64 {
    sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM {table} WHERE tenant_id = $1"
    ))
    .bind(tenant)
    .fetch_one(pool)
    .await
    .expect("count rows")
}

/// A fresh personal tenant is seeded with the full default lookup set, and two
/// users' tenants are fully isolated from each other.
#[sqlx::test]
async fn personal_tenant_seeded_with_full_default_lookups(pool: PgPool) {
    let svc = TenantService::new(Database::from_pool(pool.clone()));

    let owner_a = Uuid::new_v4();
    let owner_b = Uuid::new_v4();
    let tenant_a = svc
        .ensure_personal_tenant(owner_a)
        .await
        .expect("provision A");
    let tenant_b = svc
        .ensure_personal_tenant(owner_b)
        .await
        .expect("provision B");

    assert_ne!(
        tenant_a, tenant_b,
        "each owner gets a distinct personal tenant"
    );
    assert_ne!(tenant_a, common::DEFAULT_TENANT_ID);

    // The default set the migration-023 seed defines for the default tenant.
    let expected: &[(&str, i64)] = &[
        ("ticket_statuses", 8),
        ("ticket_priorities", 4),
        ("ticket_types", 6),
        ("work_types", 9),
        ("task_statuses", 5),
        ("business_hours", 1),
        ("tax_rates", 1),
        ("rate_cards", 1),
        ("time_rounding_rules", 1),
        ("sla_policies", 1),
    ];

    for &(table, want) in expected {
        for tenant in [tenant_a, tenant_b] {
            assert_eq!(
                count(&pool, table, tenant).await,
                want,
                "{table} should have {want} seeded rows in tenant {tenant}"
            );
        }
    }

    // FK-re-linked rows landed and point at the same tenant's parents.
    // sla_targets has no tenant_id; it is scoped through its policy.
    let targets_via_policy = |tenant: Uuid| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, i64>(
                r#"SELECT COUNT(*) FROM sla_targets t
                   JOIN sla_policies p ON p.id = t.sla_policy_id
                   WHERE p.tenant_id = $1"#,
            )
            .bind(tenant)
            .fetch_one(&pool)
            .await
            .expect("count targets")
        }
    };
    assert_eq!(
        targets_via_policy(tenant_a).await,
        targets_via_policy(common::DEFAULT_TENANT_ID).await,
        "sla_targets are re-linked into the new tenant's policy",
    );
    let rate_items_a: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM rate_card_items i
           JOIN rate_cards c ON c.id = i.rate_card_id
           WHERE c.tenant_id = $1"#,
    )
    .bind(tenant_a)
    .fetch_one(&pool)
    .await
    .expect("count A rate items");
    assert_eq!(
        rate_items_a, 9,
        "rate_card_items re-linked, one per work type"
    );

    // Isolation: the rows in A's tenant are not visible under B's tenant id and
    // vice versa (every editable lookup carries the owning tenant_id).
    let a_status_ids: Vec<Uuid> =
        sqlx::query_scalar("SELECT id FROM ticket_statuses WHERE tenant_id = $1")
            .bind(tenant_a)
            .fetch_all(&pool)
            .await
            .expect("A status ids");
    let cross: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM ticket_statuses WHERE tenant_id = $1 AND id = ANY($2)",
    )
    .bind(tenant_b)
    .bind(&a_status_ids)
    .fetch_one(&pool)
    .await
    .expect("cross count");
    assert_eq!(cross, 0, "tenant B shares no lookup rows with tenant A");

    // Idempotent: re-provisioning returns the same tenant and does not duplicate.
    let again = svc
        .ensure_personal_tenant(owner_a)
        .await
        .expect("re-provision A");
    assert_eq!(again, tenant_a);
    assert_eq!(
        count(&pool, "ticket_statuses", tenant_a).await,
        8,
        "re-provisioning must not double-seed",
    );
}

/// The reserved system-shared class (migration 039): a `tenant_id IS NULL` row
/// is read-only to ordinary sessions and globally visible once written by a
/// privileged session.
#[sqlx::test]
async fn system_shared_class_guards_global_rows(pool: PgPool) {
    // Opt a lookup table into the class (drops NOT NULL + attaches the guard).
    sqlx::query("SELECT mokosh_enable_system_shared('tax_rates')")
        .execute(&pool)
        .await
        .expect("enable system-shared on tax_rates");

    // Without the privilege flag, writing a global (tenant_id IS NULL) row is
    // rejected by the DB guard.
    let blocked =
        sqlx::query("INSERT INTO tax_rates (tenant_id, name, rate) VALUES (NULL, 'Global', 0.0)")
            .execute(&pool)
            .await;
    assert!(
        blocked.is_err(),
        "ordinary session cannot write a system-shared row"
    );

    // A privileged session (app.allow_system_writes = on) may write the global
    // row, and it is then visible without any tenant context set.
    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("SET LOCAL app.allow_system_writes = 'on'")
        .execute(&mut *tx)
        .await
        .expect("set privilege");
    sqlx::query("INSERT INTO tax_rates (tenant_id, name, rate) VALUES (NULL, 'Global', 0.0)")
        .execute(&mut *tx)
        .await
        .expect("privileged insert of global row");
    tx.commit().await.expect("commit");

    let globals: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tax_rates WHERE tenant_id IS NULL")
        .fetch_one(&pool)
        .await
        .expect("count globals");
    assert_eq!(globals, 1, "the global system-shared row persisted");
}
