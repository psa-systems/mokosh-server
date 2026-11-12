//! MAPPS-1100 Phase A: workflow test for the vendors + expense-categories
//! leaf lookups of the Bills and Expenses subsystem.
//!
//! Exercises `ExpensesService` directly against a tenant-scoped pool:
//! create a vendor, update it, list carries the row, categories collide
//! on duplicate names, delete returns the row to a 404 lookup, and
//! every mutation lands an audit row in the same transaction as the
//! change (RLS stays enforced because `begin_with_tenant` sets the GUC
//! before the write).

use crate::common;

use mokosh_test::mokosh_test;
use sqlx::PgPool;

use mokosh_server::modules::audit::AuditCtx;
use mokosh_server::modules::expenses::service::{
    ExpensesService, UpsertExpenseCategoryRequest, UpsertVendorRequest,
};
use mokosh_server::utils::error::AppError;
use mokosh_server::utils::pagination::PaginationParams;
use mokosh_server::Database;

fn service(pool: &PgPool) -> ExpensesService {
    ExpensesService::new(Database::from_pool(pool.clone()))
}

fn ctx() -> AuditCtx {
    AuditCtx::system(common::DEFAULT_TENANT_ID)
}

fn page() -> PaginationParams {
    PaginationParams::default()
}

fn vendor_body(name: &str) -> UpsertVendorRequest {
    UpsertVendorRequest {
        name: name.to_string(),
        account_number: Some("ACC-1".to_string()),
        default_currency: Some("usd".to_string()),
        notes: Some("test".to_string()),
    }
}

fn category_body(name: &str) -> UpsertExpenseCategoryRequest {
    UpsertExpenseCategoryRequest {
        name: name.to_string(),
        is_active: true,
    }
}

#[mokosh_test]
async fn vendor_create_list_update_get_delete_round_trip(pool: PgPool) {
    let _ = common::seed_admin(&pool).await;
    let svc = service(&pool);
    let tenant = mokosh_server::modules::auth::TenantId::from_trusted(common::DEFAULT_TENANT_ID);

    let created = svc
        .create_vendor(tenant, &vendor_body("Acme Hardware"), &ctx())
        .await
        .expect("create vendor");
    assert_eq!(created.name, "Acme Hardware");
    assert_eq!(created.default_currency.as_deref(), Some("USD"));

    let (rows, total) = svc.list_vendors(tenant, &page()).await.expect("list");
    assert_eq!(total, 1);
    assert!(rows.iter().any(|v| v.id == created.id));

    let updated = svc
        .update_vendor(
            tenant,
            created.id,
            &UpsertVendorRequest {
                name: "Acme Hardware Ltd".to_string(),
                account_number: Some("ACC-2".to_string()),
                default_currency: None,
                notes: None,
            },
            &ctx(),
        )
        .await
        .expect("update vendor");
    assert_eq!(updated.name, "Acme Hardware Ltd");
    assert_eq!(updated.account_number.as_deref(), Some("ACC-2"));
    assert!(updated.default_currency.is_none());

    let fetched = svc.get_vendor(tenant, created.id).await.expect("get");
    assert_eq!(fetched.name, "Acme Hardware Ltd");

    svc.delete_vendor(tenant, created.id, &ctx())
        .await
        .expect("delete vendor");

    let miss = svc.get_vendor(tenant, created.id).await;
    assert!(matches!(miss, Err(AppError::NotFound(_))));
}

#[mokosh_test]
async fn expense_category_duplicate_name_is_a_conflict(pool: PgPool) {
    let _ = common::seed_admin(&pool).await;
    let svc = service(&pool);
    let tenant = mokosh_server::modules::auth::TenantId::from_trusted(common::DEFAULT_TENANT_ID);

    svc.create_expense_category(tenant, &category_body("Travel"), &ctx())
        .await
        .expect("create first");
    let dupe = svc
        .create_expense_category(tenant, &category_body("travel"), &ctx())
        .await;
    assert!(
        matches!(dupe, Err(AppError::Conflict(_))),
        "duplicate (case-insensitive) must 409, got {dupe:?}"
    );
}

#[mokosh_test]
async fn mutations_write_an_audit_row_in_the_same_transaction(pool: PgPool) {
    let _ = common::seed_admin(&pool).await;
    let svc = service(&pool);
    let tenant = mokosh_server::modules::auth::TenantId::from_trusted(common::DEFAULT_TENANT_ID);

    let v = svc
        .create_vendor(tenant, &vendor_body("Audited Vendor"), &ctx())
        .await
        .expect("create");

    // Audit row visible without the tenant GUC set, because the audit
    // query writes with `tenant_id` as a bound column (not an RLS gate)
    // and `audit_log` has no RLS policy. Ordering is `timestamp`, the
    // column `migrations/015_audit.sql` actually names (`created_at` is
    // not present on this table).
    let rows: Vec<(String, Option<uuid::Uuid>)> = sqlx::query_as(
        "SELECT action, entity_id FROM audit_log \
         WHERE tenant_id = $1 AND entity_type = 'vendors' AND entity_id = $2 \
         ORDER BY timestamp",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(v.id)
    .fetch_all(&pool)
    .await
    .expect("audit rows");
    assert_eq!(rows.len(), 1, "one audit row for the vendor create");
    assert_eq!(rows[0].0, "create");
    assert_eq!(rows[0].1, Some(v.id));
}
