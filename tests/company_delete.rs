//! Integration regression test for PMS-170.
//!
//! `DELETE /api/v1/contacts/companies/{id}` must return 400 (not 500) when the
//! company is still referenced by a child row. `delete_company` explicitly
//! guards only `tickets`; every other table that foreign-keys `companies` is
//! `ON DELETE RESTRICT`, so the DELETE raises Postgres `23503`, which used to
//! fall through the generic error mapping to a 500. The fix maps `23503` to a
//! BadRequest.
//!
//! Uses the self-referential `companies.parent_company_id` FK as the minimal
//! blocker (no other tables / FKs to satisfy): a child company referencing the
//! parent makes the parent undeletable.

mod common;

use sqlx::PgPool;
use uuid::Uuid;

#[sqlx::test]
async fn delete_company_with_child_returns_400_not_500(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;

    let parent = Uuid::new_v4();
    let child = Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, 'Parent Co')")
        .bind(parent)
        .bind(common::DEFAULT_TENANT_ID)
        .execute(&pool)
        .await
        .expect("seed parent company");
    sqlx::query(
        "INSERT INTO companies (id, tenant_id, name, parent_company_id) \
         VALUES ($1, $2, 'Child Co', $3)",
    )
    .bind(child)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(parent)
    .execute(&pool)
    .await
    .expect("seed child company");

    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let resp = app
        .client
        .delete(app.url(&format!("/api/v1/contacts/companies/{parent}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("delete company request");

    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    assert_eq!(
        status.as_u16(),
        400,
        "delete of a company with a child should be 400, got {status} (body: {body})"
    );
}
