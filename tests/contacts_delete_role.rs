//! PMS-1298: deleting a company, contact or site needs the manager role.

mod common;

use mokosh_test::mokosh_test;
use sqlx::PgPool;
use uuid::Uuid;

const TENANT: Uuid = common::DEFAULT_TENANT_ID;

async fn seed_company(pool: &PgPool) -> Uuid {
    sqlx::query_scalar("INSERT INTO companies (tenant_id, name) VALUES ($1, 'Acme') RETURNING id")
        .bind(TENANT)
        .fetch_one(pool)
        .await
        .expect("seed company")
}

async fn seed_contact(pool: &PgPool) -> Uuid {
    let company = seed_company(pool).await;
    sqlx::query_scalar(
        "INSERT INTO contacts (tenant_id, company_id, first_name, last_name, email) \
         VALUES ($1, $2, 'Jane', 'Doe', $3) RETURNING id",
    )
    .bind(TENANT)
    .bind(company)
    .bind(format!("jane.{}@example.com", Uuid::new_v4()))
    .fetch_one(pool)
    .await
    .expect("seed contact")
}

async fn seed_site(pool: &PgPool) -> Uuid {
    let company = seed_company(pool).await;
    sqlx::query_scalar(
        "INSERT INTO sites (tenant_id, company_id, name) VALUES ($1, $2, 'HQ') RETURNING id",
    )
    .bind(TENANT)
    .bind(company)
    .fetch_one(pool)
    .await
    .expect("seed site")
}

async fn delete_status(app: &common::TestApp, token: &str, path: &str) -> u16 {
    app.client
        .delete(app.url(path))
        .bearer_auth(token)
        .send()
        .await
        .expect("delete request")
        .status()
        .as_u16()
}

/// Technician is refused with 403 and the row survives; manager succeeds.
async fn check(pool: PgPool, kind: &str, id: Uuid) {
    let (_, tech_email, pw) =
        common::seed_user(&pool, TENANT, "tech@example.com", "technician").await;
    let (_, mgr_email, _) = common::seed_user(&pool, TENANT, "mgr@example.com", "manager").await;
    let table = format!("{kind}s").replace("companys", "companies");
    let path = format!("/api/v1/contacts/{table}/{id}");
    let app = common::boot(pool.clone()).await;

    let tech = common::login(&app, &tech_email, &pw).await;
    assert_eq!(delete_status(&app, &tech, &path).await, 403);
    let left: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM {table} WHERE id = $1"))
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(left, 1, "a refused delete must not remove the row");

    let mgr = common::login(&app, &mgr_email, &pw).await;
    let status = delete_status(&app, &mgr, &path).await;
    assert!((200..300).contains(&status), "manager delete got {status}");
}

#[mokosh_test]
async fn company_delete_needs_manager(pool: PgPool) {
    let id = seed_company(&pool).await;
    check(pool, "company", id).await;
}

#[mokosh_test]
async fn contact_delete_needs_manager(pool: PgPool) {
    let id = seed_contact(&pool).await;
    check(pool, "contact", id).await;
}

#[mokosh_test]
async fn site_delete_needs_manager(pool: PgPool) {
    let id = seed_site(&pool).await;
    check(pool, "site", id).await;
}
