//! Integration tests: audit log (PMS-117).
//!
//! Covers the AC1 in-transaction write path (a mutation records a row with
//! actor + before/after) and the AC2/AC5 read path (admin-only, tenant-scoped;
//! cross-tenant rows are not visible).

mod common;

use sqlx::PgPool;
use uuid::Uuid;

#[sqlx::test]
async fn update_writes_audit_entry_with_before_and_after(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    // Create a company, then rename it.
    let created: serde_json::Value = app
        .client
        .post(app.url("/api/v1/contacts/companies"))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "name": "Acme Co" }))
        .send()
        .await
        .expect("create company")
        .json()
        .await
        .expect("create JSON");
    let company_id: Uuid = created["id"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .expect("created company id");

    let update_resp = app
        .client
        .put(app.url(&format!("/api/v1/contacts/companies/{company_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "name": "Acme Renamed" }))
        .send()
        .await
        .expect("update company");
    assert!(
        update_resp.status().is_success(),
        "update should 2xx, got {}",
        update_resp.status()
    );

    // The in-transaction writer records entity_type='companies' (the
    // coarse middleware records entity_type='contacts', so this row is
    // unambiguously the AC1 one).
    let (action, old_values, new_values, user_id): (
        String,
        Option<serde_json::Value>,
        Option<serde_json::Value>,
        Option<Uuid>,
    ) = sqlx::query_as(
        r#"SELECT action, old_values, new_values, user_id
           FROM audit_log
           WHERE entity_type = 'companies' AND entity_id = $1 AND action = 'update'"#,
    )
    .bind(company_id)
    .fetch_one(&app.pool)
    .await
    .expect("audit row for the company update exists");

    assert_eq!(action, "update");
    assert_eq!(user_id, Some(admin_id), "audit row records the acting user");
    let old = old_values.expect("old_values captured");
    let new = new_values.expect("new_values captured");
    assert_eq!(
        old["name"].as_str(),
        Some("Acme Co"),
        "before snapshot has the original name"
    );
    assert_eq!(
        new["name"].as_str(),
        Some("Acme Renamed"),
        "after snapshot has the new name"
    );
}

#[sqlx::test]
async fn audit_read_is_tenant_scoped(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;

    // A row belonging to a DIFFERENT tenant must never surface in this
    // tenant's audit read.
    let foreign_tenant = Uuid::new_v4();
    let foreign_entity = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO tenants (id, name, slug, kind) VALUES ($1, 'Other Tenant', $2, 'org')",
    )
    .bind(foreign_tenant)
    .bind(format!("other-{foreign_tenant}"))
    .execute(&pool)
    .await
    .expect("insert foreign tenant");
    sqlx::query(
        r#"INSERT INTO audit_log (tenant_id, action, entity_type, entity_id)
           VALUES ($1, 'update', 'companies', $2)"#,
    )
    .bind(foreign_tenant)
    .bind(foreign_entity)
    .execute(&pool)
    .await
    .expect("insert foreign-tenant audit row");

    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let resp = app
        .client
        .get(app.url("/api/v1/audit-log"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list audit log");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("audit-log JSON");
    let items = body["data"].as_array().expect("data array");

    assert!(
        items
            .iter()
            .all(|e| e["entity_id"].as_str() != Some(&foreign_entity.to_string())),
        "cross-tenant audit row must not be readable"
    );
}

#[sqlx::test]
async fn audit_read_requires_admin(pool: PgPool) {
    // Seed a non-admin user under the default tenant and confirm the
    // read endpoint rejects them (RequireAdmin).
    let email = "manager@example.com".to_string();
    let password = "manager-password-12345".to_string();
    let password_hash =
        mokosh_server::utils::crypto::hash_password(&password).expect("hash manager password");
    sqlx::query(
        r#"INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name, role, status, email_verified_at)
           VALUES ($1, $2, $3, $4, 'Man', 'Ager', 'manager', 'active', NOW())"#,
    )
    .bind(Uuid::new_v4())
    .bind(common::DEFAULT_TENANT_ID)
    .bind(&email)
    .bind(&password_hash)
    .execute(&pool)
    .await
    .expect("insert member");

    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let resp = app
        .client
        .get(app.url("/api/v1/audit-log"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list audit log as member");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::FORBIDDEN,
        "non-admin must be forbidden from reading the audit log"
    );
}

#[sqlx::test]
async fn login_writes_audit_event(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    // common::login asserts a 2xx and returns the access token.
    let _token = common::login(&app, &email, &password).await;

    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'login' AND entity_type = 'auth' AND user_id = $1",
    )
    .bind(admin_id)
    .fetch_one(&app.pool)
    .await
    .expect("count login audit rows");
    assert!(count >= 1, "a successful login records a login audit event");
}
