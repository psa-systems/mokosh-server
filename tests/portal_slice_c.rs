//! PMS-729 phase 2 §7 slice C: portal read-only surfaces.
//!
//! Covers assets (I3), contracts (I4), time entries (I5), and projects
//! (I6). Each resource gets a happy-path + cross-company + 401 test.
//! Everything is company-scoped from the JWT-verified contact; cross-
//! company ids surface as 404 (never 403) and cross-company list
//! filters return an empty result set.

mod common;

use rust_decimal::Decimal;
use sqlx::PgPool;
use uuid::Uuid;

const PORTAL_PASSWORD: &str = "portal-password-12345";

async fn seed_company(pool: &PgPool, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(common::DEFAULT_TENANT_ID)
        .bind(name)
        .execute(pool)
        .await
        .expect("seed company");
    id
}

async fn seed_portal_contact(pool: &PgPool, company_id: Uuid, email: &str) -> Uuid {
    let hash = mokosh_server::utils::crypto::hash_password(PORTAL_PASSWORD).expect("hash password");
    let id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO contacts (
            id, tenant_id, company_id, first_name, last_name, email,
            is_portal_user, portal_password_hash
        )
        VALUES ($1, $2, $3, 'Port', 'Al', $4, TRUE, $5)
        "#,
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company_id)
    .bind(email)
    .bind(&hash)
    .execute(pool)
    .await
    .expect("seed portal contact");
    id
}

async fn login(app: &common::TestApp, email: &str) -> String {
    let resp = app
        .client
        .post(app.url("/api/v1/portal/auth/login"))
        .json(&serde_json::json!({
            "tenant_slug": "default",
            "email": email,
            "password": PORTAL_PASSWORD,
        }))
        .send()
        .await
        .expect("login");
    assert!(resp.status().is_success());
    let body: serde_json::Value = resp.json().await.expect("login body");
    body["access_token"].as_str().unwrap().to_string()
}

// ---- assets --------------------------------------------------------------

async fn seed_asset_type(pool: &PgPool, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO asset_types (id, tenant_id, name) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(common::DEFAULT_TENANT_ID)
        .bind(name)
        .execute(pool)
        .await
        .expect("seed asset type");
    id
}

async fn seed_asset(
    pool: &PgPool,
    company_id: Uuid,
    type_id: Uuid,
    name: &str,
    serial: &str,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO assets (id, tenant_id, name, asset_type_id, company_id,
                            status, serial_number, notes)
        VALUES ($1, $2, $3, $4, $5, 'active', $6, 'internal scratch note')
        "#,
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(name)
    .bind(type_id)
    .bind(company_id)
    .bind(serial)
    .execute(pool)
    .await
    .expect("seed asset");
    id
}

#[sqlx::test]
async fn portal_assets_list_and_detail(pool: PgPool) {
    let _ = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let company = seed_company(&pool, "Assets Co").await;
    let _c = seed_portal_contact(&pool, company, "assets@example.com").await;
    let laptop_type = seed_asset_type(&pool, "Laptop").await;
    let a1 = seed_asset(&pool, company, laptop_type, "Alice's laptop", "SN-A").await;
    let _a2 = seed_asset(&pool, company, laptop_type, "Bob's laptop", "SN-B").await;

    let token = login(&app, "assets@example.com").await;
    let resp = app
        .client
        .get(app.url("/api/v1/portal/assets"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list");
    assert!(resp.status().is_success());
    let list: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(list.as_array().unwrap().len(), 2);
    // `notes` never surfaces to the portal.
    for row in list.as_array().unwrap() {
        assert!(row.get("notes").is_none(), "notes leaked: {row}");
    }

    let resp = app
        .client
        .get(app.url(&format!("/api/v1/portal/assets/{a1}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("detail");
    assert!(resp.status().is_success());
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["name"].as_str().unwrap(), "Alice's laptop");
    assert_eq!(body["asset_type"].as_str().unwrap(), "Laptop");
}

#[sqlx::test]
async fn portal_assets_cross_company_is_404(pool: PgPool) {
    let _ = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let mine = seed_company(&pool, "Mine Co").await;
    let other = seed_company(&pool, "Other Co").await;
    let _c = seed_portal_contact(&pool, mine, "me@example.com").await;
    let t = seed_asset_type(&pool, "Server").await;
    let stolen = seed_asset(&pool, other, t, "Not mine", "SN-X").await;

    let token = login(&app, "me@example.com").await;
    let resp = app
        .client
        .get(app.url(&format!("/api/v1/portal/assets/{stolen}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
    let list = app
        .client
        .get(app.url("/api/v1/portal/assets"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list");
    let body: serde_json::Value = list.json().await.unwrap();
    assert!(body.as_array().unwrap().is_empty());
}

// ---- contracts -----------------------------------------------------------

async fn seed_contract(pool: &PgPool, company_id: Uuid, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO contracts (id, tenant_id, name, company_id, contract_type,
                               status, start_date, internal_notes)
        VALUES ($1, $2, $3, $4, 'managed_services', 'active', CURRENT_DATE,
                'internal note not for customer')
        "#,
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(name)
    .bind(company_id)
    .execute(pool)
    .await
    .expect("seed contract");
    id
}

#[sqlx::test]
async fn portal_contracts_list_and_detail(pool: PgPool) {
    let _ = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let company = seed_company(&pool, "Contracts Co").await;
    let _c = seed_portal_contact(&pool, company, "cx@example.com").await;
    let c1 = seed_contract(&pool, company, "Managed services 2026").await;

    let token = login(&app, "cx@example.com").await;
    let list = app
        .client
        .get(app.url("/api/v1/portal/contracts"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list");
    assert!(list.status().is_success());
    let body: serde_json::Value = list.json().await.unwrap();
    assert_eq!(body.as_array().unwrap().len(), 1);
    // Internal notes never surface.
    assert!(body[0].get("internal_notes").is_none());
    let detail = app
        .client
        .get(app.url(&format!("/api/v1/portal/contracts/{c1}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("detail");
    assert!(detail.status().is_success());
    let body: serde_json::Value = detail.json().await.unwrap();
    assert_eq!(body["name"].as_str().unwrap(), "Managed services 2026");
    assert_eq!(body["status"].as_str().unwrap(), "active");
}

#[sqlx::test]
async fn portal_contracts_cross_company_is_404(pool: PgPool) {
    let _ = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let mine = seed_company(&pool, "Mine Co").await;
    let other = seed_company(&pool, "Other Co").await;
    let _c = seed_portal_contact(&pool, mine, "me@example.com").await;
    let stolen = seed_contract(&pool, other, "Their contract").await;

    let token = login(&app, "me@example.com").await;
    let resp = app
        .client
        .get(app.url(&format!("/api/v1/portal/contracts/{stolen}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("detail");
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
}

// ---- time entries --------------------------------------------------------

async fn seed_work_type(pool: &PgPool, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO work_types (id, tenant_id, name) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(common::DEFAULT_TENANT_ID)
        .bind(name)
        .execute(pool)
        .await
        .expect("seed work type");
    id
}

#[allow(clippy::too_many_arguments)]
async fn seed_time_entry(
    pool: &PgPool,
    company_id: Uuid,
    user_id: Uuid,
    work_type_id: Uuid,
    minutes: i32,
    is_billable: bool,
    approval: &str,
    hourly_rate: Decimal,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO time_entries
            (id, tenant_id, user_id, date, duration_minutes, work_type_id,
             company_id, is_billable, approval_status, hourly_rate,
             internal_notes)
        VALUES ($1, $2, $3, CURRENT_DATE, $4, $5, $6, $7, $8, $9,
                'internal scratch note')
        "#,
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(user_id)
    .bind(minutes)
    .bind(work_type_id)
    .bind(company_id)
    .bind(is_billable)
    .bind(approval)
    .bind(hourly_rate)
    .execute(pool)
    .await
    .expect("seed time entry");
    id
}

#[sqlx::test]
async fn portal_time_entries_filters_to_billable_visible_rows(pool: PgPool) {
    let (admin_id, _e, _p) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let company = seed_company(&pool, "Time Co").await;
    let _c = seed_portal_contact(&pool, company, "time@example.com").await;
    let wt = seed_work_type(&pool, "General").await;
    let _billable = seed_time_entry(
        &pool,
        company,
        admin_id,
        wt,
        60,
        true,
        "approved",
        Decimal::new(15000, 2),
    )
    .await;
    let _rejected = seed_time_entry(
        &pool,
        company,
        admin_id,
        wt,
        60,
        true,
        "rejected",
        Decimal::new(15000, 2),
    )
    .await;
    let _internal = seed_time_entry(
        &pool,
        company,
        admin_id,
        wt,
        60,
        false,
        "approved",
        Decimal::new(15000, 2),
    )
    .await;

    let token = login(&app, "time@example.com").await;
    let resp = app
        .client
        .get(app.url("/api/v1/portal/time-entries"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list");
    assert!(resp.status().is_success());
    let body: serde_json::Value = resp.json().await.unwrap();
    let rows = body.as_array().unwrap();
    assert_eq!(rows.len(), 1, "expected 1 visible entry: {body}");
    // Internal notes never surface; hourly_rate + total_amount never surface.
    for row in rows {
        assert!(row.get("internal_notes").is_none());
        assert!(row.get("hourly_rate").is_none());
        assert!(row.get("total_amount").is_none());
    }
    assert_eq!(rows[0]["duration_minutes"].as_i64().unwrap(), 60);
}

// ---- projects ------------------------------------------------------------

async fn seed_project(pool: &PgPool, company_id: Uuid, name: &str, project_type: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO projects (id, tenant_id, name, company_id, project_type, status)
        VALUES ($1, $2, $3, $4, $5, 'active')
        "#,
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(name)
    .bind(company_id)
    .bind(project_type)
    .execute(pool)
    .await
    .expect("seed project");
    id
}

async fn seed_project_phase(pool: &PgPool, project_id: Uuid, name: &str, sort: i32) {
    sqlx::query(
        r#"
        INSERT INTO project_phases
            (id, tenant_id, project_id, name, sort_order, status)
        VALUES ($1, $2, $3, $4, $5, 'in_progress')
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(common::DEFAULT_TENANT_ID)
    .bind(project_id)
    .bind(name)
    .bind(sort)
    .execute(pool)
    .await
    .expect("seed phase");
}

#[sqlx::test]
async fn portal_projects_list_and_detail(pool: PgPool) {
    let _ = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let company = seed_company(&pool, "Projects Co").await;
    let _c = seed_portal_contact(&pool, company, "proj@example.com").await;
    let p1 = seed_project(&pool, company, "Office migration", "client").await;
    let _internal = seed_project(&pool, company, "Internal knowledge base", "internal").await;
    seed_project_phase(&pool, p1, "Discovery", 0).await;
    seed_project_phase(&pool, p1, "Rollout", 1).await;

    let token = login(&app, "proj@example.com").await;
    let list = app
        .client
        .get(app.url("/api/v1/portal/projects"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list");
    assert!(list.status().is_success());
    let body: serde_json::Value = list.json().await.unwrap();
    let rows = body.as_array().unwrap();
    // Only the `client` project surfaces; the internal one is hidden.
    assert_eq!(rows.len(), 1, "expected 1 client project: {body}");
    assert_eq!(rows[0]["name"].as_str().unwrap(), "Office migration");

    let detail = app
        .client
        .get(app.url(&format!("/api/v1/portal/projects/{p1}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("detail");
    assert!(detail.status().is_success());
    let body: serde_json::Value = detail.json().await.unwrap();
    let phases = body["phases"].as_array().unwrap();
    assert_eq!(phases.len(), 2);
    assert_eq!(phases[0]["name"].as_str().unwrap(), "Discovery");
    assert_eq!(phases[1]["name"].as_str().unwrap(), "Rollout");
}

#[sqlx::test]
async fn portal_projects_hide_cross_company_and_internal(pool: PgPool) {
    let _ = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let mine = seed_company(&pool, "Mine Co").await;
    let other = seed_company(&pool, "Other Co").await;
    let _c = seed_portal_contact(&pool, mine, "me@example.com").await;
    let stolen = seed_project(&pool, other, "Not mine", "client").await;
    let internal = seed_project(&pool, mine, "Own internal", "internal").await;

    let token = login(&app, "me@example.com").await;
    let cross = app
        .client
        .get(app.url(&format!("/api/v1/portal/projects/{stolen}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("cross");
    assert_eq!(cross.status(), reqwest::StatusCode::NOT_FOUND);
    let own_internal = app
        .client
        .get(app.url(&format!("/api/v1/portal/projects/{internal}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("own internal");
    assert_eq!(
        own_internal.status(),
        reqwest::StatusCode::NOT_FOUND,
        "own internal project should still hide"
    );
}

// ---- 401 ---------------------------------------------------------------

#[sqlx::test]
async fn slice_c_endpoints_require_a_portal_session(pool: PgPool) {
    let _ = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    for path in [
        "/api/v1/portal/assets",
        "/api/v1/portal/contracts",
        "/api/v1/portal/time-entries",
        "/api/v1/portal/projects",
    ] {
        let resp = app.client.get(app.url(path)).send().await.expect("send");
        assert_eq!(
            resp.status(),
            reqwest::StatusCode::UNAUTHORIZED,
            "path {path} should require auth"
        );
    }
}
