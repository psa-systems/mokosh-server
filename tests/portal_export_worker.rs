//! PMS-729 phase 2 §7 slice D / I15 follow-up: export worker + download.

mod common;

use mokosh_server::modules::portal::export_worker;
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
    resp.json::<serde_json::Value>().await.expect("body")["access_token"]
        .as_str()
        .unwrap()
        .to_string()
}

#[sqlx::test]
async fn worker_drains_queue_and_download_returns_json(pool: PgPool) {
    let _ = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let company = seed_company(&pool, "Export Worker Co").await;
    let _me = seed_portal_contact(&pool, company, "exp@example.com").await;
    let token = login(&app, "exp@example.com").await;

    // Request an export.
    let post = app
        .client
        .post(app.url("/api/v1/portal/export"))
        .bearer_auth(&token)
        .json(&serde_json::json!({}))
        .send()
        .await
        .expect("post");
    assert_eq!(post.status(), reqwest::StatusCode::CREATED);
    let job: serde_json::Value = post.json().await.unwrap();
    let job_id = job["id"].as_str().unwrap().to_string();

    // Run one worker tick.
    let db = mokosh_server::Database::from_pool(pool.clone());
    export_worker::tick_once(&db).await.expect("tick");

    // Poll: status is `ready` now, signed_url populated.
    let poll = app
        .client
        .get(app.url(&format!("/api/v1/portal/export/{job_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("poll");
    assert!(poll.status().is_success());
    let job: serde_json::Value = poll.json().await.unwrap();
    assert_eq!(job["status"].as_str().unwrap(), "ready");
    let url = job["signed_url"].as_str().expect("signed_url");
    assert!(url.contains("/portal/export/") && url.ends_with("/download"));

    // Download.
    let dl = app
        .client
        .get(app.url(&format!("/api/v1{url}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("download");
    assert!(dl.status().is_success());
    assert_eq!(
        dl.headers()
            .get("content-type")
            .map(|v| v.to_str().unwrap_or(""))
            .unwrap_or(""),
        "application/json"
    );
    let bytes = dl.bytes().await.unwrap();
    let bundle: serde_json::Value = serde_json::from_slice(&bytes).expect("bundle json");
    assert_eq!(
        bundle["contact"]["email"].as_str().unwrap(),
        "exp@example.com"
    );
    // Every section present, even if empty.
    for key in ["tickets", "ticket_notes", "invoices", "quotes"] {
        assert!(bundle[key].is_array(), "missing {key}: {bundle}");
    }
}

#[sqlx::test]
async fn worker_marks_expired_row_and_download_returns_gone(pool: PgPool) {
    let _ = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let company = seed_company(&pool, "Expired Co").await;
    let me = seed_portal_contact(&pool, company, "exp@example.com").await;
    let token = login(&app, "exp@example.com").await;

    // Seed a `ready` row directly with an already-past expires_at.
    let job_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO portal_exports (
            id, tenant_id, contact_id, company_id, status,
            ready_at, expires_at, bundle_json
        )
        VALUES ($1, $2, $3, $4, 'ready',
                NOW() - INTERVAL '8 days',
                NOW() - INTERVAL '1 day',
                '{"contact": {"email": "exp@example.com"}}'::jsonb)
        "#,
    )
    .bind(job_id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(me)
    .bind(company)
    .execute(&pool)
    .await
    .expect("seed expired");

    // Poll: server auto-transitions status to `expired` in the response.
    let poll = app
        .client
        .get(app.url(&format!("/api/v1/portal/export/{job_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("poll");
    let body: serde_json::Value = poll.json().await.unwrap();
    assert_eq!(body["status"].as_str().unwrap(), "expired");
    assert!(body.get("signed_url").is_none() || body["signed_url"].is_null());

    // Download: 410 Gone.
    let dl = app
        .client
        .get(app.url(&format!("/api/v1/portal/export/{job_id}/download")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("download");
    assert_eq!(dl.status(), reqwest::StatusCode::GONE);
}
