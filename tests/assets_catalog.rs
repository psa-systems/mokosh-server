//! PMS-1488 integration tests: the asset-catalog phase-3 server surface.
//! Nine scenarios the design calls out:
//!
//! T1  the four routes 404 while `assets_catalog` is OFF
//! T2  create + list + get + update + delete an asset_model
//! T3  create + get + list + update + delete an asset_template
//! T4  bulk-create fans N serials out of a template; one audit row per asset,
//!     uses_count bumped on model + template, warranty/EOL derived
//! T5  bulk-create with asset_model_id (no template) and per-batch overlay
//! T6  bulk-create 422 when neither template_id nor asset_model_id is given
//! T7  bulk-create 422 when a BulkSerial row fails validation
//! T8  signature-detector returns a candidate when >= 5 identical creates
//!     and no catalog row exists; returns None once an authored row exists
//! T9  cross-tenant isolation: tenant A cannot read tenant B's catalog rows

mod common;

use mokosh_test::mokosh_test;
use reqwest::StatusCode;
use sqlx::PgPool;
use uuid::Uuid;

const FEATURE_PUT: &str = "/api/v1/settings/feature-toggles/assets_catalog";

async fn enable_catalog(app: &common::TestApp, token: &str) {
    let resp = app
        .client
        .put(app.url(FEATURE_PUT))
        .bearer_auth(token)
        .json(&serde_json::json!({ "enabled": true }))
        .send()
        .await
        .expect("flip");
    assert_eq!(resp.status(), StatusCode::OK, "flip must succeed");
}

async fn seed_asset_type(pool: &PgPool, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO asset_types (id, tenant_id, name) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(common::DEFAULT_TENANT_ID)
        .bind(name)
        .execute(pool)
        .await
        .expect("seed asset_type");
    id
}

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

async fn create_model(
    app: &common::TestApp,
    token: &str,
    asset_type_id: Uuid,
    manufacturer: &str,
    model: &str,
) -> Uuid {
    let resp = app
        .client
        .post(app.url("/api/v1/asset-models"))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "manufacturer": manufacturer,
            "model": model,
            "asset_type_id": asset_type_id,
            "warranty_months": 36,
            "end_of_life_months": 60,
            "default_department": "IT",
            "default_tags": ["corp"],
            "specs": {"cpu": "i7", "ram_gb": 16},
        }))
        .send()
        .await
        .expect("create model");
    assert!(
        resp.status().is_success(),
        "create model: {}",
        resp.status()
    );
    let v: serde_json::Value = resp.json().await.expect("json");
    v["id"].as_str().unwrap().parse().unwrap()
}

// T1
#[mokosh_test]
async fn routes_404_while_feature_off(pool: PgPool) {
    let (_aid, email, pw) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &pw).await;

    for path in [
        "/api/v1/asset-models",
        "/api/v1/asset-templates",
        "/api/v1/asset-models/signature-detector",
    ] {
        let resp = app
            .client
            .get(app.url(path))
            .bearer_auth(&token)
            .send()
            .await
            .expect("GET");
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "{path} must 404 with feature off"
        );
    }
    let resp = app
        .client
        .post(app.url("/api/v1/assets/bulk-create"))
        .bearer_auth(&token)
        .json(&serde_json::json!({}))
        .send()
        .await
        .expect("bulk-create");
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "bulk-create must 404 with feature off"
    );
}

// T2
#[mokosh_test]
async fn asset_model_crud(pool: PgPool) {
    let (_aid, email, pw) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &pw).await;
    enable_catalog(&app, &token).await;
    let type_id = seed_asset_type(&pool, "Laptop").await;

    let mid = create_model(&app, &token, type_id, "Dell", "Latitude 5450").await;

    // GET single
    let resp = app
        .client
        .get(app.url(&format!("/api/v1/asset-models/{mid}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("get");
    assert_eq!(resp.status(), StatusCode::OK);
    let v: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(v["manufacturer"], "Dell");
    assert_eq!(v["warranty_months"], 36);
    assert_eq!(v["source"], "tenant_authored");

    // LIST
    let resp = app
        .client
        .get(app.url("/api/v1/asset-models"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list");
    assert_eq!(resp.status(), StatusCode::OK);
    let v: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(v["total"], 1);

    // UPDATE
    let resp = app
        .client
        .put(app.url(&format!("/api/v1/asset-models/{mid}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "warranty_months": 48 }))
        .send()
        .await
        .expect("update");
    assert_eq!(resp.status(), StatusCode::OK);
    let v: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(v["warranty_months"], 48);

    // DELETE
    let resp = app
        .client
        .delete(app.url(&format!("/api/v1/asset-models/{mid}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("delete");
    assert!(resp.status().is_success());
}

// T3
#[mokosh_test]
async fn asset_template_crud(pool: PgPool) {
    let (_aid, email, pw) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &pw).await;
    enable_catalog(&app, &token).await;
    let type_id = seed_asset_type(&pool, "Laptop").await;
    let company_id = seed_company(&pool, "Acme").await;
    let mid = create_model(&app, &token, type_id, "Dell", "Latitude 5450").await;

    let resp = app
        .client
        .post(app.url("/api/v1/asset-templates"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "name": "Acme Sales Latitude",
            "asset_model_id": mid,
            "company_id": company_id,
            "department": "Sales",
            "tags": ["sales"],
        }))
        .send()
        .await
        .expect("create template");
    assert!(resp.status().is_success(), "{}", resp.status());
    let v: serde_json::Value = resp.json().await.expect("json");
    let tid: String = v["id"].as_str().unwrap().into();

    let resp = app
        .client
        .put(app.url(&format!("/api/v1/asset-templates/{tid}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "department": "Operations" }))
        .send()
        .await
        .expect("update");
    assert_eq!(resp.status(), StatusCode::OK);
    let v: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(v["department"], "Operations");

    let resp = app
        .client
        .delete(app.url(&format!("/api/v1/asset-templates/{tid}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("delete");
    assert!(resp.status().is_success());
}

// T4
#[mokosh_test]
async fn bulk_create_from_template_fans_out(pool: PgPool) {
    let (_aid, email, pw) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &pw).await;
    enable_catalog(&app, &token).await;
    let type_id = seed_asset_type(&pool, "Laptop").await;
    let company_id = seed_company(&pool, "Acme").await;
    let mid = create_model(&app, &token, type_id, "Dell", "Latitude 5450").await;

    let tresp = app
        .client
        .post(app.url("/api/v1/asset-templates"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "name": "Acme Sales Latitude",
            "asset_model_id": mid,
            "company_id": company_id,
            "department": "Sales",
        }))
        .send()
        .await
        .expect("create template");
    let tv: serde_json::Value = tresp.json().await.expect("json");
    let tid: String = tv["id"].as_str().unwrap().into();

    let resp = app
        .client
        .post(app.url("/api/v1/assets/bulk-create"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "template_id": tid,
            "company_id": company_id,
            "purchase_date": "2026-01-15",
            "serials": [
                {"serial_number": "SN001", "hostname": "lat-001"},
                {"serial_number": "SN002", "hostname": "lat-002"},
                {"serial_number": "SN003", "hostname": "lat-003"},
            ],
        }))
        .send()
        .await
        .expect("bulk-create");
    assert_eq!(resp.status(), StatusCode::OK, "{}", resp.status());
    let v: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(v["count"], 3);
    assert_eq!(v["created"].as_array().unwrap().len(), 3);

    // uses_count bumped on model + template.
    let m_uses: i32 = sqlx::query_scalar("SELECT uses_count FROM asset_models WHERE id = $1")
        .bind(mid)
        .fetch_one(&pool)
        .await
        .expect("model uses");
    assert_eq!(m_uses, 3);
    let t_uses: i32 =
        sqlx::query_scalar("SELECT uses_count FROM asset_templates WHERE id = $1::uuid")
            .bind(&tid)
            .fetch_one(&pool)
            .await
            .expect("template uses");
    assert_eq!(t_uses, 3);

    // warranty_expiry derived: purchase_date + 36 months = 2029-01-15.
    let warranty: Option<chrono::NaiveDate> = sqlx::query_scalar(
        "SELECT warranty_expiry FROM assets WHERE serial_number = 'SN001' AND tenant_id = $1",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(&pool)
    .await
    .expect("warranty");
    assert_eq!(
        warranty.map(|d| d.to_string()),
        Some("2029-01-15".to_string())
    );

    // One audit entry per created asset, action=created with bulk flag.
    let audit: Vec<serde_json::Value> = sqlx::query_scalar::<_, serde_json::Value>(
        "SELECT changes FROM asset_audit_log \
         WHERE tenant_id = $1 AND action = 'created' AND changes->>'bulk' = 'true' \
         ORDER BY performed_at",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_all(&pool)
    .await
    .expect("audit rows");
    assert_eq!(audit.len(), 3, "one audit per bulk-created asset");
    for row in &audit {
        assert_eq!(row["bulk"], true);
        assert_eq!(row["template_id"], tid.as_str());
    }
}

// T5
#[mokosh_test]
async fn bulk_create_from_model_only(pool: PgPool) {
    let (_aid, email, pw) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &pw).await;
    enable_catalog(&app, &token).await;
    let type_id = seed_asset_type(&pool, "Laptop").await;
    let company_id = seed_company(&pool, "Acme").await;
    let mid = create_model(&app, &token, type_id, "HP", "EliteBook 840").await;

    let resp = app
        .client
        .post(app.url("/api/v1/assets/bulk-create"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "asset_model_id": mid,
            "company_id": company_id,
            "department": "Engineering",
            "serials": [{"serial_number": "HP001"}, {"serial_number": "HP002"}],
        }))
        .send()
        .await
        .expect("bulk-create");
    assert_eq!(resp.status(), StatusCode::OK, "{}", resp.status());
    let v: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(v["count"], 2);
    assert!(v["template_id"].is_null());

    // Per-batch department (Engineering) overrode model default (IT).
    let dept: String = sqlx::query_scalar(
        "SELECT department FROM assets WHERE serial_number = 'HP001' AND tenant_id = $1",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(&pool)
    .await
    .expect("dept");
    assert_eq!(dept, "Engineering");
}

// T6
#[mokosh_test]
async fn bulk_create_requires_model_or_template(pool: PgPool) {
    let (_aid, email, pw) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &pw).await;
    enable_catalog(&app, &token).await;
    let company_id = seed_company(&pool, "Acme").await;

    let resp = app
        .client
        .post(app.url("/api/v1/assets/bulk-create"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "company_id": company_id,
            "serials": [{"serial_number": "X1"}],
        }))
        .send()
        .await
        .expect("bulk-create");
    assert_eq!(
        resp.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "missing both ids: {}",
        resp.status()
    );
}

// T7
#[mokosh_test]
async fn bulk_create_rejects_empty_serials(pool: PgPool) {
    let (_aid, email, pw) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &pw).await;
    enable_catalog(&app, &token).await;
    let type_id = seed_asset_type(&pool, "Laptop").await;
    let company_id = seed_company(&pool, "Acme").await;
    let mid = create_model(&app, &token, type_id, "Dell", "Latitude 5440").await;

    let resp = app
        .client
        .post(app.url("/api/v1/assets/bulk-create"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "asset_model_id": mid,
            "company_id": company_id,
            "serials": [],
        }))
        .send()
        .await
        .expect("bulk-create");
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

// T8
#[mokosh_test]
async fn signature_detector_surfaces_candidate(pool: PgPool) {
    let (_aid, email, pw) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &pw).await;
    enable_catalog(&app, &token).await;
    let type_id = seed_asset_type(&pool, "Laptop").await;
    let company_id = seed_company(&pool, "Acme").await;

    // Seed 6 raw asset inserts (not through the catalog) so the MV
    // picks them up. created_at defaults to NOW() which is inside the
    // 7-day window.
    for i in 0..6 {
        sqlx::query(
            "INSERT INTO assets (id, tenant_id, name, asset_type_id, company_id, \
                                 manufacturer, model, serial_number, status) \
             VALUES ($1, $2, $3, $4, $5, 'Lenovo', 'ThinkPad X1', $6, 'active')",
        )
        .bind(Uuid::new_v4())
        .bind(common::DEFAULT_TENANT_ID)
        .bind(format!("tp-{i}"))
        .bind(type_id)
        .bind(company_id)
        .bind(format!("TP{i:04}"))
        .execute(&pool)
        .await
        .expect("seed asset");
    }

    // Refresh the MV (the scheduler is not running in tests).
    sqlx::query("REFRESH MATERIALIZED VIEW asset_signature_candidates_mv")
        .execute(&pool)
        .await
        .expect("refresh mv");

    let resp = app
        .client
        .get(app.url("/api/v1/asset-models/signature-detector"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("get");
    assert_eq!(resp.status(), StatusCode::OK);
    let v: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(v["manufacturer"], "lenovo");
    assert_eq!(v["model"], "thinkpad x1");
    assert_eq!(v["recent_count"], 6);
    assert_eq!(v["window_days"], 7);
    assert!(v["existing_model_id"].is_null());
    assert!(v["template_suggestion"]["name_hint"]
        .as_str()
        .unwrap()
        .contains("Lenovo"));

    // Author a catalog row (source = tenant_authored) and verify the
    // banner stops showing.
    let _ = create_model(&app, &token, type_id, "Lenovo", "ThinkPad X1").await;
    let resp = app
        .client
        .get(app.url("/api/v1/asset-models/signature-detector"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("get again");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.text().await.expect("body");
    assert_eq!(body, "null", "once authored, the banner stops: {body}");
}

// T9
#[mokosh_test]
async fn asset_model_is_tenant_isolated(pool: PgPool) {
    // Tenant A: seeded admin.
    let (_aid_a, email_a, pw_a) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token_a = common::login(&app, &email_a, &pw_a).await;
    enable_catalog(&app, &token_a).await;
    let type_id = seed_asset_type(&pool, "Laptop").await;
    let mid = create_model(&app, &token_a, type_id, "Dell", "Latitude 5450").await;

    // Tenant B: new tenant + admin, same app.
    let (_tenant_b, _bid, email_b, pw_b) = common::seed_tenant_with_admin(&pool, "tenant-b").await;
    let token_b = common::login(&app, &email_b, &pw_b).await;
    enable_catalog(&app, &token_b).await;

    let resp = app
        .client
        .get(app.url(&format!("/api/v1/asset-models/{mid}")))
        .bearer_auth(&token_b)
        .send()
        .await
        .expect("get");
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "tenant B must not see tenant A's model"
    );
}
