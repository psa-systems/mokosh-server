//! PMS-1492 phase 3 MR1: asset catalog + bulk-create.
//!
//! Gated behind `Feature::AssetsCatalog`; every test flips the toggle on
//! via the admin HTTP endpoint (same shape `tests/feature_toggles.rs`
//! uses) so the gate itself is exercised on the toggle-off path.

mod common;

use mokosh_test::mokosh_test;
use reqwest::StatusCode;
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

const FLIP_PATH: &str = "/api/v1/settings/feature-toggles/assets_catalog";
const MODELS: &str = "/api/v1/asset-models";
const BULK_CREATE: &str = "/api/v1/assets/bulk-create";

async fn turn_catalog_on(app: &common::TestApp, operator: &str) {
    let r = app
        .client
        .put(app.url(FLIP_PATH))
        .bearer_auth(operator)
        .json(&json!({ "enabled": true }))
        .send()
        .await
        .expect("flip assets_catalog");
    assert_eq!(
        r.status(),
        StatusCode::OK,
        "flip body: {}",
        r.text().await.unwrap_or_default()
    );
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

async fn seed_asset_type(pool: &PgPool, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO asset_types (id, tenant_id, name, is_active) VALUES ($1, $2, $3, TRUE)",
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(name)
    .execute(pool)
    .await
    .expect("seed asset type");
    id
}

#[mokosh_test]
async fn catalog_routes_404_when_the_toggle_is_off(pool: PgPool) {
    let (_aid, email, pw) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;

    for path in [
        MODELS,
        "/api/v1/asset-models/00000000-0000-0000-0000-000000000000",
    ] {
        let r = app
            .client
            .get(app.url(path))
            .bearer_auth(&token)
            .send()
            .await
            .expect("get");
        assert_eq!(
            r.status(),
            StatusCode::NOT_FOUND,
            "{path} must 404 while assets_catalog is off"
        );
    }
    let r = app
        .client
        .post(app.url(BULK_CREATE))
        .bearer_auth(&token)
        .json(&json!({ "company_id": Uuid::new_v4(), "serials": [{"serial_number": "A"}] }))
        .send()
        .await
        .expect("post bulk");
    assert_eq!(
        r.status(),
        StatusCode::NOT_FOUND,
        "bulk-create must 404 while assets_catalog is off"
    );
}

#[mokosh_test]
async fn model_create_and_typeahead_ranks_by_uses_count(pool: PgPool) {
    let (_aid, email, pw) = common::seed_admin(&pool).await;
    let type_id = seed_asset_type(&pool, "Laptop").await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;
    turn_catalog_on(&app, &token).await;

    // Create three models under one asset type. Distinctive manufacturer
    // ("Testco") so the typeahead's `q=Testco` returns exactly these
    // three without the seed catalog's rows muddying the result set.
    for (manufacturer, model) in [
        ("Testco", "Lat-A"),
        ("Testco", "Xps-Z"),
        ("Testco", "Opti-M"),
    ] {
        let r = app
            .client
            .post(app.url(MODELS))
            .bearer_auth(&token)
            .json(&json!({
                "manufacturer": manufacturer,
                "model": model,
                "asset_type_id": type_id,
                "warranty_months": 36,
                "end_of_life_months": 60,
            }))
            .send()
            .await
            .expect("create model");
        assert_eq!(
            r.status(),
            StatusCode::CREATED,
            "{manufacturer} {model}: {}",
            r.text().await.unwrap_or_default()
        );
    }

    // Typeahead q=Testco: all three come back ordered by uses_count
    // DESC then by (manufacturer, model) ascending. Each uses_count is 0
    // at seed, so the tie-break is alphabetical on model.
    let r: Value = app
        .client
        .get(app.url("/api/v1/asset-models?q=Testco"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("typeahead")
        .json()
        .await
        .expect("models JSON");
    let names: Vec<&str> = r
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["model"].as_str().unwrap_or_default())
        .collect();
    assert_eq!(names, vec!["Lat-A", "Opti-M", "Xps-Z"]);

    // Typeahead q=lat-a should narrow to one.
    let r: Value = app
        .client
        .get(app.url("/api/v1/asset-models?q=lat-a"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("typeahead")
        .json()
        .await
        .expect("models JSON");
    let names: Vec<&str> = r
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["model"].as_str().unwrap_or_default())
        .collect();
    assert_eq!(names, vec!["Lat-A"]);

    // Duplicate shape rejected: same tenant + manufacturer + model + type.
    let r = app
        .client
        .post(app.url(MODELS))
        .bearer_auth(&token)
        .json(&json!({
            "manufacturer": "testco",
            "model": "LAT-A",
            "asset_type_id": type_id,
        }))
        .send()
        .await
        .expect("dup create");
    assert_eq!(
        r.status(),
        StatusCode::CONFLICT,
        "duplicate (case-insensitive) shape must 409"
    );
}

#[mokosh_test]
async fn bulk_create_fans_out_and_bumps_uses_count(pool: PgPool) {
    let (_aid, email, pw) = common::seed_admin(&pool).await;
    let company = seed_company(&pool, "Acme Co").await;
    let type_id = seed_asset_type(&pool, "Laptop").await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;
    turn_catalog_on(&app, &token).await;

    // Create one catalog model via the API so uses_count starts at 0.
    let model: Value = app
        .client
        .post(app.url(MODELS))
        .bearer_auth(&token)
        .json(&json!({
            "manufacturer": "Dell",
            "model": "Latitude 5450",
            "asset_type_id": type_id,
            "warranty_months": 36,
            "end_of_life_months": 60,
            "default_department": "Sales",
        }))
        .send()
        .await
        .expect("create model")
        .json()
        .await
        .expect("model JSON");
    let model_id = model["id"].as_str().unwrap();
    assert_eq!(model["uses_count"].as_i64(), Some(0));

    // Fan out 3 serials.
    let r = app
        .client
        .post(app.url(BULK_CREATE))
        .bearer_auth(&token)
        .json(&json!({
            "asset_model_id": model_id,
            "company_id": company,
            "purchase_date": "2026-01-15",
            "serials": [
                { "serial_number": "QA-001" },
                { "serial_number": "QA-002", "hostname": "ops-02" },
                { "serial_number": "QA-003" },
            ]
        }))
        .send()
        .await
        .expect("bulk create");
    assert_eq!(
        r.status(),
        StatusCode::CREATED,
        "body: {}",
        r.text().await.unwrap_or_default()
    );
    let v: Value = app
        .client
        .post(app.url(BULK_CREATE))
        .bearer_auth(&token)
        .json(&json!({
            "asset_model_id": model_id,
            "company_id": company,
            "purchase_date": "2026-01-15",
            "serials": [
                { "serial_number": "QA-004" },
            ]
        }))
        .send()
        .await
        .expect("bulk create 2")
        .json()
        .await
        .expect("json");
    assert_eq!(v["count"].as_i64(), Some(1));

    // uses_count on the model should be 4 (3 + 1).
    let m: Value = app
        .client
        .get(app.url(&format!("/api/v1/asset-models/{model_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("get model")
        .json()
        .await
        .expect("model json");
    assert_eq!(m["uses_count"].as_i64(), Some(4));

    // Each asset should have been seeded with the model's defaults:
    // manufacturer, model, asset_type_id, warranty_expiry (purchase +
    // 36 months), end_of_life (purchase + 60 months), department.
    let list: Value = app
        .client
        .get(app.url(&format!("/api/v1/assets?company_id={company}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list assets")
        .json()
        .await
        .expect("list json");
    let rows = list["data"].as_array().unwrap();
    assert_eq!(rows.len(), 4);
    let qa_001 = rows
        .iter()
        .find(|a| a["serial_number"] == "QA-001")
        .expect("QA-001 landed");
    assert_eq!(qa_001["manufacturer"], "Dell");
    assert_eq!(qa_001["model"], "Latitude 5450");
    assert_eq!(qa_001["department"], "Sales");
    assert_eq!(qa_001["warranty_expiry"], "2029-01-15");
    assert_eq!(qa_001["end_of_life"], "2031-01-15");
    // Auto-named "{manufacturer} {model} #{serial}" when no per-row name.
    assert_eq!(qa_001["name"], "Dell Latitude 5450 #QA-001");
    // PMS-1496: every row gets a unique auto-generated tag; the batch of
    // three plus the single reserved a contiguous AST-001..AST-004 range.
    let mut tags: Vec<&str> = rows
        .iter()
        .filter_map(|a| a["asset_tag"].as_str())
        .collect();
    tags.sort();
    assert_eq!(tags, vec!["AST-001", "AST-002", "AST-003", "AST-004"]);
}

/// PMS-1496 - per-serial `asset_tag` is rejected at the DTO; the server
/// owns issuance for the bulk-create fan-out too.
#[mokosh_test]
async fn bulk_create_rejects_caller_supplied_asset_tag(pool: PgPool) {
    let (_aid, email, pw) = common::seed_admin(&pool).await;
    let company = seed_company(&pool, "Acme Co").await;
    let type_id = seed_asset_type(&pool, "Laptop").await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;
    turn_catalog_on(&app, &token).await;

    let model: Value = app
        .client
        .post(app.url(MODELS))
        .bearer_auth(&token)
        .json(&json!({
            "manufacturer": "Dell",
            "model": "Latitude 5450",
            "asset_type_id": type_id,
        }))
        .send()
        .await
        .expect("create model")
        .json()
        .await
        .expect("model JSON");
    let model_id = model["id"].as_str().unwrap();

    let r = app
        .client
        .post(app.url(BULK_CREATE))
        .bearer_auth(&token)
        .json(&json!({
            "asset_model_id": model_id,
            "company_id": company,
            "serials": [
                { "serial_number": "QA-001" },
                { "serial_number": "QA-002", "asset_tag": "PICK-ME" },
            ]
        }))
        .send()
        .await
        .expect("bulk create with asset_tag");
    assert_eq!(r.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body: Value = r.json().await.unwrap_or(Value::Null);
    let found = body["error"]["errors"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .any(|e| e["field"].as_str() == Some("serials[1].asset_tag"))
        })
        .unwrap_or(false);
    assert!(
        found,
        "serials[1].asset_tag field envelope expected: {body}"
    );
}

#[mokosh_test]
async fn bulk_create_missing_asset_model_422s(pool: PgPool) {
    // The `serial_number` column on `assets` has no uniqueness constraint
    // today, so a mid-batch duplicate does not fail at the SQL layer and
    // the "collision rolls back" shape depends on a separate migration
    // not in scope for MR1. This test instead covers the shape that MR1
    // guarantees: a missing / nonexistent `asset_model_id` is a 422
    // before any row is inserted, which is the primary way the handler
    // guards the batch against an operator picking a model that was
    // deleted since the typeahead ran.
    let (_aid, email, pw) = common::seed_admin(&pool).await;
    let company = seed_company(&pool, "Acme Co").await;
    let _type_id = seed_asset_type(&pool, "Laptop").await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;
    turn_catalog_on(&app, &token).await;

    let r = app
        .client
        .post(app.url(BULK_CREATE))
        .bearer_auth(&token)
        .json(&json!({
            "asset_model_id": Uuid::new_v4(),
            "company_id": company,
            "serials": [{"serial_number": "QA-001"}, {"serial_number": "QA-002"}]
        }))
        .send()
        .await
        .expect("bulk create unknown model");
    assert_eq!(
        r.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "unknown asset_model_id must 422 (body: {})",
        r.text().await.unwrap_or_default()
    );

    // Zero rows landed because the model lookup fails before any INSERT.
    let list: Value = app
        .client
        .get(app.url(&format!("/api/v1/assets?company_id={company}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list assets")
        .json()
        .await
        .expect("list json");
    assert_eq!(list["data"].as_array().unwrap().len(), 0);
}

#[mokosh_test]
async fn bulk_create_rejects_over_500_serials(pool: PgPool) {
    let (_aid, email, pw) = common::seed_admin(&pool).await;
    let company = seed_company(&pool, "Acme Co").await;
    let type_id = seed_asset_type(&pool, "Laptop").await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;
    turn_catalog_on(&app, &token).await;

    let model: Value = app
        .client
        .post(app.url(MODELS))
        .bearer_auth(&token)
        .json(&json!({
            "manufacturer": "Dell",
            "model": "Latitude 5450",
            "asset_type_id": type_id,
        }))
        .send()
        .await
        .expect("create model")
        .json()
        .await
        .expect("model JSON");

    let serials: Vec<Value> = (0..501)
        .map(|i| json!({ "serial_number": format!("QA-{i:04}") }))
        .collect();
    let r = app
        .client
        .post(app.url(BULK_CREATE))
        .bearer_auth(&token)
        .json(&json!({
            "asset_model_id": model["id"],
            "company_id": company,
            "serials": serials,
        }))
        .send()
        .await
        .expect("bulk create 501");
    assert_eq!(
        r.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "over-cap must be 422"
    );
}

#[mokosh_test]
async fn template_crud_and_bulk_create_with_template_overlay(pool: PgPool) {
    let (_aid, email, pw) = common::seed_admin(&pool).await;
    let company_a = seed_company(&pool, "Acme Co").await;
    let company_b = seed_company(&pool, "Beta Co").await;
    let type_id = seed_asset_type(&pool, "Laptop").await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;
    turn_catalog_on(&app, &token).await;

    // Model + template.
    let model: Value = app
        .client
        .post(app.url(MODELS))
        .bearer_auth(&token)
        .json(&json!({
            "manufacturer": "Dell",
            "model": "Latitude 5450",
            "asset_type_id": type_id,
            "warranty_months": 36,
        }))
        .send()
        .await
        .expect("create model")
        .json()
        .await
        .expect("model JSON");
    let model_id = model["id"].as_str().unwrap().to_string();

    let r = app
        .client
        .post(app.url("/api/v1/asset-templates"))
        .bearer_auth(&token)
        .json(&json!({
            "name": "Sales Latitude",
            "asset_model_id": model_id,
            "company_id": company_a,
            "department": "Sales",
        }))
        .send()
        .await
        .expect("create template");
    assert_eq!(
        r.status(),
        StatusCode::CREATED,
        "body: {}",
        r.text().await.unwrap_or_default()
    );
    let template: Value = app
        .client
        .get(app.url("/api/v1/asset-templates"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list templates")
        .json()
        .await
        .expect("list json");
    let tpl = &template.as_array().unwrap()[0];
    assert_eq!(tpl["name"], "Sales Latitude");
    // Eager join must surface the model's manufacturer + model.
    assert_eq!(tpl["manufacturer"], "Dell");
    assert_eq!(tpl["model"], "Latitude 5450");
    let template_id = tpl["id"].as_str().unwrap().to_string();

    // Bulk-create with template_id + a different company in the request:
    // the template's company (Acme) wins per the plan ("template wins
    // when both are present").
    let r = app
        .client
        .post(app.url(BULK_CREATE))
        .bearer_auth(&token)
        .json(&json!({
            "template_id": template_id,
            "company_id": company_b,
            "serials": [
                { "serial_number": "T-001" },
                { "serial_number": "T-002" },
            ]
        }))
        .send()
        .await
        .expect("bulk create via template");
    assert_eq!(
        r.status(),
        StatusCode::CREATED,
        "body: {}",
        r.text().await.unwrap_or_default()
    );

    // Both created assets live at company_a (Acme), not company_b, and
    // carry the template's department.
    let list: Value = app
        .client
        .get(app.url(&format!("/api/v1/assets?company_id={company_a}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list assets")
        .json()
        .await
        .expect("list json");
    let rows = list["data"].as_array().unwrap();
    assert_eq!(rows.len(), 2, "template company overrides request");
    for row in rows {
        assert_eq!(row["department"], "Sales");
        assert_eq!(row["manufacturer"], "Dell");
    }

    // Template's uses_count bumped by 2.
    let after: Value = app
        .client
        .get(app.url(&format!("/api/v1/asset-templates/{template_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("get template")
        .json()
        .await
        .expect("tpl json");
    assert_eq!(after["uses_count"].as_i64(), Some(2));

    // Update template name.
    let r = app
        .client
        .put(app.url(&format!("/api/v1/asset-templates/{template_id}")))
        .bearer_auth(&token)
        .json(&json!({ "name": "Sales Latitude v2" }))
        .send()
        .await
        .expect("put template");
    assert_eq!(r.status(), StatusCode::OK);

    // Delete the template.
    let r = app
        .client
        .delete(app.url(&format!("/api/v1/asset-templates/{template_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("delete template");
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    let r = app
        .client
        .get(app.url("/api/v1/asset-templates"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list after delete");
    let v: Value = r.json().await.expect("json");
    assert_eq!(v.as_array().unwrap().len(), 0);
}

#[mokosh_test]
async fn model_update_and_delete(pool: PgPool) {
    let (_aid, email, pw) = common::seed_admin(&pool).await;
    let type_id = seed_asset_type(&pool, "Laptop").await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;
    turn_catalog_on(&app, &token).await;

    let model: Value = app
        .client
        .post(app.url(MODELS))
        .bearer_auth(&token)
        .json(&json!({
            "manufacturer": "Dell",
            "model": "Latitude 5450",
            "asset_type_id": type_id,
        }))
        .send()
        .await
        .expect("create")
        .json()
        .await
        .expect("json");
    let model_id = model["id"].as_str().unwrap();

    let r = app
        .client
        .put(app.url(&format!("/api/v1/asset-models/{model_id}")))
        .bearer_auth(&token)
        .json(&json!({ "warranty_months": 48 }))
        .send()
        .await
        .expect("put model");
    assert_eq!(r.status(), StatusCode::OK);
    let after: Value = r.json().await.expect("json");
    assert_eq!(after["warranty_months"].as_i64(), Some(48));

    let r = app
        .client
        .delete(app.url(&format!("/api/v1/asset-models/{model_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("delete model");
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    let r = app
        .client
        .get(app.url(&format!("/api/v1/asset-models/{model_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("get after delete");
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
}

#[mokosh_test]
async fn signature_detector_surfaces_hot_pattern_then_suppresses_once_tenant_authored(
    pool: PgPool,
) {
    let (_aid, email, pw) = common::seed_admin(&pool).await;
    let company = seed_company(&pool, "Acme Co").await;
    let type_id = seed_asset_type(&pool, "Laptop").await;

    // Seed 6 identical-signature assets so the matview's HAVING COUNT(*)
    // >= 5 picks them up on refresh. Direct INSERT so we can set
    // created_at explicitly inside the 7-day window; the API's POST sets
    // created_at to NOW() which would also work but makes the test
    // dependent on wall-clock timing.
    for i in 0..6 {
        sqlx::query(
            "INSERT INTO assets (id, tenant_id, name, asset_type_id, company_id, status, \
                                  manufacturer, model, serial_number, created_at) \
             VALUES ($1, $2, $3, $4, $5, 'active', 'Dell', 'Latitude 5450', $6, NOW() - INTERVAL '1 hour')"
        )
        .bind(Uuid::new_v4())
        .bind(common::DEFAULT_TENANT_ID)
        .bind(format!("hot-{i}"))
        .bind(type_id)
        .bind(company)
        .bind(format!("HOT-{i:03}"))
        .execute(&pool)
        .await
        .expect("seed hot asset");
    }

    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &pw).await;
    turn_catalog_on(&app, &token).await;

    // Refresh the matview so the SELECT below has data to find. The
    // scheduler runs this every 60s in production; in a test we trigger
    // it directly to avoid a sleep.
    sqlx::query("REFRESH MATERIALIZED VIEW asset_signature_candidates_mv")
        .execute(&pool)
        .await
        .expect("refresh mv");

    let r: Value = app
        .client
        .get(app.url("/api/v1/asset-models/signature-detector"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("get signature-detector")
        .json()
        .await
        .expect("sig JSON");
    let sig = &r["signature"];
    assert!(
        !sig.is_null(),
        "6 identical assets must surface a candidate: {r}"
    );
    assert_eq!(sig["manufacturer"], "Dell");
    assert_eq!(sig["model"], "Latitude 5450");
    assert_eq!(sig["recent_count"].as_i64(), Some(6));
    assert_eq!(sig["window_days"].as_i64(), Some(7));
    assert_eq!(sig["existing_model_id"].as_null(), Some(()));
    assert_eq!(
        sig["template_suggestion"]["name_hint"],
        "Dell Latitude 5450"
    );

    // Author a catalog row for the pattern - the detector must stop
    // returning the candidate because the operator has now "owned" it.
    let r = app
        .client
        .post(app.url(MODELS))
        .bearer_auth(&token)
        .json(&json!({
            "manufacturer": "Dell",
            "model": "Latitude 5450",
            "asset_type_id": type_id,
        }))
        .send()
        .await
        .expect("author catalog row");
    assert_eq!(r.status(), StatusCode::CREATED);

    let r: Value = app
        .client
        .get(app.url("/api/v1/asset-models/signature-detector"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("post-author sig")
        .json()
        .await
        .expect("sig JSON");
    assert!(
        r["signature"].is_null(),
        "tenant_authored catalog row must suppress the candidate: {r}"
    );
}

#[mokosh_test]
async fn seed_migration_populates_default_tenant_catalog(pool: PgPool) {
    // Migration 273 seeds a short mainstream catalog into the DEFAULT
    // tenant. The test harness runs every migration, so this must land
    // without touching the API. Verify a well-known row is present and
    // its asset_type_id resolves to the matching asset_types row.
    let (manufacturer, model, type_name): (String, String, String) = sqlx::query_as(
        "SELECT am.manufacturer, am.model, at.name \
         FROM asset_models am \
         JOIN asset_types at ON at.id = am.asset_type_id \
         WHERE am.tenant_id = $1 AND am.manufacturer = 'Dell' AND am.model = 'Latitude 5450'",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(&pool)
    .await
    .expect("Dell Latitude 5450 seeded");
    assert_eq!(manufacturer, "Dell");
    assert_eq!(model, "Latitude 5450");
    assert_eq!(type_name, "Laptop");

    // Row count is a smoke check that the full set landed, not just the
    // one we probed. Loose lower bound to tolerate catalog additions in
    // future migrations.
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM asset_models WHERE tenant_id = $1 AND source = 'seeded'",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(&pool)
    .await
    .expect("count seeded");
    assert!(
        count >= 30,
        "expected the seed migration to insert at least 30 rows, got {count}"
    );
}
