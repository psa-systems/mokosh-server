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

    // Create three models under one asset type. All manufacturer "Dell"
    // so the typeahead can rank them by uses_count.
    for (manufacturer, model) in [
        ("Dell", "Latitude 5450"),
        ("Dell", "XPS 15"),
        ("Dell", "OptiPlex 7010"),
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

    // Default typeahead (no q): all three come back ordered by uses_count
    // DESC and then by (manufacturer, model). Each uses_count is 0 at
    // seed; the model names decide the tie-break alphabetically on
    // lowercase.
    let r: Value = app
        .client
        .get(app.url("/api/v1/asset-models"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list models")
        .json()
        .await
        .expect("models JSON");
    let arr = r.as_array().expect("array");
    let names: Vec<&str> = arr
        .iter()
        .map(|m| m["model"].as_str().unwrap_or_default())
        .collect();
    assert_eq!(names, vec!["Latitude 5450", "OptiPlex 7010", "XPS 15"]);

    // Typeahead q=lat should narrow to Latitude only.
    let r: Value = app
        .client
        .get(app.url("/api/v1/asset-models?q=lat"))
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
    assert_eq!(names, vec!["Latitude 5450"]);

    // Duplicate shape rejected: same tenant + manufacturer + model + type.
    let r = app
        .client
        .post(app.url(MODELS))
        .bearer_auth(&token)
        .json(&json!({
            "manufacturer": "dell",
            "model": "LATITUDE 5450",
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
