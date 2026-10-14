//! PMS-1486 asset search v2: the structured-filter search endpoint and
//! its companion facets endpoint.
//!
//! The surface is gated behind the `assets_search_v2` feature toggle;
//! every test here flips it on through the admin HTTP endpoint (same
//! shape `tests/feature_toggles.rs` uses) before hitting the search
//! route, so the gate itself is exercised on the toggle-off path.

mod common;

use mokosh_test::mokosh_test;
use reqwest::StatusCode;
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

const FLIP_PATH: &str = "/api/v1/settings/feature-toggles/assets_search_v2";
const SEARCH: &str = "/api/v1/assets/search";
const FACETS: &str = "/api/v1/assets/search/facets";

/// Flip `assets_search_v2` on. Uses the admin HTTP endpoint because that is
/// the path that swaps the live snapshot (`tests/feature_toggles.rs:85`
/// documents the invariant); writing the row directly would not.
async fn turn_search_on(app: &common::TestApp, operator: &str) {
    let r = app
        .client
        .put(app.url(FLIP_PATH))
        .bearer_auth(operator)
        .json(&json!({ "enabled": true }))
        .send()
        .await
        .expect("flip assets_search_v2");
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

#[allow(clippy::too_many_arguments)]
async fn seed_asset(
    pool: &PgPool,
    company: Uuid,
    asset_type: Uuid,
    name: &str,
    status: &str,
    hostname: Option<&str>,
    ip: Option<&str>,
    mac: Option<&str>,
    manufacturer: Option<&str>,
    model: Option<&str>,
    warranty: Option<chrono::NaiveDate>,
    end_of_life: Option<chrono::NaiveDate>,
    tags: Option<&[&str]>,
) -> Uuid {
    let id = Uuid::new_v4();
    let tags_vec: Option<Vec<String>> = tags.map(|t| t.iter().map(|s| s.to_string()).collect());
    sqlx::query(
        r#"INSERT INTO assets
           (id, tenant_id, name, asset_type_id, company_id, status,
            hostname, ip_address, mac_address, manufacturer, model,
            warranty_expiry, end_of_life, tags)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8::inet, $9, $10, $11, $12, $13, $14)"#,
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(name)
    .bind(asset_type)
    .bind(company)
    .bind(status)
    .bind(hostname)
    .bind(ip)
    .bind(mac)
    .bind(manufacturer)
    .bind(model)
    .bind(warranty)
    .bind(end_of_life)
    .bind(tags_vec)
    .execute(pool)
    .await
    .expect("seed asset");
    id
}

async fn post_search(app: &common::TestApp, token: &str, body: Value) -> (StatusCode, Value) {
    let r = app
        .client
        .post(app.url(SEARCH))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .expect("search");
    let st = r.status();
    let json = r.json().await.unwrap_or(Value::Null);
    (st, json)
}

async fn post_facets(app: &common::TestApp, token: &str, body: Value) -> (StatusCode, Value) {
    let r = app
        .client
        .post(app.url(FACETS))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .expect("facets");
    let st = r.status();
    let json = r.json().await.unwrap_or(Value::Null);
    (st, json)
}

/// T1 - the gate: toggle off ⇒ 404 before any DB round trip.
#[mokosh_test]
async fn gate_search_off_returns_404(pool: PgPool) {
    let (_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let (st, _) = post_search(&app, &token, json!({})).await;
    assert_eq!(st, StatusCode::NOT_FOUND, "toggle off means 404");
    let (st, _) = post_facets(&app, &token, json!({})).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
}

/// T2 - free-text haystack: pasting a serial / hostname / mac finds the row.
#[mokosh_test]
async fn haystack_matches_hostname_serial_and_mac(pool: PgPool) {
    let (_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    turn_search_on(&app, &token).await;

    let co = seed_company(&pool, "Acme").await;
    let at = seed_asset_type(&pool, "Laptop").await;
    let a = seed_asset(
        &pool,
        co,
        at,
        "Alice's laptop",
        "active",
        Some("alice-x1.corp.local"),
        Some("10.0.0.42"),
        Some("aa:bb:cc:dd:ee:ff"),
        Some("Dell"),
        Some("Latitude 5450"),
        None,
        None,
        Some(&["kiosk", "sales"]),
    )
    .await;

    for q in ["alice-x1", "10.0.0.42", "aa:bb:cc", "latitude"] {
        let (st, body) = post_search(&app, &token, json!({ "q": q })).await;
        assert_eq!(st, StatusCode::OK, "status for q={q}");
        let hits = body["data"].as_array().expect("data array");
        assert!(
            hits.iter()
                .any(|r| r["id"].as_str() == Some(&a.to_string())),
            "q={q:?} should match the seeded asset: {body}"
        );
    }
}

/// T3 - single facet: `status in [active]` returns only active rows.
#[mokosh_test]
async fn facet_status_in_narrows_results(pool: PgPool) {
    let (_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    turn_search_on(&app, &token).await;

    let co = seed_company(&pool, "Acme").await;
    let at = seed_asset_type(&pool, "Laptop").await;
    let active = seed_asset(
        &pool,
        co,
        at,
        "Active one",
        "active",
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .await;
    let _retired = seed_asset(
        &pool,
        co,
        at,
        "Retired one",
        "retired",
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .await;

    let (st, body) = post_search(
        &app,
        &token,
        json!({
            "filters": [{"field": "status", "op": "in", "values": ["active"]}]
        }),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let ids: Vec<&str> = body["data"]
        .as_array()
        .expect("data")
        .iter()
        .map(|r| r["id"].as_str().unwrap_or(""))
        .collect();
    assert!(ids.contains(&active.to_string().as_str()));
    assert_eq!(ids.len(), 1, "retired row should be excluded: {body}");
}

/// T4 - three ANDed facets intersect correctly.
#[mokosh_test]
async fn three_anded_facets_intersect(pool: PgPool) {
    let (_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    turn_search_on(&app, &token).await;

    let acme = seed_company(&pool, "Acme").await;
    let other = seed_company(&pool, "Other").await;
    let laptop = seed_asset_type(&pool, "Laptop").await;
    let server = seed_asset_type(&pool, "Server").await;

    // The one row that matches all three facets.
    let hit = seed_asset(
        &pool,
        acme,
        laptop,
        "Hit",
        "active",
        None,
        None,
        None,
        Some("Dell"),
        None,
        None,
        None,
        None,
    )
    .await;
    // Rows that miss one facet each.
    let _wrong_company = seed_asset(
        &pool,
        other,
        laptop,
        "Wrong co",
        "active",
        None,
        None,
        None,
        Some("Dell"),
        None,
        None,
        None,
        None,
    )
    .await;
    let _wrong_type = seed_asset(
        &pool,
        acme,
        server,
        "Wrong type",
        "active",
        None,
        None,
        None,
        Some("Dell"),
        None,
        None,
        None,
        None,
    )
    .await;
    let _wrong_status = seed_asset(
        &pool,
        acme,
        laptop,
        "Wrong status",
        "retired",
        None,
        None,
        None,
        Some("Dell"),
        None,
        None,
        None,
        None,
    )
    .await;

    let (st, body) = post_search(
        &app,
        &token,
        json!({
            "filters": [
                {"field": "company",    "op": "eq", "values": [acme.to_string()]},
                {"field": "asset_type", "op": "eq", "values": [laptop.to_string()]},
                {"field": "status",     "op": "eq", "values": ["active"]}
            ]
        }),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let ids: Vec<&str> = body["data"]
        .as_array()
        .expect("data")
        .iter()
        .map(|r| r["id"].as_str().unwrap_or(""))
        .collect();
    assert_eq!(ids, vec![hit.to_string().as_str()], "{body}");
}

/// T5 - IsNull: hostname is NULL.
#[mokosh_test]
async fn is_null_facet_matches_only_null_rows(pool: PgPool) {
    let (_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    turn_search_on(&app, &token).await;

    let co = seed_company(&pool, "Acme").await;
    let at = seed_asset_type(&pool, "Laptop").await;
    let _with = seed_asset(
        &pool,
        co,
        at,
        "Has hostname",
        "active",
        Some("has.corp.local"),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .await;
    let without = seed_asset(
        &pool,
        co,
        at,
        "No hostname",
        "active",
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .await;

    let (st, body) = post_search(
        &app,
        &token,
        json!({
            "filters": [{"field": "department", "op": "is_null"}]
        }),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    // Both seeded rows have NULL department; both match. Use the known one.
    let ids: Vec<String> = body["data"]
        .as_array()
        .expect("data")
        .iter()
        .map(|r| r["id"].as_str().unwrap_or("").to_string())
        .collect();
    assert!(ids.contains(&without.to_string()));
}

/// T6 - Within {days:30}: warranty expiring in the next 30 days.
#[mokosh_test]
async fn within_days_30_matches_near_term_warranty(pool: PgPool) {
    let (_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    turn_search_on(&app, &token).await;

    let co = seed_company(&pool, "Acme").await;
    let at = seed_asset_type(&pool, "Laptop").await;
    let soon = chrono::Utc::now().date_naive() + chrono::Duration::days(15);
    let far = chrono::Utc::now().date_naive() + chrono::Duration::days(120);
    let near_asset = seed_asset(
        &pool,
        co,
        at,
        "Expires soon",
        "active",
        None,
        None,
        None,
        None,
        None,
        Some(soon),
        None,
        None,
    )
    .await;
    let _far_asset = seed_asset(
        &pool,
        co,
        at,
        "Expires far",
        "active",
        None,
        None,
        None,
        None,
        None,
        Some(far),
        None,
        None,
    )
    .await;

    let (st, body) = post_search(
        &app,
        &token,
        json!({
            "filters": [{"field": "warranty_expiry", "op": "within", "values": [{"days": 30}]}]
        }),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let ids: Vec<&str> = body["data"]
        .as_array()
        .expect("data")
        .iter()
        .map(|r| r["id"].as_str().unwrap_or(""))
        .collect();
    assert_eq!(ids, vec![near_asset.to_string().as_str()], "{body}");
}

/// T7 - ContainsTag: `tag:kiosk` matches a row carrying that tag.
#[mokosh_test]
async fn contains_tag_matches_only_tagged_rows(pool: PgPool) {
    let (_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    turn_search_on(&app, &token).await;

    let co = seed_company(&pool, "Acme").await;
    let at = seed_asset_type(&pool, "Laptop").await;
    let tagged = seed_asset(
        &pool,
        co,
        at,
        "Tagged",
        "active",
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(&["kiosk", "sales"]),
    )
    .await;
    let _plain = seed_asset(
        &pool, co, at, "Plain", "active", None, None, None, None, None, None, None, None,
    )
    .await;

    let (st, body) = post_search(
        &app,
        &token,
        json!({
            "filters": [{"field": "tags", "op": "contains_tag", "values": ["kiosk"]}]
        }),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let ids: Vec<&str> = body["data"]
        .as_array()
        .expect("data")
        .iter()
        .map(|r| r["id"].as_str().unwrap_or(""))
        .collect();
    assert_eq!(ids, vec![tagged.to_string().as_str()]);
}

/// T8 - validation: an unknown field value refuses with 422; a wrong (field, op)
/// pair refuses with 422; the request shape itself is enforced before any
/// query runs.
#[mokosh_test]
async fn validation_refuses_unknown_field_or_wrong_op(pool: PgPool) {
    let (_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    turn_search_on(&app, &token).await;

    // Unknown field name on the wire ⇒ 422 at the deserialize boundary
    // (serde enum fails ⇒ 400). Axum maps the serde failure to 422 via
    // the shared Json extractor; the handler never runs.
    let r = app
        .client
        .post(app.url(SEARCH))
        .bearer_auth(&token)
        .json(&json!({
            "filters": [{"field": "not_a_facet", "op": "eq", "values": ["x"]}]
        }))
        .send()
        .await
        .expect("send");
    assert!(
        r.status().is_client_error(),
        "unknown field should refuse at the request shape: {}",
        r.status()
    );

    // Known field, wrong op combination (ContainsTag on Status).
    let (st, body) = post_search(
        &app,
        &token,
        json!({
            "filters": [{"field": "status", "op": "contains_tag", "values": ["foo"]}]
        }),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::UNPROCESSABLE_ENTITY,
        "status + contains_tag should 422: {body}"
    );
}

/// T9 - facets endpoint returns per-facet counts under the applied filter.
#[mokosh_test]
async fn facets_counts_respect_the_applied_filter(pool: PgPool) {
    let (_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    turn_search_on(&app, &token).await;

    let acme = seed_company(&pool, "Acme").await;
    let other = seed_company(&pool, "Other").await;
    let at = seed_asset_type(&pool, "Laptop").await;
    for i in 0..3 {
        seed_asset(
            &pool,
            acme,
            at,
            &format!("A{i}"),
            "active",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await;
    }
    for i in 0..2 {
        seed_asset(
            &pool,
            other,
            at,
            &format!("O{i}"),
            "retired",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await;
    }

    // Facets with no filter: both status buckets appear.
    let (st, body) = post_facets(&app, &token, json!({})).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let status_buckets: Vec<(String, i64)> = body["status"]
        .as_array()
        .expect("status array")
        .iter()
        .map(|row| {
            (
                row["value"].as_str().unwrap_or("").to_string(),
                row["count"].as_i64().unwrap_or(0),
            )
        })
        .collect();
    assert!(status_buckets.iter().any(|(v, c)| v == "active" && *c == 3));
    assert!(status_buckets
        .iter()
        .any(|(v, c)| v == "retired" && *c == 2));

    // Facets with a company filter: only Acme's three active rows survive.
    let (st, body) = post_facets(
        &app,
        &token,
        json!({
            "filters": [{"field": "company", "op": "eq", "values": [acme.to_string()]}]
        }),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let scoped_status: Vec<(String, i64)> = body["status"]
        .as_array()
        .expect("status array")
        .iter()
        .map(|row| {
            (
                row["value"].as_str().unwrap_or("").to_string(),
                row["count"].as_i64().unwrap_or(0),
            )
        })
        .collect();
    assert!(scoped_status.iter().any(|(v, c)| v == "active" && *c == 3));
    assert!(
        !scoped_status.iter().any(|(v, _)| v == "retired"),
        "retired bucket should be gone under the Acme filter: {body}"
    );
}
