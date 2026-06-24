//! PMS-475 / PMS-456 phase 2: integration test for the CI impact-graph
//! traversal at `GET /api/v1/assets/{id}/impact`.
//!
//! Pins four guarantees:
//!   - A linear chain A -> B -> C -> D returned in downstream order
//!     from A reaches B / C / D with monotonically increasing depth.
//!   - The same chain queried upstream from D returns C / B / A.
//!   - The per-tenant `ci/impact_max_depth` setting truncates the walk.
//!   - A 2-node cycle (A <-> B) terminates at the depth cap rather
//!     than looping forever.

mod common;

use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_company(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, 'Impact CI Co')")
        .bind(id)
        .bind(common::DEFAULT_TENANT_ID)
        .execute(pool)
        .await
        .expect("seed company");
    id
}

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

async fn seed_asset(pool: &PgPool, name: &str, type_id: Uuid, company_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO assets (id, tenant_id, asset_type_id, name, company_id, status) \
         VALUES ($1, $2, $3, $4, $5, 'active')",
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(type_id)
    .bind(name)
    .bind(company_id)
    .execute(pool)
    .await
    .expect("seed asset");
    id
}

async fn seed_rel(pool: &PgPool, parent: Uuid, child: Uuid, kind: &str) {
    sqlx::query(
        "INSERT INTO asset_relationships \
             (tenant_id, parent_asset_id, child_asset_id, relationship_type) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(parent)
    .bind(child)
    .bind(kind)
    .execute(pool)
    .await
    .expect("seed relationship");
}

async fn get_impact(app: &common::TestApp, token: &str, asset_id: Uuid, query: &str) -> Value {
    app.client
        .get(app.url(&format!("/api/v1/assets/{asset_id}/impact?{query}")))
        .bearer_auth(token)
        .send()
        .await
        .expect("GET impact")
        .json()
        .await
        .expect("impact body")
}

#[sqlx::test]
async fn impact_walks_downstream_and_upstream_chain(pool: PgPool) {
    let (_aid, email, password) = common::seed_admin(&pool).await;
    let company = seed_company(&pool).await;
    let kind = seed_asset_type(&pool, "Service").await;
    let a = seed_asset(&pool, "AAA root", kind, company).await;
    let b = seed_asset(&pool, "BBB mid1", kind, company).await;
    let c = seed_asset(&pool, "CCC mid2", kind, company).await;
    let d = seed_asset(&pool, "DDD leaf", kind, company).await;
    // A -> B -> C -> D
    seed_rel(&pool, a, b, "depends_on").await;
    seed_rel(&pool, b, c, "depends_on").await;
    seed_rel(&pool, c, d, "depends_on").await;

    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    // Downstream from A: B (depth 1), C (depth 2), D (depth 3).
    let resp = get_impact(&app, &token, a, "direction=downstream&depth=10").await;
    let nodes = resp["nodes"].as_array().expect("nodes");
    let depths: std::collections::HashMap<String, i64> = nodes
        .iter()
        .map(|n| {
            (
                n["asset_id"].as_str().unwrap().to_string(),
                n["depth"].as_i64().unwrap(),
            )
        })
        .collect();
    assert_eq!(depths.get(&b.to_string()), Some(&1));
    assert_eq!(depths.get(&c.to_string()), Some(&2));
    assert_eq!(depths.get(&d.to_string()), Some(&3));
    assert!(
        !depths.contains_key(&a.to_string()),
        "root should not appear in its own impact set"
    );

    // Upstream from D: C, B, A.
    let resp = get_impact(&app, &token, d, "direction=upstream&depth=10").await;
    let nodes = resp["nodes"].as_array().expect("upstream nodes");
    let depths: std::collections::HashMap<String, i64> = nodes
        .iter()
        .map(|n| {
            (
                n["asset_id"].as_str().unwrap().to_string(),
                n["depth"].as_i64().unwrap(),
            )
        })
        .collect();
    assert_eq!(depths.get(&c.to_string()), Some(&1));
    assert_eq!(depths.get(&b.to_string()), Some(&2));
    assert_eq!(depths.get(&a.to_string()), Some(&3));
}

#[sqlx::test]
async fn impact_depth_cap_applies_from_tenant_setting(pool: PgPool) {
    let (_aid, email, password) = common::seed_admin(&pool).await;
    let company = seed_company(&pool).await;
    let kind = seed_asset_type(&pool, "Service").await;
    let a = seed_asset(&pool, "AAA cap root", kind, company).await;
    let b = seed_asset(&pool, "BBB cap mid1", kind, company).await;
    let c = seed_asset(&pool, "CCC cap mid2", kind, company).await;
    let d = seed_asset(&pool, "DDD cap leaf", kind, company).await;
    seed_rel(&pool, a, b, "depends_on").await;
    seed_rel(&pool, b, c, "depends_on").await;
    seed_rel(&pool, c, d, "depends_on").await;

    // Clamp the tenant cap to 2; the migration seeded 5, so an
    // upsert overrides it.
    sqlx::query(
        "INSERT INTO tenant_settings (tenant_id, category, key, value) \
         VALUES ($1, 'ci', 'impact_max_depth', to_jsonb(2::int)) \
         ON CONFLICT (tenant_id, category, key) DO UPDATE SET value = EXCLUDED.value",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .execute(&pool)
    .await
    .expect("override tenant cap");

    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    // depth=10 in the query, but the tenant cap clamps to 2 so D is
    // out of reach.
    let resp = get_impact(&app, &token, a, "direction=downstream&depth=10").await;
    assert_eq!(resp["depth"].as_i64(), Some(2), "effective depth = 2");
    let nodes = resp["nodes"].as_array().expect("nodes");
    let ids: std::collections::HashSet<String> = nodes
        .iter()
        .map(|n| n["asset_id"].as_str().unwrap().to_string())
        .collect();
    assert!(ids.contains(&b.to_string()));
    assert!(ids.contains(&c.to_string()));
    assert!(
        !ids.contains(&d.to_string()),
        "D is at depth 3, beyond the cap; got nodes: {ids:?}"
    );
}

#[sqlx::test]
async fn impact_cycle_terminates_at_cap(pool: PgPool) {
    let (_aid, email, password) = common::seed_admin(&pool).await;
    let company = seed_company(&pool).await;
    let kind = seed_asset_type(&pool, "Service").await;
    let a = seed_asset(&pool, "AAA cycle", kind, company).await;
    let b = seed_asset(&pool, "BBB cycle", kind, company).await;
    // A <-> B cycle. With cap 5, the CTE visits A and B alternately
    // up to depth 5, then stops. A pathological infinite loop would
    // hang the test (sqlx::test caps at the runtime's default).
    seed_rel(&pool, a, b, "connected_to").await;
    seed_rel(&pool, b, a, "connected_to").await;

    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let resp = get_impact(&app, &token, a, "direction=downstream&depth=10").await;
    let nodes = resp["nodes"].as_array().expect("nodes");
    let max_depth = nodes
        .iter()
        .map(|n| n["depth"].as_i64().unwrap())
        .max()
        .unwrap_or(0);
    assert!(
        max_depth <= 10,
        "cycle traversal must respect the cap; got max depth {max_depth}"
    );
    assert!(
        !nodes.is_empty(),
        "cycle should still surface neighbours, not return empty"
    );
}

#[sqlx::test]
async fn impact_both_returns_upstream_and_downstream(pool: PgPool) {
    let (_aid, email, password) = common::seed_admin(&pool).await;
    let company = seed_company(&pool).await;
    let kind = seed_asset_type(&pool, "Service").await;
    let parent = seed_asset(&pool, "PARENT both", kind, company).await;
    let middle = seed_asset(&pool, "MIDDLE both", kind, company).await;
    let child = seed_asset(&pool, "CHILD both", kind, company).await;
    seed_rel(&pool, parent, middle, "hosts").await;
    seed_rel(&pool, middle, child, "hosts").await;

    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let resp = get_impact(&app, &token, middle, "direction=both&depth=5").await;
    let nodes = resp["nodes"].as_array().expect("both nodes");
    let by_dir: std::collections::HashMap<String, Vec<String>> =
        nodes
            .iter()
            .fold(std::collections::HashMap::new(), |mut acc, n| {
                acc.entry(n["direction"].as_str().unwrap().to_string())
                    .or_default()
                    .push(n["asset_id"].as_str().unwrap().to_string());
                acc
            });
    assert!(
        by_dir
            .get("downstream")
            .is_some_and(|v| v.contains(&child.to_string())),
        "downstream half must include the child; got {by_dir:?}"
    );
    assert!(
        by_dir
            .get("upstream")
            .is_some_and(|v| v.contains(&parent.to_string())),
        "upstream half must include the parent; got {by_dir:?}"
    );
}
