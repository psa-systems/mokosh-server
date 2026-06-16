//! Integration tests for the assets / CMDB module (PMS-71).
//!
//! Covers asset-type + asset CRUD, an asset relationship, and the secret
//! round-trip that matters most for a CMDB: configuration items and vault
//! credentials are encrypted at rest, their plaintext NEVER appears in a
//! list, and a single-item reveal decrypts them while writing an
//! `asset_audit_log` entry.

mod common;

use sqlx::PgPool;
use uuid::Uuid;

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

/// Create an asset type, returning its id.
async fn create_asset_type(app: &common::TestApp, token: &str, name: &str) -> String {
    let resp = app
        .client
        .post(app.url("/api/v1/asset-types"))
        .bearer_auth(token)
        .json(&serde_json::json!({ "name": name }))
        .send()
        .await
        .expect("create asset type");
    assert!(
        resp.status().is_success(),
        "create asset type expected 2xx, got {}",
        resp.status()
    );
    let v: serde_json::Value = resp.json().await.expect("asset type JSON");
    v["id"].as_str().expect("asset type id").to_string()
}

/// Create an asset, returning its id.
async fn create_asset(
    app: &common::TestApp,
    token: &str,
    name: &str,
    type_id: &str,
    company_id: Uuid,
) -> String {
    let resp = app
        .client
        .post(app.url("/api/v1/assets"))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "name": name,
            "asset_type_id": type_id,
            "company_id": company_id,
            "serial_number": "SN-12345",
        }))
        .send()
        .await
        .expect("create asset");
    assert!(
        resp.status().is_success(),
        "create asset expected 2xx, got {}",
        resp.status()
    );
    let v: serde_json::Value = resp.json().await.expect("asset JSON");
    v["id"].as_str().expect("asset id").to_string()
}

// AC1/AC2: asset-type + asset CRUD, tenant-scoped and filterable, with an
// audit-log row written on mutation.
#[sqlx::test]
async fn asset_crud_and_filtering(pool: PgPool) {
    let (_aid, email, pw) = common::seed_admin(&pool).await;
    let company = seed_company(&pool, "Acme Co").await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;

    let type_id = create_asset_type(&app, &token, "Server").await;
    let asset_id = create_asset(&app, &token, "web-01", &type_id, company).await;

    // Get.
    let got: serde_json::Value = app
        .client
        .get(app.url(&format!("/api/v1/assets/{asset_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("get asset")
        .json()
        .await
        .expect("asset JSON");
    assert_eq!(got["name"].as_str(), Some("web-01"));
    // PMS-336: the asset detail surfaces the owning company name, resolved
    // via the LEFT JOIN on companies (mirrors TicketResponse.company_name).
    assert_eq!(got["company_name"].as_str(), Some("Acme Co"));

    // List, filtered by company + name search.
    let list: serde_json::Value = app
        .client
        .get(app.url(&format!("/api/v1/assets?company_id={company}&q=web")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list assets")
        .json()
        .await
        .expect("list JSON");
    let listed = list["data"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["id"].as_str() == Some(asset_id.as_str()))
        .expect("asset appears in the filtered list");
    // PMS-336: the list Company column has a value to render for every row.
    assert_eq!(listed["company_name"].as_str(), Some("Acme Co"));

    // Update status.
    let upd = app
        .client
        .put(app.url(&format!("/api/v1/assets/{asset_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "status": "in_repair" }))
        .send()
        .await
        .expect("update asset");
    assert!(upd.status().is_success(), "update asset should 2xx");

    // Audit log records the mutations (admin-only endpoint).
    let audit: serde_json::Value = app
        .client
        .get(app.url(&format!("/api/v1/assets/{asset_id}/audit-log")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("audit log")
        .json()
        .await
        .expect("audit JSON");
    assert!(
        !audit["data"].as_array().unwrap().is_empty(),
        "asset mutations write asset_audit_log rows"
    );
    // PMS-204: the status edit's audit row carries the before/after diff so
    // the detail page can show the actual content, not just "status_changed".
    let status_change = audit["data"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["changes"].as_array())
        .flatten()
        .find(|c| c["field"].as_str() == Some("status"))
        .expect("an audit row must carry the status field change");
    assert_eq!(status_change["old"].as_str(), Some("active"));
    assert_eq!(status_change["new"].as_str(), Some("in_repair"));
}

// AC3: asset relationships with the four relationship types.
#[sqlx::test]
async fn asset_relationships(pool: PgPool) {
    let (_aid, email, pw) = common::seed_admin(&pool).await;
    let company = seed_company(&pool, "Acme Co").await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;

    let type_id = create_asset_type(&app, &token, "Server").await;
    let parent = create_asset(&app, &token, "host-01", &type_id, company).await;
    let child = create_asset(&app, &token, "vm-01", &type_id, company).await;

    let created = app
        .client
        .post(app.url(&format!("/api/v1/assets/{parent}/relationships")))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "child_asset_id": child,
            "relationship_type": "hosts",
        }))
        .send()
        .await
        .expect("create relationship");
    assert!(
        created.status().is_success(),
        "create relationship expected 2xx, got {}",
        created.status()
    );

    let list: serde_json::Value = app
        .client
        .get(app.url(&format!("/api/v1/assets/{parent}/relationships")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list relationships")
        .json()
        .await
        .expect("relationships JSON");
    assert!(
        list["data"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["relationship_type"].as_str() == Some("hosts")),
        "the 'hosts' relationship is listed"
    );
}

// AC4 (credentials): encrypted at rest, NEVER leaked in a list, reveal is
// authz-gated + audited.
#[sqlx::test]
async fn credential_round_trip_no_plaintext_in_list(pool: PgPool) {
    let (_aid, email, pw) = common::seed_admin(&pool).await;
    let company = seed_company(&pool, "Acme Co").await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;

    let type_id = create_asset_type(&app, &token, "Server").await;
    let asset_id = create_asset(&app, &token, "dc-01", &type_id, company).await;

    const SECRET_PW: &str = "sup3r-s3cret-pw";
    let created = app
        .client
        .post(app.url(&format!("/api/v1/assets/{asset_id}/credentials")))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "name": "domain-admin",
            "credential_type": "domain",
            "username": "administrator",
            "password": SECRET_PW,
        }))
        .send()
        .await
        .expect("create credential");
    assert!(
        created.status().is_success(),
        "create credential should 2xx"
    );
    let cred: serde_json::Value = created.json().await.expect("credential JSON");
    let cred_id = cred["id"].as_str().expect("credential id").to_string();

    // 1) Confirm it is encrypted at rest: the raw DB column is not plaintext.
    let stored: String =
        sqlx::query_scalar("SELECT password_encrypted FROM credential_vault WHERE id = $1")
            .bind(Uuid::parse_str(&cred_id).unwrap())
            .fetch_one(&app.pool)
            .await
            .expect("read stored password");
    assert_ne!(stored, SECRET_PW, "password is encrypted at rest");

    // 2) The LIST must not leak the secret.
    let list_raw = app
        .client
        .get(app.url(&format!("/api/v1/assets/{asset_id}/credentials")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list credentials")
        .text()
        .await
        .expect("list body");
    assert!(
        !list_raw.contains(SECRET_PW),
        "credential list must not contain the plaintext password"
    );
    assert!(
        !list_raw.contains("\"password\""),
        "credential list must not even carry a password field"
    );

    // 3) The reveal endpoint decrypts the secret.
    let revealed: serde_json::Value = app
        .client
        .get(app.url(&format!("/api/v1/credentials/{cred_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("reveal credential")
        .json()
        .await
        .expect("reveal JSON");
    assert_eq!(revealed["password"].as_str(), Some(SECRET_PW));
    assert_eq!(revealed["username"].as_str(), Some("administrator"));

    // 4) The reveal is audited.
    let audit_raw = app
        .client
        .get(app.url(&format!("/api/v1/assets/{asset_id}/audit-log")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("audit log")
        .text()
        .await
        .expect("audit body");
    assert!(
        audit_raw.contains("credential_read"),
        "revealing a credential writes an audited read event"
    );
}

// AC4 (configuration items): encrypted, value never leaked in a list,
// reveal decrypts it.
#[sqlx::test]
async fn configuration_item_round_trip_no_plaintext_in_list(pool: PgPool) {
    let (_aid, email, pw) = common::seed_admin(&pool).await;
    let company = seed_company(&pool, "Acme Co").await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;

    let type_id = create_asset_type(&app, &token, "Server").await;
    let asset_id = create_asset(&app, &token, "fw-01", &type_id, company).await;

    const SECRET_VAL: &str = "bios-master-key-xyz";
    let created = app
        .client
        .post(app.url(&format!("/api/v1/assets/{asset_id}/configuration-items")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "name": "bios-password", "value": SECRET_VAL }))
        .send()
        .await
        .expect("create config item");
    assert!(
        created.status().is_success(),
        "create config item should 2xx"
    );
    let item: serde_json::Value = created.json().await.expect("config JSON");
    let item_id = item["id"].as_str().expect("config id").to_string();

    let list_raw = app
        .client
        .get(app.url(&format!("/api/v1/assets/{asset_id}/configuration-items")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list config items")
        .text()
        .await
        .expect("list body");
    assert!(
        !list_raw.contains(SECRET_VAL),
        "config-item list must not contain the plaintext value"
    );
    assert!(
        !list_raw.contains("\"value\""),
        "config-item list must not carry a value field"
    );

    let revealed: serde_json::Value = app
        .client
        .get(app.url(&format!("/api/v1/configuration-items/{item_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("reveal config item")
        .json()
        .await
        .expect("reveal JSON");
    assert_eq!(revealed["value"].as_str(), Some(SECRET_VAL));
}

// PMS-188: delete_asset writes a `deleted` asset_audit_log row in the same tx
// as the delete, and that row survives the asset's removal (migration 042 drops
// the cascade FK and widens the action CHECK to allow 'deleted'). Regression
// guard for the CHECK-violation bug where every deletion 500'd.
#[sqlx::test]
async fn delete_asset_writes_surviving_deleted_audit_row(pool: PgPool) {
    let (_aid, email, pw) = common::seed_admin(&pool).await;
    let company = seed_company(&pool, "Acme Co").await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &pw).await;

    let type_id = create_asset_type(&app, &token, "Server").await;
    let asset_id = create_asset(&app, &token, "doomed-01", &type_id, company).await;
    let asset_uuid = Uuid::parse_str(&asset_id).expect("asset uuid");

    // Delete succeeds (would 500 with a check_violation before the fix).
    let del = app
        .client
        .delete(app.url(&format!("/api/v1/assets/{asset_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("delete asset");
    assert!(
        del.status().is_success(),
        "delete asset expected 2xx, got {}",
        del.status()
    );

    // The asset row is gone.
    let assets_left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM assets WHERE id = $1")
        .bind(asset_uuid)
        .fetch_one(&pool)
        .await
        .expect("count assets");
    assert_eq!(assets_left, 0, "the asset is removed");

    // The `deleted` audit row was written AND survives the delete (FK dropped).
    let deleted_audit: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM asset_audit_log WHERE asset_id = $1 AND action = 'deleted'",
    )
    .bind(asset_uuid)
    .fetch_one(&pool)
    .await
    .expect("count deleted audit rows");
    assert_eq!(
        deleted_audit, 1,
        "a surviving 'deleted' audit row records the deletion"
    );

    // Deleting again is a 404 (the tx that would have written a second audit row
    // rolls back, so no spurious 'deleted' row for a missing asset).
    let again = app
        .client
        .delete(app.url(&format!("/api/v1/assets/{asset_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("re-delete asset");
    assert_eq!(
        again.status(),
        reqwest::StatusCode::NOT_FOUND,
        "deleting a missing asset is 404"
    );
    let deleted_audit_after: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM asset_audit_log WHERE asset_id = $1 AND action = 'deleted'",
    )
    .bind(asset_uuid)
    .fetch_one(&pool)
    .await
    .expect("recount deleted audit rows");
    assert_eq!(
        deleted_audit_after, 1,
        "the failed re-delete writes no extra audit row (tx rolled back)"
    );
}
