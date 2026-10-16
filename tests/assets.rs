//! Integration tests for the assets / CMDB module (PMS-71).
//!
//! Covers asset-type + asset CRUD, an asset relationship, and the secret
//! round-trip that matters most for a CMDB: configuration items and vault
//! credentials are encrypted at rest, their plaintext NEVER appears in a
//! list, and a single-item reveal decrypts them while writing an
//! `asset_audit_log` entry.

mod common;

use mokosh_test::mokosh_test;
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
#[mokosh_test]
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

/// PMS-1478: `AssetAuditLogResponse.performed_by_name` is resolved
/// server-side by a tenant-scoped JOIN on `users`, covering a named user, a
/// user whose profile name is still blank (falls back to email), a user id
/// that no longer resolves to any row ("deleted"), a NULL user id, and a
/// user who exists but in a different tenant (never resolved, even though
/// the id matches). Rows are inserted directly into `asset_audit_log`
/// rather than produced by API calls, since the write path is already
/// covered by `asset_crud_and_filtering`; this test is only about the read
/// side's name resolution.
#[mokosh_test]
async fn asset_audit_log_resolves_actor_name(pool: PgPool) {
    let (_aid, email, pw) = common::seed_admin(&pool).await;
    let company = seed_company(&pool, "Acme Co").await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &pw).await;

    let type_id = create_asset_type(&app, &token, "Server").await;
    let asset_id: Uuid = create_asset(&app, &token, "web-01", &type_id, company)
        .await
        .parse()
        .unwrap();

    let (named_id, _, _) = common::seed_user(
        &pool,
        common::DEFAULT_TENANT_ID,
        "named-asset@example.com",
        "technician",
    )
    .await;

    let empty_name_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name, role, status) \
         VALUES ($1, $2, $3, 'x', '', '', 'technician', 'active')",
    )
    .bind(empty_name_id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind("blank-profile-asset@example.com")
    .execute(&pool)
    .await
    .expect("seed empty-name user");

    let (_other_tenant_id, other_tenant_user_id, _, _) =
        common::seed_tenant_with_admin(&pool, "pms-1478-asset-other-tenant").await;

    let fk_name: String = sqlx::query_scalar(
        "SELECT conname FROM pg_constraint WHERE conrelid = 'asset_audit_log'::regclass \
         AND contype = 'f' AND conname LIKE '%performed_by_id%'",
    )
    .fetch_one(&pool)
    .await
    .expect("find asset_audit_log performed_by_id FK");
    sqlx::query(&format!(
        "ALTER TABLE asset_audit_log DROP CONSTRAINT {fk_name}"
    ))
    .execute(&pool)
    .await
    .expect("drop asset_audit_log performed_by_id FK for this test DB");
    let deleted_user_id = Uuid::new_v4();

    for (user_id, label) in [
        (Some(named_id), "named"),
        (Some(empty_name_id), "empty-name"),
        (Some(other_tenant_user_id), "other-tenant"),
        (Some(deleted_user_id), "deleted"),
        (None, "null"),
    ] {
        sqlx::query(
            "INSERT INTO asset_audit_log (tenant_id, asset_id, action, performed_by_id, changes) \
             VALUES ($1, $2, 'updated', $3, $4)",
        )
        .bind(common::DEFAULT_TENANT_ID)
        .bind(asset_id)
        .bind(user_id)
        .bind(serde_json::json!({ "label": label }))
        .execute(&pool)
        .await
        .expect("insert asset_audit_log row");
    }

    let audit: serde_json::Value = app
        .client
        .get(app.url(&format!("/api/v1/assets/{asset_id}/audit-log")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("asset audit log")
        .json()
        .await
        .expect("audit JSON");
    let entries = audit["data"].as_array().expect("audit has data");
    let find_by_user = |id: Option<Uuid>| {
        entries
            .iter()
            .find(|e| {
                e["performed_by_id"]
                    .as_str()
                    .and_then(|s| s.parse::<Uuid>().ok())
                    == id
            })
            .unwrap_or_else(|| panic!("no audit entry for performed_by_id {id:?}"))
    };

    assert_eq!(
        find_by_user(Some(named_id))["performed_by_name"].as_str(),
        Some("Test User"),
        "named user resolves to first + last name"
    );
    assert_eq!(
        find_by_user(Some(empty_name_id))["performed_by_name"].as_str(),
        Some("blank-profile-asset@example.com"),
        "a user with no profile name falls back to their email"
    );
    assert_eq!(
        find_by_user(Some(other_tenant_user_id))["performed_by_name"].as_str(),
        None,
        "a user who exists only in another tenant is never resolved"
    );
    assert_eq!(
        find_by_user(Some(deleted_user_id))["performed_by_name"].as_str(),
        None,
        "a user id with no matching row resolves to None, not an error"
    );
    assert_eq!(
        find_by_user(None)["performed_by_name"].as_str(),
        None,
        "a NULL performed_by_id resolves to None by contract"
    );
}

// AC3: asset relationships with the four relationship types.
#[mokosh_test]
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
#[mokosh_test]
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
#[mokosh_test]
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
#[mokosh_test]
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

/// PMS-894: `?q=` matches serial numbers, not just names.
///
/// The SPA's asset list searches both. Moving that filter server-side so the
/// page can be paged (MAPPS-546) would, on name-only matching, have silently
/// dropped serial search - and a serial is the string an operator is most
/// likely to paste into an asset search, off a sticker on the hardware.
#[mokosh_test]
async fn asset_search_matches_serial_numbers(pool: PgPool) {
    let (_admin_id, email, pw) = common::seed_admin(&pool).await;
    let company = seed_company(&pool, "Acme Co").await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;
    let type_id = create_asset_type(&app, &token, "Laptop").await;

    // `create_asset` stamps serial_number = "SN-12345".
    create_asset(&app, &token, "Reception laptop", &type_id, company).await;
    create_asset(&app, &token, "Server rack", &type_id, company).await;

    let search = |q: &str| {
        let client = app.client.clone();
        let url = app.url(&format!("/api/v1/assets?q={q}"));
        let token = token.clone();
        async move {
            let resp = client
                .get(url)
                .bearer_auth(token)
                .send()
                .await
                .expect("search assets");
            assert!(resp.status().is_success(), "got {}", resp.status());
            let v: serde_json::Value = resp.json().await.expect("assets JSON");
            v["data"]
                .as_array()
                .expect("data array")
                .iter()
                .map(|a| a["name"].as_str().unwrap_or_default().to_string())
                .collect::<Vec<_>>()
        }
    };

    // Name matching still works.
    let by_name = search("Reception").await;
    assert_eq!(by_name, vec!["Reception laptop".to_string()]);

    // The serial matches both assets, because the fixture gives them the same
    // one; what matters is that a serial matches at all, and that it is the
    // serial doing it rather than the name.
    let by_serial = search("SN-12345").await;
    assert_eq!(
        by_serial.len(),
        2,
        "a serial number must match, got {by_serial:?}"
    );

    // And a string in neither field still matches nothing, so the predicate is
    // filtering rather than passing everything through.
    assert!(search("nothing-matches-this").await.is_empty());
}

/// PMS-1490: `POST /api/v1/assets/exists` returns which of the given
/// serials already belong to an asset at the given company so the SPA's
/// bulk-create modal can trim or warn before firing the fan-out.
#[mokosh_test]
async fn assets_exists_names_matches_case_insensitively_within_the_company_scope(pool: PgPool) {
    let (_admin_id, email, pw) = common::seed_admin(&pool).await;
    let main_street = seed_company(&pool, "Main Street Dental").await;
    let riverside = seed_company(&pool, "Riverside Accounting").await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;
    let type_id = create_asset_type(&app, &token, "Laptop").await;

    // Seed with a mix of serials across both companies. `create_asset`
    // stamps SN-12345, so override via the API's full serial_number field.
    let seed = |name: &'static str, serial: &'static str, company: Uuid| {
        let client = app.client.clone();
        let url = app.url("/api/v1/assets");
        let token = token.clone();
        let type_id = type_id.clone();
        async move {
            let resp = client
                .post(url)
                .bearer_auth(token)
                .json(&serde_json::json!({
                    "name": name,
                    "asset_type_id": type_id,
                    "company_id": company,
                    "serial_number": serial,
                }))
                .send()
                .await
                .expect("create asset");
            assert!(resp.status().is_success(), "create: {}", resp.status());
        }
    };
    seed("ms-01", "QA-001", main_street).await;
    seed("ms-02", "qa-002", main_street).await;
    seed("rs-01", "QA-003", riverside).await;

    let probe = |company_id: Uuid, serials: serde_json::Value| {
        let client = app.client.clone();
        let url = app.url("/api/v1/assets/exists");
        let token = token.clone();
        async move {
            let resp = client
                .post(url)
                .bearer_auth(token)
                .json(&serde_json::json!({ "company_id": company_id, "serials": serials }))
                .send()
                .await
                .expect("post exists");
            assert!(resp.status().is_success(), "exists: {}", resp.status());
            let v: serde_json::Value = resp.json().await.expect("json");
            v["existing"]
                .as_array()
                .expect("existing array")
                .iter()
                .map(|s| s.as_str().unwrap_or_default().to_string())
                .collect::<Vec<_>>()
        }
    };

    // Case-insensitive match, response preserves request casing.
    let got = probe(
        main_street,
        serde_json::json!(["Qa-001", "QA-002", "QA-999"]),
    )
    .await;
    assert_eq!(got, vec!["Qa-001".to_string(), "QA-002".to_string()]);

    // A serial that belongs to another company does not match.
    let got = probe(main_street, serde_json::json!(["QA-003"])).await;
    assert!(got.is_empty(), "QA-003 lives at Riverside, not Main Street");

    // Empty-ish input (whitespace-only lines) still returns an empty
    // existing list, not a 400.
    let got = probe(main_street, serde_json::json!(["   ", "\t"])).await;
    assert!(got.is_empty());
}

/// MAPPS-1071 server half - an asset issued to a contact now carries that
/// contact's name on list and get, resolved via a tenant-scoped LEFT JOIN
/// on `contacts`. Lets the asset "Issued to" column render a contact name
/// without a secondary `/contacts/{id}` fetch per row.
#[mokosh_test]
async fn asset_response_resolves_contact_name(pool: PgPool) {
    let (_aid, email, pw) = common::seed_admin(&pool).await;
    let company = seed_company(&pool, "Acme").await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &pw).await;
    let type_id = create_asset_type(&app, &token, "Laptop").await;

    let contact_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO contacts (id, tenant_id, company_id, first_name, last_name) \
         VALUES ($1, $2, $3, 'Alice', 'Carter')",
    )
    .bind(contact_id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company)
    .execute(&pool)
    .await
    .expect("seed contact");

    let asset_id = create_asset(&app, &token, "customer-laptop", &type_id, company).await;
    // Attach the contact via PATCH so this exercises the write-and-read path.
    let patch = app
        .client
        .patch(app.url(&format!("/api/v1/assets/{asset_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "contact_id": contact_id }))
        .send()
        .await
        .expect("patch contact_id");
    assert!(patch.status().is_success(), "patch contact_id should 2xx");

    let got: serde_json::Value = app
        .client
        .get(app.url(&format!("/api/v1/assets/{asset_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("get asset")
        .json()
        .await
        .expect("asset json");
    assert_eq!(
        got["contact_id"].as_str(),
        Some(contact_id.to_string().as_str()),
    );
    assert_eq!(got["contact_name"].as_str(), Some("Alice Carter"));

    let list: serde_json::Value = app
        .client
        .get(app.url("/api/v1/assets"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list assets")
        .json()
        .await
        .expect("list json");
    let row = list["data"]
        .as_array()
        .expect("data")
        .iter()
        .find(|r| r["id"].as_str() == Some(asset_id.as_str()))
        .expect("asset in list");
    assert_eq!(row["contact_name"].as_str(), Some("Alice Carter"));

    // An asset with no contact link resolves to null (not an empty string),
    // so a client-side `is_some` check behaves.
    let unassigned_id = create_asset(&app, &token, "unassigned", &type_id, company).await;
    let got: serde_json::Value = app
        .client
        .get(app.url(&format!("/api/v1/assets/{unassigned_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("get asset")
        .json()
        .await
        .expect("asset json");
    assert!(got["contact_id"].is_null());
    assert!(got["contact_name"].is_null());
}

#[mokosh_test]
async fn assets_exists_rejects_over_the_500_cap(pool: PgPool) {
    let (_admin_id, email, pw) = common::seed_admin(&pool).await;
    let company = seed_company(&pool, "Acme Co").await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;

    // 501 serials to trip the validator.
    let serials: Vec<String> = (0..501).map(|i| format!("QA-{i:04}")).collect();
    let resp = app
        .client
        .post(app.url("/api/v1/assets/exists"))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "company_id": company, "serials": serials }))
        .send()
        .await
        .expect("post exists");
    assert_eq!(
        resp.status().as_u16(),
        422,
        "over-cap request must be rejected at the validator"
    );
}

/// PMS-1476: when an asset update flips `itil_lifecycle_stage` to `retired`
/// and the request does not also set `status`, the server flips the status
/// to `retired` so the Status badge, list facets and saved reports stop
/// counting the device as Active. Status explicitly sent wins over the
/// implied flip. Covers both PUT /assets/{id} and PATCH /assets/{id}.
#[mokosh_test]
async fn retiring_lifecycle_stage_flips_status_to_retired_on_put_and_patch(pool: PgPool) {
    let (_admin_id, email, pw) = common::seed_admin(&pool).await;
    let company = seed_company(&pool, "Acme Co").await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;
    let type_id = create_asset_type(&app, &token, "Workstation").await;

    // -- PUT path --
    let put_id = create_asset(&app, &token, "put-asset", &type_id, company).await;
    let r = app
        .client
        .put(app.url(&format!("/api/v1/assets/{put_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "itil_lifecycle_stage": "retired" }))
        .send()
        .await
        .expect("put lifecycle");
    assert!(r.status().is_success(), "PUT: {}", r.status());
    let after: serde_json::Value = app
        .client
        .get(app.url(&format!("/api/v1/assets/{put_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("get after put")
        .json()
        .await
        .expect("json");
    assert_eq!(after["itil_lifecycle_stage"].as_str(), Some("retired"));
    assert_eq!(
        after["status"].as_str(),
        Some("retired"),
        "PUT: lifecycle=retired must flip status to retired"
    );

    // -- PUT path, explicit status wins --
    let put2_id = create_asset(&app, &token, "put-explicit", &type_id, company).await;
    let r = app
        .client
        .put(app.url(&format!("/api/v1/assets/{put2_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "itil_lifecycle_stage": "retired",
            "status": "in_stock"
        }))
        .send()
        .await
        .expect("put both");
    assert!(r.status().is_success());
    let after: serde_json::Value = app
        .client
        .get(app.url(&format!("/api/v1/assets/{put2_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("get after put2")
        .json()
        .await
        .expect("json");
    assert_eq!(
        after["status"].as_str(),
        Some("in_stock"),
        "PUT: explicit status wins over the implied retired flip"
    );

    // -- PATCH path --
    let patch_id = create_asset(&app, &token, "patch-asset", &type_id, company).await;
    let r = app
        .client
        .patch(app.url(&format!("/api/v1/assets/{patch_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "itil_lifecycle_stage": "retired" }))
        .send()
        .await
        .expect("patch lifecycle");
    assert!(r.status().is_success(), "PATCH: {}", r.status());
    let after: serde_json::Value = app
        .client
        .get(app.url(&format!("/api/v1/assets/{patch_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("get after patch")
        .json()
        .await
        .expect("json");
    assert_eq!(after["itil_lifecycle_stage"].as_str(), Some("retired"));
    assert_eq!(
        after["status"].as_str(),
        Some("retired"),
        "PATCH: lifecycle=retired must flip status to retired"
    );

    // -- PATCH path, non-retired lifecycle does not touch status --
    let patch2_id = create_asset(&app, &token, "patch-in-service", &type_id, company).await;
    let r = app
        .client
        .patch(app.url(&format!("/api/v1/assets/{patch2_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "itil_lifecycle_stage": "in_service" }))
        .send()
        .await
        .expect("patch in_service");
    assert!(r.status().is_success());
    let after: serde_json::Value = app
        .client
        .get(app.url(&format!("/api/v1/assets/{patch2_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("get")
        .json()
        .await
        .expect("json");
    assert_eq!(after["itil_lifecycle_stage"].as_str(), Some("in_service"));
    assert_eq!(
        after["status"].as_str(),
        Some("active"),
        "PATCH: non-retired lifecycle must leave status untouched (default 'active')"
    );
}
