//! Integration tests for the contacts route group.
//!
//! Covers:
//! - PMS-124 F10: company CRUD happy path.
//! - PMS-17 AC5: site CRUD + the F4 regression pin (`update_site` actually
//!   persists), contact CRUD, the `create_portal_access` flag-flip, and
//!   the F9 filter-validation regression pin.

mod common;

use sqlx::PgPool;

/// Helper: create a company through the API and return its id.
///
/// Every PMS-17 test starts from "I have a company"; this consolidates
/// the bearer + POST boilerplate so each test body stays on the actual
/// behaviour under test.
async fn create_company(app: &common::TestApp, token: &str, name: &str) -> String {
    let body = serde_json::json!({ "name": name });
    let resp = app
        .client
        .post(app.url("/api/v1/contacts/companies"))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .expect("send create company");
    assert!(
        resp.status().is_success(),
        "create company should 2xx, got {}",
        resp.status()
    );
    let v: serde_json::Value = resp.json().await.expect("create response JSON");
    v["id"]
        .as_str()
        .expect("created company has an id")
        .to_string()
}

/// Helper: create a site through the API and return its id.
async fn create_site(
    app: &common::TestApp,
    token: &str,
    company_id: &str,
    name: &str,
    is_primary: bool,
) -> String {
    let body = serde_json::json!({
        "company_id": company_id,
        "name": name,
        "is_primary": is_primary,
    });
    let resp = app
        .client
        .post(app.url("/api/v1/contacts/sites"))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .expect("send create site");
    assert!(
        resp.status().is_success(),
        "create site {name} should 2xx, got {}",
        resp.status()
    );
    let v: serde_json::Value = resp.json().await.expect("create site response JSON");
    v["id"]
        .as_str()
        .expect("created site has an id")
        .to_string()
}

/// Helper: search companies via the picker endpoint and return the names
/// of the matched rows. Mirrors the `GET /contacts/companies?q=` call the
/// company picker makes.
async fn search_company_names(app: &common::TestApp, token: &str, q: &str) -> Vec<String> {
    let resp = app
        .client
        .get(app.url("/api/v1/contacts/companies"))
        .query(&[("q", q), ("per_page", "50")])
        .bearer_auth(token)
        .send()
        .await
        .expect("send company search");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "company search q={q:?} should 200"
    );
    let body: serde_json::Value = resp.json().await.expect("search response JSON");
    body["data"]
        .as_array()
        .expect("search has data array")
        .iter()
        .filter_map(|c| c["name"].as_str().map(str::to_string))
        .collect()
}

/// PMS-372: company search must be a case-insensitive substring (ILIKE
/// `%q%`) match, not a leading-prefix match. The picker calls
/// `GET /contacts/companies?q=` and users expect the exact full name, an
/// interior word, and a leading prefix to all find the company. The bug
/// was that only a leading prefix matched, so the full multi-word name and
/// interior words returned zero rows.
#[sqlx::test]
async fn company_search_matches_substring_not_just_prefix(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    create_company(&app, &token, "ZQA live").await;
    create_company(&app, &token, "Acme Live Corp").await;
    create_company(&app, &token, "Unrelated Inc").await;

    // AC1: the exact full multi-word name returns that company.
    let exact = search_company_names(&app, &token, "ZQA live").await;
    assert!(
        exact.iter().any(|n| n == "ZQA live"),
        "exact full name `ZQA live` must match; got {exact:?}"
    );

    // AC2: an interior word matches every company containing it,
    // case-insensitively (`live` should hit `ZQA live` and `Acme Live Corp`).
    let interior = search_company_names(&app, &token, "live").await;
    assert!(
        interior.iter().any(|n| n == "ZQA live"),
        "interior word `live` must match `ZQA live`; got {interior:?}"
    );
    assert!(
        interior.iter().any(|n| n == "Acme Live Corp"),
        "interior word `live` must match `Acme Live Corp` case-insensitively; got {interior:?}"
    );
    assert!(
        !interior.iter().any(|n| n == "Unrelated Inc"),
        "interior word `live` must not match `Unrelated Inc`; got {interior:?}"
    );

    // AC3: a leading prefix still matches (the original behaviour is kept).
    let prefix = search_company_names(&app, &token, "ZQA").await;
    assert!(
        prefix.iter().any(|n| n == "ZQA live"),
        "leading prefix `ZQA` must match `ZQA live`; got {prefix:?}"
    );
}

#[sqlx::test]
async fn company_crud_happy_path(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    // CREATE
    let create_body = serde_json::json!({ "name": "Acme Co" });
    let create_resp = app
        .client
        .post(app.url("/api/v1/contacts/companies"))
        .bearer_auth(&token)
        .json(&create_body)
        .send()
        .await
        .expect("send create company");
    assert!(
        create_resp.status().is_success(),
        "create company should 2xx, got {}",
        create_resp.status()
    );
    let created: serde_json::Value = create_resp.json().await.expect("create response JSON");
    let company_id = created["id"]
        .as_str()
        .expect("created company has an id")
        .to_string();

    // LIST
    let list_resp = app
        .client
        .get(app.url("/api/v1/contacts/companies"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send list companies");
    assert_eq!(list_resp.status(), reqwest::StatusCode::OK);
    let list: serde_json::Value = list_resp.json().await.expect("list response JSON");
    let items = list["data"].as_array().expect("list has data array");
    assert!(
        items.iter().any(|c| c["id"].as_str() == Some(&company_id)),
        "list should contain the company we just created"
    );

    // GET by id
    let get_resp = app
        .client
        .get(app.url(&format!("/api/v1/contacts/companies/{company_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send get company");
    assert_eq!(get_resp.status(), reqwest::StatusCode::OK);
    let got: serde_json::Value = get_resp.json().await.expect("get response JSON");
    assert_eq!(got["name"].as_str(), Some("Acme Co"));

    // DELETE
    let delete_resp = app
        .client
        .delete(app.url(&format!("/api/v1/contacts/companies/{company_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send delete company");
    assert!(
        delete_resp.status().is_success(),
        "delete company should 2xx, got {}",
        delete_resp.status()
    );
}

// ============================================================================
// PMS-17 AC5: company-update F4-bis pin
// ============================================================================

/// Sibling of `site_update_persists_changes` for companies. Pins the
/// PMS-17 expansion: the previous `update_company` only handled name /
/// company_type / status, silently dropping every other field (industry,
/// website, phone, address, etc.) on a 200 OK. Cover representative
/// scalar + nested-object fields and re-GET to prove the writes hit
/// Postgres.
#[sqlx::test]
async fn company_update_persists_all_fields(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let company_id = create_company(&app, &token, "Original Name").await;

    let put_resp = app
        .client
        .put(app.url(&format!("/api/v1/contacts/companies/{company_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "name": "Renamed",
            "industry": "Healthcare",
            "website": "https://example.com",
            "phone": "+1 555 0300",
            "address": {
                "line1": "123 Business Ave",
                "city": "Austin",
                "state": "TX",
                "postal_code": "78701",
                "country": "US",
            },
            "payment_terms": "net15",
            "tax_exempt": true,
            "notes": "VIP",
        }))
        .send()
        .await
        .expect("send update company");
    assert!(
        put_resp.status().is_success(),
        "update company should 2xx, got {}",
        put_resp.status()
    );
    let put_json: serde_json::Value = put_resp.json().await.expect("update JSON");
    assert_eq!(put_json["name"].as_str(), Some("Renamed"));
    assert_eq!(put_json["industry"].as_str(), Some("Healthcare"));
    assert_eq!(put_json["website"].as_str(), Some("https://example.com"));
    assert_eq!(put_json["phone"].as_str(), Some("+15550300"));
    assert_eq!(
        put_json["address"]["line1"].as_str(),
        Some("123 Business Ave")
    );
    assert_eq!(put_json["address"]["city"].as_str(), Some("Austin"));
    assert_eq!(put_json["address"]["state"].as_str(), Some("TX"));

    // Independent GET - the F4-bis pin.
    let get_resp = app
        .client
        .get(app.url(&format!("/api/v1/contacts/companies/{company_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send get company");
    assert_eq!(get_resp.status(), reqwest::StatusCode::OK);
    let get_json: serde_json::Value = get_resp.json().await.expect("get JSON");
    assert_eq!(get_json["name"].as_str(), Some("Renamed"));
    assert_eq!(get_json["industry"].as_str(), Some("Healthcare"));
    assert_eq!(get_json["website"].as_str(), Some("https://example.com"));
    assert_eq!(get_json["phone"].as_str(), Some("+15550300"));
    assert_eq!(
        get_json["address"]["line1"].as_str(),
        Some("123 Business Ave")
    );
    assert_eq!(get_json["address"]["city"].as_str(), Some("Austin"));
    assert_eq!(get_json["address"]["state"].as_str(), Some("TX"));
    assert_eq!(get_json["address"]["postal_code"].as_str(), Some("78701"));
}

/// PMS-400: a company name must be unique within a tenant
/// (case-insensitive, trimmed). Creating a second company with the same
/// name (differing only by case or surrounding whitespace) must 409 and
/// insert no row; renaming onto another company's name must 409; re-saving
/// a company with its own name unchanged must succeed.
#[sqlx::test]
async fn company_rejects_duplicate_name(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let first_id = create_company(&app, &token, "Acme").await;

    // Same name, differing only by case + surrounding whitespace -> 409.
    let dup_resp = app
        .client
        .post(app.url("/api/v1/contacts/companies"))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "name": "  acme " }))
        .send()
        .await
        .expect("send duplicate create");
    assert_eq!(
        dup_resp.status(),
        reqwest::StatusCode::CONFLICT,
        "duplicate company name should 409"
    );

    // No row was inserted: exactly one company named "Acme" exists. The
    // substring search also matches the auto-seeded "Acme Corporation (Demo)"
    // company (PMS-157 first-visit demo seeding), so filter to the exact name
    // to isolate this assertion from demo data rather than asserting against
    // the whole result set.
    let acme_count = search_company_names(&app, &token, "acme")
        .await
        .into_iter()
        .filter(|name| name == "Acme")
        .count();
    assert_eq!(acme_count, 1, "no duplicate row inserted");

    // A genuinely different name still creates fine.
    let second_id = create_company(&app, &token, "Beta").await;

    // Renaming "Beta" onto the existing "Acme" name -> 409.
    let rename_conflict = app
        .client
        .put(app.url(&format!("/api/v1/contacts/companies/{second_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "name": "ACME" }))
        .send()
        .await
        .expect("send conflicting rename");
    assert_eq!(
        rename_conflict.status(),
        reqwest::StatusCode::CONFLICT,
        "renaming onto an existing name should 409"
    );

    // Re-saving the first company with its own name unchanged must succeed.
    let self_save = app
        .client
        .put(app.url(&format!("/api/v1/contacts/companies/{first_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "name": "Acme", "industry": "IT" }))
        .send()
        .await
        .expect("send self re-save");
    assert!(
        self_save.status().is_success(),
        "re-saving own unchanged name should 2xx, got {}",
        self_save.status()
    );
}

// ============================================================================
// PMS-17 AC5: site CRUD + F4 regression pin
// ============================================================================

/// Pin the PMS-18 fix for F4. The original defect was that `update_site`
/// validated the body, then called `get_site` and returned the unmodified
/// record - a 200 OK that hid a missed write. This test makes the
/// regression cost a test failure: the PUT response is checked AND an
/// independent GET re-fetches the row to prove the change actually
/// landed in Postgres rather than only being reflected in the PUT's
/// response body.
#[sqlx::test]
async fn site_update_persists_changes(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let company_id = create_company(&app, &token, "Acme").await;
    let site_id = create_site(&app, &token, &company_id, "Main Office", false).await;

    let update_body = serde_json::json!({
        "name": "Renamed HQ",
        "is_primary": true,
        "phone": "+1 555 0100",
    });
    let put_resp = app
        .client
        .put(app.url(&format!("/api/v1/contacts/sites/{site_id}")))
        .bearer_auth(&token)
        .json(&update_body)
        .send()
        .await
        .expect("send update site");
    assert!(
        put_resp.status().is_success(),
        "update site should 2xx, got {}",
        put_resp.status()
    );
    let put_json: serde_json::Value = put_resp.json().await.expect("update response JSON");
    assert_eq!(put_json["name"].as_str(), Some("Renamed HQ"));
    assert_eq!(put_json["is_primary"].as_bool(), Some(true));
    assert_eq!(put_json["phone"].as_str(), Some("+15550100"));

    // Independent GET to prove the write hit the database, not just the
    // response builder. This is the actual F4 regression pin: a no-op
    // implementation passes the assertions above (PUT echoes the request)
    // but fails here.
    let get_resp = app
        .client
        .get(app.url(&format!("/api/v1/contacts/sites/{site_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send get site");
    assert_eq!(get_resp.status(), reqwest::StatusCode::OK);
    let get_json: serde_json::Value = get_resp.json().await.expect("get response JSON");
    assert_eq!(get_json["name"].as_str(), Some("Renamed HQ"));
    assert_eq!(get_json["is_primary"].as_bool(), Some(true));
    assert_eq!(get_json["phone"].as_str(), Some("+15550100"));
}

/// Site CRUD round-trip: covers create/list/get/update/delete plus the
/// "demote the previous primary" side-effect on `is_primary` updates
/// (mokosh-server/src/modules/contacts/service.rs::update_site, the
/// pre-UPDATE that flips other sites' is_primary to FALSE when a new
/// primary is set).
#[sqlx::test]
async fn site_crud_happy_path(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let company_id = create_company(&app, &token, "Acme").await;
    let site_a = create_site(&app, &token, &company_id, "Site A", false).await;
    let site_b = create_site(&app, &token, &company_id, "Site B", true).await;

    // LIST under the company.
    let list_resp = app
        .client
        .get(app.url(&format!("/api/v1/contacts/companies/{company_id}/sites")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send list company sites");
    assert_eq!(list_resp.status(), reqwest::StatusCode::OK);
    let list: serde_json::Value = list_resp.json().await.expect("list response JSON");
    let items = list["data"]
        .as_array()
        .expect("sites response has a data array");
    assert_eq!(items.len(), 2, "should see both sites");
    let by_id = |id: &str| {
        items
            .iter()
            .find(|s| s["id"].as_str() == Some(id))
            .unwrap_or_else(|| panic!("site {id} present in list"))
    };
    assert_eq!(by_id(&site_a)["is_primary"].as_bool(), Some(false));
    assert_eq!(by_id(&site_b)["is_primary"].as_bool(), Some(true));

    // Flip A to primary; B should demote.
    let put_resp = app
        .client
        .put(app.url(&format!("/api/v1/contacts/sites/{site_a}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "is_primary": true }))
        .send()
        .await
        .expect("send update site A primary");
    assert!(put_resp.status().is_success());

    let list2: serde_json::Value = app
        .client
        .get(app.url(&format!("/api/v1/contacts/companies/{company_id}/sites")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send list company sites after demote")
        .json()
        .await
        .expect("list2 JSON");
    let items2 = list2["data"].as_array().expect("list2 has data array");
    let by_id2 = |id: &str| {
        items2
            .iter()
            .find(|s| s["id"].as_str() == Some(id))
            .unwrap_or_else(|| panic!("site {id} present in list2"))
    };
    assert_eq!(
        by_id2(&site_a)["is_primary"].as_bool(),
        Some(true),
        "A should now be primary"
    );
    assert_eq!(
        by_id2(&site_b)["is_primary"].as_bool(),
        Some(false),
        "B should have been demoted when A flipped to primary"
    );

    // DELETE A.
    let del_resp = app
        .client
        .delete(app.url(&format!("/api/v1/contacts/sites/{site_a}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send delete site A");
    assert!(
        del_resp.status().is_success(),
        "delete site A should 2xx, got {}",
        del_resp.status()
    );

    let list3: serde_json::Value = app
        .client
        .get(app.url(&format!("/api/v1/contacts/companies/{company_id}/sites")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send list after delete")
        .json()
        .await
        .expect("list3 JSON");
    let items3 = list3["data"].as_array().expect("list3 has data array");
    assert_eq!(items3.len(), 1, "only B should remain");
    assert_eq!(items3[0]["id"].as_str(), Some(site_b.as_str()));
}

// ============================================================================
// PMS-17 AC5: contact CRUD
// ============================================================================

#[sqlx::test]
async fn contact_crud_happy_path(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let company_id = create_company(&app, &token, "Acme").await;

    // CREATE
    let create_body = serde_json::json!({
        "company_id": company_id,
        "first_name": "Bob",
        "last_name": "Johnson",
        "email": "bob@acme.example",
    });
    let create_resp = app
        .client
        .post(app.url("/api/v1/contacts/contacts"))
        .bearer_auth(&token)
        .json(&create_body)
        .send()
        .await
        .expect("send create contact");
    assert!(
        create_resp.status().is_success(),
        "create contact should 2xx, got {}",
        create_resp.status()
    );
    let created: serde_json::Value = create_resp.json().await.expect("create JSON");
    let contact_id = created["id"].as_str().expect("contact has id").to_string();
    // PMS-334: the create response carries the linked company's name,
    // resolved via the LEFT JOIN to companies (previously hardcoded null).
    assert_eq!(
        created["company_name"].as_str(),
        Some("Acme"),
        "create response should populate company_name"
    );

    // LIST contains it.
    let list_resp = app
        .client
        .get(app.url("/api/v1/contacts/contacts"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send list contacts");
    assert_eq!(list_resp.status(), reqwest::StatusCode::OK);
    let list: serde_json::Value = list_resp.json().await.expect("list JSON");
    let items = list["data"].as_array().expect("list has data array");
    let listed = items
        .iter()
        .find(|c| c["id"].as_str() == Some(&contact_id))
        .expect("contact list should contain the new contact");
    // PMS-334: the Contacts list Company column is backed by company_name,
    // which the list query now fills from the joined company.
    assert_eq!(
        listed["company_name"].as_str(),
        Some("Acme"),
        "contact list row should populate company_name"
    );

    // GET single.
    let get_resp = app
        .client
        .get(app.url(&format!("/api/v1/contacts/contacts/{contact_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send get contact");
    assert_eq!(get_resp.status(), reqwest::StatusCode::OK);
    let got: serde_json::Value = get_resp.json().await.expect("get JSON");
    assert_eq!(got["first_name"].as_str(), Some("Bob"));
    assert_eq!(got["last_name"].as_str(), Some("Johnson"));
    // PMS-334: single-contact GET also populates company_name.
    assert_eq!(got["company_name"].as_str(), Some("Acme"));

    // UPDATE - touch two fields and re-GET to verify persistence (same
    // pattern as the site_update test for symmetry).
    // UPDATE many fields at once. The previous implementation only
    // wrote first_name / last_name / email; title, department, phone,
    // mobile, etc. were silently dropped on a 200 OK. Cover the full
    // surface so a regression to partial-update behavior fails here.
    let put_resp = app
        .client
        .put(app.url(&format!("/api/v1/contacts/contacts/{contact_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "title": "CTO",
            "department": "Engineering",
            "phone": "+1 555 0100",
            "mobile": "+1 555 0200",
        }))
        .send()
        .await
        .expect("send update contact");
    assert!(
        put_resp.status().is_success(),
        "update contact should 2xx, got {}",
        put_resp.status()
    );
    let put_json: serde_json::Value = put_resp.json().await.expect("update JSON");
    assert_eq!(put_json["title"].as_str(), Some("CTO"));
    assert_eq!(put_json["department"].as_str(), Some("Engineering"));
    assert_eq!(put_json["phone"].as_str(), Some("+15550100"));
    assert_eq!(put_json["mobile"].as_str(), Some("+15550200"));

    let reget: serde_json::Value = app
        .client
        .get(app.url(&format!("/api/v1/contacts/contacts/{contact_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send re-get contact")
        .json()
        .await
        .expect("re-get JSON");
    assert_eq!(reget["title"].as_str(), Some("CTO"));
    assert_eq!(reget["department"].as_str(), Some("Engineering"));
    assert_eq!(reget["phone"].as_str(), Some("+15550100"));
    assert_eq!(reget["mobile"].as_str(), Some("+15550200"));

    // DELETE then confirm 404.
    let del_resp = app
        .client
        .delete(app.url(&format!("/api/v1/contacts/contacts/{contact_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send delete contact");
    assert!(
        del_resp.status().is_success(),
        "delete contact should 2xx, got {}",
        del_resp.status()
    );

    let after_get = app
        .client
        .get(app.url(&format!("/api/v1/contacts/contacts/{contact_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send post-delete get");
    assert_eq!(
        after_get.status(),
        reqwest::StatusCode::NOT_FOUND,
        "GET after delete should 404"
    );
}

// ============================================================================
// PMS-402: freeform company on contacts (nullable company_id + company_name)
// ============================================================================

/// A contact created with a freeform `company_name` and no `company_id`
/// round-trips: create returns the typed company name and a null
/// `company_id`, and a subsequent GET surfaces the same. Backs the read-side
/// `COALESCE(co.name, c.company_name)` projection and the nullable FK.
#[sqlx::test]
async fn freeform_company_contact_round_trips(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    // CREATE with a freeform company and NO company_id.
    let create_resp = app
        .client
        .post(app.url("/api/v1/contacts/contacts"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "company_name": "Bob's Plumbing",
            "first_name": "Bob",
            "last_name": "Smith",
        }))
        .send()
        .await
        .expect("send create freeform contact");
    assert!(
        create_resp.status().is_success(),
        "create freeform contact should 2xx, got {}",
        create_resp.status()
    );
    let created: serde_json::Value = create_resp.json().await.expect("create JSON");
    let contact_id = created["id"].as_str().expect("contact has id").to_string();
    assert_eq!(
        created["company_name"].as_str(),
        Some("Bob's Plumbing"),
        "freeform company_name should surface on create"
    );
    assert!(
        created["company_id"].is_null(),
        "freeform contact should have a null company_id, got {:?}",
        created["company_id"]
    );

    // GET surfaces the freeform name and a null company_id.
    let got: serde_json::Value = app
        .client
        .get(app.url(&format!("/api/v1/contacts/contacts/{contact_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send get freeform contact")
        .json()
        .await
        .expect("get JSON");
    assert_eq!(got["company_name"].as_str(), Some("Bob's Plumbing"));
    assert!(got["company_id"].is_null());

    // A contact with neither company_id nor company_name is also valid.
    let bare_resp = app
        .client
        .post(app.url("/api/v1/contacts/contacts"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "first_name": "Lone",
            "last_name": "Person",
        }))
        .send()
        .await
        .expect("send create bare contact");
    assert!(
        bare_resp.status().is_success(),
        "bare contact (no company) should 2xx, got {}",
        bare_resp.status()
    );
    let bare: serde_json::Value = bare_resp.json().await.expect("bare JSON");
    assert!(bare["company_id"].is_null());
    assert!(bare["company_name"].is_null());

    // Supplying BOTH a company_id and a non-empty company_name is rejected.
    let company_id = create_company(&app, &token, "Acme").await;
    let both_resp = app
        .client
        .post(app.url("/api/v1/contacts/contacts"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "company_id": company_id,
            "company_name": "Acme Typed",
            "first_name": "Clash",
            "last_name": "Case",
        }))
        .send()
        .await
        .expect("send conflicting contact");
    assert_eq!(
        both_resp.status(),
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "supplying both company_id and company_name should 422"
    );
}

/// Updating a freeform contact to point at a real CRM company clears the
/// stored freeform name; the read side then surfaces the CRM name and a
/// non-null company_id.
#[sqlx::test]
async fn updating_freeform_to_fk_clears_freeform_name(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    // Start freeform.
    let created: serde_json::Value = app
        .client
        .post(app.url("/api/v1/contacts/contacts"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "company_name": "Typed Co",
            "first_name": "Mover",
            "last_name": "Upper",
        }))
        .send()
        .await
        .expect("send create")
        .json()
        .await
        .expect("create JSON");
    let contact_id = created["id"].as_str().expect("id").to_string();

    // Link to a real CRM company.
    let company_id = create_company(&app, &token, "Real CRM Co").await;
    let put_resp = app
        .client
        .put(app.url(&format!("/api/v1/contacts/contacts/{contact_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "company_id": company_id }))
        .send()
        .await
        .expect("send link update");
    assert!(
        put_resp.status().is_success(),
        "linking to a CRM company should 2xx, got {}",
        put_resp.status()
    );

    // Re-GET: CRM name wins, company_id is set, freeform name was cleared.
    let reget: serde_json::Value = app
        .client
        .get(app.url(&format!("/api/v1/contacts/contacts/{contact_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send re-get")
        .json()
        .await
        .expect("re-get JSON");
    assert_eq!(reget["company_name"].as_str(), Some("Real CRM Co"));
    assert_eq!(reget["company_id"].as_str(), Some(company_id.as_str()));
}

// ============================================================================
// PMS-17 AC2: create_portal_access flips is_portal_user
// ============================================================================

/// Pins the PMS-19 behaviour: the create_portal_access flag actually
/// drives the contact's is_portal_user state. Includes a negative
/// control (a second contact without the flag) so a future impl that
/// silently always returns is_portal_user=true does NOT pass.
#[sqlx::test]
async fn create_contact_with_portal_access_flips_flag(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let company_id = create_company(&app, &token, "Acme").await;

    // With the flag.
    let with_resp = app
        .client
        .post(app.url("/api/v1/contacts/contacts"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "company_id": company_id,
            "first_name": "Portal",
            "last_name": "User",
            "email": "portal@acme.example",
            "create_portal_access": true,
        }))
        .send()
        .await
        .expect("send create-portal contact");
    assert!(with_resp.status().is_success());
    let with_json: serde_json::Value = with_resp.json().await.expect("with JSON");
    let with_id = with_json["id"].as_str().expect("with id").to_string();

    // Without the flag (negative control).
    let without_resp = app
        .client
        .post(app.url("/api/v1/contacts/contacts"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "company_id": company_id,
            "first_name": "Plain",
            "last_name": "Contact",
            "email": "plain@acme.example",
        }))
        .send()
        .await
        .expect("send no-portal contact");
    assert!(without_resp.status().is_success());
    let without_json: serde_json::Value = without_resp.json().await.expect("without JSON");
    let without_id = without_json["id"].as_str().expect("without id").to_string();

    // Verify each contact's persisted flag via an independent GET.
    let with_get: serde_json::Value = app
        .client
        .get(app.url(&format!("/api/v1/contacts/contacts/{with_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send re-get with")
        .json()
        .await
        .expect("with re-get JSON");
    assert_eq!(
        with_get["is_portal_user"].as_bool(),
        Some(true),
        "create_portal_access=true should set is_portal_user=true"
    );

    let without_get: serde_json::Value = app
        .client
        .get(app.url(&format!("/api/v1/contacts/contacts/{without_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send re-get without")
        .json()
        .await
        .expect("without re-get JSON");
    assert_eq!(
        without_get["is_portal_user"].as_bool(),
        Some(false),
        "omitting create_portal_access should leave is_portal_user=false"
    );
}

// ============================================================================
// PMS-136: granting portal access enqueues a setup-link email + token row
// ============================================================================

/// Count outstanding (unused, unexpired) setup tokens for a contact.
async fn setup_token_count(pool: &PgPool, contact_id: &str) -> i64 {
    sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM portal_setup_tokens \
         WHERE contact_id = $1 AND used_at IS NULL AND expires_at > NOW()",
    )
    .bind(uuid::Uuid::parse_str(contact_id).expect("contact uuid"))
    .fetch_one(pool)
    .await
    .expect("count setup tokens")
}

/// AC2 + AC3 + AC8: `create_portal_access: true` on create and a
/// `false -> true` `is_portal_user` transition on update each insert exactly
/// one `portal_setup_tokens` row (the emailed setup link). A re-grant of an
/// already-portal contact mints no second token, and a plain contact (no
/// flag) gets none (negative control).
#[sqlx::test]
async fn granting_portal_access_mints_setup_token(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let company_id = create_company(&app, &token, "Acme").await;

    // (1) create_portal_access: true -> one token row.
    let created = app
        .client
        .post(app.url("/api/v1/contacts/contacts"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "company_id": company_id,
            "first_name": "Portal",
            "last_name": "User",
            "email": "portal@acme.example",
            "create_portal_access": true,
        }))
        .send()
        .await
        .expect("create portal contact");
    assert!(created.status().is_success());
    let created_json: serde_json::Value = created.json().await.expect("created JSON");
    let portal_id = created_json["id"].as_str().expect("portal id").to_string();
    assert_eq!(
        setup_token_count(&pool, &portal_id).await,
        1,
        "create_portal_access=true inserts exactly one setup token"
    );

    // (2) Negative control: a plain contact gets no token.
    let plain = app
        .client
        .post(app.url("/api/v1/contacts/contacts"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "company_id": company_id,
            "first_name": "Plain",
            "last_name": "Contact",
            "email": "plain@acme.example",
        }))
        .send()
        .await
        .expect("create plain contact");
    assert!(plain.status().is_success());
    let plain_json: serde_json::Value = plain.json().await.expect("plain JSON");
    let plain_id = plain_json["id"].as_str().expect("plain id").to_string();
    assert_eq!(
        setup_token_count(&pool, &plain_id).await,
        0,
        "omitting create_portal_access mints no token"
    );

    // (3) update_contact transition false -> true grants + mints a token.
    let granted = app
        .client
        .put(app.url(&format!("/api/v1/contacts/contacts/{plain_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "is_portal_user": true }))
        .send()
        .await
        .expect("grant via update");
    assert!(
        granted.status().is_success(),
        "update grant should 2xx, got {}",
        granted.status()
    );
    let granted_json: serde_json::Value = granted.json().await.expect("granted JSON");
    assert_eq!(
        granted_json["is_portal_user"].as_bool(),
        Some(true),
        "update with is_portal_user=true flips the flag"
    );
    assert_eq!(
        setup_token_count(&pool, &plain_id).await,
        1,
        "false->true transition mints exactly one setup token"
    );

    // (4) Re-grant (already true) mints NO second token.
    let regrant = app
        .client
        .put(app.url(&format!("/api/v1/contacts/contacts/{plain_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "is_portal_user": true }))
        .send()
        .await
        .expect("re-grant via update");
    assert!(regrant.status().is_success());
    assert_eq!(
        setup_token_count(&pool, &plain_id).await,
        1,
        "re-saving an already-portal contact does not mint a second token"
    );
}

// ============================================================================
// PMS-17 AC4 (F9 regression pin)
// ============================================================================

/// Pin the PMS-17 AC4 / F9 fix: CompanyFilter.q has #[validate(length(max
/// = 200))], the route handler calls filter.validate()?, and an oversize
/// q should be rejected with a 4xx rather than silently truncated or
/// ILIKE'd into a slow scan. ContactFilter shares the same code path so
/// covering one is sufficient.
#[sqlx::test]
async fn company_filter_rejects_oversize_q(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let huge = "a".repeat(1000);
    let resp = app
        .client
        .get(app.url(&format!("/api/v1/contacts/companies?q={huge}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send oversize q list");
    let status = resp.status();
    assert!(
        status == reqwest::StatusCode::BAD_REQUEST
            || status == reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "oversize q should be rejected with 400 or 422, got {status}"
    );
}

// ============================================================================
// PMS-325: contact / company / site field validation.
//
// Invalid phone, time zone, country, and postal code must return a 422 field
// error (never a 500, never silent acceptance), and a formatted phone must be
// normalized to E.164 on the way in.
// ============================================================================

#[sqlx::test]
async fn contact_field_validation(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;
    let company_id = create_company(&app, &token, "Validation Co").await;

    let post_contact = |body: serde_json::Value| {
        let app = &app;
        let token = &token;
        async move {
            app.client
                .post(app.url("/api/v1/contacts/contacts"))
                .bearer_auth(token)
                .json(&body)
                .send()
                .await
                .expect("send create contact")
        }
    };
    let base = serde_json::json!({
        "company_id": company_id,
        "first_name": "Ada",
        "last_name": "Lovelace",
    });
    let with = |k: &str, v: serde_json::Value| {
        let mut b = base.clone();
        b[k] = v;
        b
    };

    // Invalid phone -> 422, not 500 (the reported contact-phone failure).
    let bad_phone = post_contact(with("phone", serde_json::json!("not-a-phone"))).await;
    assert_eq!(
        bad_phone.status(),
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "invalid phone must 422, got {}",
        bad_phone.status()
    );

    // Time zone with a space -> 422.
    let bad_tz = post_contact(with("timezone", serde_json::json!("America/New York"))).await;
    assert_eq!(
        bad_tz.status(),
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "invalid timezone must 422, got {}",
        bad_tz.status()
    );

    // Formatted phone is accepted and normalized to E.164.
    let ok = post_contact(with("phone", serde_json::json!("+1 (415) 555-1234"))).await;
    assert!(
        ok.status().is_success(),
        "formatted phone should 2xx, got {}",
        ok.status()
    );
    let created: serde_json::Value = ok.json().await.expect("contact JSON");
    assert_eq!(created["phone"].as_str(), Some("+14155551234"));
}

#[sqlx::test]
async fn company_address_validation(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let post_company = |body: serde_json::Value| {
        let app = &app;
        let token = &token;
        async move {
            app.client
                .post(app.url("/api/v1/contacts/companies"))
                .bearer_auth(token)
                .json(&body)
                .send()
                .await
                .expect("send create company")
        }
    };

    // Non-ISO country -> 422.
    let bad_country = post_company(serde_json::json!({
        "name": "Geo Co",
        "address": { "country": "United States" }
    }))
    .await;
    assert_eq!(
        bad_country.status(),
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "non-ISO country must 422, got {}",
        bad_country.status()
    );

    // Over-long postal code -> 422.
    let bad_postal = post_company(serde_json::json!({
        "name": "Geo Co",
        "address": { "postal_code": "X".repeat(20) }
    }))
    .await;
    assert_eq!(
        bad_postal.status(),
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "over-long postal code must 422, got {}",
        bad_postal.status()
    );

    // Valid ISO country + postal -> 2xx.
    let ok = post_company(serde_json::json!({
        "name": "Geo Co",
        "address": { "country": "us", "postal_code": "94105" }
    }))
    .await;
    assert!(
        ok.status().is_success(),
        "valid address should 2xx, got {}",
        ok.status()
    );
}

/// PMS-413: an `internal` own-company is excluded from the default
/// `GET /contacts/companies` customer list (so it never appears as a fake
/// client in pickers), but a direct lookup by id still resolves it.
#[sqlx::test]
async fn internal_company_hidden_from_list_but_resolvable_by_id(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;

    // Seed one real client and one internal own-company directly. The API
    // exposes no path to create an internal company, which is intended.
    let client_id = create_company_row(&pool, "Acme Client", "client").await;
    let internal_id = create_company_row(&pool, "Tenant Own Co", "internal").await;

    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    // Default list: client visible, internal hidden.
    let resp = app
        .client
        .get(app.url("/api/v1/contacts/companies"))
        .query(&[("per_page", "50")])
        .bearer_auth(&token)
        .send()
        .await
        .expect("send list companies");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("list JSON");
    let ids: Vec<String> = body["data"]
        .as_array()
        .expect("data array")
        .iter()
        .filter_map(|c| c["id"].as_str().map(str::to_string))
        .collect();
    assert!(
        ids.contains(&client_id),
        "client company appears in the list"
    );
    assert!(
        !ids.contains(&internal_id),
        "internal own-company must NOT appear in the default customer list"
    );

    // Lookup by id still resolves the internal company.
    let get_resp = app
        .client
        .get(app.url(&format!("/api/v1/contacts/companies/{internal_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send get internal company");
    assert_eq!(
        get_resp.status(),
        reqwest::StatusCode::OK,
        "internal company resolves by id"
    );
    let got: serde_json::Value = get_resp.json().await.expect("get JSON");
    assert_eq!(got["company_type"].as_str(), Some("internal"));
}

/// Insert a company row of a given `company_type` directly under the default
/// tenant; returns its id as a string. Used to seed an `internal` company,
/// which the API has no create path for.
async fn create_company_row(pool: &PgPool, name: &str, company_type: &str) -> String {
    let id = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO companies (id, tenant_id, name, company_type) VALUES ($1, $2, $3, $4)",
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(name)
    .bind(company_type)
    .execute(pool)
    .await
    .expect("insert company row");
    id.to_string()
}

// ============================================================================
// PMS-805: a scheme-less website is normalized on the way in, and the website
// probe endpoint is reachable, guarded and input-validated.
// ============================================================================

/// The reporter's case: typing `DentalArtsPractice.com` into the website field
/// must save, and must persist with the scheme the product wants. The
/// dangerous-scheme rejection that MAPPS-149 added must survive the change.
#[sqlx::test]
async fn company_website_accepts_a_bare_domain(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let resp = app
        .client
        .post(app.url("/api/v1/contacts/companies"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "name": "Dental Arts Practice",
            "website": "DentalArtsPractice.com",
        }))
        .send()
        .await
        .expect("send create company");
    assert!(
        resp.status().is_success(),
        "a bare domain should save, got {}",
        resp.status()
    );
    let created: serde_json::Value = resp.json().await.expect("create JSON");
    assert_eq!(
        created["website"].as_str(),
        Some("https://dentalartspractice.com")
    );

    // Independent GET: the normalized value is what reached Postgres, not just
    // what the create response echoed.
    let company_id = created["id"].as_str().expect("created company has an id");
    let got: serde_json::Value = app
        .client
        .get(app.url(&format!("/api/v1/contacts/companies/{company_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send get company")
        .json()
        .await
        .expect("get JSON");
    assert_eq!(
        got["website"].as_str(),
        Some("https://dentalartspractice.com")
    );

    // The normalizer never manufactures a URL out of a dangerous scheme.
    let rejected = app
        .client
        .post(app.url("/api/v1/contacts/companies"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "name": "XSS Co",
            "website": "javascript:alert(1)",
        }))
        .send()
        .await
        .expect("send create company");
    assert_eq!(
        rejected.status(),
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "javascript: must still be a 422"
    );

    // Same rule on the update path.
    let updated: serde_json::Value = app
        .client
        .put(app.url(&format!("/api/v1/contacts/companies/{company_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "website": "Example.COM/About" }))
        .send()
        .await
        .expect("send update company")
        .json()
        .await
        .expect("update JSON");
    assert_eq!(
        updated["website"].as_str(),
        Some("https://example.com/About")
    );
}

/// The probe endpoint is authenticated, resolves ahead of `/companies/{id}`,
/// and refuses to connect to anything off the public internet. A loopback
/// target must come back as a successful probe reporting `blocked_host`, which
/// is what proves the SSRF guard is wired into the live route.
#[sqlx::test]
async fn website_probe_blocks_non_public_hosts(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    // Unauthenticated callers never reach the probe at all.
    let anon = app
        .client
        .get(app.url("/api/v1/contacts/companies/website-probe?url=example.com"))
        .send()
        .await
        .expect("send anonymous probe");
    assert_eq!(anon.status(), reqwest::StatusCode::UNAUTHORIZED);

    // The static segment wins over `/companies/{company_id}`: an unparseable
    // UUID would otherwise 4xx from the path extractor, never reaching here.
    let resp = app
        .client
        .get(app.url("/api/v1/contacts/companies/website-probe?url=http://127.0.0.1"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send loopback probe");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "an unreachable verdict is a successful probe, not an error"
    );
    let body: serde_json::Value = resp.json().await.expect("probe JSON");
    assert_eq!(body["reachable"], serde_json::json!(false));
    assert_eq!(
        body["unreachable_reason"],
        serde_json::json!("blocked_host")
    );
    assert_eq!(body["canonical_url"], serde_json::Value::Null);
    assert_eq!(body["www_change"], serde_json::json!("none"));
    assert_eq!(body["input"], serde_json::json!("http://127.0.0.1"));

    // An RFC1918 literal is refused by the same guard.
    let private: serde_json::Value = app
        .client
        .get(app.url("/api/v1/contacts/companies/website-probe?url=http://10.1.2.3"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send private probe")
        .json()
        .await
        .expect("probe JSON");
    assert_eq!(
        private["unreachable_reason"],
        serde_json::json!("blocked_host")
    );
}

/// Input that cannot be a website at all is a 400, never a silently
/// "unreachable" 200: a form has to tell "that is not a URL" apart from "your
/// site is down".
#[sqlx::test]
async fn website_probe_rejects_impossible_input(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    for bad in [
        "javascript:alert(1)",
        "data:text/html,<script>",
        "ftp://example.com",
        "http://user:pass@example.com",
        "https://example.com:8080",
        "exa mple.com",
        "",
    ] {
        let resp = app
            .client
            .get(app.url("/api/v1/contacts/companies/website-probe"))
            .query(&[("url", bad)])
            .bearer_auth(&token)
            .send()
            .await
            .expect("send probe");
        assert_eq!(
            resp.status(),
            reqwest::StatusCode::BAD_REQUEST,
            "{bad:?} should be a 400, got {}",
            resp.status()
        );
    }

    // A missing `url` parameter fails at the extractor, not inside the probe.
    let missing = app
        .client
        .get(app.url("/api/v1/contacts/companies/website-probe"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send probe with no url");
    assert!(
        missing.status().is_client_error(),
        "a missing url should be a 4xx, got {}",
        missing.status()
    );
}

// ============================================================================
// PMS-806: typed phone list + links to multiple companies
// ============================================================================

/// Helper: create a contact through the API and return the response body.
async fn create_contact(
    app: &common::TestApp,
    token: &str,
    body: serde_json::Value,
) -> serde_json::Value {
    let resp = app
        .client
        .post(app.url("/api/v1/contacts/contacts"))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .expect("send create contact");
    assert!(
        resp.status().is_success(),
        "create contact should 2xx, got {}",
        resp.status()
    );
    resp.json().await.expect("create contact JSON")
}

/// Helper: POST a contact and return the raw status, for the 422 cases.
async fn post_contact_status(
    app: &common::TestApp,
    token: &str,
    body: serde_json::Value,
) -> reqwest::Response {
    app.client
        .post(app.url("/api/v1/contacts/contacts"))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .expect("send create contact")
}

async fn get_contact(app: &common::TestApp, token: &str, contact_id: &str) -> serde_json::Value {
    app.client
        .get(app.url(&format!("/api/v1/contacts/contacts/{contact_id}")))
        .bearer_auth(token)
        .send()
        .await
        .expect("send get contact")
        .json()
        .await
        .expect("get contact JSON")
}

async fn update_contact(
    app: &common::TestApp,
    token: &str,
    contact_id: &str,
    body: serde_json::Value,
) -> serde_json::Value {
    let resp = app
        .client
        .put(app.url(&format!("/api/v1/contacts/contacts/{contact_id}")))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .expect("send update contact");
    assert!(
        resp.status().is_success(),
        "update contact should 2xx, got {}",
        resp.status()
    );
    resp.json().await.expect("update contact JSON")
}

/// The company ids of a contact payload's `companies`, in the order returned.
fn link_order(contact: &serde_json::Value) -> Vec<String> {
    contact["companies"]
        .as_array()
        .expect("companies")
        .iter()
        .map(|l| l["company_id"].as_str().expect("company_id").to_string())
        .collect()
}

/// Contact ids returned by `GET /contacts?company_id=`.
async fn contact_ids_for_company_filter(
    app: &common::TestApp,
    token: &str,
    company_id: &str,
) -> Vec<String> {
    let body: serde_json::Value = app
        .client
        .get(app.url("/api/v1/contacts/contacts"))
        .query(&[("company_id", company_id), ("per_page", "50")])
        .bearer_auth(token)
        .send()
        .await
        .expect("send filtered contact list")
        .json()
        .await
        .expect("filtered list JSON");
    body["data"]
        .as_array()
        .expect("data array")
        .iter()
        .map(|c| c["id"].as_str().expect("id").to_string())
        .collect()
}

/// Contact ids returned by `GET /companies/{id}/contacts`, plus the total.
async fn company_contact_ids(
    app: &common::TestApp,
    token: &str,
    company_id: &str,
) -> (Vec<String>, i64) {
    let body: serde_json::Value = app
        .client
        .get(app.url(&format!("/api/v1/contacts/companies/{company_id}/contacts")))
        .bearer_auth(token)
        .send()
        .await
        .expect("send company contacts")
        .json()
        .await
        .expect("company contacts JSON");
    let ids = body["data"]
        .as_array()
        .expect("data array")
        .iter()
        .map(|c| c["id"].as_str().expect("id").to_string())
        .collect();
    let total = body["meta"]["total"]
        .as_i64()
        .expect("a total in the paginated envelope");
    (ids, total)
}

/// `contact_count` as the company list reports it.
async fn company_contact_count(app: &common::TestApp, token: &str, company_id: &str) -> i64 {
    let body: serde_json::Value = app
        .client
        .get(app.url("/api/v1/contacts/companies"))
        .query(&[("per_page", "50")])
        .bearer_auth(token)
        .send()
        .await
        .expect("send company list")
        .json()
        .await
        .expect("company list JSON");
    body["data"]
        .as_array()
        .expect("data array")
        .iter()
        .find(|c| c["id"].as_str() == Some(company_id))
        .expect("company is in the list")["contact_count"]
        .as_i64()
        .expect("contact_count is populated")
}

/// AC: with `phones` / `companies` absent, an existing-shaped request creates
/// exactly the same contact AND materializes the matching child rows.
#[sqlx::test]
async fn legacy_shaped_request_still_creates_the_same_contact_and_materializes_children(
    pool: PgPool,
) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;
    let company_id = create_company(&app, &token, "Acme").await;

    let created = create_contact(
        &app,
        &token,
        serde_json::json!({
            "company_id": company_id,
            "first_name": "Bob",
            "last_name": "Johnson",
            "phone": "+1 555 0100",
            "mobile": "+1 555 0200",
            "fax": "+1 555 0300",
        }),
    )
    .await;

    // The mirrors are byte-for-byte what the pre-PMS-806 request produced.
    assert_eq!(created["phone"].as_str(), Some("+15550100"));
    assert_eq!(created["mobile"].as_str(), Some("+15550200"));
    assert_eq!(created["company_id"].as_str(), Some(company_id.as_str()));
    assert_eq!(created["company_name"].as_str(), Some("Acme"));

    // ... and the child rows now exist, derived from those scalars.
    let phones = created["phones"].as_array().expect("phones array");
    assert_eq!(phones.len(), 3, "one child row per populated scalar");
    assert_eq!(phones[0]["phone_type"].as_str(), Some("work"));
    assert_eq!(phones[0]["number"].as_str(), Some("+15550100"));
    assert_eq!(phones[0]["is_primary"].as_bool(), Some(true));
    assert_eq!(phones[1]["phone_type"].as_str(), Some("mobile"));
    assert_eq!(phones[2]["phone_type"].as_str(), Some("fax"));
    assert_eq!(phones[2]["number"].as_str(), Some("+15550300"));

    let companies = created["companies"].as_array().expect("companies array");
    assert_eq!(companies.len(), 1);
    assert_eq!(
        companies[0]["company_id"].as_str(),
        Some(company_id.as_str())
    );
    assert_eq!(companies[0]["company_name"].as_str(), Some("Acme"));
    assert_eq!(companies[0]["is_primary"].as_bool(), Some(true));

    // A contact with only a mobile keeps `contacts.phone` NULL: the mirror
    // rule must not promote the mobile into the primary slot.
    let mobile_only = create_contact(
        &app,
        &token,
        serde_json::json!({
            "company_id": company_id,
            "first_name": "Mo",
            "last_name": "Bile",
            "mobile": "+1 555 0400",
        }),
    )
    .await;
    assert!(mobile_only["phone"].is_null(), "no work number, no mirror");
    assert_eq!(mobile_only["mobile"].as_str(), Some("+15550400"));
    assert_eq!(mobile_only["phones"].as_array().expect("phones").len(), 1);
}

/// AC: explicit lists are authoritative and the mirrors are recomputed from
/// them, in the same transaction as the write.
#[sqlx::test]
async fn explicit_child_lists_drive_the_mirrors(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;
    let acme = create_company(&app, &token, "Acme").await;
    let globex = create_company(&app, &token, "Globex").await;

    let created = create_contact(
        &app,
        &token,
        serde_json::json!({
            // The scalars below are deliberately contradictory: with the lists
            // present they must be ignored and recomputed.
            "phone": "+15559999999",
            "first_name": "Cora",
            "last_name": "Tractor",
            "phones": [
                { "phone_type": "work", "number": "+1 (415) 555-1234", "extension": "204" },
                { "phone_type": "mobile", "number": "+14155559999" },
                { "phone_type": "fax", "number": "+14155550000" },
            ],
            "companies": [
                { "company_id": acme, "title": "Consultant" },
                { "company_id": globex, "title": "IT Director", "is_primary": true },
            ],
        }),
    )
    .await;

    // Mirrors: primary phone, first mobile, first fax, primary link.
    assert_eq!(created["phone"].as_str(), Some("+14155551234"));
    assert_eq!(created["mobile"].as_str(), Some("+14155559999"));
    assert_eq!(created["company_id"].as_str(), Some(globex.as_str()));
    assert_eq!(created["company_name"].as_str(), Some("Globex"));

    let phones = created["phones"].as_array().expect("phones");
    assert_eq!(phones.len(), 3);
    assert_eq!(phones[0]["extension"].as_str(), Some("204"));
    assert!(
        phones[0]["is_primary"].as_bool() == Some(true),
        "no entry flagged primary promotes the first"
    );

    let companies = created["companies"].as_array().expect("companies");
    assert_eq!(companies.len(), 2);
    let globex_link = companies
        .iter()
        .find(|l| l["company_id"].as_str() == Some(globex.as_str()))
        .expect("globex link");
    assert_eq!(globex_link["title"].as_str(), Some("IT Director"));
    assert_eq!(globex_link["is_primary"].as_bool(), Some(true));

    // The stored `fax` mirror comes back on a re-GET too.
    let contact_id = created["id"].as_str().expect("id");
    let refetched = get_contact(&app, &token, contact_id).await;
    assert_eq!(refetched["phones"].as_array().expect("phones").len(), 3);
    assert_eq!(
        refetched["companies"].as_array().expect("companies").len(),
        2
    );
}

/// AC: filtering by company matches ANY link, and each company counts the
/// contact exactly once.
#[sqlx::test]
async fn filtering_by_company_matches_any_link(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;
    let a = create_company(&app, &token, "Alpha").await;
    let b = create_company(&app, &token, "Beta").await;

    let created = create_contact(
        &app,
        &token,
        serde_json::json!({
            "first_name": "Dana",
            "last_name": "Dual",
            "companies": [
                { "company_id": a, "is_primary": true },
                { "company_id": b },
            ],
        }),
    )
    .await;
    let contact_id = created["id"].as_str().expect("id").to_string();

    for company in [&a, &b] {
        assert!(
            contact_ids_for_company_filter(&app, &token, company)
                .await
                .contains(&contact_id),
            "GET /contacts?company_id={company} must find the contact through its link"
        );
        let (ids, total) = company_contact_ids(&app, &token, company).await;
        assert!(
            ids.contains(&contact_id),
            "get_company_contacts({company}) must find the contact"
        );
        assert_eq!(total, 1, "the {company} page total counts it once");
        assert_eq!(
            company_contact_count(&app, &token, company).await,
            1,
            "the {company} contact_count counts it exactly once"
        );
    }
}

/// AC: removing the primary link promotes the oldest remaining link and
/// recomputes the mirrors; removing the last link nulls `contacts.company_id`.
#[sqlx::test]
async fn removing_links_repromotes_and_recomputes(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;
    let a = create_company(&app, &token, "Alpha").await;
    let b = create_company(&app, &token, "Beta").await;
    let c = create_company(&app, &token, "Gamma").await;

    let created = create_contact(
        &app,
        &token,
        serde_json::json!({
            "first_name": "Dana",
            "last_name": "Dual",
            "companies": [
                { "company_id": a, "is_primary": true },
                { "company_id": b },
                { "company_id": c },
            ],
        }),
    )
    .await;
    let contact_id = created["id"].as_str().expect("id").to_string();
    assert_eq!(created["company_id"].as_str(), Some(a.as_str()));
    // Links written by one call share a `created_at` (NOW() is the transaction
    // timestamp), so the list order has to come from the write position, not
    // from a random uuid tiebreak (PMS-815).
    assert_eq!(
        link_order(&created),
        vec![a.clone(), b.clone(), c.clone()],
        "the primary leads, then the links in the order they were written"
    );

    // Drop the primary (A) and hand back B and C with NO primary flagged. B is
    // the oldest survivor, so it is promoted and the mirror follows.
    let updated = update_contact(
        &app,
        &token,
        &contact_id,
        serde_json::json!({
            "companies": [
                { "company_id": c },
                { "company_id": b },
            ],
        }),
    )
    .await;
    let links = updated["companies"].as_array().expect("companies");
    assert_eq!(links.len(), 2, "A is unlinked");
    assert!(
        links
            .iter()
            .all(|l| l["company_id"].as_str() != Some(a.as_str())),
        "the removed link is gone: {links:#?}"
    );
    let primary = links
        .iter()
        .find(|l| l["is_primary"].as_bool() == Some(true))
        .expect("a primary link survives");
    assert_eq!(
        primary["company_id"].as_str(),
        Some(b.as_str()),
        "the oldest remaining link is promoted, not the first in the request"
    );
    assert_eq!(updated["company_id"].as_str(), Some(b.as_str()));
    assert_eq!(
        link_order(&updated),
        vec![b.clone(), c.clone()],
        "the surviving links keep their original order, promoted one first"
    );
    // A no longer sees the contact.
    assert!(contact_ids_for_company_filter(&app, &token, &a)
        .await
        .is_empty());

    // Removing the last link nulls the mirror.
    let cleared = update_contact(
        &app,
        &token,
        &contact_id,
        serde_json::json!({ "companies": [] }),
    )
    .await;
    assert!(cleared["companies"]
        .as_array()
        .expect("companies")
        .is_empty());
    assert!(
        cleared["company_id"].is_null(),
        "no links means contacts.company_id is NULL"
    );
    assert!(cleared["company_name"].is_null());
}

/// AC: an invalid phone entry is a 422 that names the failing entry; two
/// primaries in either list is a 422; a `companies` list plus a freeform
/// `company_name` is a 422; a foreign `company_id` in the list is rejected
/// before any row is written.
#[sqlx::test]
async fn child_list_validation_is_enforced_end_to_end(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;
    let a = create_company(&app, &token, "Alpha").await;
    let b = create_company(&app, &token, "Beta").await;

    // Invalid phone entry -> 422 naming `phones[1].number`.
    let resp = post_contact_status(
        &app,
        &token,
        serde_json::json!({
            "first_name": "Bad",
            "last_name": "Phone",
            "phones": [
                { "phone_type": "work", "number": "+14155551234" },
                { "phone_type": "home", "number": "not-a-phone" },
            ],
        }),
    )
    .await;
    assert_eq!(resp.status(), reqwest::StatusCode::UNPROCESSABLE_ENTITY);
    let body: serde_json::Value = resp.json().await.expect("error JSON");
    let fields: Vec<&str> = body["error"]["errors"]
        .as_array()
        .expect("field errors")
        .iter()
        .filter_map(|e| e["field"].as_str())
        .collect();
    assert!(
        fields.contains(&"phones[1].number"),
        "the 422 must identify the failing entry, got {fields:?}"
    );

    // Two primaries, phones.
    assert_eq!(
        post_contact_status(
            &app,
            &token,
            serde_json::json!({
                "first_name": "Two",
                "last_name": "Primaries",
                "phones": [
                    { "phone_type": "work", "number": "+14155551234", "is_primary": true },
                    { "phone_type": "home", "number": "+14155555678", "is_primary": true },
                ],
            }),
        )
        .await
        .status(),
        reqwest::StatusCode::UNPROCESSABLE_ENTITY
    );

    // Two primaries, companies.
    assert_eq!(
        post_contact_status(
            &app,
            &token,
            serde_json::json!({
                "first_name": "Two",
                "last_name": "Companies",
                "companies": [
                    { "company_id": a, "is_primary": true },
                    { "company_id": b, "is_primary": true },
                ],
            }),
        )
        .await
        .status(),
        reqwest::StatusCode::UNPROCESSABLE_ENTITY
    );

    // A non-empty companies list plus a freeform company_name.
    assert_eq!(
        post_contact_status(
            &app,
            &token,
            serde_json::json!({
                "first_name": "Both",
                "last_name": "Ways",
                "company_name": "Acme Plumbing",
                "companies": [{ "company_id": a }],
            }),
        )
        .await
        .status(),
        reqwest::StatusCode::UNPROCESSABLE_ENTITY
    );

    // A company_id that does not exist in this tenant is rejected, and nothing
    // is written.
    let foreign = uuid::Uuid::new_v4();
    let resp = post_contact_status(
        &app,
        &token,
        serde_json::json!({
            "first_name": "Foreign",
            "last_name": "Link",
            "companies": [{ "company_id": a }, { "company_id": foreign }],
        }),
    )
    .await;
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "an unknown company in the list must be rejected"
    );
    assert!(
        !contact_ids_for_company_filter(&app, &token, &a)
            .await
            .iter()
            .any(|_| true),
        "the rejected create must not have linked anything to Alpha"
    );
}

/// AC: a non-empty list with no `is_primary` promotes the first entry rather
/// than erroring, on both the create and the update path.
#[sqlx::test]
async fn a_list_with_no_primary_promotes_the_first_entry(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;
    let a = create_company(&app, &token, "Alpha").await;
    let b = create_company(&app, &token, "Beta").await;

    let created = create_contact(
        &app,
        &token,
        serde_json::json!({
            "first_name": "No",
            "last_name": "Primary",
            "phones": [
                { "phone_type": "home", "number": "+14155551234" },
                { "phone_type": "mobile", "number": "+14155559999" },
            ],
            "companies": [{ "company_id": a }, { "company_id": b }],
        }),
    )
    .await;
    assert_eq!(
        created["phones"].as_array().expect("phones")[0]["is_primary"].as_bool(),
        Some(true)
    );
    assert_eq!(created["phone"].as_str(), Some("+14155551234"));
    assert_eq!(created["company_id"].as_str(), Some(a.as_str()));

    // Update with a fresh, unflagged list: the first entry wins again.
    let contact_id = created["id"].as_str().expect("id");
    let updated = update_contact(
        &app,
        &token,
        contact_id,
        serde_json::json!({
            "phones": [{ "phone_type": "work", "number": "+14155550000" }],
        }),
    )
    .await;
    assert_eq!(updated["phone"].as_str(), Some("+14155550000"));
    assert_eq!(updated["phones"].as_array().expect("phones").len(), 1);
}

/// AC: an update that touches only the scalar phone fields still rebuilds the
/// child rows, so the two representations never diverge.
#[sqlx::test]
async fn a_scalar_only_update_keeps_the_child_rows_in_step(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;
    let company_id = create_company(&app, &token, "Acme").await;

    let created = create_contact(
        &app,
        &token,
        serde_json::json!({
            "company_id": company_id,
            "first_name": "Sca",
            "last_name": "Lar",
            "phone": "+15550100",
        }),
    )
    .await;
    let contact_id = created["id"].as_str().expect("id");

    let updated = update_contact(
        &app,
        &token,
        contact_id,
        serde_json::json!({ "mobile": "+1 555 0200" }),
    )
    .await;
    assert_eq!(updated["phone"].as_str(), Some("+15550100"));
    assert_eq!(updated["mobile"].as_str(), Some("+15550200"));
    let phones = updated["phones"].as_array().expect("phones");
    assert_eq!(phones.len(), 2, "the mobile joined the list: {phones:#?}");
    assert_eq!(phones[0]["phone_type"].as_str(), Some("work"));
    assert_eq!(phones[1]["phone_type"].as_str(), Some("mobile"));
    assert_eq!(phones[1]["number"].as_str(), Some("+15550200"));
}

/// MAPPS-533: an unrecognised `?sort=` is a 422 that says what is accepted,
/// not a silently different ordering.
///
/// `order_by` used to drop an unknown field and sort by the default, answering
/// 200 with rows in an order the caller never asked for. That silence is what
/// let a client-side mismatch survive three parity audits (2026-07-30 F7,
/// 2026-08-07, 2026-08-14 CF-2): the SPA sent `company_type`, `company_name`
/// and `-updated_at`, none allow-listed, and no request ever failed.
///
/// `company_type` is the exact key from that finding, which is why it is the
/// one used here.
#[sqlx::test]
async fn an_unknown_sort_field_is_rejected_with_what_is_accepted(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let resp = app
        .client
        .get(app.url("/api/v1/contacts/companies?sort=company_type"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send companies list with a bad sort");
    assert_eq!(resp.status(), reqwest::StatusCode::UNPROCESSABLE_ENTITY);

    let body: serde_json::Value = resp.json().await.expect("error JSON");
    let field_errors = body["error"]["errors"]
        .as_array()
        .unwrap_or_else(|| panic!("the 422 carries field errors, got {body}"));
    let sort_error = field_errors
        .iter()
        .find(|e| e["field"].as_str() == Some("sort"))
        .unwrap_or_else(|| panic!("the 422 names the `sort` field, got {body}"));
    let message = sort_error["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("company_type"),
        "it says which value was rejected, got {message}"
    );
    for accepted in ["name", "created_at", "updated_at"] {
        assert!(
            message.contains(accepted),
            "it lists `{accepted}` as accepted, got {message}"
        );
    }

    // An allow-listed key is unaffected, and so is a request that asks for no
    // sort at all - which is every caller that never touched the parameter.
    for query in ["?sort=name", ""] {
        let resp = app
            .client
            .get(app.url(&format!("/api/v1/contacts/companies{query}")))
            .bearer_auth(&token)
            .send()
            .await
            .expect("send companies list");
        assert!(
            resp.status().is_success(),
            "`{query}` must still work, got {}",
            resp.status()
        );
    }
}

// ============================================================================
// PMS-993: the billing contact is a per-company role
// ============================================================================

/// Helper: create a contact of `company_id` and return its id.
async fn create_contact_at(
    app: &common::TestApp,
    token: &str,
    company_id: &str,
    first: &str,
    email: &str,
) -> String {
    let resp = app
        .client
        .post(app.url("/api/v1/contacts/contacts"))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "company_id": company_id,
            "first_name": first,
            "last_name": "Contact",
            "email": email,
        }))
        .send()
        .await
        .expect("send create contact");
    assert!(resp.status().is_success(), "create contact should 2xx");
    let created: serde_json::Value = resp.json().await.expect("create JSON");
    created["id"].as_str().expect("contact id").to_string()
}

async fn set_billing_contact(
    app: &common::TestApp,
    token: &str,
    company_id: &str,
    contact_id: &str,
) -> reqwest::Response {
    app.client
        .put(app.url(&format!("/api/v1/contacts/companies/{company_id}")))
        .bearer_auth(token)
        .json(&serde_json::json!({ "default_billing_contact_id": contact_id }))
        .send()
        .await
        .expect("send set billing contact")
}

/// AC1 + AC4: a contact can be given the billing role for a company, the
/// company record reads it back (so a missing one is visible), and assigning a
/// second contact replaces the first - the role is single-valued per company by
/// construction, so there is nothing to demote separately.
#[sqlx::test]
async fn company_billing_contact_is_assigned_and_readable(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let company_id = create_company(&app, &token, "Acme").await;

    // A company with no billing contact says so, rather than omitting the field.
    let before: serde_json::Value = app
        .client
        .get(app.url(&format!("/api/v1/contacts/companies/{company_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("get company")
        .json()
        .await
        .expect("company JSON");
    assert!(
        before
            .get("default_billing_contact_id")
            .is_some_and(|v| v.is_null()),
        "a company with no billing contact reports it as null, not absent"
    );

    let first = create_contact_at(&app, &token, &company_id, "First", "first@acme.example").await;
    let resp = set_billing_contact(&app, &token, &company_id, &first).await;
    assert!(resp.status().is_success(), "assigning the role should 2xx");
    let after: serde_json::Value = app
        .client
        .get(app.url(&format!("/api/v1/contacts/companies/{company_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("get company")
        .json()
        .await
        .expect("company JSON");
    assert_eq!(
        after["default_billing_contact_id"].as_str(),
        Some(first.as_str()),
        "the assigned billing contact reads back"
    );

    // Reassigning replaces: exactly one billing contact per company.
    let second =
        create_contact_at(&app, &token, &company_id, "Second", "second@acme.example").await;
    let resp = set_billing_contact(&app, &token, &company_id, &second).await;
    assert!(resp.status().is_success(), "reassigning should 2xx");
    let reassigned: serde_json::Value = app
        .client
        .get(app.url(&format!("/api/v1/contacts/companies/{company_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("get company")
        .json()
        .await
        .expect("company JSON");
    assert_eq!(
        reassigned["default_billing_contact_id"].as_str(),
        Some(second.as_str()),
        "assigning a second contact replaces the first"
    );
}

/// AC1 negative: the role can only be given to a contact OF the company. The
/// pointer drives the invoice recipient and the portal invoice grant, so a
/// stranger in it would address the bill outside the account.
#[sqlx::test]
async fn company_billing_contact_must_belong_to_the_company(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let company_id = create_company(&app, &token, "Acme").await;
    let other_id = create_company(&app, &token, "Globex").await;
    let stranger = create_contact_at(
        &app,
        &token,
        &other_id,
        "Stranger",
        "stranger@globex.example",
    )
    .await;

    let resp = set_billing_contact(&app, &token, &company_id, &stranger).await;
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "a contact of another company cannot hold this company's billing role"
    );
}

/// The failure branch: unlinking the contact takes the role with it. A plain
/// `PUT /contacts/{id}` with a `company_id` rewrites the whole link set, so
/// without this the pointer would keep naming somebody who left.
#[sqlx::test]
async fn unlinking_the_billing_contact_clears_the_role(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let company_id = create_company(&app, &token, "Acme").await;
    let other_id = create_company(&app, &token, "Globex").await;
    let contact_id =
        create_contact_at(&app, &token, &company_id, "Mover", "mover@acme.example").await;
    assert!(
        set_billing_contact(&app, &token, &company_id, &contact_id)
            .await
            .status()
            .is_success(),
        "assigning the role should 2xx"
    );

    // Move the contact to the other company. This is not a billing edit at all,
    // which is exactly why the role has to follow the link.
    let moved = app
        .client
        .put(app.url(&format!("/api/v1/contacts/contacts/{contact_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "company_id": other_id }))
        .send()
        .await
        .expect("send move contact");
    assert!(moved.status().is_success(), "moving the contact should 2xx");

    let after: serde_json::Value = app
        .client
        .get(app.url(&format!("/api/v1/contacts/companies/{company_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("get company")
        .json()
        .await
        .expect("company JSON");
    assert!(
        after["default_billing_contact_id"].is_null(),
        "unlinking the contact clears the billing role it held"
    );
}
