//! Integration regression tests for PMS-170 and PMS-812.
//!
//! `DELETE /api/v1/contacts/companies/{id}` must return 400 (not 500) when the
//! company is still referenced by a child row. `delete_company` explicitly
//! guards only `tickets`; every other table that foreign-keys `companies` is
//! `ON DELETE RESTRICT`, so the DELETE raises Postgres `23503`, which used to
//! fall through the generic error mapping to a 500. The fix maps `23503` to a
//! BadRequest.
//!
//! Uses the self-referential `companies.parent_company_id` FK as the minimal
//! blocker (no other tables / FKs to satisfy): a child company referencing the
//! parent makes the parent undeletable.

mod common;

use sqlx::PgPool;
use uuid::Uuid;

#[sqlx::test]
async fn delete_company_with_child_returns_400_not_500(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;

    let parent = Uuid::new_v4();
    let child = Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, 'Parent Co')")
        .bind(parent)
        .bind(common::DEFAULT_TENANT_ID)
        .execute(&pool)
        .await
        .expect("seed parent company");
    sqlx::query(
        "INSERT INTO companies (id, tenant_id, name, parent_company_id) \
         VALUES ($1, $2, 'Child Co', $3)",
    )
    .bind(child)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(parent)
    .execute(&pool)
    .await
    .expect("seed child company");

    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let resp = app
        .client
        .delete(app.url(&format!("/api/v1/contacts/companies/{parent}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("delete company request");

    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    assert_eq!(
        status.as_u16(),
        400,
        "delete of a company with a child should be 400, got {status} (body: {body})"
    );
}

// ============================================================================
// PMS-812: deleting a company unlinks its contacts, it does not delete them.
//
// `contacts.company_id` was `ON DELETE CASCADE` (migration 004) and PMS-402
// dropped its NOT NULL without touching the action, so deleting a company took
// every linked contact with it. Migration 110 makes the action `SET NULL` and
// `delete_company` drops the `contact_companies` rows + recomputes the mirrors
// in the same transaction.
// ============================================================================

/// Create a company through the API and return its id.
async fn create_company(app: &common::TestApp, token: &str, name: &str) -> String {
    let resp = app
        .client
        .post(app.url("/api/v1/contacts/companies"))
        .bearer_auth(token)
        .json(&serde_json::json!({ "name": name }))
        .send()
        .await
        .expect("send create company");
    assert!(
        resp.status().is_success(),
        "create company should 2xx, got {}",
        resp.status()
    );
    let v: serde_json::Value = resp.json().await.expect("create company JSON");
    v["id"].as_str().expect("company id").to_string()
}

/// Create a contact through the API and return the response body.
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

/// `DELETE /contacts/companies/{id}`, asserting it succeeded.
async fn delete_company(app: &common::TestApp, token: &str, company_id: &str) {
    let resp = app
        .client
        .delete(app.url(&format!("/api/v1/contacts/companies/{company_id}")))
        .bearer_auth(token)
        .send()
        .await
        .expect("send delete company");
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    assert!(
        status.is_success(),
        "delete company should 2xx, got {status} (body: {body})"
    );
}

/// `GET /contacts/contacts/{id}` -> (status, body).
async fn get_contact(
    app: &common::TestApp,
    token: &str,
    contact_id: &str,
) -> (u16, serde_json::Value) {
    let resp = app
        .client
        .get(app.url(&format!("/api/v1/contacts/contacts/{contact_id}")))
        .bearer_auth(token)
        .send()
        .await
        .expect("send get contact");
    let status = resp.status().as_u16();
    let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
    (status, body)
}

/// Contact ids returned by `GET /companies/{id}/contacts`.
async fn company_contact_ids(app: &common::TestApp, token: &str, company_id: &str) -> Vec<String> {
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
    body["data"]
        .as_array()
        .expect("data array")
        .iter()
        .map(|c| c["id"].as_str().expect("id").to_string())
        .collect()
}

/// AC: a contact linked to A (primary) and B survives the delete of A with B
/// promoted to primary, `contacts.company_id = B`, and the contact still
/// listed under B.
#[sqlx::test]
async fn deleting_a_company_unlinks_a_multi_linked_contact_and_promotes_the_survivor(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let a = create_company(&app, &token, "Alpha").await;
    let b = create_company(&app, &token, "Beta").await;
    let created = create_contact(
        &app,
        &token,
        serde_json::json!({
            "first_name": "Casey",
            "last_name": "Contractor",
            "companies": [
                { "company_id": a, "is_primary": true },
                { "company_id": b },
            ],
        }),
    )
    .await;
    let contact_id = created["id"].as_str().expect("contact id").to_string();
    assert_eq!(created["company_id"].as_str(), Some(a.as_str()));

    delete_company(&app, &token, &a).await;

    let (status, contact) = get_contact(&app, &token, &contact_id).await;
    assert_eq!(
        status, 200,
        "the contact survives the delete of its primary company: {contact:#?}"
    );
    assert_eq!(
        contact["company_id"].as_str(),
        Some(b.as_str()),
        "the mirror follows the promoted link"
    );
    let links = contact["companies"].as_array().expect("companies");
    assert_eq!(links.len(), 1, "only the A link is gone: {links:#?}");
    assert_eq!(links[0]["company_id"].as_str(), Some(b.as_str()));
    assert_eq!(
        links[0]["is_primary"].as_bool(),
        Some(true),
        "B is promoted to primary"
    );

    assert_eq!(
        company_contact_ids(&app, &token, &b).await,
        vec![contact_id],
        "the contact is still listed under B"
    );

    // The link row for the deleted company is gone, not orphaned.
    let orphaned: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM contact_companies WHERE company_id = $1::uuid")
            .bind(&a)
            .fetch_one(&pool)
            .await
            .expect("count links for the deleted company");
    assert_eq!(orphaned, 0);
}

/// AC: a contact linked only to A survives the delete of A as a company-less
/// contact (`company_id` NULL, no links) and is still readable.
#[sqlx::test]
async fn deleting_a_company_leaves_its_only_contact_company_less(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let a = create_company(&app, &token, "Alpha").await;
    let created = create_contact(
        &app,
        &token,
        serde_json::json!({
            "first_name": "Solo",
            "last_name": "Contact",
            "email": "solo@alpha.example",
            "companies": [{ "company_id": a, "is_primary": true }],
        }),
    )
    .await;
    let contact_id = created["id"].as_str().expect("contact id").to_string();

    delete_company(&app, &token, &a).await;

    let (status, contact) = get_contact(&app, &token, &contact_id).await;
    assert_eq!(
        status, 200,
        "the contact survives as a company-less contact: {contact:#?}"
    );
    assert!(
        contact["company_id"].is_null(),
        "the mirror is nulled, not left dangling: {contact:#?}"
    );
    assert!(
        contact["companies"]
            .as_array()
            .expect("companies")
            .is_empty(),
        "no links survive: {contact:#?}"
    );
    assert_eq!(contact["email"].as_str(), Some("solo@alpha.example"));

    // The row itself is still there. Under the old CASCADE it was deleted.
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM contacts WHERE id = $1::uuid")
        .bind(&contact_id)
        .fetch_one(&pool)
        .await
        .expect("count the contact row");
    assert_eq!(rows, 1);
}

/// The `ON DELETE SET NULL` action from migration 110 is the backstop for a
/// delete that does NOT go through `delete_company` (a direct SQL delete, or a
/// mirror that outlives its link row). Under the old CASCADE this deleted the
/// contact outright.
#[sqlx::test]
async fn a_raw_company_delete_nulls_the_contact_mirror_instead_of_cascading(pool: PgPool) {
    let company_id = Uuid::new_v4();
    let contact_id = Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, 'Raw Co')")
        .bind(company_id)
        .bind(common::DEFAULT_TENANT_ID)
        .execute(&pool)
        .await
        .expect("seed company");
    sqlx::query(
        "INSERT INTO contacts (id, tenant_id, company_id, first_name, last_name) \
         VALUES ($1, $2, $3, 'Raw', 'Contact')",
    )
    .bind(contact_id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company_id)
    .execute(&pool)
    .await
    .expect("seed contact");

    sqlx::query("DELETE FROM companies WHERE id = $1")
        .bind(company_id)
        .execute(&pool)
        .await
        .expect("raw delete of the company");

    let surviving: Option<Option<Uuid>> =
        sqlx::query_scalar("SELECT company_id FROM contacts WHERE id = $1")
            .bind(contact_id)
            .fetch_optional(&pool)
            .await
            .expect("read the contact back");
    assert_eq!(
        surviving,
        Some(None),
        "the contact row survives with a NULL company_id (SET NULL, not CASCADE)"
    );
}
