//! Integration regression tests for PMS-170, PMS-812 and PMS-919.
//!
//! `DELETE /api/v1/contacts/companies/{id}` must return 400 (not 500) when the
//! company is still referenced by a child row that cannot be unlinked. Those
//! references default to NO ACTION, so the DELETE raises Postgres `23503`,
//! which used to fall through the generic error mapping to a 500. PMS-170 maps
//! `23503` to a BadRequest.
//!
//! PMS-919 changed WHICH rows block. A reference on a nullable column is now
//! `ON DELETE SET NULL` (migration 113), because a row with no company was
//! already a valid state the app produces on its own, so blocking on it only
//! forced hand-clearing. What still blocks is the `NOT NULL` group, where a
//! company-less row is not representable, plus `credential_vault`, which is
//! nullable but keeps blocking on purpose rather than orphaning secrets.
//!
//! This suite used `companies.parent_company_id` as its minimal blocker, which
//! PMS-919 turns into the opposite behaviour: a parent delete now promotes its
//! children. That test became the promotion test below, and the 400 mapping is
//! pinned on `credential_vault` instead.

mod common;

use sqlx::PgPool;
use uuid::Uuid;

/// Seed a company. Returns its id.
async fn seed_company_named(pool: &PgPool, name: &str) -> Uuid {
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

/// `DELETE` the company over HTTP and return `(status, body)`.
async fn delete_company_raw(app: &common::TestApp, token: &str, company_id: Uuid) -> (u16, String) {
    let resp = app
        .client
        .delete(app.url(&format!("/api/v1/contacts/companies/{company_id}")))
        .bearer_auth(token)
        .send()
        .await
        .expect("delete company request");
    let status = resp.status().as_u16();
    (status, resp.text().await.unwrap_or_default())
}

/// PMS-170: a blocker that cannot be unlinked maps `23503` to 400, not 500.
///
/// Pinned on `credential_vault` since PMS-919. It is the one nullable column
/// that deliberately still blocks, so it exercises the `23503` path without
/// depending on a `NOT NULL` table's own seeding requirements.
#[sqlx::test]
async fn delete_company_with_stored_credentials_returns_400_not_500(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let company = seed_company_named(&pool, "Vault Co").await;

    sqlx::query(
        "INSERT INTO credential_vault \
           (tenant_id, name, company_id, credential_type, username_encrypted, password_encrypted) \
         VALUES ($1, 'Domain admin', $2, 'domain', 'x', 'y')",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company)
    .execute(&pool)
    .await
    .expect("seed credential");

    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;
    let (status, body) = delete_company_raw(&app, &token, company).await;

    assert_eq!(
        status, 400,
        "a company with stored credentials should be 400, got {status} (body: {body})"
    );
    assert!(
        body.contains("stored credentials"),
        "the refusal must name what blocked it; got: {body}"
    );
    // PMS-920: credentials are removable, so the "remove or reassign" advice is
    // advice the operator can actually take here.
    assert!(
        body.contains("Remove or reassign"),
        "a removable blocker must offer removal; got: {body}"
    );
    assert!(
        body.contains("Inactive"),
        "every refusal names the archive alternative; got: {body}"
    );
}

/// PMS-919 AC2: a parent company delete promotes its children to top level
/// instead of blocking. This is the inversion of the original PMS-170 test.
#[sqlx::test]
async fn deleting_a_parent_company_promotes_its_children_to_top_level(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let parent = seed_company_named(&pool, "Parent Co").await;

    let child = Uuid::new_v4();
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
    let (status, body) = delete_company_raw(&app, &token, parent).await;

    assert_eq!(
        status, 200,
        "a sub-company is a nullable link, so it must not block; got {status} ({body})"
    );

    let surviving: Option<Option<Uuid>> =
        sqlx::query_scalar("SELECT parent_company_id FROM companies WHERE id = $1")
            .bind(child)
            .fetch_optional(&app.pool)
            .await
            .expect("read child");
    assert_eq!(
        surviving,
        Some(None),
        "the child must survive as a top-level company, not be deleted or left dangling"
    );
}

/// PMS-919 AC1: every nullable dependent survives the delete with a NULL
/// `company_id`, rather than blocking it.
///
/// All four in one test on one company, because the property is about the
/// company delete as a whole: a delete that unlinked three of them and blocked
/// on the fourth would still be the MAPPS-574 defect, and four separate tests
/// would each pass while the combination failed.
#[sqlx::test]
async fn deleting_a_company_unlinks_every_nullable_dependent(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company = seed_company_named(&pool, "Unlink Co").await;
    let tenant = common::DEFAULT_TENANT_ID;

    let project = Uuid::new_v4();
    sqlx::query("INSERT INTO projects (id, tenant_id, name, company_id) VALUES ($1, $2, 'P', $3)")
        .bind(project)
        .bind(tenant)
        .bind(company)
        .execute(&pool)
        .await
        .expect("seed project");

    let appointment = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO appointments \
           (id, tenant_id, title, assigned_to_id, start_time, end_time, company_id) \
         VALUES ($1, $2, 'A', $3, NOW(), NOW() + INTERVAL '1 hour', $4)",
    )
    .bind(appointment)
    .bind(tenant)
    .bind(admin_id)
    .bind(company)
    .execute(&pool)
    .await
    .expect("seed appointment");

    let timer = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO active_timers (id, tenant_id, user_id, company_id) VALUES ($1, $2, $3, $4)",
    )
    .bind(timer)
    .bind(tenant)
    .bind(admin_id)
    .bind(company)
    .execute(&pool)
    .await
    .expect("seed active timer");

    let connection = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO rmm_connections \
           (id, tenant_id, name, provider, api_url, api_key_encrypted) \
         VALUES ($1, $2, 'C', 'tactical_rmm', 'https://rmm.test', 'k')",
    )
    .bind(connection)
    .bind(tenant)
    .execute(&pool)
    .await
    .expect("seed rmm connection");

    let mapping = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO rmm_device_mappings \
           (id, tenant_id, rmm_connection_id, rmm_device_id, company_id) \
         VALUES ($1, $2, $3, 'dev-1', $4)",
    )
    .bind(mapping)
    .bind(tenant)
    .bind(connection)
    .bind(company)
    .execute(&pool)
    .await
    .expect("seed rmm device mapping");

    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;
    let (status, body) = delete_company_raw(&app, &token, company).await;

    assert_eq!(
        status, 200,
        "every dependent here is on a nullable column, so none may block; got {status} ({body})"
    );

    for (table, id) in [
        ("projects", project),
        ("appointments", appointment),
        ("active_timers", timer),
        ("rmm_device_mappings", mapping),
    ] {
        let found: Option<Option<Uuid>> =
            sqlx::query_scalar(&format!("SELECT company_id FROM {table} WHERE id = $1"))
                .bind(id)
                .fetch_optional(&app.pool)
                .await
                .unwrap_or_else(|e| panic!("read {table}: {e}"));
        assert_eq!(
            found,
            Some(None),
            "{table} must survive the delete with a NULL company_id, not be destroyed \
             (CASCADE) or block it (NO ACTION)"
        );
    }
}

/// PMS-919 AC3: the `NOT NULL` group is untouched and still refuses. A
/// company-less asset is not representable, so unlinking is not an option and
/// the block is the data model rather than an omission.
#[sqlx::test]
async fn a_company_with_assets_still_refuses(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let company = seed_company_named(&pool, "Asset Co").await;

    let asset_type: Uuid =
        sqlx::query_scalar("SELECT id FROM asset_types WHERE tenant_id = $1 LIMIT 1")
            .bind(common::DEFAULT_TENANT_ID)
            .fetch_one(&pool)
            .await
            .expect("a seeded asset type");

    sqlx::query(
        "INSERT INTO assets (tenant_id, name, asset_type_id, company_id) \
         VALUES ($1, 'Server 1', $2, $3)",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(asset_type)
    .bind(company)
    .execute(&pool)
    .await
    .expect("seed asset");

    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;
    let (status, body) = delete_company_raw(&app, &token, company).await;

    assert_eq!(status, 400, "an asset must still block; body: {body}");
    assert!(
        body.contains("assets"),
        "the refusal must still name assets; got: {body}"
    );
}

/// PMS-919 AC4 and AC6: the tenant's own company is refused for its ROLE, and
/// that refusal is distinguishable from every other one.
///
/// Without the explicit guard this is the quiet case. `tenants.own_company_id`
/// is nullable, so on a tenant with no overhead time yet the delete would
/// succeed, the pointer would go NULL, and the failure would surface much later
/// as a NOT NULL violation on `time_entries` (PMS-413, MAPPS-243).
#[sqlx::test]
async fn deleting_the_tenants_own_company_names_its_role(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let own = seed_company_named(&pool, "Our MSP").await;
    sqlx::query("UPDATE tenants SET own_company_id = $1 WHERE id = $2")
        .bind(own)
        .bind(common::DEFAULT_TENANT_ID)
        .execute(&pool)
        .await
        .expect("point the tenant at its own company");

    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;
    let (status, body) = delete_company_raw(&app, &token, own).await;

    assert_eq!(status, 400, "the own company must refuse; body: {body}");
    assert!(
        body.contains("own company record"),
        "the refusal must name the company's ROLE, not read as a generic \
         related-records error, which is what the FK alone would produce; got: {body}"
    );
    assert!(
        !body.contains("remove them first"),
        "there is nothing for the operator to remove here, so the generic advice \
         must not be what they are given; got: {body}"
    );

    let still_pointed: Option<Uuid> =
        sqlx::query_scalar("SELECT own_company_id FROM tenants WHERE id = $1")
            .bind(common::DEFAULT_TENANT_ID)
            .fetch_one(&app.pool)
            .await
            .expect("read tenant");
    assert_eq!(
        still_pointed,
        Some(own),
        "a refused delete must leave the pointer intact"
    );
}

/// PMS-920: a blocker that must be KEPT does not tell the operator to remove it.
///
/// The old message listed every blocking table and said "remove them first".
/// For an invoice that is advice they must not take: deleting the billing
/// record to tidy a client list destroys exactly what the refusal exists to
/// protect. This is the half of the message that was actively harmful.
#[sqlx::test]
async fn a_retained_blocker_is_not_something_the_operator_is_told_to_delete(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let company = seed_company_named(&pool, "Billed Co").await;

    sqlx::query(
        "INSERT INTO invoices (tenant_id, company_id, invoice_number, invoice_date, due_date) \
         VALUES ($1, $2, 'INV-0001', CURRENT_DATE, CURRENT_DATE + 30)",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company)
    .execute(&pool)
    .await
    .expect("seed invoice");

    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;
    let (status, body) = delete_company_raw(&app, &token, company).await;

    assert_eq!(status, 400, "an invoice must block; body: {body}");
    assert!(
        body.contains("invoices"),
        "the refusal must name the blocker; got: {body}"
    );
    assert!(
        !body.contains("Remove or reassign") && !body.contains("remove them first"),
        "an invoice must never be something the operator is told to remove to enable \
         a delete; got: {body}"
    );
    assert!(
        body.contains("Inactive"),
        "and the refusal must offer the alternative that actually applies; got: {body}"
    );
}

/// The two halves must be distinguishable from each other, or splitting them
/// bought nothing. Same company shape, different blocker, different advice.
#[sqlx::test]
async fn retained_and_removable_blockers_give_different_advice(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let retained = seed_company_named(&pool, "Retained Co").await;
    let removable = seed_company_named(&pool, "Removable Co").await;

    sqlx::query(
        "INSERT INTO invoices (tenant_id, company_id, invoice_number, invoice_date, due_date) \
         VALUES ($1, $2, 'INV-0002', CURRENT_DATE, CURRENT_DATE + 30)",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(retained)
    .execute(&pool)
    .await
    .expect("seed invoice");

    sqlx::query(
        "INSERT INTO credential_vault \
           (tenant_id, name, company_id, credential_type, username_encrypted, password_encrypted) \
         VALUES ($1, 'Domain admin', $2, 'domain', 'x', 'y')",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(removable)
    .execute(&pool)
    .await
    .expect("seed credential");

    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;
    let (_, retained_body) = delete_company_raw(&app, &token, retained).await;
    let (_, removable_body) = delete_company_raw(&app, &token, removable).await;

    assert_ne!(
        retained_body, removable_body,
        "a blocker that must be kept and one that can be cleared must not read \
         identically, which is the whole point of PMS-920"
    );
    assert!(retained_body.contains("must not be removed"));
    assert!(removable_body.contains("Remove or reassign"));
    // Both still end at the same place, because archiving is what the operator
    // wanted in either case.
    assert!(retained_body.contains("Inactive") && removable_body.contains("Inactive"));
}

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
