//! PMS-759: server-side drafts for the request-form builder.
//!
//! The builder autosaves to `localStorage` too (PMS-754), and that tier needs
//! no server test. What is covered here is the tier that makes a draft survive
//! a different machine: it is stored, it is one row per user per form however
//! many times autosave fires, it belongs to exactly one person, and saving the
//! form retires it.

mod common;

use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

/// A form definition to hang an "editing an existing form" draft off.
async fn seed_form(app: &common::TestApp, token: &str) -> String {
    let resp = app
        .client
        .post(app.url("/api/v1/forms"))
        .bearer_auth(token)
        .json(&json!({
            "name": "New starter",
            "slug": "new-starter",
            "fields": [{
                "name": "first_name",
                "label": "First name",
                "field_type": "text",
                "is_required": true,
                "sort_order": 1
            }]
        }))
        .send()
        .await
        .expect("send create form");
    assert!(resp.status().is_success(), "create form should 2xx");
    let body: serde_json::Value = resp.json().await.expect("create form JSON");
    body["id"].as_str().expect("form id").to_string()
}

async fn put_draft(
    app: &common::TestApp,
    token: &str,
    definition_id: Option<&str>,
    payload: serde_json::Value,
) -> serde_json::Value {
    let resp = app
        .client
        .put(app.url("/api/v1/forms/drafts"))
        .bearer_auth(token)
        .json(&json!({ "form_definition_id": definition_id, "payload": payload }))
        .send()
        .await
        .expect("send draft");
    assert!(
        resp.status().is_success(),
        "draft upsert should 2xx, got {}",
        resp.status()
    );
    resp.json().await.expect("draft JSON")
}

async fn list_drafts(app: &common::TestApp, token: &str) -> Vec<serde_json::Value> {
    app.client
        .get(app.url("/api/v1/forms/drafts"))
        .bearer_auth(token)
        .send()
        .await
        .expect("send list drafts")
        .json()
        .await
        .expect("drafts JSON")
}

/// Autosave fires on a debounce while someone types, so the same draft is
/// written over and over. Each write has to replace the last rather than
/// accumulate, or a five-minute editing session leaves hundreds of rows and a
/// drafts list nobody can use.
#[sqlx::test]
async fn repeated_autosaves_leave_exactly_one_draft(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let token = common::login(&app, &email, &password).await;

    let first = put_draft(
        &app,
        &token,
        None,
        json!({ "name": "Leaver", "fields": [] }),
    )
    .await;
    let second = put_draft(
        &app,
        &token,
        None,
        json!({ "name": "Leaver process", "fields": [{"label": "Last day"}] }),
    )
    .await;

    assert_eq!(
        first["id"], second["id"],
        "the second autosave must update the first draft, not create another"
    );

    let drafts = list_drafts(&app, &token).await;
    assert_eq!(drafts.len(), 1, "one draft per user per form: {drafts:?}");
    assert_eq!(
        drafts[0]["payload"]["name"].as_str(),
        Some("Leaver process"),
        "the list carries the latest snapshot"
    );
    assert_eq!(
        drafts[0]["name"].as_str(),
        Some("Leaver process"),
        "the label is lifted out of the payload so the list needs no parsing"
    );
}

/// A draft for a new form and a draft for an existing one are different
/// drafts. Keying them together would mean opening the editor on a saved form
/// silently restored whatever unrelated thing was typed on the New button.
#[sqlx::test]
async fn a_new_form_draft_and_an_edit_draft_coexist(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let token = common::login(&app, &email, &password).await;
    let form_id = seed_form(&app, &token).await;

    put_draft(&app, &token, None, json!({ "name": "Something new" })).await;
    put_draft(
        &app,
        &token,
        Some(&form_id),
        json!({ "name": "New starter, revised" }),
    )
    .await;

    let drafts = list_drafts(&app, &token).await;
    assert_eq!(drafts.len(), 2, "both drafts stand: {drafts:?}");
    let for_form: Vec<_> = drafts
        .iter()
        .filter(|d| d["form_definition_id"].as_str() == Some(form_id.as_str()))
        .collect();
    assert_eq!(for_form.len(), 1, "one of them is keyed to the definition");
}

/// A half-built form is working state, not a shared document. Another admin in
/// the same tenant must not see it in their list, and must not be able to
/// delete it: the delete is scoped by owner, so someone else's id reads as
/// absent rather than forbidden.
#[sqlx::test]
async fn a_draft_belongs_to_one_user_only(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let token = common::login(&app, &email, &password).await;

    let (_other_id, other_email, other_password) = common::seed_user(
        &pool,
        common::DEFAULT_TENANT_ID,
        "second-admin@example.com",
        "admin",
    )
    .await;
    let other_token = common::login(&app, &other_email, &other_password).await;

    let mine = put_draft(&app, &token, None, json!({ "name": "Mine alone" })).await;

    let theirs = list_drafts(&app, &other_token).await;
    assert!(
        theirs.is_empty(),
        "another admin must not see my draft: {theirs:?}"
    );

    let refused = app
        .client
        .delete(app.url(&format!(
            "/api/v1/forms/drafts/{}",
            mine["id"].as_str().expect("draft id")
        )))
        .bearer_auth(&other_token)
        .send()
        .await
        .expect("send cross-user delete");
    assert_eq!(
        refused.status(),
        404,
        "someone else's draft is absent, not forbidden"
    );

    assert_eq!(
        list_drafts(&app, &token).await.len(),
        1,
        "and it is still there"
    );
}

/// Discarding removes the record. The point of the confirmation in the SPA is
/// that the user meant it, so nothing should bring the draft back on the next
/// open.
#[sqlx::test]
async fn discarding_a_draft_removes_it(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let token = common::login(&app, &email, &password).await;

    let draft = put_draft(&app, &token, None, json!({ "name": "Abandoned" })).await;
    let deleted = app
        .client
        .delete(app.url(&format!(
            "/api/v1/forms/drafts/{}",
            draft["id"].as_str().expect("draft id")
        )))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send delete");
    assert_eq!(deleted.status(), 204);
    assert!(list_drafts(&app, &token).await.is_empty());
}

/// Saving the form is what the draft was protecting against losing, so the
/// draft goes with it. Cleared server-side rather than by the SPA: a draft
/// exists to survive the browser going away, so it cannot rely on the browser
/// to tidy up.
#[sqlx::test]
async fn saving_the_form_clears_its_draft(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let token = common::login(&app, &email, &password).await;

    // The "new form" draft is cleared by creating a form...
    put_draft(&app, &token, None, json!({ "name": "About to be created" })).await;
    let form_id = seed_form(&app, &token).await;
    assert!(
        list_drafts(&app, &token).await.is_empty(),
        "creating a form retires the new-form draft"
    );

    // ...and the per-definition draft by updating that form.
    put_draft(&app, &token, Some(&form_id), json!({ "name": "Edited" })).await;
    assert_eq!(list_drafts(&app, &token).await.len(), 1);

    let updated = app
        .client
        .patch(app.url(&format!("/api/v1/forms/{form_id}")))
        .bearer_auth(&token)
        .json(&json!({ "name": "New starter (v2)" }))
        .send()
        .await
        .expect("send update");
    assert!(updated.status().is_success(), "update should 2xx");
    assert!(
        list_drafts(&app, &token).await.is_empty(),
        "saving the form retires its draft"
    );
}

/// A draft filed against another tenant's definition id would come back on
/// every list, which tells the caller that id exists. The definition is
/// checked inside the tenant transaction for that reason.
///
/// The other tenant's form is inserted directly rather than through the API:
/// `POST /auth/login` resolves a tenant-less login against the default tenant
/// (PMS-138), so there is no token for a second tenant's admin to be had, and
/// the test only needs an id that belongs somewhere else.
#[sqlx::test]
async fn a_draft_cannot_name_another_tenants_form(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let token = common::login(&app, &email, &password).await;

    let (other_tenant, other_user, _email, _password) =
        common::seed_tenant_with_admin(&pool, "pms759-other").await;
    let their_form = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO form_definitions (id, tenant_id, name, slug, created_by_id) \
         VALUES ($1, $2, 'Theirs', 'theirs', $3)",
    )
    .bind(their_form)
    .bind(other_tenant)
    .bind(other_user)
    .execute(&pool)
    .await
    .expect("seed the other tenant's form");

    let refused = app
        .client
        .put(app.url("/api/v1/forms/drafts"))
        .bearer_auth(&token)
        .json(&json!({ "form_definition_id": their_form, "payload": { "name": "Peek" } }))
        .send()
        .await
        .expect("send cross-tenant draft");
    assert_eq!(refused.status(), 404, "another tenant's form is not found");
    assert!(list_drafts(&app, &token).await.is_empty());
}

/// The payload is opaque and client-supplied, so it is bounded. Rejected
/// rather than truncated: a truncated draft restores as a corrupted form,
/// which is worse than a draft that says it could not be saved.
#[sqlx::test]
async fn an_oversized_draft_is_refused(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let token = common::login(&app, &email, &password).await;

    let huge = "x".repeat(300 * 1024);
    let refused = app
        .client
        .put(app.url("/api/v1/forms/drafts"))
        .bearer_auth(&token)
        .json(&json!({ "form_definition_id": Option::<Uuid>::None, "payload": { "name": huge } }))
        .send()
        .await
        .expect("send oversized draft");
    assert_eq!(refused.status(), 400);
    assert!(list_drafts(&app, &token).await.is_empty());
}
