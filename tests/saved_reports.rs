//! PMS-457 phase 1: integration test for saved-report definitions.
//!
//! Pins the visibility and authorship guarantees that the future
//! Phase 2 runtime depends on:
//!   - author CRUD round-trip works;
//!   - `is_shared=true` is visible to other users in the same
//!     tenant; `is_shared=false` is not;
//!   - a non-author cannot mutate (PATCH/DELETE) someone else's
//!     report, even a shared one (they get 404, same as a missing
//!     row);
//!   - `?entity_type=` filters the list to a single discriminator.

mod common;

use serde_json::Value;
use sqlx::PgPool;

#[sqlx::test]
async fn saved_reports_crud_and_visibility(pool: PgPool) {
    let (_admin_id, admin_email, admin_pw) = common::seed_admin(&pool).await;
    // Seed a SECOND active admin in the same tenant so the visibility
    // checks have a non-author identity to log in as.
    let (_other_id, other_email, other_pw) = common::seed_user(
        &pool,
        common::DEFAULT_TENANT_ID,
        "second-admin@example.com",
        "admin",
    )
    .await;

    let app = common::boot(pool).await;
    let admin_token = common::login(&app, &admin_email, &admin_pw).await;
    let other_token = common::login(&app, &other_email, &other_pw).await;

    // Author creates two reports: a private one and a shared one.
    let private: Value = app
        .client
        .post(app.url("/api/v1/reports/saved"))
        .bearer_auth(&admin_token)
        .json(&serde_json::json!({
            "name": "My personal triage view",
            "entity_type": "tickets",
            "filters": { "status": ["open"] },
            "columns": [{"field": "ticket_number"}, {"field": "title"}],
            "is_shared": false,
        }))
        .send()
        .await
        .expect("create private")
        .json()
        .await
        .expect("private body");
    assert_eq!(private["is_shared"], false);
    let private_id = private["id"].as_str().expect("private id").to_string();

    let shared: Value = app
        .client
        .post(app.url("/api/v1/reports/saved"))
        .bearer_auth(&admin_token)
        .json(&serde_json::json!({
            "name": "Team weekly KPIs",
            "entity_type": "tickets",
            "is_shared": true,
        }))
        .send()
        .await
        .expect("create shared")
        .json()
        .await
        .expect("shared body");
    assert_eq!(shared["is_shared"], true);
    let shared_id = shared["id"].as_str().expect("shared id").to_string();

    // The OTHER user can only see the shared row via the default
    // `?scope=any` view, never the private one. Scope=mine returns
    // nothing for them.
    let any_for_other: Value = app
        .client
        .get(app.url("/api/v1/reports/saved"))
        .bearer_auth(&other_token)
        .send()
        .await
        .expect("other list any")
        .json()
        .await
        .expect("other list body");
    let arr = any_for_other.as_array().expect("array");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["id"].as_str(), Some(shared_id.as_str()));

    let mine_for_other: Value = app
        .client
        .get(app.url("/api/v1/reports/saved?scope=mine"))
        .bearer_auth(&other_token)
        .send()
        .await
        .expect("other list mine")
        .json()
        .await
        .expect("other mine body");
    assert!(
        mine_for_other.as_array().expect("array").is_empty(),
        "scope=mine must be empty for a non-author"
    );

    // entity_type filter narrows the list.
    let filtered: Value = app
        .client
        .get(app.url("/api/v1/reports/saved?entity_type=invoices"))
        .bearer_auth(&admin_token)
        .send()
        .await
        .expect("filter list")
        .json()
        .await
        .expect("filter body");
    assert!(
        filtered.as_array().expect("array").is_empty(),
        "no reports on 'invoices' yet"
    );

    // Non-author cannot PATCH the shared report (only the author may
    // mutate). Surfaces 404 to match the "absent or off-limits"
    // posture.
    let bad_patch = app
        .client
        .patch(app.url(&format!("/api/v1/reports/saved/{shared_id}")))
        .bearer_auth(&other_token)
        .json(&serde_json::json!({ "name": "I am taking over your report" }))
        .send()
        .await
        .expect("foreign patch");
    assert_eq!(bad_patch.status().as_u16(), 404);

    // Non-author cannot DELETE either.
    let bad_delete = app
        .client
        .delete(app.url(&format!("/api/v1/reports/saved/{shared_id}")))
        .bearer_auth(&other_token)
        .send()
        .await
        .expect("foreign delete");
    assert_eq!(bad_delete.status().as_u16(), 404);

    // Author can rename + flip is_shared.
    let patched: Value = app
        .client
        .patch(app.url(&format!("/api/v1/reports/saved/{private_id}")))
        .bearer_auth(&admin_token)
        .json(&serde_json::json!({
            "name": "Personal triage v2",
            "is_shared": true,
        }))
        .send()
        .await
        .expect("self patch")
        .json()
        .await
        .expect("patched body");
    assert_eq!(patched["name"], "Personal triage v2");
    assert_eq!(patched["is_shared"], true);

    // The "private" row was just flipped to shared, so the other
    // user now sees BOTH reports.
    let any_after: Value = app
        .client
        .get(app.url("/api/v1/reports/saved"))
        .bearer_auth(&other_token)
        .send()
        .await
        .expect("other list after flip")
        .json()
        .await
        .expect("any after body");
    assert_eq!(any_after.as_array().expect("array").len(), 2);

    // Author deletes the row they just flipped; the other user sees
    // only the original shared row again.
    let del = app
        .client
        .delete(app.url(&format!("/api/v1/reports/saved/{private_id}")))
        .bearer_auth(&admin_token)
        .send()
        .await
        .expect("self delete");
    assert!(del.status().is_success());

    // GET on the deleted id is 404.
    let gone = app
        .client
        .get(app.url(&format!("/api/v1/reports/saved/{private_id}")))
        .bearer_auth(&admin_token)
        .send()
        .await
        .expect("get deleted");
    assert_eq!(gone.status().as_u16(), 404);
}
