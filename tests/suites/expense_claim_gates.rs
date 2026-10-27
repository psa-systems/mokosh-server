//! PMS-1535: who may do what with an expense claim, over HTTP.
//!
//! The gates are route-level, so the service suites cannot see them: a
//! test calling `ExpensesService` directly proves the write happens and
//! says nothing about whether a technician was allowed to ask. Every case
//! here goes through `create_api_router` with a real bearer.
//!
//! The rule being pinned: a claim belongs to the person who made it.
//! Anybody in the tenant can file one and submit their own; finance sees
//! every claim and decides them.

use crate::common;

use mokosh_test::mokosh_test;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

/// A claim body with one line, in the shape `CreateExpenseRequest` takes.
fn claim(description: &str) -> serde_json::Value {
    json!({
        "incurred_on": "2026-10-23",
        "currency": "USD",
        "lines": [{
            "description": description,
            "amount_minor": 3250,
        }],
    })
}

async fn technician(pool: &PgPool) -> (Uuid, String, String) {
    common::seed_user(
        pool,
        common::DEFAULT_TENANT_ID,
        "tech@example.com",
        "technician",
    )
    .await
}

/// A technician files their own claim, reads it back and submits it.
///
/// Before PMS-1535 every one of these four calls was a 403, which is the
/// whole feature being unusable by the people it is for.
#[mokosh_test]
async fn a_technician_files_reads_and_submits_their_own_claim(pool: PgPool) {
    let (_admin, _email, _password) = common::seed_admin(&pool).await;
    let (tech_id, tech_email, tech_password) = technician(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &tech_email, &tech_password).await;

    let created = app
        .client
        .post(app.url("/api/v1/expenses"))
        .bearer_auth(&token)
        .json(&claim("Taxi to site"))
        .send()
        .await
        .expect("send create");
    assert_eq!(
        created.status(),
        reqwest::StatusCode::OK,
        "a member can file a claim"
    );
    let body: serde_json::Value = created.json().await.expect("create JSON");
    let id = body["id"].as_str().expect("the new claim's id").to_string();
    assert_eq!(
        body["user_id"].as_str(),
        Some(tech_id.to_string().as_str()),
        "the submitter is the caller, not whoever is handy"
    );
    assert_eq!(body["status"], "draft");

    let read = app
        .client
        .get(app.url(&format!("/api/v1/expenses/{id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send read");
    assert_eq!(read.status(), reqwest::StatusCode::OK, "and read it back");

    let submitted = app
        .client
        .post(app.url(&format!("/api/v1/expenses/{id}/submit")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send submit");
    assert_eq!(
        submitted.status(),
        reqwest::StatusCode::OK,
        "submitting is the submitter's own act"
    );
    let body: serde_json::Value = submitted.json().await.expect("submit JSON");
    assert_eq!(body["status"], "submitted");
}

/// A technician's list is their own claims and nobody else's.
///
/// `list_expenses` had no filter, so without the forced scope this call
/// would have answered with every claim in the tenant.
#[mokosh_test]
async fn a_technician_lists_only_their_own_claims(pool: PgPool) {
    let (_admin, admin_email, admin_password) = common::seed_admin(&pool).await;
    let (tech_id, tech_email, tech_password) = technician(&pool).await;
    let app = common::boot(pool).await;
    let admin_token = common::login(&app, &admin_email, &admin_password).await;
    let tech_token = common::login(&app, &tech_email, &tech_password).await;

    for (token, description) in [
        (&admin_token, "Admin's conference ticket"),
        (&tech_token, "Taxi to site"),
    ] {
        let resp = app
            .client
            .post(app.url("/api/v1/expenses"))
            .bearer_auth(token)
            .json(&claim(description))
            .send()
            .await
            .expect("send create");
        assert_eq!(resp.status(), reqwest::StatusCode::OK, "{description}");
    }

    let listed: serde_json::Value = app
        .client
        .get(app.url("/api/v1/expenses"))
        .bearer_auth(&tech_token)
        .send()
        .await
        .expect("send list")
        .json()
        .await
        .expect("list JSON");
    let rows = listed["data"].as_array().expect("a data array");
    assert_eq!(rows.len(), 1, "one claim, theirs: {listed}");
    assert_eq!(
        rows[0]["user_id"].as_str(),
        Some(tech_id.to_string().as_str())
    );
    assert_eq!(
        listed["meta"]["total"], 1,
        "and the total agrees with the page, so the pager does not walk them through claims they cannot read"
    );

    // Finance sees both, which is the half that did not change.
    let listed: serde_json::Value = app
        .client
        .get(app.url("/api/v1/expenses"))
        .bearer_auth(&admin_token)
        .send()
        .await
        .expect("send list")
        .json()
        .await
        .expect("list JSON");
    assert_eq!(listed["data"].as_array().map(|r| r.len()), Some(2));
    assert_eq!(listed["meta"]["total"], 2);
}

/// Somebody else's claim is refused by id, and the refusal is a 403 and
/// not a 404: the claim exists, and the caller is in the tenant.
#[mokosh_test]
async fn another_members_claim_is_refused(pool: PgPool) {
    let (_admin, admin_email, admin_password) = common::seed_admin(&pool).await;
    let (_tech_id, tech_email, tech_password) = technician(&pool).await;
    let app = common::boot(pool).await;
    let admin_token = common::login(&app, &admin_email, &admin_password).await;
    let tech_token = common::login(&app, &tech_email, &tech_password).await;

    let created: serde_json::Value = app
        .client
        .post(app.url("/api/v1/expenses"))
        .bearer_auth(&admin_token)
        .json(&claim("Admin's conference ticket"))
        .send()
        .await
        .expect("send create")
        .json()
        .await
        .expect("create JSON");
    let id = created["id"].as_str().expect("the new claim's id");

    let read = app
        .client
        .get(app.url(&format!("/api/v1/expenses/{id}")))
        .bearer_auth(&tech_token)
        .send()
        .await
        .expect("send read");
    assert_eq!(read.status(), reqwest::StatusCode::FORBIDDEN);

    let submitted = app
        .client
        .post(app.url(&format!("/api/v1/expenses/{id}/submit")))
        .bearer_auth(&tech_token)
        .send()
        .await
        .expect("send submit");
    assert_eq!(
        submitted.status(),
        reqwest::StatusCode::FORBIDDEN,
        "and submitting it for them is refused too"
    );

    // An id that names nothing is still a 404 for the same caller: the
    // refusal above is about ownership, not about hiding the route.
    let missing = app
        .client
        .get(app.url(&format!("/api/v1/expenses/{}", Uuid::new_v4())))
        .bearer_auth(&tech_token)
        .send()
        .await
        .expect("send read");
    assert_eq!(missing.status(), reqwest::StatusCode::NOT_FOUND);
}

/// Deciding a claim stays finance's: the three transitions a technician
/// must not make are all refused, on their own claim.
#[mokosh_test]
async fn a_technician_cannot_decide_a_claim(pool: PgPool) {
    let (_admin, admin_email, admin_password) = common::seed_admin(&pool).await;
    let (_tech_id, tech_email, tech_password) = technician(&pool).await;
    let app = common::boot(pool).await;
    let admin_token = common::login(&app, &admin_email, &admin_password).await;
    let tech_token = common::login(&app, &tech_email, &tech_password).await;

    let created: serde_json::Value = app
        .client
        .post(app.url("/api/v1/expenses"))
        .bearer_auth(&tech_token)
        .json(&claim("Taxi to site"))
        .send()
        .await
        .expect("send create")
        .json()
        .await
        .expect("create JSON");
    let id = created["id"]
        .as_str()
        .expect("the new claim's id")
        .to_string();
    app.client
        .post(app.url(&format!("/api/v1/expenses/{id}/submit")))
        .bearer_auth(&tech_token)
        .send()
        .await
        .expect("send submit");

    for action in ["approve", "reject", "reimburse"] {
        let resp = app
            .client
            .post(app.url(&format!("/api/v1/expenses/{id}/{action}")))
            .bearer_auth(&tech_token)
            .send()
            .await
            .expect("send transition");
        assert_eq!(
            resp.status(),
            reqwest::StatusCode::FORBIDDEN,
            "a technician cannot {action} a claim, even their own"
        );
    }

    // Finance can, which is what makes the refusals above a gate rather
    // than a broken route.
    let approved = app
        .client
        .post(app.url(&format!("/api/v1/expenses/{id}/approve")))
        .bearer_auth(&admin_token)
        .send()
        .await
        .expect("send approve");
    assert_eq!(approved.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = approved.json().await.expect("approve JSON");
    assert_eq!(body["status"], "approved");
}

/// Vendors, categories and bills stay finance's: they are the MSP's own
/// books, and PMS-1535 opened the claim surface alone.
#[mokosh_test]
async fn the_rest_of_the_subsystem_stays_finance_only(pool: PgPool) {
    let (_admin, _email, _password) = common::seed_admin(&pool).await;
    let (_tech_id, tech_email, tech_password) = technician(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &tech_email, &tech_password).await;

    for path in [
        "/api/v1/vendors",
        "/api/v1/expense-categories",
        "/api/v1/bills",
    ] {
        let resp = app
            .client
            .get(app.url(path))
            .bearer_auth(&token)
            .send()
            .await
            .expect("send list");
        assert_eq!(
            resp.status(),
            reqwest::StatusCode::FORBIDDEN,
            "{path} is the MSP's own books"
        );
    }
}
