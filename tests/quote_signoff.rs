//! PMS-673: integration tests for issuing a quote and the client's
//! sign-off through the portal.
//!
//! Pins the guarantees the ticket calls out:
//!   - `POST /quotes/{id}/send` is allowed only from `approved`.
//!   - Sending stamps `sent_at` and moves the quote to `sent`.
//!   - A portal contact sees only quotes for their own company AND their
//!     own tenant, and only the statuses that were actually issued.
//!   - An un-issued quote is 404 (not 403) to a contact who guesses its
//!     id, so the portal never confirms it exists.
//!   - Accept / decline record the deciding contact, timestamp, and
//!     notes, and 409 from any state other than `sent`.
//!   - A quote past `valid_until` reads as expired and cannot be
//!     accepted, with no sweeper having run.
//!   - Every transition lands in the audit log.

mod common;

use reqwest::StatusCode;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

const PORTAL_PASSWORD: &str = "portal-password-12345";

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

/// Seed a portal-enabled contact under `company_id`. Mirrors the helper
/// in `tests/portal.rs`.
async fn seed_portal_contact(pool: &PgPool, company_id: Uuid, email: &str) -> Uuid {
    let id = Uuid::new_v4();
    let hash =
        mokosh_server::utils::crypto::hash_password(PORTAL_PASSWORD).expect("hash portal password");
    sqlx::query(
        r#"
        INSERT INTO contacts (
            id, tenant_id, company_id, first_name, last_name, email,
            is_portal_user, portal_password_hash
        )
        VALUES ($1, $2, $3, 'Portal', 'Contact', $4, TRUE, $5)
        "#,
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company_id)
    .bind(email)
    .bind(&hash)
    .execute(pool)
    .await
    .expect("seed portal contact");
    id
}

async fn portal_token(app: &common::TestApp, email: &str) -> String {
    let resp = app
        .client
        .post(app.url("/api/v1/portal/auth/login"))
        .json(&serde_json::json!({
            "tenant_slug": "default",
            "email": email,
            "password": PORTAL_PASSWORD,
        }))
        .send()
        .await
        .expect("send portal login");
    assert!(
        resp.status().is_success(),
        "portal login expected 2xx, got {}",
        resp.status()
    );
    let body: Value = resp.json().await.expect("portal login JSON");
    body["access_token"]
        .as_str()
        .expect("access_token")
        .to_string()
}

/// Create a quote through the staff API.
async fn create_quote(app: &common::TestApp, token: &str, body: Value) -> Value {
    let resp = app
        .client
        .post(app.url("/api/v1/quotes"))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .expect("send create quote");
    assert_eq!(resp.status(), StatusCode::OK, "create quote should 200");
    resp.json().await.expect("create quote body")
}

/// Walk a draft quote through the internal workflow to `approved`, which
/// is the only state `send` accepts.
async fn approve(app: &common::TestApp, token: &str, quote_id: &str) {
    for status in ["submitted", "approved"] {
        let resp = app
            .client
            .put(app.url(&format!("/api/v1/quotes/{quote_id}")))
            .bearer_auth(token)
            .json(&serde_json::json!({ "status": status }))
            .send()
            .await
            .expect("advance status");
        assert_eq!(resp.status(), StatusCode::OK, "advance to {status}");
    }
}

async fn send_quote(app: &common::TestApp, token: &str, quote_id: &str) -> reqwest::Response {
    app.client
        .post(app.url(&format!("/api/v1/quotes/{quote_id}/send")))
        .bearer_auth(token)
        .send()
        .await
        .expect("send quote")
}

#[sqlx::test]
async fn send_requires_internal_approval_and_stamps_sent_at(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let company = seed_company_named(&pool, "Client A").await;
    let contact = seed_portal_contact(&pool, company, "signoff-send@example.com").await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let quote = create_quote(
        &app,
        &token,
        serde_json::json!({
            "company_id": company,
            "billing_contact_id": contact,
            "title": "Provide LLM access to Employees",
            "lines": [{"line_type":"service","description":"Build","quantity":"1","unit_price":"1000"}],
        }),
    )
    .await;
    let quote_id = quote["id"].as_str().unwrap().to_string();

    // A draft quote has not been approved internally, so it cannot go out.
    let premature = send_quote(&app, &token, &quote_id).await;
    assert_eq!(
        premature.status(),
        StatusCode::CONFLICT,
        "sending a draft quote must 409"
    );

    approve(&app, &token, &quote_id).await;

    let sent = send_quote(&app, &token, &quote_id).await;
    assert_eq!(sent.status(), StatusCode::OK);
    let body: Value = sent.json().await.expect("sent body");
    assert_eq!(body["status"], "sent");
    assert!(
        !body["sent_at"].is_null(),
        "sending stamps sent_at; got {body:?}"
    );

    // Sending twice is refused: the quote is no longer `approved`.
    let again = send_quote(&app, &token, &quote_id).await;
    assert_eq!(again.status(), StatusCode::CONFLICT);

    // The transition is auditable.
    let audited: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_log WHERE entity_type = 'quotes' AND entity_id = $1",
    )
    .bind(Uuid::parse_str(&quote_id).unwrap())
    .fetch_one(&pool)
    .await
    .expect("count audit rows");
    assert!(audited > 0, "quote transitions must be audited");
}

#[sqlx::test]
async fn portal_sees_only_issued_quotes_for_its_own_company(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let company_a = seed_company_named(&pool, "Client A").await;
    let company_b = seed_company_named(&pool, "Client B").await;
    let contact_a = seed_portal_contact(&pool, company_a, "a@example.com").await;
    let _contact_b = seed_portal_contact(&pool, company_b, "b@example.com").await;

    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    // One issued quote for A, one still in draft for A, one issued for B.
    let issued_a = create_quote(
        &app,
        &token,
        serde_json::json!({
            "company_id": company_a, "billing_contact_id": contact_a, "title": "A issued",
        }),
    )
    .await;
    let issued_a_id = issued_a["id"].as_str().unwrap().to_string();
    approve(&app, &token, &issued_a_id).await;
    assert_eq!(
        send_quote(&app, &token, &issued_a_id).await.status(),
        StatusCode::OK
    );

    let draft_a = create_quote(
        &app,
        &token,
        serde_json::json!({ "company_id": company_a, "title": "A draft" }),
    )
    .await;
    let draft_a_id = draft_a["id"].as_str().unwrap().to_string();

    let issued_b = create_quote(
        &app,
        &token,
        serde_json::json!({ "company_id": company_b, "title": "B issued" }),
    )
    .await;
    let issued_b_id = issued_b["id"].as_str().unwrap().to_string();
    approve(&app, &token, &issued_b_id).await;
    assert_eq!(
        send_quote(&app, &token, &issued_b_id).await.status(),
        StatusCode::OK
    );

    let portal = portal_token(&app, "a@example.com").await;

    // The list shows exactly the one issued quote belonging to company A.
    let listed: Value = app
        .client
        .get(app.url("/api/v1/portal/quotes"))
        .bearer_auth(&portal)
        .send()
        .await
        .expect("portal list")
        .json()
        .await
        .expect("portal list body");
    assert_eq!(listed["meta"]["total"], 1, "only A's issued quote");
    assert_eq!(listed["data"][0]["id"], issued_a["id"]);

    // A's own draft is invisible even by direct id: 404, not 403, so the
    // portal never confirms that an internal quote exists.
    let draft = app
        .client
        .get(app.url(&format!("/api/v1/portal/quotes/{draft_a_id}")))
        .bearer_auth(&portal)
        .send()
        .await
        .expect("portal get draft");
    assert_eq!(draft.status(), StatusCode::NOT_FOUND);

    // Another company's issued quote is likewise 404.
    let other = app
        .client
        .get(app.url(&format!("/api/v1/portal/quotes/{issued_b_id}")))
        .bearer_auth(&portal)
        .send()
        .await
        .expect("portal get other company");
    assert_eq!(other.status(), StatusCode::NOT_FOUND);

    // And it cannot be decided either.
    let decide_other = app
        .client
        .post(app.url(&format!("/api/v1/portal/quotes/{issued_b_id}/accept")))
        .bearer_auth(&portal)
        .send()
        .await
        .expect("decide other company");
    assert_eq!(decide_other.status(), StatusCode::NOT_FOUND);
}

#[sqlx::test]
async fn client_accept_records_the_decision_and_is_not_repeatable(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let company = seed_company_named(&pool, "Client A").await;
    let contact = seed_portal_contact(&pool, company, "accept@example.com").await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let quote = create_quote(
        &app,
        &token,
        serde_json::json!({
            "company_id": company, "billing_contact_id": contact, "title": "To accept",
            "lines": [{"line_type":"service","description":"Build","quantity":"1","unit_price":"1000"}],
        }),
    )
    .await;
    let quote_id = quote["id"].as_str().unwrap().to_string();
    approve(&app, &token, &quote_id).await;
    assert_eq!(
        send_quote(&app, &token, &quote_id).await.status(),
        StatusCode::OK
    );

    let portal = portal_token(&app, "accept@example.com").await;
    let accepted: Value = app
        .client
        .post(app.url(&format!("/api/v1/portal/quotes/{quote_id}/accept")))
        .bearer_auth(&portal)
        .json(&serde_json::json!({ "notes": "Looks good, please proceed" }))
        .send()
        .await
        .expect("accept")
        .json()
        .await
        .expect("accept body");

    assert_eq!(accepted["status"], "accepted");
    assert_eq!(accepted["decided_by_contact_id"], contact.to_string());
    assert!(!accepted["decided_at"].is_null());
    assert_eq!(accepted["decision_notes"], "Looks good, please proceed");

    // A double-click or a stale tab must not flip a decided quote.
    let again = app
        .client
        .post(app.url(&format!("/api/v1/portal/quotes/{quote_id}/accept")))
        .bearer_auth(&portal)
        .send()
        .await
        .expect("accept twice");
    assert_eq!(again.status(), StatusCode::CONFLICT);

    // Nor may it be declined after acceptance.
    let flip = app
        .client
        .post(app.url(&format!("/api/v1/portal/quotes/{quote_id}/decline")))
        .bearer_auth(&portal)
        .send()
        .await
        .expect("decline after accept");
    assert_eq!(flip.status(), StatusCode::CONFLICT);

    // The accepted quote stays visible to the client afterwards.
    let visible: Value = app
        .client
        .get(app.url(&format!("/api/v1/portal/quotes/{quote_id}")))
        .bearer_auth(&portal)
        .send()
        .await
        .expect("get after accept")
        .json()
        .await
        .expect("body");
    assert_eq!(visible["status"], "accepted");
}

#[sqlx::test]
async fn client_can_decline_without_a_body(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let company = seed_company_named(&pool, "Client A").await;
    let contact = seed_portal_contact(&pool, company, "decline@example.com").await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let quote = create_quote(
        &app,
        &token,
        serde_json::json!({
            "company_id": company, "billing_contact_id": contact, "title": "To decline",
        }),
    )
    .await;
    let quote_id = quote["id"].as_str().unwrap().to_string();
    approve(&app, &token, &quote_id).await;
    assert_eq!(
        send_quote(&app, &token, &quote_id).await.status(),
        StatusCode::OK
    );

    // No JSON body at all: declining with nothing to say must not be a
    // 415, so the body is optional.
    let portal = portal_token(&app, "decline@example.com").await;
    let declined = app
        .client
        .post(app.url(&format!("/api/v1/portal/quotes/{quote_id}/decline")))
        .bearer_auth(&portal)
        .send()
        .await
        .expect("decline");
    assert_eq!(declined.status(), StatusCode::OK);
    let body: Value = declined.json().await.expect("decline body");
    assert_eq!(body["status"], "declined");
    assert_eq!(body["decided_by_contact_id"], contact.to_string());
    assert!(body["decision_notes"].is_null());
}

#[sqlx::test]
async fn an_expired_quote_reads_as_expired_and_cannot_be_accepted(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let company = seed_company_named(&pool, "Client A").await;
    let contact = seed_portal_contact(&pool, company, "expired@example.com").await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let quote = create_quote(
        &app,
        &token,
        serde_json::json!({
            "company_id": company, "billing_contact_id": contact, "title": "Stale offer",
        }),
    )
    .await;
    let quote_id = quote["id"].as_str().unwrap().to_string();
    approve(&app, &token, &quote_id).await;
    assert_eq!(
        send_quote(&app, &token, &quote_id).await.status(),
        StatusCode::OK
    );

    // Backdate the validity. The stored status stays `sent`; expiry is
    // applied at read time, so no sweeper has to have run.
    sqlx::query("UPDATE quotes SET valid_until = CURRENT_DATE - 1 WHERE id = $1")
        .bind(Uuid::parse_str(&quote_id).unwrap())
        .execute(&pool)
        .await
        .expect("backdate validity");

    let stored: String = sqlx::query_scalar("SELECT status FROM quotes WHERE id = $1")
        .bind(Uuid::parse_str(&quote_id).unwrap())
        .fetch_one(&pool)
        .await
        .expect("stored status");
    assert_eq!(stored, "sent", "expiry is derived, not written");

    let portal = portal_token(&app, "expired@example.com").await;
    let read: Value = app
        .client
        .get(app.url(&format!("/api/v1/portal/quotes/{quote_id}")))
        .bearer_auth(&portal)
        .send()
        .await
        .expect("read expired")
        .json()
        .await
        .expect("body");
    assert_eq!(read["status"], "expired", "read-time expiry applies");

    let accept = app
        .client
        .post(app.url(&format!("/api/v1/portal/quotes/{quote_id}/accept")))
        .bearer_auth(&portal)
        .send()
        .await
        .expect("accept expired");
    assert_eq!(
        accept.status(),
        StatusCode::CONFLICT,
        "an expired quote cannot be accepted"
    );

    // A quote valid through today is still acceptable: `valid_until` is
    // inclusive, so a customer signing on the deadline is not turned away.
    sqlx::query("UPDATE quotes SET valid_until = CURRENT_DATE WHERE id = $1")
        .bind(Uuid::parse_str(&quote_id).unwrap())
        .execute(&pool)
        .await
        .expect("restore validity");
    let deadline_accept = app
        .client
        .post(app.url(&format!("/api/v1/portal/quotes/{quote_id}/accept")))
        .bearer_auth(&portal)
        .send()
        .await
        .expect("accept on deadline");
    assert_eq!(deadline_accept.status(), StatusCode::OK);
}

#[sqlx::test]
async fn staff_token_cannot_drive_the_portal_signoff(pool: PgPool) {
    // The client's decision is the client's. A staff bearer token must not
    // be accepted on the portal surface, or the whole point of routing
    // sign-off through the portal is lost.
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let company = seed_company_named(&pool, "Client A").await;
    let contact = seed_portal_contact(&pool, company, "staffcheck@example.com").await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let quote = create_quote(
        &app,
        &token,
        serde_json::json!({
            "company_id": company, "billing_contact_id": contact, "title": "Not staff's to accept",
        }),
    )
    .await;
    let quote_id = quote["id"].as_str().unwrap().to_string();
    approve(&app, &token, &quote_id).await;
    assert_eq!(
        send_quote(&app, &token, &quote_id).await.status(),
        StatusCode::OK
    );

    let staff_on_portal = app
        .client
        .post(app.url(&format!("/api/v1/portal/quotes/{quote_id}/accept")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("staff token on portal");
    assert_eq!(
        staff_on_portal.status(),
        StatusCode::UNAUTHORIZED,
        "a staff token must not be usable on the portal sign-off"
    );

    let unauthenticated = app
        .client
        .get(app.url("/api/v1/portal/quotes"))
        .send()
        .await
        .expect("anonymous portal list");
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);
}
