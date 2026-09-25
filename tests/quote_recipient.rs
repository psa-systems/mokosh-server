//! PMS-1000: a quote cannot be sent to nobody.
//!
//! `send_quote` committed the `approved -> sent` transition and then called
//! `mail_quote_to_client`, which returned early when the quote named no
//! billing contact and said so in an `info` line. So a quote reached `sent`,
//! was stamped `sent_at`, showed as delivered on the staff page, and nobody
//! was ever told. The customer's silence was the only other signal.
//!
//! The recipient is settled before the transition now, the shape PMS-992 gave
//! the invoice send: an explicit contact if the quote names one, else the
//! company's billing contact, written back onto the quote; and a 409 naming
//! the company when neither yields anybody.

mod common;

use mokosh_test::mokosh_test;
use reqwest::StatusCode;
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_company_named(pool: &PgPool, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO companies (id, tenant_id, name, status) VALUES ($1, $2, $3, 'active')",
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(name)
    .execute(pool)
    .await
    .expect("seed company");
    id
}

/// A contact of `company_id` that is NOT the company's default billing
/// contact, for the cross-company checks.
async fn seed_contact_of(pool: &PgPool, company_id: Uuid, email: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO contacts (id, tenant_id, company_id, first_name, last_name, email) \
         VALUES ($1, $2, $3, 'Some', 'Body', $4)",
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company_id)
    .bind(email)
    .execute(pool)
    .await
    .expect("seed contact");
    id
}

async fn create_quote(app: &common::TestApp, token: &str, body: Value) -> reqwest::Response {
    app.client
        .post(app.url("/api/v1/quotes"))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .expect("create quote")
}

fn quote_body(company_id: Uuid, contact: Option<Uuid>) -> Value {
    let mut body = json!({
        "company_id": company_id,
        "title": "Managed services",
        "lines": [{
            "line_type": "service",
            "description": "Onboarding",
            "quantity": "1",
            "unit_price": "500",
        }],
    });
    if let Some(contact) = contact {
        body["billing_contact_id"] = json!(contact);
    }
    body
}

/// `approved` is the only state `send` accepts.
async fn approve(app: &common::TestApp, token: &str, quote_id: &str) {
    for status in ["submitted", "approved"] {
        let resp = app
            .client
            .put(app.url(&format!("/api/v1/quotes/{quote_id}")))
            .bearer_auth(token)
            .json(&json!({ "status": status }))
            .send()
            .await
            .expect("advance status");
        assert_eq!(resp.status(), StatusCode::OK, "advance to {status}");
    }
}

async fn send(app: &common::TestApp, token: &str, quote_id: &str) -> reqwest::Response {
    app.client
        .post(app.url(&format!("/api/v1/quotes/{quote_id}/send")))
        .bearer_auth(token)
        .send()
        .await
        .expect("send quote")
}

async fn quote_row(pool: &PgPool, quote_id: &str) -> (String, Option<Uuid>, Option<String>) {
    sqlx::query_as("SELECT status, billing_contact_id, sent_at::text FROM quotes WHERE id = $1")
        .bind(Uuid::parse_str(quote_id).expect("quote id"))
        .fetch_one(pool)
        .await
        .expect("quote row")
}

/// The case the issue was filed for: nobody to send to, so the send is
/// refused and the quote does not move.
#[mokosh_test]
async fn sending_a_quote_with_no_recipient_is_refused(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let company = seed_company_named(&pool, "Nobody Home Ltd").await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let created: Value = create_quote(&app, &token, quote_body(company, None))
        .await
        .json()
        .await
        .expect("quote json");
    let quote_id = created["id"].as_str().expect("quote id").to_string();
    assert!(
        created["billing_contact_id"].is_null(),
        "the company has nobody, so the draft names nobody: {created}"
    );
    approve(&app, &token, &quote_id).await;

    let refused = send(&app, &token, &quote_id).await;
    assert_eq!(refused.status(), StatusCode::CONFLICT);
    let body: Value = refused.json().await.expect("refusal json");
    let message = body["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("Nobody Home Ltd"),
        "the refusal names the company: {message}"
    );
    assert!(
        message.contains("billing contact"),
        "and what is missing: {message}"
    );

    // The quote did not move, so there is no half-sent state to unpick.
    let (status, contact, sent_at) = quote_row(&pool, &quote_id).await;
    assert_eq!(status, "approved", "still approved");
    assert!(contact.is_none());
    assert!(sent_at.is_none(), "sent_at was never stamped");
}

/// A quote naming nobody, whose company HAS a billing contact, sends and
/// records who it went to. Persisted rather than merely resolved, because the
/// mail reads the recipient back off the quote.
#[mokosh_test]
async fn a_send_inherits_the_companys_billing_contact_and_records_it(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let company = seed_company_named(&pool, "Has A Contact Ltd").await;
    let billing = common::seed_billing_contact(&pool, company).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let created: Value = create_quote(&app, &token, quote_body(company, None))
        .await
        .json()
        .await
        .expect("quote json");
    let quote_id = created["id"].as_str().expect("quote id").to_string();
    // The draft carries its recipient from the moment it exists.
    assert_eq!(
        created["billing_contact_id"].as_str(),
        Some(billing.to_string().as_str()),
        "a create with no contact inherits the company's: {created}"
    );

    approve(&app, &token, &quote_id).await;
    let sent = send(&app, &token, &quote_id).await;
    assert!(sent.status().is_success(), "{}", sent.status());

    let (status, contact, sent_at) = quote_row(&pool, &quote_id).await;
    assert_eq!(status, "sent");
    assert_eq!(contact, Some(billing), "the recipient is on the quote");
    assert!(sent_at.is_some());
}

/// Even when the draft named nobody at create time, because the company's
/// billing contact was set afterwards, the send resolves it.
#[mokosh_test]
async fn a_contact_set_after_the_draft_is_resolved_at_send(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let company = seed_company_named(&pool, "Late Contact Ltd").await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let created: Value = create_quote(&app, &token, quote_body(company, None))
        .await
        .json()
        .await
        .expect("quote json");
    let quote_id = created["id"].as_str().expect("quote id").to_string();
    assert!(created["billing_contact_id"].is_null());
    approve(&app, &token, &quote_id).await;

    // The operator fixes the company rather than the quote, which is the
    // recovery the refusal above points at.
    let billing = common::seed_billing_contact(&pool, company).await;

    let sent = send(&app, &token, &quote_id).await;
    assert!(sent.status().is_success(), "{}", sent.status());
    let (_status, contact, _sent_at) = quote_row(&pool, &quote_id).await;
    assert_eq!(contact, Some(billing));
}

/// A contact of another company is refused on create and on update. Before
/// this the check was against the TENANT, so a quote could be addressed to a
/// different customer's contact: a disclosure rather than a typo.
#[mokosh_test]
async fn a_contact_of_another_company_is_refused(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let ours = seed_company_named(&pool, "Ours Ltd").await;
    let theirs = seed_company_named(&pool, "Theirs Ltd").await;
    let their_contact = seed_contact_of(&pool, theirs, "theirs@example.test").await;
    common::seed_billing_contact(&pool, ours).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    // On create.
    let refused = create_quote(&app, &token, quote_body(ours, Some(their_contact))).await;
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    let body: Value = refused.json().await.expect("refusal json");
    assert!(
        body.to_string().contains("contact of this company"),
        "{body}"
    );

    // And on update, against a quote that was created legitimately.
    let created: Value = create_quote(&app, &token, quote_body(ours, None))
        .await
        .json()
        .await
        .expect("quote json");
    let quote_id = created["id"].as_str().expect("quote id").to_string();
    let refused = app
        .client
        .put(app.url(&format!("/api/v1/quotes/{quote_id}")))
        .bearer_auth(&token)
        .json(&json!({ "billing_contact_id": their_contact }))
        .send()
        .await
        .expect("update quote");
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);

    let (_status, contact, _sent_at) = quote_row(&pool, &quote_id).await;
    assert_ne!(
        contact,
        Some(their_contact),
        "the other company's contact was not written"
    );
}
