//! PMS-1624: a staff approvals decision on a quote moves the quote's status.
//!
//! The rule, from `quotes::approval_sync`: a quote goes `approved` when every
//! staff-addressed approval on it is decided and all approved; any rejection
//! moves it to `rejected` at once and the veto stands. Only out of
//! `submitted`, and only staff-addressed rows count, because a row addressed
//! to a contact is the CLIENT's sign-off and `QuoteStatus` keeps that in
//! `Accepted` / `Declined`.
//!
//! Driven through HTTP rather than against `approval_sync` directly, because
//! what PMS-1573 showed is that a rule nobody can reach through a route is
//! indistinguishable from a rule that is not there. The arithmetic itself is
//! unit-tested in `quotes::approval_sync::tests`.

use crate::common;

use mokosh_test::mokosh_test;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_quote(pool: &PgPool, admin_id: Uuid, status: &str) -> Uuid {
    let company_id = common::seed_company(pool).await;
    let id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO quotes
           (id, tenant_id, company_id, title, summary, requested_by_id, total, currency, status)
           VALUES ($1, $2, $3, 'Rack refresh', 'Two switches', $4, 4200.00, 'USD', $5)"#,
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company_id)
    .bind(admin_id)
    .bind(status)
    .execute(pool)
    .await
    .expect("seed quote");
    id
}

/// Ask for sign-off from a role, through the route a client would use.
async fn request_approval(app: &common::TestApp, token: &str, quote: Uuid, role: &str) -> Uuid {
    let response = app
        .client
        .post(app.url(&format!("/api/v1/quotes/{quote}/approvals")))
        .bearer_auth(token)
        .json(&serde_json::json!({ "approver_role": role, "notes": "sign off" }))
        .send()
        .await
        .expect("request approval");
    // 2xx rather than a specific code: the create route answers 200 and the
    // existing polymorphic suite asserts the class, not the number.
    assert!(
        response.status().is_success(),
        "request approval: {}",
        response.status()
    );
    let body: Value = response.json().await.expect("approval json");
    body["id"]
        .as_str()
        .expect("the approval id")
        .parse()
        .expect("a uuid")
}

/// Seed a contact-addressed approval directly: the staff route cannot write
/// one, and what this suite needs is a row the internal chain must ignore.
async fn seed_contact_approval(pool: &PgPool, quote: Uuid, company_id: Uuid) -> Uuid {
    let contact_id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO contacts (id, tenant_id, company_id, first_name, last_name, email)
           VALUES ($1, $2, $3, 'Ada', 'Byron', 'ada@example.test')"#,
    )
    .bind(contact_id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company_id)
    .execute(pool)
    .await
    .expect("seed contact");
    let id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO ticket_approvals
           (id, tenant_id, target, entity_id, approver_contact_id, status)
           VALUES ($1, $2, 'quote', $3, $4, 'pending')"#,
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(quote)
    .bind(contact_id)
    .execute(pool)
    .await
    .expect("seed contact approval");
    id
}

async fn decide(app: &common::TestApp, token: &str, approval: Uuid, decision: &str) -> u16 {
    app.client
        .post(app.url(&format!("/api/v1/approvals/{approval}/decision")))
        .bearer_auth(token)
        .json(&serde_json::json!({ "decision": decision }))
        .send()
        .await
        .expect("decide")
        .status()
        .as_u16()
}

async fn status_of(pool: &PgPool, quote: Uuid) -> String {
    sqlx::query_scalar("SELECT status FROM quotes WHERE id = $1")
        .bind(quote)
        .fetch_one(pool)
        .await
        .expect("read the quote status")
}

#[mokosh_test]
async fn approving_the_only_approval_approves_the_quote(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let quote = seed_quote(&pool, admin_id, "submitted").await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let approval = request_approval(&app, &token, quote, "super_admin").await;
    assert_eq!(status_of(&pool, quote).await, "submitted", "nothing yet");

    assert_eq!(decide(&app, &token, approval, "approve").await, 200);
    assert_eq!(status_of(&pool, quote).await, "approved");
}

#[mokosh_test]
async fn the_quote_waits_for_every_approver(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let quote = seed_quote(&pool, admin_id, "submitted").await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    // Both addressed to this caller's own role. `decide` authorises per row
    // (`approver_user_id == caller || approver_role == caller_role`), so a
    // chain this test can drive end to end has to be a chain it may decide;
    // two sign-offs from one role group is a real shape anyway.
    let first = request_approval(&app, &token, quote, "super_admin").await;
    let second = request_approval(&app, &token, quote, "super_admin").await;

    assert_eq!(decide(&app, &token, first, "approve").await, 200);
    assert_eq!(
        status_of(&pool, quote).await,
        "submitted",
        "one approver has answered; the chain is not complete"
    );

    assert_eq!(decide(&app, &token, second, "approve").await, 200);
    assert_eq!(status_of(&pool, quote).await, "approved");
}

#[mokosh_test]
async fn one_rejection_vetoes_without_waiting_for_the_rest(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let quote = seed_quote(&pool, admin_id, "submitted").await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let first = request_approval(&app, &token, quote, "super_admin").await;
    let second = request_approval(&app, &token, quote, "super_admin").await;

    assert_eq!(decide(&app, &token, first, "reject").await, 200);
    assert_eq!(
        status_of(&pool, quote).await,
        "rejected",
        "a named approver has turned it down; waiting for the rest would leave it in submitted"
    );

    // And the veto stands: the quote has left `submitted`, so the second
    // approval finds nothing to move.
    assert_eq!(decide(&app, &token, second, "approve").await, 200);
    assert_eq!(status_of(&pool, quote).await, "rejected");
}

#[mokosh_test]
async fn a_contact_addressed_approval_neither_moves_nor_blocks(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let quote = seed_quote(&pool, admin_id, "submitted").await;
    let company_id: Uuid = sqlx::query_scalar("SELECT company_id FROM quotes WHERE id = $1")
        .bind(quote)
        .fetch_one(&pool)
        .await
        .expect("the quote's company");
    seed_contact_approval(&pool, quote, company_id).await;

    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let staff = request_approval(&app, &token, quote, "super_admin").await;

    // The client's pending row must not hold the internal chain open: staff
    // sign-off cannot be made to wait on a customer.
    assert_eq!(decide(&app, &token, staff, "approve").await, 200);
    assert_eq!(status_of(&pool, quote).await, "approved");
}

#[mokosh_test]
async fn a_decision_on_a_quote_that_is_not_submitted_is_still_recorded(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let quote = seed_quote(&pool, admin_id, "draft").await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let approval = request_approval(&app, &token, quote, "super_admin").await;
    assert_eq!(
        decide(&app, &token, approval, "approve").await,
        200,
        "an approver is never blocked by a status change they had no part in"
    );
    assert_eq!(
        status_of(&pool, quote).await,
        "draft",
        "and the quote is not dragged into approved from draft"
    );
    let recorded: String = sqlx::query_scalar("SELECT status FROM ticket_approvals WHERE id = $1")
        .bind(approval)
        .fetch_one(&pool)
        .await
        .expect("the approval row");
    assert_eq!(recorded, "approved", "the decision itself stands");
}

#[mokosh_test]
async fn marking_approved_by_hand_is_refused_while_a_decision_is_outstanding(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let quote = seed_quote(&pool, admin_id, "submitted").await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let approval = request_approval(&app, &token, quote, "super_admin").await;

    let manual = app
        .client
        .put(app.url(&format!("/api/v1/quotes/{quote}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "status": "approved" }))
        .send()
        .await
        .expect("manual approve");
    assert_eq!(
        manual.status(),
        reqwest::StatusCode::CONFLICT,
        "two authorities would race, and the loser would be ignored silently"
    );
    let body: Value = manual.json().await.expect("refusal json");
    let message = body["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("approvals queue"),
        "the refusal names where to do it instead: {message}"
    );

    // A manual rejection is the same answer a veto gives, so it is allowed:
    // refusing it would strand a quote whose named approver is away.
    let manual_reject = app
        .client
        .put(app.url(&format!("/api/v1/quotes/{quote}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "status": "rejected" }))
        .send()
        .await
        .expect("manual reject");
    assert_eq!(manual_reject.status(), reqwest::StatusCode::OK);
    assert_eq!(status_of(&pool, quote).await, "rejected");

    // And once the chain is out of the way, the manual path works again.
    let cancel = app
        .client
        .delete(app.url(&format!("/api/v1/approvals/{approval}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("cancel the approval");
    assert!(
        cancel.status().is_success(),
        "cancel: {:?}",
        cancel.text().await
    );
    let manual = app
        .client
        .put(app.url(&format!("/api/v1/quotes/{quote}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "status": "approved" }))
        .send()
        .await
        .expect("manual approve after cancel");
    assert_eq!(manual.status(), reqwest::StatusCode::OK);
    assert_eq!(status_of(&pool, quote).await, "approved");
}

#[mokosh_test]
async fn the_status_change_is_audited_against_the_quote(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let quote = seed_quote(&pool, admin_id, "submitted").await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let approval = request_approval(&app, &token, quote, "super_admin").await;
    assert_eq!(decide(&app, &token, approval, "approve").await, 200);

    let row: Option<Value> = sqlx::query_scalar(
        r#"SELECT new_values FROM audit_log
           WHERE entity_type = 'quotes' AND entity_id = $1
             AND new_values->>'event' = 'quote.approval_decided'"#,
    )
    .bind(quote)
    .fetch_optional(&pool)
    .await
    .expect("read the audit row");
    let row = row.expect("an approvals-driven status change writes an audit row");
    assert_eq!(row["status"], "approved");
    assert_eq!(row["decision"], "approved");
    assert_eq!(
        row["approval_id"].as_str().expect("the approval id"),
        approval.to_string(),
        "so the history says which approval moved it"
    );
}
