//! PMS-914 close-out: cap-gate + Company-scope matrix for the
//! `POST /api/v1/invoices/{id}/pay` route. Mirrors the four-shape rows
//! `tests/portal_expanded_caps.rs` runs against the sibling PDF route:
//!
//!   1. contact WITH `invoices:pay`, matching Company -> the cap + scope
//!      gates pass, and the service returns 400 with "no active payment
//!      provider is configured for this account" (the seeded tenant has
//!      no Stripe gateway). That 400 is the correct downstream behaviour
//!      and proves the handler reached the service after clearing every
//!      auth gate; the Stripe-integrated success case is exercised by
//!      `tests/pms711_stripe_pay_now.rs`.
//!   2. contact WITHOUT the cap -> 403.
//!   3. contact WITH the cap, foreign Company -> 404 (leak-free scope
//!      check fires before the service is called).
//!   4. staff caller with billing+finance -> bypasses the cap gate, hits
//!      the same 400 as row 1.
//!
//! Plus one DTO row: a malformed `success_url` is rejected 400 with a
//! validation envelope so the callers cannot smuggle non-URL strings
//! into the provider redirect.

mod common;

use reqwest::StatusCode;
use sqlx::PgPool;
use uuid::Uuid;

const NO_GATEWAY: &str = "no active payment provider is configured";

async fn seed_contact_with_roles(
    app: &common::TestApp,
    pool: &PgPool,
    email_local: &str,
    role_names: &[&str],
) -> (Uuid, Uuid, String, String) {
    let tenant_id = common::DEFAULT_TENANT_ID;
    let email = format!("{email_local}@invoice-pay.example");
    let company_id = Uuid::new_v4();
    let slug = format!("pip-{}", &Uuid::new_v4().simple().to_string()[..12]);
    sqlx::query("INSERT INTO companies (id, tenant_id, name, portal_slug) VALUES ($1, $2, $3, $4)")
        .bind(company_id)
        .bind(tenant_id)
        .bind(format!("PIP Co {email_local}"))
        .bind(&slug)
        .execute(pool)
        .await
        .expect("seed company");

    let contact_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO contacts (id, tenant_id, company_id, first_name, last_name, email) \
         VALUES ($1, $2, $3, 'Test', 'Payer', $4)",
    )
    .bind(contact_id)
    .bind(tenant_id)
    .bind(company_id)
    .bind(&email)
    .execute(pool)
    .await
    .expect("seed contact");

    let db = mokosh_server::Database::from_pool(pool.clone());
    let contact_svc = mokosh_server::modules::contacts::ContactService::new(db);
    let mut role_ids = Vec::new();
    for name in role_names {
        let id: Uuid =
            sqlx::query_scalar("SELECT id FROM portal_roles WHERE tenant_id = $1 AND name = $2")
                .bind(tenant_id)
                .bind(name)
                .fetch_one(pool)
                .await
                .unwrap_or_else(|e| panic!("read portal_role {name}: {e}"));
        role_ids.push(id);
    }
    let outcome = contact_svc
        .grant_portal_access(
            mokosh_server::modules::auth::TenantId::from_trusted(tenant_id),
            contact_id,
            &role_ids,
            &mokosh_server::modules::audit::AuditCtx::system(tenant_id),
        )
        .await
        .expect("grant_portal_access");

    let prefix = format!("/portal/{}/set-password?token=", outcome.portal_slug);
    let token = outcome
        .setup_link
        .split(&prefix)
        .nth(1)
        .expect("token in setup_link")
        .to_string();
    let strong = "Kq7$mZ2n#PxR9wLf";
    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/set-password"))
        .json(&serde_json::json!({ "token": token, "password": strong }))
        .send()
        .await
        .expect("set-password");
    assert_eq!(resp.status(), StatusCode::NO_CONTENT, "set-password 204");

    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/login"))
        .json(&serde_json::json!({
            "slug": outcome.portal_slug,
            "email": email,
            "password": strong,
        }))
        .send()
        .await
        .expect("contact login");
    assert_eq!(resp.status(), StatusCode::OK, "contact login 200");
    let body: serde_json::Value = resp.json().await.expect("login JSON");
    let access = body["access_token"]
        .as_str()
        .expect("access_token in login response")
        .to_string();
    (company_id, contact_id, email, access)
}

async fn seed_plain_company(pool: &PgPool, tenant_id: Uuid, label: &str) -> Uuid {
    let company_id = Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, $3)")
        .bind(company_id)
        .bind(tenant_id)
        .bind(label)
        .execute(pool)
        .await
        .expect("seed plain company");
    company_id
}

async fn seed_invoice_on_company(pool: &PgPool, tenant_id: Uuid, company_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO invoices (id, tenant_id, invoice_number, company_id, status, \
         invoice_date, due_date, subtotal, total, amount_paid, balance_due, currency) \
         VALUES ($1, $2, $3, $4, 'sent', CURRENT_DATE, CURRENT_DATE + 30, 100, 100, 0, 100, 'USD')",
    )
    .bind(id)
    .bind(tenant_id)
    .bind(format!("PIP-INV-{}", &id.simple().to_string()[..8]))
    .bind(company_id)
    .execute(pool)
    .await
    .expect("seed invoice");
    id
}

fn pay_body() -> serde_json::Value {
    serde_json::json!({
        "success_url": "https://portal.example/invoices/paid",
        "cancel_url":  "https://portal.example/invoices/cancelled",
    })
}

#[sqlx::test]
async fn contact_with_invoices_pay_reaches_service_400_no_gateway(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (own_company, _c, _e, token) =
        seed_contact_with_roles(&app, &pool, "pay-ok", &["Billing Contact"]).await;
    let invoice_id = seed_invoice_on_company(&pool, common::DEFAULT_TENANT_ID, own_company).await;

    let resp = app
        .client
        .post(app.url(&format!("/api/v1/invoices/{invoice_id}/pay")))
        .bearer_auth(&token)
        .json(&pay_body())
        .send()
        .await
        .expect("pay");
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "PMS-914: cap + scope gates pass; service refuses without a Stripe gateway"
    );
    let body: serde_json::Value = resp.json().await.expect("json");
    let msg = body["error"]["message"]
        .as_str()
        .or_else(|| body["message"].as_str())
        .unwrap_or("");
    assert!(
        msg.to_ascii_lowercase().contains(NO_GATEWAY),
        "PMS-914: no-gateway message expected, got {body}"
    );
}

#[sqlx::test]
async fn contact_without_invoices_pay_403(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    // Support Contact has tickets:* but not invoices:pay.
    let (own_company, _c, _e, token) =
        seed_contact_with_roles(&app, &pool, "pay-nocap", &["Support Contact"]).await;
    let invoice_id = seed_invoice_on_company(&pool, common::DEFAULT_TENANT_ID, own_company).await;

    let resp = app
        .client
        .post(app.url(&format!("/api/v1/invoices/{invoice_id}/pay")))
        .bearer_auth(&token)
        .json(&pay_body())
        .send()
        .await
        .expect("pay");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "PMS-914: contact without invoices:pay must 403"
    );
}

#[sqlx::test]
async fn contact_with_invoices_pay_foreign_company_404(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (_own_company, _c, _e, token) =
        seed_contact_with_roles(&app, &pool, "pay-foreign", &["Billing Contact"]).await;
    let other_company =
        seed_plain_company(&pool, common::DEFAULT_TENANT_ID, "pay-foreign-co").await;
    let invoice_id = seed_invoice_on_company(&pool, common::DEFAULT_TENANT_ID, other_company).await;

    let resp = app
        .client
        .post(app.url(&format!("/api/v1/invoices/{invoice_id}/pay")))
        .bearer_auth(&token)
        .json(&pay_body())
        .send()
        .await
        .expect("pay");
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "PMS-914: cross-Company pay must 404, not 400 or 403"
    );
}

#[sqlx::test]
async fn staff_bypasses_invoices_pay_cap_400_no_gateway(pool: PgPool) {
    let (_admin_id, admin_email, admin_password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let staff_token = common::login(&app, &admin_email, &admin_password).await;
    let plain_co = seed_plain_company(&pool, common::DEFAULT_TENANT_ID, "staff-pay-co").await;
    let invoice_id = seed_invoice_on_company(&pool, common::DEFAULT_TENANT_ID, plain_co).await;

    let resp = app
        .client
        .post(app.url(&format!("/api/v1/invoices/{invoice_id}/pay")))
        .bearer_auth(&staff_token)
        .json(&pay_body())
        .send()
        .await
        .expect("pay");
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "PMS-914: staff caller clears the RequireBilling+RequireFinance gate; hits the no-gateway 400"
    );
    let body: serde_json::Value = resp.json().await.expect("json");
    let msg = body["error"]["message"]
        .as_str()
        .or_else(|| body["message"].as_str())
        .unwrap_or("");
    assert!(
        msg.to_ascii_lowercase().contains(NO_GATEWAY),
        "PMS-914: no-gateway message expected, got {body}"
    );
}

#[sqlx::test]
async fn pay_body_rejects_non_url_success_url(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (own_company, _c, _e, token) =
        seed_contact_with_roles(&app, &pool, "pay-badurl", &["Billing Contact"]).await;
    let invoice_id = seed_invoice_on_company(&pool, common::DEFAULT_TENANT_ID, own_company).await;

    let resp = app
        .client
        .post(app.url(&format!("/api/v1/invoices/{invoice_id}/pay")))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "success_url": "not a url",
            "cancel_url": "https://portal.example/cancel",
        }))
        .send()
        .await
        .expect("pay");
    assert_eq!(
        resp.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "PMS-914: DTO validation refuses non-URL success_url with 422 (AppError::Validation)"
    );
}

/// MAPPS-667 (mokosh-invoices P1b): a Draft invoice cannot be paid. The
/// pre-P1b guard refused only `void` + `written_off`; a Draft is by
/// definition an invoice not yet shown to the customer, so paying one
/// from the contact plane is either a leak (list surfaced a row it
/// shouldn't have) or an accident on the staff plane that would charge
/// a card for an amount not yet finalized. Security-review F9.
#[sqlx::test]
async fn contact_with_invoices_pay_refuses_draft_400(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (own_company, _c, _e, token) =
        seed_contact_with_roles(&app, &pool, "pay-draft", &["Billing Contact"]).await;
    // Seed a Draft invoice on the contact's own Company. Uses raw SQL
    // rather than the seed helper so the status is explicit.
    let invoice_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO invoices (id, tenant_id, invoice_number, company_id, status, \
         invoice_date, due_date, subtotal, total, amount_paid, balance_due, currency) \
         VALUES ($1, $2, $3, $4, 'draft', CURRENT_DATE, CURRENT_DATE + 30, 100, 100, 0, 100, 'USD')",
    )
    .bind(invoice_id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(format!("PIP-DRAFT-{}", &invoice_id.simple().to_string()[..8]))
    .bind(own_company)
    .execute(&pool)
    .await
    .expect("seed draft invoice");

    let resp = app
        .client
        .post(app.url(&format!("/api/v1/invoices/{invoice_id}/pay")))
        .bearer_auth(&token)
        .json(&pay_body())
        .send()
        .await
        .expect("pay");
    // The service's status-guard fires before the no-gateway 400, so a
    // Draft invoice returns the status-specific error even in the
    // test's no-gateway environment. Message includes the status name
    // so a caller can render "This invoice is a draft" copy without
    // matching on a status-agnostic string.
    assert_eq!(
        resp.status(),
        StatusCode::CONFLICT,
        "MAPPS-667: pay on a Draft invoice must refuse before the gateway check"
    );
    let body: serde_json::Value = resp.json().await.expect("json");
    let msg = body["error"]["message"]
        .as_str()
        .or_else(|| body["message"].as_str())
        .unwrap_or("");
    assert!(
        msg.contains("'draft'"),
        "MAPPS-667: refusal message must name the status, got {body}"
    );
}

/// MAPPS-677: the pay-mint rate limiter is wired on the route with the
/// production 20/min-per-caller + 10/min-per-invoice quotas. This
/// integration test proves the WIRING: an 11th mint on one invoice, from
/// one contact, trips the invoice bucket and answers 429 with a
/// `Retry-After` header. The limiter LOGIC (per-caller cap, per-invoice
/// cap across mixed callers, charge-on-every-call) is covered end-to-end
/// by the unit tests in `src/modules/auth/rate_limit.rs`; running the
/// same shapes here would multiply the 10-11 request round-trips by
/// three for no new coverage of anything the unit tests do not already
/// pin. The invoice bucket trips at 10 vs 20 for the caller bucket, so
/// hitting the invoice bucket is the cheapest way to observe the 429
/// shape without seeding twenty-plus unique invoices.
#[sqlx::test]
async fn eleventh_pay_attempt_on_one_invoice_is_429_with_retry_after(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (own_company, _c, _e, token) =
        seed_contact_with_roles(&app, &pool, "pay-rate", &["Billing Contact"]).await;
    let invoice_id = seed_invoice_on_company(&pool, common::DEFAULT_TENANT_ID, own_company).await;

    // The first 10 mints on this invoice all pass the limiter and hit the
    // service's no-gateway 400 (the test app has no Stripe configured).
    // Nothing here asserts on their body: the point is the count.
    for i in 0..10 {
        let resp = app
            .client
            .post(app.url(&format!("/api/v1/invoices/{invoice_id}/pay")))
            .bearer_auth(&token)
            .json(&pay_body())
            .send()
            .await
            .expect("pay");
        assert_ne!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "MAPPS-677: request #{} of 10 must clear the invoice bucket",
            i + 1
        );
    }

    // The 11th mint on the same invoice trips the invoice bucket
    // regardless of whether the caller bucket still has headroom.
    let resp = app
        .client
        .post(app.url(&format!("/api/v1/invoices/{invoice_id}/pay")))
        .bearer_auth(&token)
        .json(&pay_body())
        .send()
        .await
        .expect("pay");
    assert_eq!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "MAPPS-677: the 11th mint on one invoice must be refused with 429"
    );
    let retry_after = resp
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .expect("MAPPS-677: 429 must carry a numeric Retry-After header");
    assert!(
        retry_after >= 1,
        "MAPPS-677: Retry-After is at least one second, got {retry_after}"
    );
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(
        body["error"], "rate_limited",
        "MAPPS-677: the 429 body uses the rate_limited envelope shape shared with the auth limiters"
    );
}

// -- MAPPS-673 partial-payment tests ----------------------------------------
//
// The partial-payment gate stacks a second capability (`invoices:pay_partial`)
// on top of the existing `invoices:pay` cap, adds range validation in the
// service, and readiness reports whether the SPA should render the amount
// input. The tests below cover every arm of the branch so a regression to any
// one gate fails LOUD rather than surfacing as "the wrong amount was
// charged" when a customer clicks.

fn pay_body_with_amount(amount: &str) -> serde_json::Value {
    serde_json::json!({
        "success_url": "https://portal.example/invoices/paid",
        "cancel_url":  "https://portal.example/invoices/cancelled",
        "amount": amount,
    })
}

/// MAPPS-673: a Billing Contact (which the migration grants
/// `invoices:pay_partial` on top of `invoices:pay`) can send an amount
/// below the balance. The service clears both gates and hits the same
/// no-gateway 400 the full-pay test does; that reaching the service is
/// what proves the cap gate passed. The Stripe-integrated success case is
/// exercised by the sibling suite that seeds a gateway.
#[sqlx::test]
async fn contact_with_pay_partial_and_amount_reaches_service_400_no_gateway(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (own_company, _c, _e, token) =
        seed_contact_with_roles(&app, &pool, "pay-partial-ok", &["Billing Contact"]).await;
    let invoice_id = seed_invoice_on_company(&pool, common::DEFAULT_TENANT_ID, own_company).await;

    let resp = app
        .client
        .post(app.url(&format!("/api/v1/invoices/{invoice_id}/pay")))
        .bearer_auth(&token)
        .json(&pay_body_with_amount("25.00"))
        .send()
        .await
        .expect("pay");
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "MAPPS-673: cap + scope + range gates pass; service refuses without a gateway"
    );
    let body: serde_json::Value = resp.json().await.expect("json");
    let msg = body["error"]["message"]
        .as_str()
        .or_else(|| body["message"].as_str())
        .unwrap_or("");
    assert!(
        msg.to_ascii_lowercase().contains(NO_GATEWAY),
        "MAPPS-673: no-gateway message expected on partial pay, got {body}"
    );
}

/// MAPPS-673: an amount above `balance_due` is refused before the mint
/// with a 400 that names the ceiling. The seed invoice has `balance_due
/// = 100`; asking for 150 must refuse.
#[sqlx::test]
async fn pay_amount_above_balance_is_400(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (own_company, _c, _e, token) =
        seed_contact_with_roles(&app, &pool, "pay-over", &["Billing Contact"]).await;
    let invoice_id = seed_invoice_on_company(&pool, common::DEFAULT_TENANT_ID, own_company).await;

    let resp = app
        .client
        .post(app.url(&format!("/api/v1/invoices/{invoice_id}/pay")))
        .bearer_auth(&token)
        .json(&pay_body_with_amount("150.00"))
        .send()
        .await
        .expect("pay");
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "MAPPS-673: amount > balance_due must 400 before the mint"
    );
    let body: serde_json::Value = resp.json().await.expect("json");
    let msg = body["error"]["message"]
        .as_str()
        .or_else(|| body["message"].as_str())
        .unwrap_or("");
    assert!(
        msg.contains("above the invoice balance"),
        "MAPPS-673: refusal must name the balance ceiling, got {body}"
    );
}

/// MAPPS-673: an amount below `DEFAULT_MIN_PARTIAL_AMOUNT` ($1.00) is
/// refused. The seed tenant has no `payment_gateway_configs` row, so the
/// floor falls back to the code default via `min_partial_amount_across_active`.
/// This proves the fee-abuse guard fires even when the tenant has not set
/// a value in the column.
#[sqlx::test]
async fn pay_amount_below_min_partial_is_400(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (own_company, _c, _e, token) =
        seed_contact_with_roles(&app, &pool, "pay-under", &["Billing Contact"]).await;
    let invoice_id = seed_invoice_on_company(&pool, common::DEFAULT_TENANT_ID, own_company).await;

    // Seed an active gateway row with a NULL min_partial_amount so the
    // floor falls back to DEFAULT_MIN_PARTIAL_AMOUNT via
    // `min_partial_amount_across_active`. `config_encrypted` is empty on
    // purpose: the range check MUST run without decrypting the provider
    // config, so a mid-migration or unbuildable row still refuses a below-
    // floor amount with a 400 rather than 500ing on the decrypt.
    sqlx::query(
        "INSERT INTO payment_gateway_configs (id, tenant_id, provider, is_active, is_test_mode, \
         config_encrypted) VALUES ($1, $2, 'stripe', TRUE, TRUE, '')",
    )
    .bind(Uuid::new_v4())
    .bind(common::DEFAULT_TENANT_ID)
    .execute(&pool)
    .await
    .expect("seed active gateway config");

    let resp = app
        .client
        .post(app.url(&format!("/api/v1/invoices/{invoice_id}/pay")))
        .bearer_auth(&token)
        .json(&pay_body_with_amount("0.50"))
        .send()
        .await
        .expect("pay");
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "MAPPS-673: amount below the min-partial floor must 400"
    );
    let body: serde_json::Value = resp.json().await.expect("json");
    let msg = body["error"]["message"]
        .as_str()
        .or_else(|| body["message"].as_str())
        .unwrap_or("");
    assert!(
        msg.contains("below the minimum partial payment"),
        "MAPPS-673: refusal must name the floor, got {body}"
    );
}

/// MAPPS-673: a contact holding `invoices:pay` but NOT
/// `invoices:pay_partial` cannot mint a partial-amount checkout. The
/// route refuses with 403 rather than silently ignoring the `amount` and
/// charging the full balance - a caller whose attempt did not do what
/// they asked has to know. Seeded via a bespoke role so we do not rely
/// on the migration having flipped Billing Contact's caps.
#[sqlx::test]
async fn contact_without_pay_partial_with_amount_is_403(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    // Custom role: `invoices:pay` alone (no `invoices:pay_partial`).
    let role_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO portal_roles (id, tenant_id, name, capabilities, is_builtin) \
         VALUES ($1, $2, 'Pay Only', ARRAY['invoices:pay']::text[], FALSE)",
    )
    .bind(role_id)
    .bind(common::DEFAULT_TENANT_ID)
    .execute(&pool)
    .await
    .expect("seed Pay Only role");

    let (own_company, _c, _e, token) =
        seed_contact_with_roles(&app, &pool, "pay-no-partial", &["Pay Only"]).await;
    let invoice_id = seed_invoice_on_company(&pool, common::DEFAULT_TENANT_ID, own_company).await;

    let resp = app
        .client
        .post(app.url(&format!("/api/v1/invoices/{invoice_id}/pay")))
        .bearer_auth(&token)
        .json(&pay_body_with_amount("25.00"))
        .send()
        .await
        .expect("pay");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "MAPPS-673: `amount` without `invoices:pay_partial` must 403"
    );
}

/// MAPPS-673: a staff caller with billing + finance bypasses the
/// partial-payment cap the same way they bypass `invoices:pay`. Hits the
/// same no-gateway 400 as row 1 of the full-pay matrix.
#[sqlx::test]
async fn staff_bypasses_pay_partial_cap_400_no_gateway(pool: PgPool) {
    let (_admin_id, admin_email, admin_password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let staff_token = common::login(&app, &admin_email, &admin_password).await;
    let plain_co =
        seed_plain_company(&pool, common::DEFAULT_TENANT_ID, "staff-pay-partial-co").await;
    let invoice_id = seed_invoice_on_company(&pool, common::DEFAULT_TENANT_ID, plain_co).await;

    let resp = app
        .client
        .post(app.url(&format!("/api/v1/invoices/{invoice_id}/pay")))
        .bearer_auth(&staff_token)
        .json(&pay_body_with_amount("25.00"))
        .send()
        .await
        .expect("pay");
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "MAPPS-673: staff caller clears the pay + pay_partial gate; hits the no-gateway 400"
    );
    let body: serde_json::Value = resp.json().await.expect("json");
    let msg = body["error"]["message"]
        .as_str()
        .or_else(|| body["message"].as_str())
        .unwrap_or("");
    assert!(
        msg.to_ascii_lowercase().contains(NO_GATEWAY),
        "MAPPS-673: staff partial pay expects no-gateway message, got {body}"
    );
}
