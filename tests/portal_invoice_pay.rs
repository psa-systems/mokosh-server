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
