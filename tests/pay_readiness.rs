//! MAPPS-666 (mokosh-invoices P1a): `GET /api/v1/invoices/{id}/payment-
//! readiness` five-shape matrix. Same seed pattern as
//! `tests/portal_invoice_pay.rs`; the readiness read never mints a
//! checkout session so the tenant does not need a Stripe gateway to
//! exercise the not-configured branch (that IS the branch we assert
//! on).

mod common;

use reqwest::StatusCode;
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_contact_with_roles(
    app: &common::TestApp,
    pool: &PgPool,
    email_local: &str,
    role_names: &[&str],
) -> (Uuid, Uuid, String, String) {
    let tenant_id = common::DEFAULT_TENANT_ID;
    let email = format!("{email_local}@pay-readiness.example");
    let company_id = Uuid::new_v4();
    let slug = format!("pr-{}", &Uuid::new_v4().simple().to_string()[..12]);
    sqlx::query("INSERT INTO companies (id, tenant_id, name, portal_slug) VALUES ($1, $2, $3, $4)")
        .bind(company_id)
        .bind(tenant_id)
        .bind(format!("PR Co {email_local}"))
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

async fn seed_sent_invoice(pool: &PgPool, tenant_id: Uuid, company_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO invoices (id, tenant_id, invoice_number, company_id, status, \
         invoice_date, due_date, subtotal, total, amount_paid, balance_due, currency) \
         VALUES ($1, $2, $3, $4, 'sent', CURRENT_DATE, CURRENT_DATE + 30, 100, 100, 0, 100, 'USD')",
    )
    .bind(id)
    .bind(tenant_id)
    .bind(format!("PR-INV-{}", &id.simple().to_string()[..8]))
    .bind(company_id)
    .execute(pool)
    .await
    .expect("seed sent invoice");
    id
}

async fn seed_draft_invoice(pool: &PgPool, tenant_id: Uuid, company_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO invoices (id, tenant_id, invoice_number, company_id, status, \
         invoice_date, due_date, subtotal, total, amount_paid, balance_due, currency) \
         VALUES ($1, $2, $3, $4, 'draft', CURRENT_DATE, CURRENT_DATE + 30, 100, 100, 0, 100, 'USD')",
    )
    .bind(id)
    .bind(tenant_id)
    .bind(format!("PR-DRAFT-{}", &id.simple().to_string()[..8]))
    .bind(company_id)
    .execute(pool)
    .await
    .expect("seed draft invoice");
    id
}

/// Seed an active Stripe gateway row so `has_active_gateway` returns
/// true. The credential doesn't have to be real - the readiness read
/// never touches the provider network - but `active_provider_id` reads
/// the discriminator string, so it must equal `"stripe"` to match
/// `provider::is_supported`.
async fn seed_stripe_gateway(pool: &PgPool, tenant_id: Uuid) {
    sqlx::query(
        "INSERT INTO payment_gateway_configs \
            (tenant_id, provider, is_active, is_test_mode) \
         VALUES ($1, 'stripe', TRUE, TRUE)",
    )
    .bind(tenant_id)
    .execute(pool)
    .await
    .expect("seed stripe gateway");
}

/// MAPPS-671: set the admin override on the tenant's active Stripe row.
async fn set_stripe_client_display_name(pool: &PgPool, tenant_id: Uuid, label: &str) {
    sqlx::query(
        "UPDATE payment_gateway_configs SET client_display_name = $2 \
         WHERE tenant_id = $1 AND provider = 'stripe'",
    )
    .bind(tenant_id)
    .bind(label)
    .execute(pool)
    .await
    .expect("set client_display_name");
}

#[sqlx::test]
async fn readiness_ready_when_gateway_and_payable(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (own_company, _c, _e, token) =
        seed_contact_with_roles(&app, &pool, "ready-ok", &["Billing Contact"]).await;
    let invoice_id = seed_sent_invoice(&pool, common::DEFAULT_TENANT_ID, own_company).await;
    seed_stripe_gateway(&pool, common::DEFAULT_TENANT_ID).await;

    let resp = app
        .client
        .get(app.url(&format!("/api/v1/invoices/{invoice_id}/payment-readiness")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("readiness");
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(
        body["gateway_ready"].as_bool(),
        Some(true),
        "MAPPS-666: gateway configured -> gateway_ready = true, got {body}"
    );
    assert_eq!(
        body["invoice_payable"].as_bool(),
        Some(true),
        "MAPPS-666: sent invoice with balance > 0 -> invoice_payable = true"
    );
    assert_eq!(
        body["button_label"].as_str(),
        Some("Pay with card"),
        "MAPPS-666: Stripe -> 'Pay with card' default label"
    );
    assert!(
        body["balance_due_display"]
            .as_str()
            .is_some_and(|s| s.contains("100")),
        "MAPPS-666: balance_due_display carries the amount"
    );
}

#[sqlx::test]
async fn readiness_not_payable_when_draft(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (own_company, _c, _e, token) =
        seed_contact_with_roles(&app, &pool, "ready-draft", &["Billing Contact"]).await;
    let invoice_id = seed_draft_invoice(&pool, common::DEFAULT_TENANT_ID, own_company).await;
    seed_stripe_gateway(&pool, common::DEFAULT_TENANT_ID).await;

    let resp = app
        .client
        .get(app.url(&format!("/api/v1/invoices/{invoice_id}/payment-readiness")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("readiness");
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(
        body["invoice_payable"].as_bool(),
        Some(false),
        "MAPPS-666: draft invoice -> invoice_payable = false"
    );
    // Gateway can still be ready even when this invoice can't be paid.
    assert_eq!(
        body["gateway_ready"].as_bool(),
        Some(true),
        "MAPPS-666: draft-invoice does not affect gateway_ready"
    );
}

#[sqlx::test]
async fn readiness_not_ready_when_no_gateway(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (own_company, _c, _e, token) =
        seed_contact_with_roles(&app, &pool, "ready-nogw", &["Billing Contact"]).await;
    let invoice_id = seed_sent_invoice(&pool, common::DEFAULT_TENANT_ID, own_company).await;
    // Deliberately NO seed_stripe_gateway call.

    let resp = app
        .client
        .get(app.url(&format!("/api/v1/invoices/{invoice_id}/payment-readiness")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("readiness");
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(
        body["gateway_ready"].as_bool(),
        Some(false),
        "MAPPS-666: no active gateway -> gateway_ready = false"
    );
    assert!(
        body["button_label"].is_null(),
        "MAPPS-666: no gateway -> button_label is null, got {body}"
    );
}

#[sqlx::test]
async fn readiness_cross_company_404(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (_own_company, _c, _e, token) =
        seed_contact_with_roles(&app, &pool, "ready-foreign", &["Billing Contact"]).await;
    let other_company =
        seed_plain_company(&pool, common::DEFAULT_TENANT_ID, "ready-foreign-co").await;
    let invoice_id = seed_sent_invoice(&pool, common::DEFAULT_TENANT_ID, other_company).await;

    let resp = app
        .client
        .get(app.url(&format!("/api/v1/invoices/{invoice_id}/payment-readiness")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("readiness");
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "MAPPS-666: cross-Company invoice must 404, not leak the row's payability"
    );
}

/// MAPPS-671 (mokosh-invoices P2a): the admin-set button label wins
/// when set. Same seed as the ready-and-payable happy path plus one
/// UPDATE to set the override.
#[sqlx::test]
async fn readiness_button_label_uses_override_when_set(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (own_company, _c, _e, token) =
        seed_contact_with_roles(&app, &pool, "ready-override", &["Billing Contact"]).await;
    let invoice_id = seed_sent_invoice(&pool, common::DEFAULT_TENANT_ID, own_company).await;
    seed_stripe_gateway(&pool, common::DEFAULT_TENANT_ID).await;
    set_stripe_client_display_name(
        &pool,
        common::DEFAULT_TENANT_ID,
        "Pay with your credit card",
    )
    .await;

    let resp = app
        .client
        .get(app.url(&format!("/api/v1/invoices/{invoice_id}/payment-readiness")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("readiness");
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(
        body["button_label"].as_str(),
        Some("Pay with your credit card"),
        "MAPPS-671: the admin's override replaces the provider default"
    );
}

/// MAPPS-671: whitespace-only override does not ship a blank button.
#[sqlx::test]
async fn readiness_button_label_falls_back_when_override_is_blank(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (own_company, _c, _e, token) =
        seed_contact_with_roles(&app, &pool, "ready-blank", &["Billing Contact"]).await;
    let invoice_id = seed_sent_invoice(&pool, common::DEFAULT_TENANT_ID, own_company).await;
    seed_stripe_gateway(&pool, common::DEFAULT_TENANT_ID).await;
    set_stripe_client_display_name(&pool, common::DEFAULT_TENANT_ID, "   ").await;

    let resp = app
        .client
        .get(app.url(&format!("/api/v1/invoices/{invoice_id}/payment-readiness")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("readiness");
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(
        body["button_label"].as_str(),
        Some("Pay with card"),
        "MAPPS-671: whitespace-only override must fall through to the provider default"
    );
}

/// MAPPS-670 (mokosh-invoices P1e): the portal must never see a draft
/// invoice, and the exclusion runs server-side so the paginated `total`
/// agrees with the returned rows.
#[sqlx::test]
async fn list_invoices_contact_plane_hides_drafts(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (own_company, _c, _e, token) =
        seed_contact_with_roles(&app, &pool, "list-hides-draft", &["Billing Contact"]).await;
    let sent_id = seed_sent_invoice(&pool, common::DEFAULT_TENANT_ID, own_company).await;
    let _draft_id = seed_draft_invoice(&pool, common::DEFAULT_TENANT_ID, own_company).await;

    let resp = app
        .client
        .get(app.url("/api/v1/invoices"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list");
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("json");
    let rows = body["data"].as_array().expect("data array");
    assert_eq!(
        rows.len(),
        1,
        "MAPPS-670: contact list must contain only the sent invoice, got {body}"
    );
    assert_eq!(
        rows[0]["id"].as_str(),
        Some(sent_id.to_string().as_str()),
        "MAPPS-670: the surviving row is the sent invoice"
    );
    assert!(
        rows.iter().all(|r| r["status"].as_str() != Some("draft")),
        "MAPPS-670: no draft may leak into the contact list"
    );
    assert_eq!(
        body["meta"]["total"].as_u64(),
        Some(1),
        "MAPPS-670: `total` must count only the visible rows, not the hidden drafts"
    );
}

/// MAPPS-670: `exclude_draft` is not a client-tunable filter. A contact
/// posting `?exclude_draft=false` in the query string must NOT re-expose
/// drafts (the field is `serde(skip_deserializing)` and the route sets
/// it unconditionally for the contact plane).
#[sqlx::test]
async fn list_invoices_contact_plane_ignores_client_exclude_draft_override(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (own_company, _c, _e, token) =
        seed_contact_with_roles(&app, &pool, "list-no-override", &["Billing Contact"]).await;
    let _sent = seed_sent_invoice(&pool, common::DEFAULT_TENANT_ID, own_company).await;
    let _draft = seed_draft_invoice(&pool, common::DEFAULT_TENANT_ID, own_company).await;

    let resp = app
        .client
        .get(app.url("/api/v1/invoices?exclude_draft=false"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list");
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("json");
    let rows = body["data"].as_array().expect("data array");
    assert!(
        rows.iter().all(|r| r["status"].as_str() != Some("draft")),
        "MAPPS-670: exclude_draft override in the URL must NOT re-expose drafts to a contact"
    );
}

#[sqlx::test]
async fn readiness_no_invoices_read_cap_403(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    // Support Contact has tickets:* but not invoices:read.
    let (own_company, _c, _e, token) =
        seed_contact_with_roles(&app, &pool, "ready-nocap", &["Support Contact"]).await;
    let invoice_id = seed_sent_invoice(&pool, common::DEFAULT_TENANT_ID, own_company).await;

    let resp = app
        .client
        .get(app.url(&format!("/api/v1/invoices/{invoice_id}/payment-readiness")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("readiness");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "MAPPS-666: contact without invoices:read must 403"
    );
}
