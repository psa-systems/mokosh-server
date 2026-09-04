//! PMS-729 phase 2 §7 slice B / I8: authenticated portal form list +
//! detail + submit HTTP tests.
//!
//! Pins the portal-visible gate (internal-only forms never surface), the
//! submit path (creates a submission + a ticket, returns the ticket
//! number), and the cross-company isolation (a form is a per-tenant
//! resource but the ticket it opens is company-scoped from the
//! authenticated contact).

mod common;

use sqlx::PgPool;
use uuid::Uuid;

const PORTAL_PASSWORD: &str = "portal-password-12345";

async fn seed_company(pool: &PgPool, name: &str) -> Uuid {
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

async fn seed_portal_contact(pool: &PgPool, company_id: Uuid, email: &str) -> Uuid {
    let hash = mokosh_server::utils::crypto::hash_password(PORTAL_PASSWORD).expect("hash password");
    let id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO contacts (
            id, tenant_id, company_id, first_name, last_name, email,
            is_portal_user, portal_password_hash
        )
        VALUES ($1, $2, $3, 'Port', 'Al', $4, TRUE, $5)
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

async fn login(app: &common::TestApp, email: &str) -> String {
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
        .expect("login");
    assert!(resp.status().is_success());
    let body: serde_json::Value = resp.json().await.expect("login body");
    body["access_token"].as_str().unwrap().to_string()
}

/// Insert a form definition + one required text field. `portal_visible`
/// flips whether the form appears in the portal picker.
async fn seed_form(pool: &PgPool, admin_id: Uuid, name: &str, portal_visible: bool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO form_definitions
            (id, tenant_id, name, slug, description, is_active,
             portal_visible, created_by_id)
        VALUES ($1, $2, $3, $4, 'test form', TRUE, $5, $6)
        "#,
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(name)
    .bind(format!("slug-{}", &id.to_string()[..8]))
    .bind(portal_visible)
    .bind(admin_id)
    .execute(pool)
    .await
    .expect("seed form");
    sqlx::query(
        r#"
        INSERT INTO form_fields
            (id, tenant_id, form_definition_id, name, label, field_type,
             is_required, sort_order)
        VALUES ($1, $2, $3, 'subject', 'Subject', 'text', TRUE, 0)
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(common::DEFAULT_TENANT_ID)
    .bind(id)
    .execute(pool)
    .await
    .expect("seed field");
    id
}

// -- tests -----------------------------------------------------------------

/// Only forms with `portal_visible = TRUE` (and `is_active = TRUE`) show
/// up in the list. An internal-only form is invisible.
#[sqlx::test]
async fn portal_forms_list_only_returns_portal_visible_active_forms(pool: PgPool) {
    let (admin_id, _e, _p) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let company = seed_company(&pool, "Forms Co").await;
    let _c = seed_portal_contact(&pool, company, "forms@example.com").await;
    let public_id = seed_form(&pool, admin_id, "New starter", true).await;
    let _hidden = seed_form(&pool, admin_id, "Internal payroll", false).await;

    let token = login(&app, "forms@example.com").await;
    let resp = app
        .client
        .get(app.url("/api/v1/portal/forms"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list");
    assert!(resp.status().is_success());
    let body: serde_json::Value = resp.json().await.unwrap();
    let forms = body.as_array().unwrap();
    assert_eq!(forms.len(), 1, "expected 1 portal-visible form: {body}");
    assert_eq!(forms[0]["id"].as_str().unwrap(), public_id.to_string());
    assert_eq!(forms[0]["name"].as_str().unwrap(), "New starter");
}

/// Detail endpoint returns the public field-set for a portal-visible
/// form; requesting an internal-only form is a 404 (not 403), same
/// enumeration posture as every other portal detail-view.
#[sqlx::test]
async fn portal_forms_detail_hides_non_portal_forms(pool: PgPool) {
    let (admin_id, _e, _p) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let company = seed_company(&pool, "Detail Co").await;
    let _c = seed_portal_contact(&pool, company, "detail@example.com").await;
    let hidden = seed_form(&pool, admin_id, "Internal payroll", false).await;

    let token = login(&app, "detail@example.com").await;
    let resp = app
        .client
        .get(app.url(&format!("/api/v1/portal/forms/{hidden}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("detail");
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
}

/// Successful submission validates, creates a submission, opens a
/// ticket in the caller's company, and returns the ticket number.
#[sqlx::test]
async fn portal_forms_submit_opens_a_ticket_with_the_number(pool: PgPool) {
    let (admin_id, _e, _p) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let company = seed_company(&pool, "Submit Co").await;
    let contact = seed_portal_contact(&pool, company, "submit@example.com").await;
    let form_id = seed_form(&pool, admin_id, "New starter", true).await;

    let token = login(&app, "submit@example.com").await;
    let resp = app
        .client
        .post(app.url(&format!("/api/v1/portal/forms/{form_id}/submit")))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "payload": {"subject": "Onboard Alice next Monday"}
        }))
        .send()
        .await
        .expect("submit");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::CREATED,
        "{}",
        resp.status()
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    let ticket_number = body["ticket_number"].as_str().expect("ticket_number");
    assert!(!ticket_number.is_empty());

    // Assert the submission row was persisted against this contact and
    // linked to the ticket the endpoint returned.
    let (submitted_by, ticket_id): (Option<Uuid>, Option<Uuid>) = sqlx::query_as(
        r#"SELECT submitted_by_contact_id, ticket_id
           FROM form_submissions
           WHERE tenant_id = $1 AND form_definition_id = $2
           ORDER BY created_at DESC LIMIT 1"#,
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(form_id)
    .fetch_one(&pool)
    .await
    .expect("submission row");
    assert_eq!(submitted_by, Some(contact));
    assert!(ticket_id.is_some(), "submission never linked to a ticket");

    // Assert the ticket was scoped to the caller's company.
    let ticket_company_id: Uuid =
        sqlx::query_scalar("SELECT company_id FROM tickets WHERE tenant_id = $1 AND id = $2")
            .bind(common::DEFAULT_TENANT_ID)
            .bind(ticket_id.unwrap())
            .fetch_one(&pool)
            .await
            .expect("ticket");
    assert_eq!(ticket_company_id, company);
}

/// Missing required field surfaces as a validation failure with the
/// per-field error the shared validator emits.
#[sqlx::test]
async fn portal_forms_submit_rejects_missing_required_field(pool: PgPool) {
    let (admin_id, _e, _p) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let company = seed_company(&pool, "Reject Co").await;
    let _c = seed_portal_contact(&pool, company, "reject@example.com").await;
    let form_id = seed_form(&pool, admin_id, "New starter", true).await;

    let token = login(&app, "reject@example.com").await;
    let resp = app
        .client
        .post(app.url(&format!("/api/v1/portal/forms/{form_id}/submit")))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "payload": {}
        }))
        .send()
        .await
        .expect("submit");
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        status.is_client_error(),
        "expected client-error status: {status}, body: {body}"
    );
}

/// Missing bearer: 401.
#[sqlx::test]
async fn portal_forms_require_a_portal_session(pool: PgPool) {
    let _a = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let list = app
        .client
        .get(app.url("/api/v1/portal/forms"))
        .send()
        .await
        .expect("list");
    assert_eq!(list.status(), reqwest::StatusCode::UNAUTHORIZED);
}
