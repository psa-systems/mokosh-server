//! MAPPS-617/618 integration tests for the branding surface.
//!
//! Covers:
//! - Staff PUT /contacts/companies/{id} with a `branding` block
//!   persists and round-trips on the read side (regression: pre-fix
//!   `CompanyResponse` dropped `branding` so the SPA editor looked
//!   like nothing had saved).
//! - Contact PATCH /contact/companies/self/branding refuses a caller
//!   without `settings:manage_company_branding` (403) and accepts a
//!   caller who holds it.
//! - Contact GET /contact/companies/self/branding returns the raw
//!   tenant + Company blocks + the resolved effective set.
//! - GET /contact/portal/{portal_id}/host merges tenant + Company
//!   branding field-by-field (Company wins where set).
//!
//! Multipart upload endpoints (PUT /companies/{id}/logo etc.) are
//! covered by the module's own unit tests
//! (`modules::branding::assets`); asserting them here would need a
//! multipart-request builder and adds little coverage the unit tests
//! don't already give.

mod common;

use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

/// Seed a Company + Contact + granted portal access. Returns
/// `(company_id, contact_id, portal_slug, portal_id, set_password_token)`.
/// The default seeded role is "Support Contact" — tests that need a
/// specific cap grant swap it after this call.
async fn seed_company_and_contact(pool: &PgPool, email: &str) -> (Uuid, Uuid, String, i64, String) {
    let company_id = Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, 'Branding Test Co')")
        .bind(company_id)
        .bind(common::DEFAULT_TENANT_ID)
        .execute(pool)
        .await
        .expect("seed company");
    let contact_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO contacts (id, tenant_id, company_id, first_name, last_name, email) \
         VALUES ($1, $2, $3, 'Brand', 'Tester', $4)",
    )
    .bind(contact_id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company_id)
    .bind(email)
    .execute(pool)
    .await
    .expect("seed contact");
    let db = mokosh_server::Database::from_pool(pool.clone());
    let contact_svc = mokosh_server::modules::contacts::ContactService::new(db);
    let roles: Vec<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM portal_roles WHERE tenant_id = $1 AND name = 'Support Contact'",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_all(pool)
    .await
    .expect("read Support role");
    let role_ids: Vec<Uuid> = roles.into_iter().map(|(id,)| id).collect();
    let outcome = contact_svc
        .grant_portal_access(
            mokosh_server::modules::auth::TenantId::from_trusted(common::DEFAULT_TENANT_ID),
            contact_id,
            &role_ids,
            &mokosh_server::modules::audit::AuditCtx::system(common::DEFAULT_TENANT_ID),
        )
        .await
        .expect("grant_portal_access");
    // Portal id lands on the row via prompt 011; SELECT it back for
    // the /host test.
    let portal_id: i64 = sqlx::query_scalar("SELECT portal_id FROM companies WHERE id = $1")
        .bind(company_id)
        .fetch_one(pool)
        .await
        .expect("read portal_id");
    let prefix = format!("/portal/{}/set-password?token=", outcome.portal_slug);
    let token = outcome
        .setup_link
        .split(&prefix)
        .nth(1)
        .expect("token in setup_link")
        .to_string();
    (
        contact_id,
        company_id,
        outcome.portal_slug,
        portal_id,
        token,
    )
}

/// Redeem the setup link + POST /contact/auth/login. Returns the
/// contact-plane Bearer.
async fn sign_in_contact(
    app: &common::TestApp,
    slug: &str,
    email: &str,
    setup_token: &str,
) -> String {
    let strong = "Kq7$mZ2n#PxR9wLf";
    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/set-password"))
        .json(&json!({ "token": setup_token, "password": strong }))
        .send()
        .await
        .expect("set-password");
    assert_eq!(resp.status(), reqwest::StatusCode::NO_CONTENT);
    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/login"))
        .json(&json!({ "slug": slug, "email": email, "password": strong }))
        .send()
        .await
        .expect("login");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("login JSON");
    body["access_token"]
        .as_str()
        .expect("access_token")
        .to_string()
}

/// Add a portal role that carries `settings:manage_company_branding`
/// and grant it to `contact_id`. The migration seed catalog does not
/// hold this cap on any builtin, so branding tests create their own.
async fn grant_branding_cap(pool: &PgPool, contact_id: Uuid) {
    let role_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO portal_roles (id, tenant_id, name, capabilities, is_builtin) \
         VALUES ($1, $2, 'Brand Manager (test)', $3, FALSE)",
    )
    .bind(role_id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(vec!["settings:manage_company_branding".to_string()])
    .execute(pool)
    .await
    .expect("seed brand role");
    sqlx::query(
        "INSERT INTO contact_role_assignments (tenant_id, contact_id, role_id) \
         VALUES ($1, $2, $3)",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(contact_id)
    .bind(role_id)
    .execute(pool)
    .await
    .expect("assign brand role");
}

/// MAPPS-617 read-side fix: PUT /companies/{id} with a branding
/// block persists AND surfaces on the subsequent GET response. The
/// pre-fix bug: `CompanyResponse` dropped the field on the wire, so
/// the SPA editor looked like nothing had saved.
#[sqlx::test]
async fn staff_put_company_branding_round_trips(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let staff_token = common::login(&app, &email, &password).await;
    let company_id = Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, 'Round-Trip Co')")
        .bind(company_id)
        .bind(common::DEFAULT_TENANT_ID)
        .execute(&pool)
        .await
        .unwrap();
    let patch = json!({
        "branding": {
            "display_name": "Widgets Inc Portal",
            "primary_color": "#deadbe",
            "support_email": "help@widgets.example",
        }
    });
    let put = app
        .client
        .put(app.url(&format!("/api/v1/contacts/companies/{company_id}")))
        .bearer_auth(&staff_token)
        .json(&patch)
        .send()
        .await
        .expect("PUT company");
    assert!(put.status().is_success(), "PUT status {}", put.status());
    let get = app
        .client
        .get(app.url(&format!("/api/v1/contacts/companies/{company_id}")))
        .bearer_auth(&staff_token)
        .send()
        .await
        .expect("GET company");
    assert_eq!(get.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = get.json().await.expect("GET JSON");
    let b = &body["branding"];
    assert_eq!(
        b["display_name"].as_str(),
        Some("Widgets Inc Portal"),
        "branding.display_name must round-trip on the wire (pre-fix regression)"
    );
    assert_eq!(b["primary_color"].as_str(), Some("#deadbe"));
    assert_eq!(b["support_email"].as_str(), Some("help@widgets.example"));
}

/// MAPPS-618: PATCH /contact/companies/self/branding without the
/// `settings:manage_company_branding` cap must 403.
#[sqlx::test]
async fn contact_patch_branding_without_cap_is_forbidden(pool: PgPool) {
    let (_contact_id, _company_id, slug, _portal_id, token) =
        seed_company_and_contact(&pool, "nocap@brand.example").await;
    let app = common::boot(pool.clone()).await;
    let bearer = sign_in_contact(&app, &slug, "nocap@brand.example", &token).await;
    let resp = app
        .client
        .patch(app.url("/api/v1/contact/companies/self/branding"))
        .bearer_auth(&bearer)
        .json(&json!({ "display_name": "Sneaky" }))
        .send()
        .await
        .expect("PATCH");
    assert_eq!(resp.status(), reqwest::StatusCode::FORBIDDEN);
}

/// MAPPS-618: with the cap, PATCH lands + GET returns the updated
/// Company block + the tenant/Company/effective triple.
#[sqlx::test]
async fn contact_with_cap_patches_own_company_branding(pool: PgPool) {
    let (contact_id, _company_id, slug, _portal_id, token) =
        seed_company_and_contact(&pool, "hascap@brand.example").await;
    grant_branding_cap(&pool, contact_id).await;
    let app = common::boot(pool.clone()).await;
    let bearer = sign_in_contact(&app, &slug, "hascap@brand.example", &token).await;

    let patch = json!({
        "display_name": "Widget Client Portal",
        "primary_color": "#c0ffee",
        "support_email": "it@widgets.example",
    });
    let resp = app
        .client
        .patch(app.url("/api/v1/contact/companies/self/branding"))
        .bearer_auth(&bearer)
        .json(&patch)
        .send()
        .await
        .expect("PATCH");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    let resp = app
        .client
        .get(app.url("/api/v1/contact/companies/self/branding"))
        .bearer_auth(&bearer)
        .send()
        .await
        .expect("GET");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("GET JSON");
    // Response shape: { tenant, company, effective }.
    assert_eq!(
        body["company"]["display_name"].as_str(),
        Some("Widget Client Portal")
    );
    assert_eq!(body["company"]["primary_color"].as_str(), Some("#c0ffee"));
    // The tenant block should still be an object (empty is fine on
    // the default seeded tenant); the effective block reflects the
    // Company override for the fields we set.
    assert!(body["tenant"].is_object());
    assert_eq!(
        body["effective"]["display_name"].as_str(),
        Some("Widget Client Portal")
    );
    assert_eq!(body["effective"]["primary_color"].as_str(), Some("#c0ffee"));
}

/// MAPPS-617: GET /contact/portal/{portal_id}/host returns
/// `effective_branding` merged from tenant + Company (Company wins
/// per-field where set). Pre-auth endpoint, no session needed.
#[sqlx::test]
async fn portal_host_returns_merged_effective_branding(pool: PgPool) {
    let (_contact_id, company_id, _slug, portal_id, _token) =
        seed_company_and_contact(&pool, "merge@brand.example").await;
    // Tenant carries a primary color + support email; Company
    // overrides just the primary color. The merged effective block
    // should show Company's primary + tenant's email.
    sqlx::query(
        "UPDATE tenants \
         SET branding = branding || '{\"primary_color\": \"#111111\", \
                                        \"support_email\": \"help@tenant.example\"}'::jsonb \
         WHERE id = $1",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE companies \
         SET branding = branding || '{\"primary_color\": \"#222222\"}'::jsonb \
         WHERE id = $1",
    )
    .bind(company_id)
    .execute(&pool)
    .await
    .unwrap();
    let app = common::boot(pool.clone()).await;
    let resp = app
        .client
        .get(app.url(&format!("/api/v1/contact/portal/{portal_id}/host")))
        .send()
        .await
        .expect("GET /host");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("host JSON");
    let eff = &body["effective_branding"];
    assert_eq!(
        eff["primary_color"].as_str(),
        Some("#222222"),
        "Company override must win over the tenant default per field"
    );
    assert_eq!(
        eff["support_email"].as_str(),
        Some("help@tenant.example"),
        "unset Company field must fall through to the tenant default"
    );
}
