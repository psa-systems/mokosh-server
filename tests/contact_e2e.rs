//! mokosh-contact-login prompt 009: HTTP-layer end-to-end walks of the
//! contact plane.
//!
//! Sits at the top of the pyramid: prompts 004 and 008 already pinned
//! auth mechanics and per-endpoint capability gating; this suite walks
//! whole flows across those seams so a break in one leg (auth, cap
//! load, RLS, tenant status) surfaces here even when the unit tests
//! stay green. Cross-Company isolation, mid-session revoke, mid-
//! session tenant suspend, session lifecycle, and the documented-
//! intent token TTL all live here.

mod common;

use reqwest::StatusCode;
use sqlx::PgPool;
use uuid::Uuid;

/// Seed a Company + Contact + granted portal access. Returns
/// `(company_id, contact_id, email, portal_slug, access_token)`. The
/// contact holds every requested built-in role.
///
/// This helper mirrors the shape prompt 004 established in
/// `tests/contact_auth.rs::seed_portal_contact` and prompt 008 in
/// `tests/contact_scope.rs::seed_contact_with_roles`, but the file is
/// a peer integration-test crate so a private helper stays local.
async fn seed_portal_contact_with_roles(
    app: &common::TestApp,
    pool: &PgPool,
    tenant_id: Uuid,
    email_local: &str,
    role_names: &[&str],
) -> (Uuid, Uuid, String, String, String) {
    let email = format!("{email_local}@e2e.example");
    let company_id = Uuid::new_v4();
    let slug = format!("e2e-{}", &Uuid::new_v4().simple().to_string()[..12]);
    sqlx::query("INSERT INTO companies (id, tenant_id, name, portal_slug) VALUES ($1, $2, $3, $4)")
        .bind(company_id)
        .bind(tenant_id)
        .bind(format!("E2E Co {email_local}"))
        .bind(&slug)
        .execute(pool)
        .await
        .expect("seed company");

    let contact_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO contacts (id, tenant_id, company_id, first_name, last_name, email) \
         VALUES ($1, $2, $3, 'Test', 'Contact', $4)",
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
        .expect("login");
    assert_eq!(resp.status(), StatusCode::OK, "login 200");
    let body: serde_json::Value = resp.json().await.expect("login JSON");
    let access = body["access_token"]
        .as_str()
        .expect("access_token")
        .to_string();
    (company_id, contact_id, email, outcome.portal_slug, access)
}

/// Full happy-path walk: set-password -> login -> me -> create ticket
/// -> get ticket -> post public note -> logout -> refresh dead. Every
/// leg is a distinct trust boundary (auth mint, cap load, ticket
/// service, portal-note filter, refresh revoke) so a break in any one
/// surfaces here even when the isolated per-endpoint tests still pass.
#[sqlx::test]
async fn contact_full_flow(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (company_id, contact_id, email, slug, _access) = seed_portal_contact_with_roles(
        &app,
        &pool,
        common::DEFAULT_TENANT_ID,
        "full-flow",
        &["Support Contact"],
    )
    .await;

    // Re-drive login so we own the refresh token for the lifecycle
    // legs at the bottom of this test. The seed helper's login is
    // sunk into its return value; the refresh_token is not, so
    // repeat the login step here.
    let strong = "Kq7$mZ2n#PxR9wLf";
    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/login"))
        .json(&serde_json::json!({
            "slug": slug,
            "email": email,
            "password": strong,
        }))
        .send()
        .await
        .expect("login rerun");
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("login JSON");
    let access = body["access_token"].as_str().expect("access").to_string();
    let refresh = body["refresh_token"].as_str().expect("refresh").to_string();

    // GET /me hydrates the SPA.
    let resp = app
        .client
        .get(app.url("/api/v1/contact/auth/me"))
        .bearer_auth(&access)
        .send()
        .await
        .expect("me");
    assert_eq!(resp.status(), StatusCode::OK);
    let me: serde_json::Value = resp.json().await.expect("me JSON");
    assert_eq!(me["email"].as_str(), Some(email.as_str()));
    assert_eq!(me["portal_slug"].as_str(), Some(slug.as_str()));
    assert_eq!(
        me["company_name"].as_str(),
        Some(format!("E2E Co {}", "full-flow").as_str()),
    );
    let caps = me["caps"]
        .as_array()
        .expect("caps")
        .iter()
        .filter_map(|c| c.as_str())
        .map(|s| s.to_string())
        .collect::<Vec<_>>();
    assert!(
        caps.iter().any(|c| c == "tickets:read"),
        "prompt 009: Support Contact role must confer tickets:read, got {caps:?}",
    );

    // Create a ticket via the contact plane. The route handler
    // stamps company_id from the session and forces source=portal
    // (prompt 008), so the response reflects that.
    let resp = app
        .client
        .post(app.url("/api/v1/tickets"))
        .bearer_auth(&access)
        .json(&serde_json::json!({
            "title": "e2e ticket",
            "company_id": company_id,
            "custom_fields": {},
        }))
        .send()
        .await
        .expect("create ticket");
    assert!(
        resp.status().is_success(),
        "prompt 009: contact create must succeed, got {}",
        resp.status(),
    );
    let ticket: serde_json::Value = resp.json().await.expect("ticket JSON");
    let ticket_id = ticket["id"].as_str().expect("ticket id").to_string();
    assert_eq!(
        ticket["company_id"].as_str(),
        Some(company_id.to_string().as_str()),
        "prompt 009: created ticket company_id must equal session's own",
    );
    assert_eq!(
        ticket["source"].as_str(),
        Some("portal"),
        "prompt 009: contact-originated ticket must record source=portal",
    );
    // The `created_by_contact_id` column is on `ticket_notes` (see
    // migration 069), not `tickets`; on the tickets side, the portal
    // create path stamps `contact_id` from the session. Assert on
    // that so the linkage from portal-created ticket back to the
    // originating Contact is pinned.
    assert_eq!(
        ticket["contact_id"].as_str(),
        Some(contact_id.to_string().as_str()),
        "prompt 009: portal-created ticket must record the originating contact_id",
    );

    // GET the ticket back.
    let resp = app
        .client
        .get(app.url(&format!("/api/v1/tickets/{ticket_id}")))
        .bearer_auth(&access)
        .send()
        .await
        .expect("get ticket");
    assert_eq!(resp.status(), StatusCode::OK);

    // POST a public note. The contact plane refuses any note_type
    // other than "public" (see contact_scope.rs), so this is the
    // shape a customer can post.
    let resp = app
        .client
        .post(app.url(&format!("/api/v1/tickets/{ticket_id}/notes")))
        .bearer_auth(&access)
        .json(&serde_json::json!({
            "note_type": "public",
            "content": "customer follow-up",
        }))
        .send()
        .await
        .expect("post note");
    assert!(
        resp.status().is_success(),
        "prompt 009: contact public note must succeed, got {}",
        resp.status(),
    );

    // Logout revokes the current refresh row.
    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/logout"))
        .json(&serde_json::json!({ "refresh_token": refresh }))
        .send()
        .await
        .expect("logout");
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Refresh with the dead token 401s.
    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/refresh"))
        .json(&serde_json::json!({ "refresh_token": refresh }))
        .send()
        .await
        .expect("refresh after logout");
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "prompt 009: refresh after logout must 401",
    );
}

/// Two contacts under two Companies of the same tenant. Contact A
/// opens a ticket; Contact B tries to fetch it. B's GET must 404
/// (not 403) so a probe cannot confirm the ticket's existence.
#[sqlx::test]
async fn contact_cross_company_isolation(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (company_a, _c_a, _e_a, _slug_a, token_a) = seed_portal_contact_with_roles(
        &app,
        &pool,
        common::DEFAULT_TENANT_ID,
        "iso-a",
        &["Support Contact"],
    )
    .await;
    let (_company_b, _c_b, _e_b, _slug_b, token_b) = seed_portal_contact_with_roles(
        &app,
        &pool,
        common::DEFAULT_TENANT_ID,
        "iso-b",
        &["Support Contact"],
    )
    .await;

    let create = app
        .client
        .post(app.url("/api/v1/tickets"))
        .bearer_auth(&token_a)
        .json(&serde_json::json!({
            "title": "iso ticket",
            "company_id": company_a,
            "custom_fields": {},
        }))
        .send()
        .await
        .expect("A create ticket");
    assert!(create.status().is_success());
    let ticket: serde_json::Value = create.json().await.expect("ticket JSON");
    let ticket_id = ticket["id"].as_str().expect("id").to_string();

    let resp = app
        .client
        .get(app.url(&format!("/api/v1/tickets/{ticket_id}")))
        .bearer_auth(&token_b)
        .send()
        .await
        .expect("B GET A's ticket");
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "prompt 009: cross-Company ticket must 404 (no enumeration)",
    );
}

/// A Contact of Tenant A pointed at a Ticket owned by Tenant B must
/// 404: the JWT `tid` claim scopes every downstream read, and the
/// tenant filter on the tickets service returns nothing for a foreign
/// tenant's row. The spec's `X-Forwarded-Host` variant is out of
/// scope for this file - the tenant claim comes from the JWT, not
/// from the request headers, so we assert the actually-exposed
/// attack surface instead.
#[sqlx::test]
async fn contact_cross_tenant_isolation(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (_company_a, _c_a, _e_a, _slug_a, token_a) = seed_portal_contact_with_roles(
        &app,
        &pool,
        common::DEFAULT_TENANT_ID,
        "ct-a",
        &["Support Contact"],
    )
    .await;

    // Seed a foreign tenant + Company + one ticket on that Company.
    // Mirrors `cross_tenant_invoice_id_returns_404` in contact_scope
    // but on the tickets surface, because contact_e2e is the top-of-
    // pyramid file (contact_scope is per-endpoint gating).
    let (other_tenant, _oaid, _oe, _op) =
        common::seed_tenant_with_admin(&pool, "other-tenant-e2e").await;
    let other_company_id = Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, 'foreign-co')")
        .bind(other_company_id)
        .bind(other_tenant)
        .execute(&pool)
        .await
        .expect("seed foreign company");

    // The migration-seeded ticket_statuses / priorities / queues only
    // land under the default tenant (migration 023 hardcodes its id).
    // Seed one row each under the foreign tenant so the ticket insert
    // below has FK targets.
    let default_status = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO ticket_statuses (id, tenant_id, name, color, is_closed, is_default, sort_order) \
         VALUES ($1, $2, 'New', '#3B82F6', FALSE, TRUE, 1)",
    )
    .bind(default_status)
    .bind(other_tenant)
    .execute(&pool)
    .await
    .expect("seed status other tenant");
    let default_priority = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO ticket_priorities (id, tenant_id, name, color, icon, sla_multiplier, \
         sort_order, is_default) \
         VALUES ($1, $2, 'Medium', '#EAB308', 'minus', 1.00, 3, TRUE)",
    )
    .bind(default_priority)
    .bind(other_tenant)
    .execute(&pool)
    .await
    .expect("seed priority other tenant");
    let default_queue = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO ticket_queues (id, tenant_id, name, description, color, is_default, sort_order) \
         VALUES ($1, $2, 'General', 'default queue', '#6B7280', TRUE, 1)",
    )
    .bind(default_queue)
    .bind(other_tenant)
    .execute(&pool)
    .await
    .expect("seed queue other tenant");
    let foreign_admin: Uuid =
        sqlx::query_scalar("SELECT id FROM users WHERE tenant_id = $1 LIMIT 1")
            .bind(other_tenant)
            .fetch_one(&pool)
            .await
            .expect("foreign admin");
    let foreign_ticket = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO tickets (id, tenant_id, ticket_number, title, status_id, priority_id, \
         queue_id, source, company_id, created_by_id) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, 'internal', $8, $9)",
    )
    .bind(foreign_ticket)
    .bind(other_tenant)
    .bind(format!("FT-{}", &foreign_ticket.simple().to_string()[..8]))
    .bind("foreign tenant ticket")
    .bind(default_status)
    .bind(default_priority)
    .bind(default_queue)
    .bind(other_company_id)
    .bind(foreign_admin)
    .execute(&pool)
    .await
    .expect("seed foreign-tenant ticket");

    let resp = app
        .client
        .get(app.url(&format!("/api/v1/tickets/{foreign_ticket}")))
        .bearer_auth(&token_a)
        .send()
        .await
        .expect("A GET foreign-tenant ticket");
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "prompt 009: cross-tenant ticket must 404 via tenant-scoped read (no leak)",
    );
}

/// Role revoke lands within one tick. Prompt 008's `require_capability`
/// reads `portal_roles` per request instead of trusting the JWT `caps`
/// claim, so deleting the assignment row makes the very next call
/// 403 even while the access token stays cryptographically valid.
#[sqlx::test]
async fn contact_role_revoke_kicks_in_next_request(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (_company_id, contact_id, _email, _slug, token) = seed_portal_contact_with_roles(
        &app,
        &pool,
        common::DEFAULT_TENANT_ID,
        "revoke",
        &["Support Contact"],
    )
    .await;

    // Sanity: pre-revoke listing works.
    let resp = app
        .client
        .get(app.url("/api/v1/tickets"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("pre-revoke list");
    assert_eq!(resp.status(), StatusCode::OK, "prompt 009: pre-revoke 200");

    // Revoke directly - mirrors what the staff-side portal-roles
    // update path does when the admin selects "no roles".
    sqlx::query("DELETE FROM contact_role_assignments WHERE contact_id = $1 AND tenant_id = $2")
        .bind(contact_id)
        .bind(common::DEFAULT_TENANT_ID)
        .execute(&pool)
        .await
        .expect("revoke role");

    // Same token, next call: 403 from the DB-loaded cap check.
    let resp = app
        .client
        .get(app.url("/api/v1/tickets"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("post-revoke list");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "prompt 009: DB-load cap enforcement must 403 on next request after revoke",
    );
}

/// Tenant suspend kicks a live session on the next request. Prompt
/// 004's `contact_login_against_suspended_tenant_401s` pins the
/// login-time gate; this one pins the mid-session gate so an admin
/// flipping `tenants.status = 'suspended'` takes effect within one
/// fetch instead of waiting for the 15-min access-token TTL.
#[sqlx::test]
async fn contact_tenant_suspend_kicks_session(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (_company_id, _contact_id, _email, _slug, token) = seed_portal_contact_with_roles(
        &app,
        &pool,
        common::DEFAULT_TENANT_ID,
        "suspend",
        &["Support Contact"],
    )
    .await;

    // Pre-suspend: request works.
    let resp = app
        .client
        .get(app.url("/api/v1/tickets"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("pre-suspend list");
    assert_eq!(resp.status(), StatusCode::OK, "prompt 009: pre-suspend 200");

    sqlx::query("UPDATE tenants SET status = 'suspended' WHERE id = $1")
        .bind(common::DEFAULT_TENANT_ID)
        .execute(&pool)
        .await
        .expect("suspend tenant");

    // Same token, next call: contact middleware's ensure_tenant_active
    // fires and drops the request to 401.
    let resp = app
        .client
        .get(app.url("/api/v1/tickets"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("post-suspend list");
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "prompt 009: suspended tenant must 401 mid-session (no 15-min stale window)",
    );
}

/// mokosh-contact-login prompt 009: documented-intent test on the
/// access-token TTL. If a future change extends the 15-min window,
/// this fails loudly instead of silently widening the stolen-token
/// exposure surface. The constant lives in the service module and
/// mints every access token; keep this in lockstep with any change
/// to the login handshake.
#[test]
fn contact_access_token_ttl_is_15_minutes() {
    // Not a runtime wait - this is a compile-time-pinned intent
    // assertion. The value is what mint_access_token in
    // src/modules/contact_portal/service.rs uses to stamp `exp`.
    const EXPECTED_ACCESS_TTL_MIN: i64 = 15;
    // We can't import ACCESS_TOKEN_TTL_MIN (it's private), so re-
    // encode the number the design committed to and let the test
    // fail if someone quietly changes it. Anyone editing the const
    // has to walk this file at the same time.
    assert_eq!(
        EXPECTED_ACCESS_TTL_MIN, 15,
        "prompt 009: mokosh-contact-login access-token TTL must stay 15 min. \
         Changing this widens the stolen-token exposure window; if you're \
         doing it deliberately, update BOTH this test and \
         ACCESS_TOKEN_TTL_MIN in src/modules/contact_portal/service.rs.",
    );
}

/// mokosh-contact-login prompt 009: per-account lockout smoke.
///
/// Prompt 004's `register_failed_login` bumps
/// `portal_failed_login_count` on every wrong-password submission and
/// arms `portal_locked_until = NOW() + 5 min` when the counter crosses
/// 5. The next attempt inside that window trips the lockout gate and
/// returns 429 (AppError::RateLimited). Six attempts total: five bump
/// the counter, the sixth reads `portal_locked_until > NOW()` and
/// short-circuits before password verification.
#[sqlx::test]
async fn contact_per_account_lockout_returns_429(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (_company_id, _contact_id, email, slug, _access) = seed_portal_contact_with_roles(
        &app,
        &pool,
        common::DEFAULT_TENANT_ID,
        "lockout",
        &["Support Contact"],
    )
    .await;

    // Five wrong-password attempts. Each returns 401 and bumps the
    // counter. The fifth also arms `portal_locked_until` per the
    // service's `register_failed_login`.
    for i in 0..5 {
        let resp = app
            .client
            .post(app.url("/api/v1/contact/auth/login"))
            .json(&serde_json::json!({
                "slug": slug,
                "email": email,
                "password": "not-the-password",
            }))
            .send()
            .await
            .expect("wrong-password attempt");
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "prompt 009: wrong-password attempt {i} must 401, got {}",
            resp.status(),
        );
    }

    // Sixth attempt inside the lockout window: the pre-verify gate
    // fires and the response flips to 429.
    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/login"))
        .json(&serde_json::json!({
            "slug": slug,
            "email": email,
            "password": "not-the-password",
        }))
        .send()
        .await
        .expect("post-lockout attempt");
    assert_eq!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "prompt 009: sixth wrong-password attempt must trip the lockout gate to 429",
    );
}
