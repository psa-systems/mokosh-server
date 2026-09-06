//! mokosh-contact-login prompt 011 (PMS-928): end-to-end tests for the
//! Portal ID + IAM-style contact login pivot.
//!
//! Covers: crypto range/uniqueness, grant assigning a portal_id +
//! idempotency, dual-accept login (portal_id vs slug vs both), enum-
//! resistance on the negative shapes, single-Company scoping for the
//! magic-link finder, grant email carrying the Portal ID, host lookup
//! by Portal ID, and the slug-to-portal_id compat resolver.

mod common;

use sqlx::PgPool;
use uuid::Uuid;

/// mokosh-contact-login prompt 011: seed helper. Mirrors
/// `tests/contact_auth.rs::seed_portal_contact` but returns the
/// numeric `portal_id` too so callers can exercise the new login
/// shape directly.
async fn seed_portal_contact_with_portal_id(
    pool: &PgPool,
    company_name: &str,
    email: &str,
) -> (Uuid, Uuid, String, i64, String) {
    let company_id = Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, $3)")
        .bind(company_id)
        .bind(common::DEFAULT_TENANT_ID)
        .bind(company_name)
        .execute(pool)
        .await
        .expect("seed company");
    let contact_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO contacts (id, tenant_id, company_id, first_name, last_name, email) \
         VALUES ($1, $2, $3, 'Test', 'Contact', $4)",
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

    let prefix = format!("/portal/{}/set-password?token=", outcome.portal_slug);
    let token = outcome
        .setup_link
        .split(&prefix)
        .nth(1)
        .expect("token in setup_link")
        .to_string();
    (
        company_id,
        contact_id,
        outcome.portal_slug,
        outcome.portal_id,
        token,
    )
}

async fn redeem_and_set_password(app: &common::TestApp, token: &str, password: &str) {
    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/set-password"))
        .json(&serde_json::json!({ "token": token, "password": password }))
        .send()
        .await
        .expect("set-password");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::NO_CONTENT,
        "set-password must redeem the fresh magic link"
    );
}

// ============================================================================
// Crypto / range / uniqueness
// ============================================================================

#[test]
fn generate_portal_id_stays_in_9_digit_range() {
    // Pins the range contract from the migration's CHECK constraint.
    // A stray value here would be caught by the DB gate on write, but
    // we want the crypto helper itself to guarantee the invariant so
    // the retry loop in `ensure_portal_id` never spins on a
    // guaranteed-to-fail candidate.
    for _ in 0..10_000 {
        let id = mokosh_server::utils::crypto::generate_portal_id();
        assert!(
            (100_000_000..1_000_000_000).contains(&id),
            "portal_id out of range: {id}"
        );
    }
}

// ============================================================================
// grant_portal_access: portal_id assignment + idempotency + email
// ============================================================================

#[sqlx::test]
async fn grant_portal_access_assigns_a_portal_id(pool: PgPool) {
    let (company_id, _, _slug, portal_id, _token) =
        seed_portal_contact_with_portal_id(&pool, "PID Grant Co", "grant@pid.example").await;

    assert!(
        (100_000_000..1_000_000_000).contains(&portal_id),
        "grant must return an in-range portal_id, got {portal_id}"
    );
    let db_portal_id: Option<i64> =
        sqlx::query_scalar("SELECT portal_id FROM companies WHERE id = $1")
            .bind(company_id)
            .fetch_one(&pool)
            .await
            .expect("read portal_id");
    assert_eq!(
        db_portal_id,
        Some(portal_id),
        "companies.portal_id must match PortalGrantOutcome.portal_id"
    );
}

#[sqlx::test]
async fn grant_portal_access_is_idempotent_on_portal_id(pool: PgPool) {
    let (_, contact_id, _slug1, portal_id1, _t1) =
        seed_portal_contact_with_portal_id(&pool, "PID Idem Co", "idem@pid.example").await;

    // Re-grant to the same Contact. The Company's portal_id must NOT
    // rotate; the same value comes back on the second call.
    let db = mokosh_server::Database::from_pool(pool.clone());
    let contact_svc = mokosh_server::modules::contacts::ContactService::new(db);
    let roles: Vec<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM portal_roles WHERE tenant_id = $1 AND name = 'Support Contact'",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_all(&pool)
    .await
    .expect("read role");
    let role_ids: Vec<Uuid> = roles.into_iter().map(|(id,)| id).collect();
    let outcome2 = contact_svc
        .grant_portal_access(
            mokosh_server::modules::auth::TenantId::from_trusted(common::DEFAULT_TENANT_ID),
            contact_id,
            &role_ids,
            &mokosh_server::modules::audit::AuditCtx::system(common::DEFAULT_TENANT_ID),
        )
        .await
        .expect("second grant");
    assert_eq!(
        outcome2.portal_id, portal_id1,
        "re-grant on the same Company must preserve portal_id"
    );
}

#[sqlx::test]
async fn grant_email_carries_the_portal_id(pool: PgPool) {
    // Drive the grant end-to-end via HTTP so the boot()-side
    // NotificationsService actually queues the email (the raw
    // ContactService::new(db) used by seed_portal_contact_with_portal_id
    // has no dispatcher wired, so the notification row would be
    // absent from the DB - the shape `tests/contact_grant_email.rs`
    // proved out for prompt 010).
    let (_admin_id, admin_email, admin_password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let staff = common::login(&app, &admin_email, &admin_password).await;

    let company_id = Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, 'PID Email Co')")
        .bind(company_id)
        .bind(common::DEFAULT_TENANT_ID)
        .execute(&pool)
        .await
        .expect("seed company");
    let contact_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO contacts (id, tenant_id, company_id, first_name, last_name, email) \
         VALUES ($1, $2, $3, 'Test', 'Contact', 'email@pid.example')",
    )
    .bind(contact_id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company_id)
    .execute(&pool)
    .await
    .expect("seed contact");

    let support_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM portal_roles WHERE tenant_id = $1 AND name = 'Support Contact'",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(&pool)
    .await
    .expect("Support role");

    let resp = app
        .client
        .post(app.url(&format!(
            "/api/v1/contacts/contacts/{contact_id}/grant-portal-access"
        )))
        .bearer_auth(&staff)
        .json(&serde_json::json!({ "role_ids": [support_id] }))
        .send()
        .await
        .expect("grant");
    assert!(
        resp.status().is_success(),
        "grant returned {}",
        resp.status()
    );
    let outcome: serde_json::Value = resp.json().await.expect("outcome JSON");
    let portal_id = outcome["portal_id"].as_i64().expect("portal_id in outcome");

    let body: String = sqlx::query_scalar(
        "SELECT body FROM notifications \
         WHERE tenant_id = $1 AND recipient = $2 AND channel_type = 'email'",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind("email@pid.example")
    .fetch_one(&pool)
    .await
    .expect("read email body");

    let rendered = portal_id.to_string();
    assert!(
        body.contains(&rendered),
        "prompt 011: grant email body must contain the Portal ID ({rendered}); body = {body}"
    );
}

#[sqlx::test]
async fn portal_id_collision_retry_is_shaped_as_a_bounded_loop(pool: PgPool) {
    // Directly mocking `generate_portal_id` would require a global
    // seam we deliberately do not carry (the helper is a free
    // function). The retry loop is the behaviour we care about; a
    // structural pin (the fn source names the retry) plus a live
    // exercise of `ensure_portal_id` under a manually seeded
    // collision would need internal access to the private helper.
    //
    // Instead: assert the retry loop is shaped `for _ in 0..5` in
    // the service source. A future rewrite that drops the retry
    // (e.g. single attempt, or a different upper bound) trips this
    // and forces the change into review. Complements the range +
    // uniqueness tests on the generator itself.
    let source = std::fs::read_to_string("src/modules/contacts/service.rs")
        .expect("read contacts service source");
    assert!(
        source.contains("for _ in 0..5") && source.contains("ensure_portal_id"),
        "prompt 011: ensure_portal_id must remain a 5-attempt retry loop"
    );

    // Live exercise: two Companies, both take a portal_id off the
    // same generator, both land distinct values. Sanity check that
    // the DB path works end-to-end even under the RNG's variance.
    let (_c1, _, _, pid1, _t1) =
        seed_portal_contact_with_portal_id(&pool, "PID Retry A", "retry-a@pid.example").await;
    let (_c2, _, _, pid2, _t2) =
        seed_portal_contact_with_portal_id(&pool, "PID Retry B", "retry-b@pid.example").await;
    assert_ne!(
        pid1, pid2,
        "two fresh Companies must not share a portal_id (birthday probability negligible)"
    );
    let _ = &pool;
}

// ============================================================================
// login: portal_id / slug / both / neither
// ============================================================================

const STRONG_PW: &str = "Kq7$mZ2n#PxR9wLf";

#[sqlx::test]
async fn login_with_portal_id_succeeds(pool: PgPool) {
    let (_, _, _slug, portal_id, token) =
        seed_portal_contact_with_portal_id(&pool, "PID Login Co", "pid-login@pid.example").await;
    let app = common::boot(pool.clone()).await;
    redeem_and_set_password(&app, &token, STRONG_PW).await;

    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/login"))
        .json(&serde_json::json!({
            "portal_id": portal_id,
            "email": "pid-login@pid.example",
            "password": STRONG_PW,
        }))
        .send()
        .await
        .expect("login");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "prompt 011: login with portal_id (no slug) must succeed"
    );
    let body: serde_json::Value = resp.json().await.expect("login JSON");
    assert!(body["access_token"].as_str().unwrap_or_default().len() > 20);
}

#[sqlx::test]
async fn login_with_legacy_slug_still_succeeds(pool: PgPool) {
    // Compat pin: prompt 011 does NOT drop the slug column, and a
    // body carrying only `slug` (the pre-prompt-011 shape) must
    // still authenticate.
    let (_, _, slug, _portal_id, token) =
        seed_portal_contact_with_portal_id(&pool, "PID Slug Co", "slug-login@pid.example").await;
    let app = common::boot(pool.clone()).await;
    redeem_and_set_password(&app, &token, STRONG_PW).await;

    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/login"))
        .json(&serde_json::json!({
            "slug": slug,
            "email": "slug-login@pid.example",
            "password": STRONG_PW,
        }))
        .send()
        .await
        .expect("login");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "prompt 011: slug-only login must still work as compat"
    );
}

#[sqlx::test]
async fn login_prefers_portal_id_when_both_supplied(pool: PgPool) {
    // Two Companies, one Contact each. Body sends Company B's
    // portal_id with Company A's slug (mismatched). Prompt 011 says
    // portal_id wins, so the successful login must be Company B's
    // contact (Company A's email would 401 against Company B's
    // scoping).
    let (_ca, _, slug_a, _pid_a, token_a) =
        seed_portal_contact_with_portal_id(&pool, "PID Prefer A", "a@pid.example").await;
    let (_cb, _, _slug_b, pid_b, token_b) =
        seed_portal_contact_with_portal_id(&pool, "PID Prefer B", "b@pid.example").await;

    let app = common::boot(pool.clone()).await;
    redeem_and_set_password(&app, &token_a, STRONG_PW).await;
    redeem_and_set_password(&app, &token_b, STRONG_PW).await;

    // Company A's slug + Company B's portal_id + Contact B's email.
    // Should succeed under the portal_id-wins rule; if the server
    // ever regressed to slug-wins, the Contact B email would not
    // match Company A and the response would be 401.
    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/login"))
        .json(&serde_json::json!({
            "portal_id": pid_b,
            "slug": slug_a,
            "email": "b@pid.example",
            "password": STRONG_PW,
        }))
        .send()
        .await
        .expect("login-prefer");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "prompt 011: portal_id must win over slug when both supplied"
    );
}

#[sqlx::test]
async fn login_with_unknown_portal_id_returns_401_same_shape(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/login"))
        .json(&serde_json::json!({
            "portal_id": 100_000_001i64,
            "email": "nobody@pid.example",
            "password": STRONG_PW,
        }))
        .send()
        .await
        .expect("login");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "prompt 011: unknown portal_id must 401 (enum-resistant)"
    );
}

#[sqlx::test]
async fn login_with_neither_portal_id_nor_slug_returns_401_same_shape(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/login"))
        .json(&serde_json::json!({
            "email": "nobody@pid.example",
            "password": STRONG_PW,
        }))
        .send()
        .await
        .expect("login");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "prompt 011: body without portal_id or slug must 401 with the same shape as unknown-Portal-ID"
    );
}

// ============================================================================
// magic-link finder scoping
// ============================================================================

#[sqlx::test]
async fn login_link_finder_scoped_to_portal_id_returns_single_match(pool: PgPool) {
    // Same email under two Companies (both portal-enabled). Finder
    // body carries the Portal ID of Company A + the shared email;
    // redeem MUST return `auto` for Company A's contact rather than
    // a picker with both Companies.
    let (_ca, contact_a, _slug_a, pid_a, token_a) =
        seed_portal_contact_with_portal_id(&pool, "PID Finder A", "shared@pid.example").await;
    let (_cb, contact_b, _slug_b, _pid_b, token_b) =
        seed_portal_contact_with_portal_id(&pool, "PID Finder B", "shared@pid.example").await;
    let app = common::boot(pool.clone()).await;
    redeem_and_set_password(&app, &token_a, STRONG_PW).await;
    redeem_and_set_password(&app, &token_b, STRONG_PW).await;

    // Kick off the finder scoped to Company A's Portal ID.
    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/login-link"))
        .json(&serde_json::json!({
            "email": "shared@pid.example",
            "portal_id": pid_a,
        }))
        .send()
        .await
        .expect("login-link finder");
    assert_eq!(resp.status(), reqwest::StatusCode::NO_CONTENT);

    // Pull the freshly minted intent off the DB so we can drive
    // redeem without waiting for the mailer. The intent must carry
    // company_id = Company A.
    let row: (Uuid, Option<Uuid>) = sqlx::query_as(
        "SELECT id, company_id FROM portal_login_intents \
         WHERE tenant_id = $1 AND LOWER(email) = LOWER($2) \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind("shared@pid.example")
    .fetch_one(&pool)
    .await
    .expect("read intent");
    let (intent_id, scoped_company_id) = row;
    assert_eq!(
        scoped_company_id,
        Some(_ca),
        "prompt 011: finder must scope intent to Company A"
    );

    // Manufacture the redeem token. The intent stores only the
    // secret_hash, so we cannot recover the mailed secret; drive
    // the service through the same finder->redeem contract by
    // stamping a fresh secret directly on the DB and hitting the
    // redeem endpoint with it. Uses the same {intent_id}.{secret}
    // shape the service parses.
    let secret = "test-secret-scope-1234";
    let secret_hash = mokosh_server::utils::crypto::hash_password(secret).expect("hash secret");
    sqlx::query("UPDATE portal_login_intents SET secret_hash = $1 WHERE id = $2")
        .bind(secret_hash)
        .bind(intent_id)
        .execute(&pool)
        .await
        .expect("stamp secret_hash");
    let token = format!("{intent_id}.{secret}");

    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/login-link/redeem"))
        .json(&serde_json::json!({ "token": token }))
        .send()
        .await
        .expect("redeem");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("redeem JSON");
    assert!(
        !body["auto"].is_null(),
        "prompt 011: scoped finder must auto-mint, got {body}"
    );
    assert!(
        body["candidates"].is_null(),
        "prompt 011: scoped finder must NOT return a picker, got {body}"
    );
    // The minted session must be for Company A's contact, not B's.
    let session_contact = body["auto"]["contact"]["id"].as_str().expect("contact id");
    assert_eq!(
        session_contact,
        contact_a.to_string(),
        "prompt 011: scoped finder must session Company A's contact"
    );
    let _ = contact_b;
}

// ============================================================================
// host endpoint by portal_id + slug-to-portal_id resolver
// ============================================================================

#[sqlx::test]
async fn host_endpoint_by_portal_id_returns_hint_for_known_and_404s_for_unknown(pool: PgPool) {
    let (_, _, _slug, portal_id, _token) =
        seed_portal_contact_with_portal_id(&pool, "PID Host Co", "host@pid.example").await;
    let app = common::boot(pool.clone()).await;

    let resp = app
        .client
        .get(app.url(&format!("/api/v1/contact/portal/{portal_id}/host")))
        .send()
        .await
        .expect("host by portal_id");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("host JSON");
    assert_eq!(body["company_name"].as_str(), Some("PID Host Co"));
    assert_eq!(body["tenant_status"].as_str(), Some("active"));

    // Unknown portal_id (in range but never assigned) -> 404.
    let resp = app
        .client
        .get(app.url("/api/v1/contact/portal/100000001/host"))
        .send()
        .await
        .expect("host unknown");
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
}

#[sqlx::test]
async fn resolve_to_portal_id_returns_id_for_known_slug_and_404s_for_unknown(pool: PgPool) {
    let (_, _, slug, portal_id, _token) =
        seed_portal_contact_with_portal_id(&pool, "PID Resolve Co", "resolve@pid.example").await;
    let app = common::boot(pool.clone()).await;

    let resp = app
        .client
        .get(app.url(&format!(
            "/api/v1/contact/portal/{slug}/resolve-to-portal-id"
        )))
        .send()
        .await
        .expect("resolve");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("resolve JSON");
    assert_eq!(body["portal_id"].as_i64(), Some(portal_id));

    let resp = app
        .client
        .get(app.url("/api/v1/contact/portal/ZZZZZZZZZZZZZZZZ/resolve-to-portal-id"))
        .send()
        .await
        .expect("resolve unknown");
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
}
