//! mokosh-contact-login prompt 010 (PMS-918): end-to-end tests for
//! the magic-link login + multi-Company picker.
//!
//! Covers all 14 cases in the spec's Tests section: enumeration
//! resistance of the finder, rate limits (per-IP + per-email), the
//! redeem branches (auto-mint / picker / MFA / replay / expired /
//! revoked), the select branch (happy path + candidate-swap guard +
//! expired selection token), and the cross-tenant isolation
//! invariant.

mod common;

use chrono::{Duration, Utc};
use sqlx::PgPool;
use uuid::Uuid;

/// Seed a Company + Contact + granted portal access under
/// `tenant_id`. Returns `(contact_id, company_id, portal_slug)` so a
/// test can drive the redeem endpoint without going through the
/// finder first.
async fn seed_portal_contact_in_tenant(
    pool: &PgPool,
    tenant_id: Uuid,
    company_name: &str,
    email: &str,
) -> (Uuid, Uuid, String) {
    let company_id = Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, $3)")
        .bind(company_id)
        .bind(tenant_id)
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
    .bind(tenant_id)
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
    .bind(tenant_id)
    .fetch_all(pool)
    .await
    .expect("read Support role");
    let role_ids: Vec<Uuid> = roles.into_iter().map(|(id,)| id).collect();
    let outcome = contact_svc
        .grant_portal_access(
            mokosh_server::modules::auth::TenantId::from_trusted(tenant_id),
            contact_id,
            &role_ids,
            &mokosh_server::modules::audit::AuditCtx::system(tenant_id),
        )
        .await
        .expect("grant_portal_access");
    (contact_id, company_id, outcome.portal_slug)
}

async fn seed_portal_contact(pool: &PgPool, email: &str) -> (Uuid, Uuid, String) {
    seed_portal_contact_in_tenant(pool, common::DEFAULT_TENANT_ID, "MCL P010 Co", email).await
}

/// The grant-portal-access path mints one login-link intent as a
/// side-effect (that is prompt 010's whole point). Tests that pin
/// the intent counter for a downstream finder call need a clean
/// counter baseline; nuking the table after seed keeps the two
/// concerns separate. Rate-limit tests read the counter via
/// `insert_intent_row` afterward, so any test that calls this MUST
/// re-populate rows explicitly.
async fn clear_intents(pool: &PgPool) {
    sqlx::query("DELETE FROM portal_login_intents")
        .execute(pool)
        .await
        .expect("clear intents");
}

/// Direct-insert helper: build a rate-limit counter without firing
/// full HTTP requests. Uses the migrator pool through a superuser
/// connection so RLS doesn't gate the write.
async fn insert_intent_row(
    pool: &PgPool,
    tenant_id: Uuid,
    email: &str,
    ip: Option<&str>,
    minutes_ago: i64,
) {
    let expires = Utc::now() + Duration::minutes(15);
    let created = Utc::now() - Duration::minutes(minutes_ago);
    sqlx::query(
        "INSERT INTO portal_login_intents \
         (id, tenant_id, email, secret_hash, expires_at, ip, user_agent, created_at) \
         VALUES ($1, $2, $3, 'unusable-hash-for-counter', $4, NULLIF($5, '')::inet, 'seed', $6)",
    )
    .bind(Uuid::new_v4())
    .bind(tenant_id)
    .bind(email)
    .bind(expires)
    .bind(ip.unwrap_or_default())
    .bind(created)
    .execute(pool)
    .await
    .expect("insert intent row for rate-limit setup");
}

/// Mint a real magic-link intent for `email` under `tenant_id` and
/// return the full `{intent_id}.{secret}` token so a redeem test
/// doesn't have to go through the finder. `used_at` = NULL and
/// `expires_at` = `expires_at_override.unwrap_or(NOW() + 15 min)`.
async fn mint_intent_direct(
    pool: &PgPool,
    tenant_id: Uuid,
    email: &str,
    expires_at_override: Option<chrono::DateTime<Utc>>,
) -> String {
    let intent_id = Uuid::new_v4();
    let secret = mokosh_server::utils::crypto::generate_token(32);
    let hash = mokosh_server::utils::crypto::hash_password(&secret).expect("hash");
    let expires = expires_at_override.unwrap_or_else(|| Utc::now() + Duration::minutes(15));
    sqlx::query(
        "INSERT INTO portal_login_intents \
         (id, tenant_id, email, secret_hash, expires_at) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(intent_id)
    .bind(tenant_id)
    .bind(email)
    .bind(&hash)
    .bind(expires)
    .execute(pool)
    .await
    .expect("insert intent row");
    format!("{intent_id}.{secret}")
}

// ---------------------------------------------------------------------------
// Finder: enumeration resistance + rate limits
// ---------------------------------------------------------------------------

/// mokosh-contact-login prompt 010: unknown email -> 204, no side
/// effects. Pins the enumeration-resistance contract of the finder.
#[sqlx::test]
async fn login_link_returns_204_for_unknown_email(pool: PgPool) {
    // Seed a contact so the tenant/slug is well-formed, then request
    // the link for a DIFFERENT email under the same slug.
    let (_contact_id, _company_id, slug) = seed_portal_contact(&pool, "known@mcl.example").await;
    // Clear the intent row `grant_portal_access` mints as a side-
    // effect so the assertion below reflects only the finder call.
    clear_intents(&pool).await;
    let app = common::boot(pool.clone()).await;

    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/login-link"))
        .json(&serde_json::json!({ "email": "nobody@mcl.example", "slug": slug }))
        .send()
        .await
        .expect("login-link");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::NO_CONTENT,
        "prompt 010: unknown email must 204 (enum-resistant)"
    );

    let intent_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM portal_login_intents WHERE tenant_id = $1")
            .bind(common::DEFAULT_TENANT_ID)
            .fetch_one(&pool)
            .await
            .expect("count intents");
    assert_eq!(
        intent_count, 0,
        "prompt 010: unknown email must NOT insert an intent row"
    );

    let notif_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM notifications \
         WHERE tenant_id = $1 AND recipient = 'nobody@mcl.example'",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(&pool)
    .await
    .expect("count notifs");
    assert_eq!(
        notif_count, 0,
        "prompt 010: unknown email must NOT enqueue a notification"
    );
}

/// mokosh-contact-login prompt 010: known email + slug -> 204, one
/// intent row minted, AND (post-migration 149) one auth.login_link
/// email queued to the recipient. Before migration 149 seeded the
/// template + rule, the dispatcher silently no-op'd on this event and
/// operators saw every finder click quietly drop the email on the floor.
/// This test pins both the row + the queued notification so the
/// silent-drop regression cannot come back.
#[sqlx::test]
async fn login_link_returns_204_for_known_email_and_mints_intent(pool: PgPool) {
    let (_contact_id, _company_id, slug) = seed_portal_contact(&pool, "hit@mcl.example").await;
    clear_intents(&pool).await;
    let app = common::boot(pool.clone()).await;

    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/login-link"))
        .json(&serde_json::json!({ "email": "hit@mcl.example", "slug": slug }))
        .send()
        .await
        .expect("login-link");
    assert_eq!(resp.status(), reqwest::StatusCode::NO_CONTENT);

    let intent_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM portal_login_intents \
         WHERE tenant_id = $1 AND LOWER(email) = LOWER($2)",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind("hit@mcl.example")
    .fetch_one(&pool)
    .await
    .expect("count intents");
    assert_eq!(
        intent_count, 1,
        "prompt 010: known email must mint exactly one intent row"
    );

    // Migration 149: the auth.login_link template + rule are now seeded
    // so the finder actually queues an email. A zero here means either
    // the template is missing (migration 149 didn't run / was reverted)
    // OR the finder is dispatching under the wrong event type.
    let email_body: String = sqlx::query_scalar(
        "SELECT body FROM notifications \
         WHERE tenant_id = $1 AND recipient = $2 AND channel_type = 'email' \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind("hit@mcl.example")
    .fetch_one(&pool)
    .await
    .expect("read email body; if RowNotFound the auth.login_link template + rule are not seeded");
    assert!(
        email_body.contains("/portal/pick?token="),
        "prompt 010 finder email must carry the /portal/pick?token=... magic link, got: {email_body}"
    );
}

/// mokosh-contact-login prompt 010: per-email rate limit blocks the
/// 6th request inside 15 min without any 4xx leak (still 204).
#[sqlx::test]
async fn login_link_respects_per_email_rate_limit(pool: PgPool) {
    let (_contact_id, _company_id, slug) = seed_portal_contact(&pool, "rate@mcl.example").await;
    clear_intents(&pool).await;
    // Pre-insert 5 rows so the 6th real request hits the ceiling
    // without firing 5 real HTTP calls.
    for _ in 0..5 {
        insert_intent_row(
            &pool,
            common::DEFAULT_TENANT_ID,
            "rate@mcl.example",
            None,
            1,
        )
        .await;
    }
    let app = common::boot(pool.clone()).await;

    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/login-link"))
        .json(&serde_json::json!({ "email": "rate@mcl.example", "slug": slug }))
        .send()
        .await
        .expect("login-link");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::NO_CONTENT,
        "prompt 010: over-limit response must still be 204 (silent drop)"
    );

    // Counter stays at 5 - the request did NOT insert.
    let intent_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM portal_login_intents \
         WHERE tenant_id = $1 AND LOWER(email) = LOWER($2)",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind("rate@mcl.example")
    .fetch_one(&pool)
    .await
    .expect("count intents");
    assert_eq!(
        intent_count, 5,
        "prompt 010: per-email rate limit must silently drop the write"
    );
}

/// mokosh-contact-login prompt 010: per-IP rate limit blocks the 21st
/// request inside 1 min across DIFFERENT emails without any 4xx leak.
#[sqlx::test]
async fn login_link_respects_per_ip_rate_limit(pool: PgPool) {
    // Seed one real contact so the finder resolves the tenant; the
    // rate-limit assertion targets a different email so the finder
    // has nothing to write on the 21st call.
    let (_contact_id, _company_id, slug) = seed_portal_contact(&pool, "ip-real@mcl.example").await;
    clear_intents(&pool).await;
    // Pre-insert 20 rows attributed to the client's loopback address
    // (reqwest connects from 127.0.0.1 for a `127.0.0.1:0` bind, so
    // the axum `ConnectInfo` sees it too). Different email so the
    // per-email limit does not fire first.
    for i in 0..20 {
        insert_intent_row(
            &pool,
            common::DEFAULT_TENANT_ID,
            &format!("ip-fill-{i}@mcl.example"),
            Some("127.0.0.1"),
            0,
        )
        .await;
    }
    let app = common::boot(pool.clone()).await;

    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/login-link"))
        .json(&serde_json::json!({ "email": "ip-real@mcl.example", "slug": slug }))
        .send()
        .await
        .expect("login-link");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::NO_CONTENT,
        "prompt 010: over-limit response must still be 204 (silent drop)"
    );

    // The real email must not have a fresh intent row (rate-limited).
    let intent_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM portal_login_intents \
         WHERE tenant_id = $1 AND LOWER(email) = LOWER($2)",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind("ip-real@mcl.example")
    .fetch_one(&pool)
    .await
    .expect("count intents");
    assert_eq!(
        intent_count, 0,
        "prompt 010: per-IP rate limit must silently drop the 21st insert"
    );
}

// ---------------------------------------------------------------------------
// Redeem: happy paths + failure modes
// ---------------------------------------------------------------------------

/// mokosh-contact-login prompt 010: single-match auto-mint. Redeem
/// returns `auto.access_token` + `auto.refresh_token`, and the
/// refresh token is usable on POST /contact/auth/refresh.
#[sqlx::test]
async fn redeem_single_match_auto_mints_session(pool: PgPool) {
    let (_contact_id, _company_id, _slug) = seed_portal_contact(&pool, "one@mcl.example").await;
    let token = mint_intent_direct(&pool, common::DEFAULT_TENANT_ID, "one@mcl.example", None).await;
    let app = common::boot(pool.clone()).await;

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
        body["candidates"].is_null(),
        "prompt 010: single-match must not return picker candidates, got {body}"
    );
    let auto = &body["auto"];
    assert!(!auto.is_null(), "prompt 010: single-match must set auto");
    let refresh = auto["refresh_token"]
        .as_str()
        .expect("refresh_token present");
    assert!(!refresh.is_empty());

    // Refresh path proves the minted session is real.
    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/refresh"))
        .json(&serde_json::json!({ "refresh_token": refresh }))
        .send()
        .await
        .expect("refresh");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
}

/// mokosh-contact-login prompt 010: multi-match returns the picker
/// payload. Two Companies under the same email + same tenant. No
/// session tokens are set on the response.
#[sqlx::test]
async fn redeem_multi_match_returns_picker_payload(pool: PgPool) {
    let (_a_id, _a_co, _a_slug) = seed_portal_contact_in_tenant(
        &pool,
        common::DEFAULT_TENANT_ID,
        "Alpha Co",
        "multi@mcl.example",
    )
    .await;
    let (_b_id, _b_co, _b_slug) = seed_portal_contact_in_tenant(
        &pool,
        common::DEFAULT_TENANT_ID,
        "Beta Co",
        "multi@mcl.example",
    )
    .await;
    let token =
        mint_intent_direct(&pool, common::DEFAULT_TENANT_ID, "multi@mcl.example", None).await;
    let app = common::boot(pool.clone()).await;

    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/login-link/redeem"))
        .json(&serde_json::json!({ "token": token }))
        .send()
        .await
        .expect("redeem multi");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("redeem JSON");
    assert!(
        body["auto"].is_null(),
        "prompt 010: multi-match must not mint an auto session"
    );
    let candidates = &body["candidates"];
    assert!(
        !candidates.is_null(),
        "prompt 010: multi-match must return candidates"
    );
    let companies = candidates["companies"]
        .as_array()
        .expect("candidates.companies");
    assert_eq!(
        companies.len(),
        2,
        "prompt 010: picker must list both Companies"
    );
    assert!(
        candidates["selection_token"]
            .as_str()
            .map(|s| !s.is_empty())
            .unwrap_or(false),
        "prompt 010: multi-match must carry a non-empty selection_token"
    );
}

/// mokosh-contact-login prompt 010: replay of a used token folds to
/// the generic 400.
#[sqlx::test]
async fn redeem_replayed_token_returns_400(pool: PgPool) {
    let (_c_id, _co_id, _slug) = seed_portal_contact(&pool, "replay@mcl.example").await;
    let token =
        mint_intent_direct(&pool, common::DEFAULT_TENANT_ID, "replay@mcl.example", None).await;
    let app = common::boot(pool.clone()).await;

    let first = app
        .client
        .post(app.url("/api/v1/contact/auth/login-link/redeem"))
        .json(&serde_json::json!({ "token": token }))
        .send()
        .await
        .expect("redeem first");
    assert_eq!(first.status(), reqwest::StatusCode::OK);

    let replay = app
        .client
        .post(app.url("/api/v1/contact/auth/login-link/redeem"))
        .json(&serde_json::json!({ "token": token }))
        .send()
        .await
        .expect("redeem replay");
    assert_eq!(
        replay.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "prompt 010: replayed token must 400"
    );
}

/// mokosh-contact-login prompt 010: expired token folds to 400.
#[sqlx::test]
async fn redeem_expired_token_returns_400(pool: PgPool) {
    let (_c_id, _co_id, _slug) = seed_portal_contact(&pool, "exp@mcl.example").await;
    // Insert an already-expired intent (expires_at = 1 hour ago).
    let token = mint_intent_direct(
        &pool,
        common::DEFAULT_TENANT_ID,
        "exp@mcl.example",
        Some(Utc::now() - Duration::hours(1)),
    )
    .await;
    let app = common::boot(pool.clone()).await;

    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/login-link/redeem"))
        .json(&serde_json::json!({ "token": token }))
        .send()
        .await
        .expect("redeem expired");
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
}

/// mokosh-contact-login prompt 010: contact revoked between mint +
/// click. The revoke path (is_portal_user = FALSE) leaves zero
/// candidates at redeem. Response is the same generic 400 - do NOT
/// leak that revocation happened.
#[sqlx::test]
async fn redeem_revoked_between_mint_and_click_returns_400(pool: PgPool) {
    let (contact_id, _co_id, _slug) = seed_portal_contact(&pool, "revoke@mcl.example").await;
    let token =
        mint_intent_direct(&pool, common::DEFAULT_TENANT_ID, "revoke@mcl.example", None).await;
    sqlx::query("UPDATE contacts SET is_portal_user = FALSE WHERE id = $1")
        .bind(contact_id)
        .execute(&pool)
        .await
        .expect("revoke");
    let app = common::boot(pool.clone()).await;

    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/login-link/redeem"))
        .json(&serde_json::json!({ "token": token }))
        .send()
        .await
        .expect("redeem revoked");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "prompt 010: revoked-between-mint-and-click must return the generic 400"
    );
}

/// mokosh-contact-login prompt 010: single-match auto-mint gated on
/// MFA. When the target contact has `portal_mfa_secret` set, the
/// redeem returns `mfa_required = true` with empty tokens.
#[sqlx::test]
async fn mfa_gates_single_match_auto_mint(pool: PgPool) {
    let (contact_id, _co_id, _slug) = seed_portal_contact(&pool, "mfa@mcl.example").await;
    sqlx::query("UPDATE contacts SET portal_mfa_secret = 'JBSWY3DPEHPK3PXP' WHERE id = $1")
        .bind(contact_id)
        .execute(&pool)
        .await
        .expect("set mfa secret");
    let token = mint_intent_direct(&pool, common::DEFAULT_TENANT_ID, "mfa@mcl.example", None).await;
    let app = common::boot(pool.clone()).await;

    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/login-link/redeem"))
        .json(&serde_json::json!({ "token": token }))
        .send()
        .await
        .expect("redeem mfa");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("mfa JSON");
    let auto = &body["auto"];
    assert!(!auto.is_null(), "prompt 010: MFA gate still sets auto");
    assert_eq!(
        auto["mfa_required"].as_bool(),
        Some(true),
        "prompt 010: MFA-enrolled contact must return mfa_required = true"
    );
    assert_eq!(
        auto["access_token"].as_str(),
        Some(""),
        "prompt 010: MFA gate must NOT hand out a session token"
    );
}

// ---------------------------------------------------------------------------
// Select: happy path + guards
// ---------------------------------------------------------------------------

/// mokosh-contact-login prompt 010: multi-match then select mints a
/// session for the chosen contact. `sub` claim on the access token
/// matches the picked contact_id.
#[sqlx::test]
async fn select_mints_session_for_chosen_contact(pool: PgPool) {
    let (a_id, _a_co, _a_slug) = seed_portal_contact_in_tenant(
        &pool,
        common::DEFAULT_TENANT_ID,
        "Alpha Co",
        "sel@mcl.example",
    )
    .await;
    let (_b_id, _b_co, _b_slug) = seed_portal_contact_in_tenant(
        &pool,
        common::DEFAULT_TENANT_ID,
        "Beta Co",
        "sel@mcl.example",
    )
    .await;
    let token = mint_intent_direct(&pool, common::DEFAULT_TENANT_ID, "sel@mcl.example", None).await;
    let app = common::boot(pool.clone()).await;

    let redeem = app
        .client
        .post(app.url("/api/v1/contact/auth/login-link/redeem"))
        .json(&serde_json::json!({ "token": token }))
        .send()
        .await
        .expect("redeem multi");
    let redeem_body: serde_json::Value = redeem.json().await.expect("redeem JSON");
    let selection_token = redeem_body["candidates"]["selection_token"]
        .as_str()
        .expect("selection_token")
        .to_string();

    let select = app
        .client
        .post(app.url("/api/v1/contact/auth/login-link/select"))
        .json(&serde_json::json!({
            "selection_token": selection_token,
            "contact_id": a_id,
        }))
        .send()
        .await
        .expect("select a");
    assert_eq!(select.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = select.json().await.expect("select JSON");
    assert_eq!(
        body["contact"]["id"].as_str(),
        Some(a_id.to_string().as_str()),
        "prompt 010: session me.id must match the picked contact"
    );
}

/// mokosh-contact-login prompt 010: select with a contact_id that
/// was NOT part of the redeem's candidate list returns 400. Prevents
/// a caller from swapping to an unrelated contact.
#[sqlx::test]
async fn select_rejects_contact_id_not_in_candidates(pool: PgPool) {
    let (_a_id, _a_co, _a_slug) = seed_portal_contact_in_tenant(
        &pool,
        common::DEFAULT_TENANT_ID,
        "Alpha Co",
        "guard@mcl.example",
    )
    .await;
    let (_b_id, _b_co, _b_slug) = seed_portal_contact_in_tenant(
        &pool,
        common::DEFAULT_TENANT_ID,
        "Beta Co",
        "guard@mcl.example",
    )
    .await;
    // Third contact under a THIRD Company / same tenant, NOT part of
    // the intent's email match.
    let (foreign_id, _c_co, _c_slug) = seed_portal_contact_in_tenant(
        &pool,
        common::DEFAULT_TENANT_ID,
        "Gamma Co",
        "foreign@mcl.example",
    )
    .await;
    let token =
        mint_intent_direct(&pool, common::DEFAULT_TENANT_ID, "guard@mcl.example", None).await;
    let app = common::boot(pool.clone()).await;

    let redeem = app
        .client
        .post(app.url("/api/v1/contact/auth/login-link/redeem"))
        .json(&serde_json::json!({ "token": token }))
        .send()
        .await
        .expect("redeem");
    let redeem_body: serde_json::Value = redeem.json().await.expect("redeem JSON");
    let selection_token = redeem_body["candidates"]["selection_token"]
        .as_str()
        .expect("selection_token")
        .to_string();

    let select = app
        .client
        .post(app.url("/api/v1/contact/auth/login-link/select"))
        .json(&serde_json::json!({
            "selection_token": selection_token,
            "contact_id": foreign_id,
        }))
        .send()
        .await
        .expect("select foreign");
    assert_eq!(
        select.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "prompt 010: unrelated contact_id must 400"
    );
}

/// mokosh-contact-login prompt 010: selection JWT expired -> 400.
/// Constructs a JWT with `exp` in the past under the same shape the
/// service issues.
#[sqlx::test]
async fn select_rejects_expired_selection_token(pool: PgPool) {
    let (a_id, _a_co, _a_slug) = seed_portal_contact_in_tenant(
        &pool,
        common::DEFAULT_TENANT_ID,
        "Alpha Co",
        "expsel@mcl.example",
    )
    .await;
    let app = common::boot(pool.clone()).await;

    // Build an already-expired selection JWT under the same secret
    // the router uses (`test-jwt-secret-that-is-clearly-not-for-prod`,
    // set in `tests/common/mod.rs`).
    #[derive(serde::Serialize)]
    struct Claims<'a> {
        intent_id: Uuid,
        tid: Uuid,
        candidate_contact_ids: Vec<Uuid>,
        #[serde(rename = "typ")]
        typ: &'a str,
        iat: i64,
        exp: i64,
    }
    let now = Utc::now();
    let claims = Claims {
        intent_id: Uuid::new_v4(),
        tid: common::DEFAULT_TENANT_ID,
        candidate_contact_ids: vec![a_id],
        typ: "contact_login_select",
        iat: (now - Duration::minutes(30)).timestamp(),
        // Well past the jsonwebtoken default 60s leeway.
        exp: (now - Duration::minutes(15)).timestamp(),
    };
    let selection_token = jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(b"test-jwt-secret-that-is-clearly-not-for-prod"),
    )
    .expect("encode expired JWT");

    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/login-link/select"))
        .json(&serde_json::json!({
            "selection_token": selection_token,
            "contact_id": a_id,
        }))
        .send()
        .await
        .expect("select expired");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "prompt 010: expired selection_token must 400"
    );
}

// ---------------------------------------------------------------------------
// Cross-tenant isolation
// ---------------------------------------------------------------------------

/// mokosh-contact-login prompt 010: same email under tenant A and
/// tenant B. Finder at tenant A's slug mints an intent that only
/// resolves tenant A's Companies at redeem time - tenant B's
/// Company never appears in the picker.
#[sqlx::test]
async fn cross_tenant_email_never_leaks_across_msps(pool: PgPool) {
    // Tenant B (fresh) + one Company under it, plus the seeded
    // portal roles (grant_portal_access requires the Support role
    // under the target tenant).
    let (tenant_b, _admin_id, _email, _pw) =
        common::seed_tenant_with_admin(&pool, "tenant-b-mcl").await;
    // Seed the built-in portal roles for tenant B (production does
    // this in `TenantService::create_tenant`; the raw
    // `seed_tenant_with_admin` helper skips it).
    let db = mokosh_server::Database::from_pool(pool.clone());
    let tenant_svc = mokosh_server::modules::tenants::TenantService::new(db.clone());
    tenant_svc
        .seed_builtin_portal_roles(tenant_b)
        .await
        .expect("seed builtin roles for tenant B");

    // Same email in both tenants.
    let (_a_id, _a_co, a_slug) = seed_portal_contact_in_tenant(
        &pool,
        common::DEFAULT_TENANT_ID,
        "Alpha Co (T-A)",
        "cross@mcl.example",
    )
    .await;
    let (_b_id, _b_co, _b_slug) =
        seed_portal_contact_in_tenant(&pool, tenant_b, "Beta Co (T-B)", "cross@mcl.example").await;
    // Clear the intents both grants minted so the finder call below
    // observes only its own write.
    clear_intents(&pool).await;

    let app = common::boot(pool.clone()).await;

    // Request the link via tenant A's slug.
    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/login-link"))
        .json(&serde_json::json!({
            "email": "cross@mcl.example",
            "slug": a_slug,
        }))
        .send()
        .await
        .expect("login-link");
    assert_eq!(resp.status(), reqwest::StatusCode::NO_CONTENT);

    // Read the freshly minted intent's tenant + fabricate a matching
    // redeem token by inserting our own intent (the real one used a
    // hashed secret we can't recover). Assert the intent landed under
    // tenant A, not tenant B.
    let intent_rows: Vec<(Uuid, Uuid)> = sqlx::query_as(
        "SELECT id, tenant_id FROM portal_login_intents \
         WHERE LOWER(email) = LOWER($1) AND created_at > NOW() - INTERVAL '1 minute'",
    )
    .bind("cross@mcl.example")
    .fetch_all(&pool)
    .await
    .expect("read intents");
    assert_eq!(
        intent_rows.len(),
        1,
        "prompt 010: exactly one intent should land on the tenant-A finder call"
    );
    assert_eq!(
        intent_rows[0].1,
        common::DEFAULT_TENANT_ID,
        "prompt 010: finder must attribute the intent to the resolved (tenant-A) tenant, got {:?}",
        intent_rows[0].1
    );

    // Now mint a redeem-usable intent under tenant A and confirm the
    // redeem outcome carries ONLY tenant-A's Company.
    let token =
        mint_intent_direct(&pool, common::DEFAULT_TENANT_ID, "cross@mcl.example", None).await;
    let redeem = app
        .client
        .post(app.url("/api/v1/contact/auth/login-link/redeem"))
        .json(&serde_json::json!({ "token": token }))
        .send()
        .await
        .expect("redeem");
    assert_eq!(redeem.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = redeem.json().await.expect("redeem JSON");
    // Single-match auto (only tenant A's contact matches).
    let auto = &body["auto"];
    assert!(
        !auto.is_null(),
        "prompt 010: cross-tenant leak - candidates were shown, expected auto"
    );
    assert_eq!(
        auto["contact"]["tenant_id"].as_str(),
        Some(common::DEFAULT_TENANT_ID.to_string().as_str()),
        "prompt 010: cross-tenant leak - session pinned to wrong tenant"
    );
    let _ = tenant_b;
}
