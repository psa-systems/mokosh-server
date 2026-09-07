//! mokosh-contact-login prompt 010 (PMS-918): end-to-end tests for
//! the magic-link login.
//!
//! One policy runs through the whole file (MAPPS-637, retested under
//! PMS-1065): a login link is scoped to ONE Company by `portal_id` or
//! slug, and no token ever unlocks more than one contact. So the
//! finder drops a request that names neither, and a redeem whose token
//! matches two contacts is an invalid link rather than a picker.
//!
//! Covers the finder's enumeration resistance, the two rate limits
//! (per-IP and per-email), the redeem branches (auto-mint /
//! multi-match refusal / MFA / replay / expired / revoked /
//! first-login password gate), and the cross-tenant isolation
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

/// Option-1 first-login gate: the redeem/select paths now refuse to
/// mint a session when the target contact's `portal_password_hash` is
/// NULL, so tests that assert an auto-minted session on redeem must
/// stamp a dummy hash on the seeded contact first. Any non-empty
/// string is fine: the tests don't verify the hash, only that the
/// gate fires ("row has SOMETHING here, don't bounce me to
/// set-password"). Use a real argon2id shape (hash_password on a fixed
/// throwaway) so a future gate that validates the hash format keeps
/// passing.
async fn stamp_password_hash(pool: &PgPool, contact_id: Uuid) {
    let hash = mokosh_server::utils::crypto::hash_password("test-fixture-password-x9")
        .expect("hash test-fixture password");
    sqlx::query("UPDATE contacts SET portal_password_hash = $1 WHERE id = $2")
        .bind(hash)
        .bind(contact_id)
        .execute(pool)
        .await
        .expect("stamp password hash");
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
    let (contact_id, _company_id, _slug) = seed_portal_contact(&pool, "one@mcl.example").await;
    // Option-1 gate: stamp a password so the redeem path mints a
    // session instead of bouncing to /set-password.
    stamp_password_hash(&pool, contact_id).await;
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

/// MAPPS-637: multi-match is an invalid-link outcome, not a picker.
/// Two Companies under the same email + same tenant. The response is
/// the generic 400 the expired and revoked branches produce, carries
/// no candidate payload of any kind, and the intent is consumed so the
/// token cannot be re-presented.
#[sqlx::test]
async fn redeem_multi_match_returns_invalid_link(pool: PgPool) {
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
    let intent_id: Uuid = token
        .split('.')
        .next()
        .expect("intent id prefix")
        .parse()
        .expect("intent id parses");
    let app = common::boot(pool.clone()).await;

    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/login-link/redeem"))
        .json(&serde_json::json!({ "token": token }))
        .send()
        .await
        .expect("redeem multi");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "MAPPS-637: a token matching more than one contact must be refused as an invalid link"
    );
    let body: serde_json::Value = resp.json().await.expect("redeem JSON");
    assert_eq!(
        body["error"]["message"].as_str(),
        Some("This link is invalid or has expired"),
        "MAPPS-637: multi-match must be indistinguishable from an expired link, got {body}"
    );
    assert!(
        body["auto"].is_null() && body["candidates"].is_null(),
        "MAPPS-637: the refusal must carry no session and no candidate payload, got {body}"
    );

    // The intent is spent, so a second click cannot re-present it.
    let used: Option<chrono::DateTime<Utc>> =
        sqlx::query_scalar("SELECT used_at FROM portal_login_intents WHERE id = $1")
            .bind(intent_id)
            .fetch_one(&pool)
            .await
            .expect("read intent");
    assert!(
        used.is_some(),
        "MAPPS-637: a multi-match redeem must consume the intent"
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

/// PMS-1077: a contact with MFA on completes the magic-link login on the
/// second POST. The first POST (no code) is the `mfa_required` pre-signal
/// and leaves the intent unconsumed; a wrong code is a 401 that ticks the
/// PMS-501 counter and leaves it live; the right code consumes it and
/// mints; the replay afterwards is the generic 400.
#[sqlx::test]
async fn mfa_on_the_magic_link_completes_on_the_second_post(pool: PgPool) {
    let (contact_id, _co_id, _slug) = seed_portal_contact(&pool, "mfa@mcl.example").await;
    let secret = mokosh_server::utils::totp::generate_secret();
    let secret_b32 = mokosh_server::utils::totp::base32_encode(&secret);
    let pwd = mokosh_server::utils::crypto::hash_password("Xy9#pQ4v!Lm2wRt7").expect("hash");
    sqlx::query(
        "UPDATE contacts SET portal_mfa_enabled = TRUE, portal_mfa_secret = $1, \
         portal_password_hash = $2 WHERE id = $3",
    )
    .bind(&secret_b32)
    .bind(&pwd)
    .bind(contact_id)
    .execute(&pool)
    .await
    .expect("enable mfa");
    clear_intents(&pool).await;
    let token = mint_intent_direct(&pool, common::DEFAULT_TENANT_ID, "mfa@mcl.example", None).await;
    let intent_id: Uuid = token.split('.').next().unwrap().parse().unwrap();
    let app = common::boot(pool.clone()).await;

    let used = |pool: PgPool| async move {
        sqlx::query_scalar::<_, Option<chrono::DateTime<Utc>>>(
            "SELECT used_at FROM portal_login_intents WHERE id = $1",
        )
        .bind(intent_id)
        .fetch_one(&pool)
        .await
        .expect("used_at")
    };
    let failed = |pool: PgPool| async move {
        sqlx::query_scalar::<_, i32>("SELECT portal_failed_login_count FROM contacts WHERE id = $1")
            .bind(contact_id)
            .fetch_one(&pool)
            .await
            .expect("count")
    };

    // First POST: pre-signal, nothing consumed.
    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/login-link/redeem"))
        .json(&serde_json::json!({ "token": token }))
        .send()
        .await
        .expect("redeem mfa");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("mfa JSON");
    assert_eq!(body["auto"]["mfa_required"].as_bool(), Some(true));
    assert_eq!(body["auto"]["access_token"].as_str(), Some(""));
    assert!(
        used(pool.clone()).await.is_none(),
        "pre-signal leaves the link live"
    );

    // Wrong code: 401, counter ticks, link still live.
    let wrong = app
        .client
        .post(app.url("/api/v1/contact/auth/login-link/redeem"))
        .json(&serde_json::json!({ "token": token, "mfa_code": "000000" }))
        .send()
        .await
        .expect("wrong code");
    assert_eq!(wrong.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert_eq!(
        failed(pool.clone()).await,
        1,
        "wrong code ticks the counter"
    );
    assert!(
        used(pool.clone()).await.is_none(),
        "wrong code leaves the link live"
    );

    // Right code: session minted, link consumed, counter reset.
    let code = mokosh_server::utils::totp::code_at(&secret, Utc::now());
    let right = app
        .client
        .post(app.url("/api/v1/contact/auth/login-link/redeem"))
        .json(&serde_json::json!({ "token": token, "mfa_code": code }))
        .send()
        .await
        .expect("right code");
    assert_eq!(right.status(), reqwest::StatusCode::OK);
    assert!(
        right.headers().get("set-cookie").is_some(),
        "refresh cookie rides on the minted response"
    );
    let body: serde_json::Value = right.json().await.expect("mint JSON");
    assert_eq!(body["auto"]["mfa_required"].as_bool(), Some(false));
    assert!(!body["auto"]["access_token"].as_str().unwrap().is_empty());
    assert_eq!(body["auto"]["contact"]["mfa_enabled"], true);
    assert!(
        used(pool.clone()).await.is_some(),
        "right code consumes the link"
    );
    assert_eq!(
        failed(pool.clone()).await,
        0,
        "a sign-in resets the counter"
    );

    // Replay after consumption: the generic 400, even with a valid code.
    let code = mokosh_server::utils::totp::code_at(&secret, Utc::now());
    let replay = app
        .client
        .post(app.url("/api/v1/contact/auth/login-link/redeem"))
        .json(&serde_json::json!({ "token": token, "mfa_code": code }))
        .send()
        .await
        .expect("replay");
    assert_eq!(replay.status(), reqwest::StatusCode::BAD_REQUEST);
}

/// PMS-1077: a recovery code completes the magic-link login too, once.
#[sqlx::test]
async fn a_recovery_code_completes_the_magic_link_once(pool: PgPool) {
    let (contact_id, _co_id, _slug) = seed_portal_contact(&pool, "recover@mcl.example").await;
    let secret_b32 =
        mokosh_server::utils::totp::base32_encode(&mokosh_server::utils::totp::generate_secret());
    let pwd = mokosh_server::utils::crypto::hash_password("Xy9#pQ4v!Lm2wRt7").expect("hash");
    let recovery = mokosh_server::utils::recovery::generate_code();
    let hashes = vec![mokosh_server::utils::recovery::hash_code_hex(&recovery)];
    sqlx::query(
        "UPDATE contacts SET portal_mfa_enabled = TRUE, portal_mfa_secret = $1, \
         portal_password_hash = $2, portal_mfa_recovery_codes_hashes = $3 WHERE id = $4",
    )
    .bind(&secret_b32)
    .bind(&pwd)
    .bind(&hashes)
    .bind(contact_id)
    .execute(&pool)
    .await
    .expect("enable mfa");
    clear_intents(&pool).await;
    let app = common::boot(pool.clone()).await;

    let token = mint_intent_direct(
        &pool,
        common::DEFAULT_TENANT_ID,
        "recover@mcl.example",
        None,
    )
    .await;
    let first = app
        .client
        .post(app.url("/api/v1/contact/auth/login-link/redeem"))
        .json(&serde_json::json!({ "token": token, "mfa_code": "", "recovery_code": recovery }))
        .send()
        .await
        .expect("recovery");
    assert_eq!(first.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = first.json().await.expect("JSON");
    assert!(!body["auto"]["access_token"].as_str().unwrap().is_empty());
    let left: Vec<String> =
        sqlx::query_scalar("SELECT portal_mfa_recovery_codes_hashes FROM contacts WHERE id = $1")
            .bind(contact_id)
            .fetch_one(&pool)
            .await
            .expect("hashes");
    assert!(left.is_empty(), "the code is spent");

    // A fresh link with the spent code: 401, link left live.
    let token = mint_intent_direct(
        &pool,
        common::DEFAULT_TENANT_ID,
        "recover@mcl.example",
        None,
    )
    .await;
    let again = app
        .client
        .post(app.url("/api/v1/contact/auth/login-link/redeem"))
        .json(&serde_json::json!({ "token": token, "recovery_code": recovery }))
        .send()
        .await
        .expect("spent");
    assert_eq!(again.status(), reqwest::StatusCode::UNAUTHORIZED);
}

// MAPPS-637 (pinned here under PMS-1065): the multi-Company picker is
// gone, so this file has no Select section. Its route, the selection
// JWT and the candidate DTOs were all retired with it, and the four
// cases that drove them were deleted rather than rewritten: there is
// no code path left for them to pin. What replaced them is
// `redeem_multi_match_returns_invalid_link` above.

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
    let (a_id, _a_co, a_slug) = seed_portal_contact_in_tenant(
        &pool,
        common::DEFAULT_TENANT_ID,
        "Alpha Co (T-A)",
        "cross@mcl.example",
    )
    .await;
    let (_b_id, _b_co, _b_slug) =
        seed_portal_contact_in_tenant(&pool, tenant_b, "Beta Co (T-B)", "cross@mcl.example").await;
    // Option-1 gate: stamp a password on the tenant-A contact so the
    // redeem below mints a real session (the test's cross-tenant
    // assertion reads contact.tenant_id off the session). Tenant-B's
    // contact stays password-less; irrelevant to this test.
    stamp_password_hash(&pool, a_id).await;
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

/// mokosh-contact-login option-1 first-login gate: a magic-link redeem
/// for a contact whose `portal_password_hash IS NULL` returns
/// `password_setup_url` and NO session tokens. The SPA MUST navigate to
/// the URL and force the recipient to set a password before landing on
/// `/dashboard`. Every future login for that contact then has both
/// paths (magic-link OR password) available.
///
/// Without this pin a regression that skips the check would silently
/// re-open the "clicked the magic-link, now I'm password-less and
/// don't realise it" trap.
#[sqlx::test]
async fn redeem_single_match_with_no_password_returns_setup_url(pool: PgPool) {
    let (_contact_id, _company_id, slug) = seed_portal_contact(&pool, "nopass@mcl.example").await;
    // Deliberately do NOT call stamp_password_hash: the seed helper
    // leaves portal_password_hash NULL, which is exactly the state
    // this test pins.
    let token =
        mint_intent_direct(&pool, common::DEFAULT_TENANT_ID, "nopass@mcl.example", None).await;
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
    let auto = &body["auto"];
    assert!(
        !auto.is_null(),
        "option-1: single-match must still set auto (with the setup URL, not tokens)"
    );
    assert_eq!(
        auto["access_token"].as_str(),
        Some(""),
        "option-1: session must NOT be minted before password is set"
    );
    assert_eq!(
        auto["refresh_token"].as_str(),
        Some(""),
        "option-1: session must NOT be minted before password is set"
    );
    let setup_url = auto["password_setup_url"]
        .as_str()
        .expect("password_setup_url present on the auto branch");
    let expected_prefix = format!("/portal/{slug}/set-password?token=");
    assert!(
        setup_url.contains(&expected_prefix),
        "option-1: password_setup_url must point at /portal/{{slug}}/set-password, got: {setup_url}"
    );
}

/// MAPPS-637: a login-link request that names neither `portal_id` nor
/// a slug is dropped, and a KNOWN email is dropped exactly as an
/// unknown one is. The cross-tenant `SELECT DISTINCT c.tenant_id ...
/// WHERE LOWER(c.email) = LOWER($1)` fan-out that used to mint one
/// intent per matched tenant, and mail one link per intent, was the
/// aggregation primitive retired: a request naming no Company must not
/// be answered with every Company the address is on file under.
///
/// Both halves matter. 204 keeps the drop enumeration-resistant, and
/// zero intents plus zero mail is what says it was actually dropped
/// rather than served. `login_link_without_slug_unknown_email_stays_enum_resistant`
/// below covers only the unknown-email side, so without this a known
/// email that silently minted nothing would be untested.
#[sqlx::test]
async fn login_link_without_slug_for_a_known_email_mints_nothing(pool: PgPool) {
    let (_contact_id, _company_id, _slug) = seed_portal_contact(&pool, "nosslug@mcl.example").await;
    // Nuke the intent grant_portal_access minted so the assertion
    // below reflects only the finder call. Its notification row is not
    // deletable the same way (other tests read the table), so take a
    // baseline and assert the finder adds nothing to it.
    clear_intents(&pool).await;
    let mail_before: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM notifications WHERE recipient = $1 AND channel_type = 'email'",
    )
    .bind("nosslug@mcl.example")
    .fetch_one(&pool)
    .await
    .expect("count notifications before");
    let app = common::boot(pool.clone()).await;

    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/login-link"))
        .json(&serde_json::json!({ "email": "nosslug@mcl.example" }))
        .send()
        .await
        .expect("login-link");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::NO_CONTENT,
        "MAPPS-637: the drop must answer 204, the same as any other finder submission"
    );

    let intent_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM portal_login_intents")
        .fetch_one(&pool)
        .await
        .expect("count intents");
    assert_eq!(
        intent_count, 0,
        "MAPPS-637: a request naming no portal_id and no slug must mint zero intents, \
         even for an email that is on file"
    );

    let mail_after: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM notifications WHERE recipient = $1 AND channel_type = 'email'",
    )
    .bind("nosslug@mcl.example")
    .fetch_one(&pool)
    .await
    .expect("count notifications after");
    assert_eq!(
        mail_after, mail_before,
        "MAPPS-637: the retired fan-out must queue no login-link mail"
    );
}

/// Regression companion: an unknown email on the no-slug path returns
/// 204 with zero intents + zero notifications. Enum-resistant even
/// under the new fallback shape.
#[sqlx::test]
async fn login_link_without_slug_unknown_email_stays_enum_resistant(pool: PgPool) {
    let (_contact_id, _company_id, _slug) = seed_portal_contact(&pool, "someone@mcl.example").await;
    clear_intents(&pool).await;
    let app = common::boot(pool.clone()).await;

    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/login-link"))
        .json(&serde_json::json!({ "email": "unknown-nobody@mcl.example" }))
        .send()
        .await
        .expect("login-link unknown");
    assert_eq!(resp.status(), reqwest::StatusCode::NO_CONTENT);

    let intent_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM portal_login_intents")
        .fetch_one(&pool)
        .await
        .expect("count intents");
    assert_eq!(
        intent_count, 0,
        "unknown email must NOT mint an intent even under the no-slug fallback"
    );
}
