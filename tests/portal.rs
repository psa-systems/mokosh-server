//! Integration tests for the customer portal API (PMS-25, F6).
//!
//! Portal identity is a `contacts` row, never a `users` row, so these
//! tests pin the two guarantees that matter for a customer-facing
//! surface: the session is contact-scoped (a staff token cannot act on
//! the portal and a portal token cannot act on staff routes), and every
//! read is isolated to the contact's own company. Each acceptance
//! criterion from the story maps to one test below.

mod common;

use sqlx::PgPool;
use uuid::Uuid;

const PORTAL_PASSWORD: &str = "portal-password-12345";

/// Seed a company under the default tenant. Returns its id.
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

/// Seed a portal-enabled contact (`is_portal_user = TRUE` with a real
/// password hash) under the given company. Returns its contact id.
async fn seed_portal_contact(pool: &PgPool, company_id: Uuid, email: &str) -> Uuid {
    let id = Uuid::new_v4();
    let hash =
        mokosh_server::utils::crypto::hash_password(PORTAL_PASSWORD).expect("hash portal password");
    sqlx::query(
        r#"
        INSERT INTO contacts (
            id, tenant_id, company_id, first_name, last_name, email,
            is_portal_user, portal_password_hash
        )
        VALUES ($1, $2, $3, 'Portal', 'Contact', $4, TRUE, $5)
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

/// Seed a portal-enabled contact with NO password hash (the state right
/// after an agent grants access but before the customer redeems their
/// setup link). Returns its contact id.
async fn seed_contact_awaiting_setup(pool: &PgPool, company_id: Uuid, email: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO contacts (
            id, tenant_id, company_id, first_name, last_name, email, is_portal_user
        )
        VALUES ($1, $2, $3, 'Setup', 'Pending', $4, TRUE)
        "#,
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company_id)
    .bind(email)
    .execute(pool)
    .await
    .expect("seed contact awaiting setup");
    id
}

/// Insert a portal setup token for `contact_id` with the given expiry and
/// return the plaintext token (`{contact_id}.{secret}`) the customer would
/// receive in their email. Mirrors `ContactService::insert_setup_token`.
async fn seed_setup_token(
    pool: &PgPool,
    contact_id: Uuid,
    secret: &str,
    expires_at: chrono::DateTime<chrono::Utc>,
) -> String {
    let hash = mokosh_server::utils::crypto::hash_password(secret).expect("hash setup secret");
    sqlx::query(
        r#"
        INSERT INTO portal_setup_tokens (tenant_id, contact_id, token_hash, expires_at)
        VALUES ($1, $2, $3, $4)
        "#,
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(contact_id)
    .bind(&hash)
    .bind(expires_at)
    .execute(pool)
    .await
    .expect("seed setup token");
    format!("{contact_id}.{secret}")
}

/// Seed an invoice for a company. Only the NOT-NULL-without-default
/// columns are supplied; the rest take their schema defaults. Returns
/// the invoice id.
async fn seed_invoice(pool: &PgPool, company_id: Uuid, number: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO invoices (
            id, tenant_id, invoice_number, company_id, invoice_date, due_date,
            status, total, balance_due
        )
        VALUES ($1, $2, $3, $4, '2026-01-01', '2026-01-31', 'sent', 100, 100)
        "#,
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(number)
    .bind(company_id)
    .execute(pool)
    .await
    .expect("seed invoice");
    id
}

/// Seed a KB article with explicit visibility / status / company scope.
/// `published_at` is stamped only for `published`, matching the service
/// create path. Mirrors the helper in `tests/knowledge_base.rs`.
async fn seed_kb_article(
    pool: &PgPool,
    author_id: Uuid,
    slug: &str,
    visibility: &str,
    status: &str,
    company_ids: &[Uuid],
) {
    sqlx::query(
        r#"
        INSERT INTO kb_articles
            (tenant_id, title, slug, content, visibility, status, author_id,
             company_ids, published_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8,
                CASE WHEN $6 = 'published' THEN NOW() ELSE NULL END)
        "#,
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(slug)
    .bind(slug)
    .bind("body")
    .bind(visibility)
    .bind(status)
    .bind(author_id)
    .bind(company_ids.to_vec())
    .execute(pool)
    .await
    .expect("seed kb article");
}

/// `POST /api/v1/portal/auth/login` -> raw response so the caller can
/// assert on the status of both success and failure paths.
async fn portal_login(app: &common::TestApp, email: &str, password: &str) -> reqwest::Response {
    app.client
        .post(app.url("/api/v1/portal/auth/login"))
        .json(&serde_json::json!({
            "tenant_slug": "default",
            "email": email,
            "password": password,
        }))
        .send()
        .await
        .expect("send portal login")
}

/// Log in as a portal contact and return the access token. Panics on a
/// non-2xx login (callers here always seed a valid contact first).
async fn portal_token(app: &common::TestApp, email: &str) -> String {
    let resp = portal_login(app, email, PORTAL_PASSWORD).await;
    assert!(
        resp.status().is_success(),
        "portal login expected 2xx, got {}",
        resp.status()
    );
    let body: serde_json::Value = resp.json().await.expect("portal login JSON");
    body["access_token"]
        .as_str()
        .expect("login response has access_token")
        .to_string()
}

// AC1: login authenticates a contact and issues a contact-scoped
// session; staff tokens are rejected on the portal and portal tokens are
// rejected on staff routes.
#[sqlx::test]
async fn portal_login_is_contact_scoped(pool: PgPool) {
    let (_admin_id, admin_email, admin_pw) = common::seed_admin(&pool).await;
    let company = seed_company(&pool, "Acme Co").await;
    seed_portal_contact(&pool, company, "contact@acme.example").await;
    // A contact row without portal access must not be able to log in.
    let no_access = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO contacts (id, tenant_id, company_id, first_name, last_name, email) VALUES ($1, $2, $3, 'No', 'Portal', 'noportal@acme.example')",
    )
    .bind(no_access)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company)
    .execute(&pool)
    .await
    .expect("seed non-portal contact");

    let app = common::boot(pool).await;

    // Happy path.
    let ok = portal_login(&app, "contact@acme.example", PORTAL_PASSWORD).await;
    assert!(ok.status().is_success(), "valid portal login should 2xx");
    let body: serde_json::Value = ok.json().await.expect("login JSON");
    assert!(
        body["access_token"].as_str().is_some(),
        "login returns an access token"
    );
    assert_eq!(
        body["contact"]["company_id"].as_str(),
        Some(company.to_string().as_str()),
        "the session carries the contact's company scope"
    );

    // Wrong password -> 401.
    let bad = portal_login(&app, "contact@acme.example", "wrong-password").await;
    assert_eq!(bad.status(), reqwest::StatusCode::UNAUTHORIZED);

    // Contact without portal access -> 401 (enumeration-resistant).
    let no = portal_login(&app, "noportal@acme.example", PORTAL_PASSWORD).await;
    assert_eq!(no.status(), reqwest::StatusCode::UNAUTHORIZED);

    let portal = portal_token(&app, "contact@acme.example").await;
    let staff = common::login(&app, &admin_email, &admin_pw).await;

    // A staff token must NOT be accepted on the portal surface.
    let staff_on_portal = app
        .client
        .get(app.url("/api/v1/portal/auth/me"))
        .bearer_auth(&staff)
        .send()
        .await
        .expect("staff token on portal");
    assert_eq!(
        staff_on_portal.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "staff token rejected on /portal/auth/me"
    );

    // A portal token must NOT be accepted on the staff surface.
    let portal_on_staff = app
        .client
        .get(app.url("/api/v1/auth/me"))
        .bearer_auth(&portal)
        .send()
        .await
        .expect("portal token on staff");
    assert_eq!(
        portal_on_staff.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "portal token rejected on /auth/me"
    );

    // Sanity: the portal token DOES work on its own surface.
    let me = app
        .client
        .get(app.url("/api/v1/portal/auth/me"))
        .bearer_auth(&portal)
        .send()
        .await
        .expect("portal me");
    assert!(me.status().is_success(), "portal token works on the portal");
}

// AC2 + AC6 (tickets): a portal contact can create a ticket and list
// only their own company's tickets, with populated DTOs; one company's
// contact cannot read another company's ticket.
#[sqlx::test]
async fn portal_tickets_are_company_scoped(pool: PgPool) {
    // create_portal_ticket attributes the ticket to an admin/manager in
    // the tenant, so one must exist.
    let _admin = common::seed_admin(&pool).await;
    let company_a = seed_company(&pool, "Company A").await;
    let company_b = seed_company(&pool, "Company B").await;
    seed_portal_contact(&pool, company_a, "a@a.example").await;
    seed_portal_contact(&pool, company_b, "b@b.example").await;
    let app = common::boot(pool).await;

    let token_a = portal_token(&app, "a@a.example").await;
    let token_b = portal_token(&app, "b@b.example").await;

    // Contact A files a ticket.
    let created = app
        .client
        .post(app.url("/api/v1/portal/tickets"))
        .bearer_auth(&token_a)
        .json(&serde_json::json!({ "title": "Printer down" }))
        .send()
        .await
        .expect("create portal ticket");
    assert!(
        created.status().is_success(),
        "portal ticket create should 2xx, got {}",
        created.status()
    );
    let ticket: serde_json::Value = created.json().await.expect("ticket JSON");
    let ticket_id = ticket["id"].as_str().expect("ticket id").to_string();
    assert_eq!(ticket["title"].as_str(), Some("Printer down"));
    // Populated DTO (F3): the joined ticket number is present, not blank.
    assert!(
        ticket["ticket_number"]
            .as_str()
            .map(|n| !n.is_empty())
            .unwrap_or(false),
        "created ticket carries a populated ticket_number"
    );

    // A sees their ticket in the list.
    let list_a: serde_json::Value = app
        .client
        .get(app.url("/api/v1/portal/tickets"))
        .bearer_auth(&token_a)
        .send()
        .await
        .expect("list A tickets")
        .json()
        .await
        .expect("list A JSON");
    assert!(
        list_a["data"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["id"].as_str() == Some(ticket_id.as_str())),
        "company A lists its own ticket"
    );

    // B does NOT see A's ticket.
    let list_b: serde_json::Value = app
        .client
        .get(app.url("/api/v1/portal/tickets"))
        .bearer_auth(&token_b)
        .send()
        .await
        .expect("list B tickets")
        .json()
        .await
        .expect("list B JSON");
    assert!(
        !list_b["data"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["id"].as_str() == Some(ticket_id.as_str())),
        "company B must not see company A's ticket in its list"
    );

    // B cannot fetch A's ticket by id -> 404 (never confirms existence).
    let get_b = app
        .client
        .get(app.url(&format!("/api/v1/portal/tickets/{ticket_id}")))
        .bearer_auth(&token_b)
        .send()
        .await
        .expect("B fetch A ticket");
    assert_eq!(
        get_b.status(),
        reqwest::StatusCode::NOT_FOUND,
        "cross-company ticket read returns 404"
    );
}

// AC3 + AC6 (invoices): the invoices feed returns only the contact's
// company invoices, and a contact cannot read another company's invoice.
#[sqlx::test]
async fn portal_invoices_are_company_scoped(pool: PgPool) {
    let company_a = seed_company(&pool, "Company A").await;
    let company_b = seed_company(&pool, "Company B").await;
    seed_portal_contact(&pool, company_a, "a@a.example").await;
    let invoice_a = seed_invoice(&pool, company_a, "INV-A-0001").await;
    let invoice_b = seed_invoice(&pool, company_b, "INV-B-0001").await;
    let app = common::boot(pool).await;

    let token_a = portal_token(&app, "a@a.example").await;

    // List returns only company A's invoice.
    let list: serde_json::Value = app
        .client
        .get(app.url("/api/v1/portal/invoices"))
        .bearer_auth(&token_a)
        .send()
        .await
        .expect("list invoices")
        .json()
        .await
        .expect("invoices JSON");
    let rows = list["data"].as_array().expect("data array");
    assert_eq!(rows.len(), 1, "company A sees exactly its own invoice");
    assert_eq!(rows[0]["id"].as_str(), Some(invoice_a.to_string().as_str()));

    // A can read its own invoice.
    let get_a = app
        .client
        .get(app.url(&format!("/api/v1/portal/invoices/{invoice_a}")))
        .bearer_auth(&token_a)
        .send()
        .await
        .expect("A get own invoice");
    assert!(get_a.status().is_success(), "A reads its own invoice");

    // A cannot read company B's invoice -> 404.
    let get_b = app
        .client
        .get(app.url(&format!("/api/v1/portal/invoices/{invoice_b}")))
        .bearer_auth(&token_a)
        .send()
        .await
        .expect("A get B invoice");
    assert_eq!(
        get_b.status(),
        reqwest::StatusCode::NOT_FOUND,
        "cross-company invoice read returns 404"
    );
}

// AC4: the KB feed returns only articles visible to the contact's
// company: published + (public OR client_specific scoped to the company).
#[sqlx::test]
async fn portal_kb_returns_only_visible_articles(pool: PgPool) {
    let (admin_id, _e, _p) = common::seed_admin(&pool).await;
    let company_a = seed_company(&pool, "Company A").await;
    let company_b = seed_company(&pool, "Company B").await;
    seed_portal_contact(&pool, company_a, "a@a.example").await;

    // Visible to A.
    seed_kb_article(&pool, admin_id, "public-pub", "public", "published", &[]).await;
    seed_kb_article(
        &pool,
        admin_id,
        "client-a-pub",
        "client_specific",
        "published",
        &[company_a],
    )
    .await;
    // NOT visible to A.
    seed_kb_article(&pool, admin_id, "public-draft", "public", "draft", &[]).await;
    seed_kb_article(
        &pool,
        admin_id,
        "internal-pub",
        "internal",
        "published",
        &[],
    )
    .await;
    seed_kb_article(
        &pool,
        admin_id,
        "client-b-pub",
        "client_specific",
        "published",
        &[company_b],
    )
    .await;

    let app = common::boot(pool).await;
    let token_a = portal_token(&app, "a@a.example").await;

    let feed: serde_json::Value = app
        .client
        .get(app.url("/api/v1/portal/kb"))
        .bearer_auth(&token_a)
        .send()
        .await
        .expect("portal kb")
        .json()
        .await
        .expect("kb JSON");
    let slugs: Vec<&str> = feed["data"]
        .as_array()
        .expect("kb data array")
        .iter()
        .filter_map(|a| a["slug"].as_str())
        .collect();

    assert!(slugs.contains(&"public-pub"), "public published is visible");
    assert!(
        slugs.contains(&"client-a-pub"),
        "client_specific scoped to A is visible"
    );
    assert!(
        !slugs.contains(&"public-draft"),
        "drafts are hidden from the portal"
    );
    assert!(
        !slugs.contains(&"internal-pub"),
        "internal articles are hidden from the portal"
    );
    assert!(
        !slugs.contains(&"client-b-pub"),
        "another company's client_specific article is hidden"
    );
    assert_eq!(slugs.len(), 2, "exactly the two A-visible articles appear");
}

// PMS-136 AC4 + AC5 + AC6 + AC7: redeeming a setup token sets the contact's
// portal password (204), replay is 410, an expired token is 400, and after
// set-password the PMS-26 login endpoint accepts the new credential.
#[sqlx::test]
async fn portal_setup_password_redeem_replay_expire(pool: PgPool) {
    let company = seed_company(&pool, "Acme Co").await;
    let contact = seed_contact_awaiting_setup(&pool, company, "setup@acme.example").await;
    let valid_token = seed_setup_token(
        &pool,
        contact,
        "setup-secret-abcdefghijklmnopqrstuvwxyz",
        chrono::Utc::now() + chrono::Duration::hours(72),
    )
    .await;
    let app = common::boot(pool.clone()).await;

    let new_password = "fresh-portal-pw-9876";

    // AC4: valid token -> 204 and portal_password_hash is set.
    let ok = app
        .client
        .post(app.url("/api/v1/portal/auth/setup-password"))
        .json(&serde_json::json!({ "token": valid_token, "password": new_password }))
        .send()
        .await
        .expect("setup-password");
    assert_eq!(
        ok.status(),
        reqwest::StatusCode::NO_CONTENT,
        "valid setup token returns 204"
    );
    let hash: Option<String> =
        sqlx::query_scalar("SELECT portal_password_hash FROM contacts WHERE id = $1")
            .bind(contact)
            .fetch_one(&pool)
            .await
            .expect("select hash");
    assert!(
        hash.is_some(),
        "set-password writes contacts.portal_password_hash"
    );

    // AC7: the new credential works on the PMS-26 login endpoint.
    let login = portal_login(&app, "setup@acme.example", new_password).await;
    assert!(
        login.status().is_success(),
        "login with the new password should 2xx, got {}",
        login.status()
    );
    let body: serde_json::Value = login.json().await.expect("login JSON");
    assert!(
        body["access_token"].as_str().is_some(),
        "login returns a portal-scoped access token"
    );

    // AC5: replaying the same (now used) token -> 410 Gone.
    let replay = app
        .client
        .post(app.url("/api/v1/portal/auth/setup-password"))
        .json(&serde_json::json!({ "token": valid_token, "password": "another-pw-12345" }))
        .send()
        .await
        .expect("replay setup-password");
    assert_eq!(
        replay.status(),
        reqwest::StatusCode::GONE,
        "replaying a used token returns 410"
    );

    // AC6: an expired token -> 400.
    let expired_contact = seed_contact_awaiting_setup(&pool, company, "expired@acme.example").await;
    let expired_token = seed_setup_token(
        &pool,
        expired_contact,
        "expired-secret-abcdefghijklmnop",
        chrono::Utc::now() - chrono::Duration::hours(1),
    )
    .await;
    let expired = app
        .client
        .post(app.url("/api/v1/portal/auth/setup-password"))
        .json(&serde_json::json!({ "token": expired_token, "password": new_password }))
        .send()
        .await
        .expect("expired setup-password");
    assert_eq!(
        expired.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "an expired token returns 400"
    );

    // A garbage token -> 400 (indistinguishable from expired/invalid).
    let bogus = app
        .client
        .post(app.url("/api/v1/portal/auth/setup-password"))
        .json(&serde_json::json!({
            "token": format!("{contact}.not-the-real-secret"),
            "password": new_password,
        }))
        .send()
        .await
        .expect("bogus setup-password");
    assert_eq!(
        bogus.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "an unknown token returns 400"
    );
}

// AC1 (unauth) + AC5 (no route returns 501): unauthenticated calls to
// the protected portal routes get 401, never 501 or a 500.
#[sqlx::test]
async fn portal_protected_routes_require_auth_and_never_501(pool: PgPool) {
    let app = common::boot(pool).await;
    let some_id = Uuid::new_v4();
    let routes = [
        "/api/v1/portal/auth/me".to_string(),
        "/api/v1/portal/tickets".to_string(),
        format!("/api/v1/portal/tickets/{some_id}"),
        "/api/v1/portal/invoices".to_string(),
        format!("/api/v1/portal/invoices/{some_id}"),
        "/api/v1/portal/kb".to_string(),
    ];
    for path in routes {
        let resp = app
            .client
            .get(app.url(&path))
            .send()
            .await
            .expect("unauth portal request");
        assert_eq!(
            resp.status(),
            reqwest::StatusCode::UNAUTHORIZED,
            "{path} should 401 without a token"
        );
        assert_ne!(
            resp.status(),
            reqwest::StatusCode::NOT_IMPLEMENTED,
            "{path} must never return 501"
        );
    }
}

/// Read the persistent portal lockout columns for a contact (PMS-501).
async fn read_lockout(
    pool: &PgPool,
    contact_id: Uuid,
) -> (i32, Option<chrono::DateTime<chrono::Utc>>) {
    sqlx::query_as(
        "SELECT portal_failed_login_count, portal_locked_until FROM contacts WHERE id = $1",
    )
    .bind(contact_id)
    .fetch_one(pool)
    .await
    .expect("read portal lockout columns")
}

// PMS-501: repeated failed portal logins persist a failed-attempt counter
// and arm a temporary account lockout, so a brute-force run is throttled
// in a way that survives a process restart (the in-memory limiter alone
// does not).
#[sqlx::test]
async fn portal_login_locks_account_after_repeated_failures(pool: PgPool) {
    let company = seed_company(&pool, "Acme Co").await;
    let contact = seed_portal_contact(&pool, company, "victim@acme.example").await;
    let app = common::boot(pool).await;

    // Five wrong-password attempts. The first five reach the service (the
    // per-account in-memory quota is 5/min); the fifth crosses the lockout
    // threshold and arms `portal_locked_until`.
    for _ in 0..5 {
        let resp = portal_login(&app, "victim@acme.example", "wrong-password").await;
        assert!(
            matches!(
                resp.status(),
                reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::TOO_MANY_REQUESTS
            ),
            "a failed attempt is 401 or 429, got {}",
            resp.status()
        );
    }

    // The durable lockout state is recorded on the contact row.
    let (count, locked_until) = read_lockout(&app.pool, contact).await;
    assert!(count >= 5, "failed counter persisted, got {count}");
    let locked_until = locked_until.expect("lockout window armed");
    assert!(
        locked_until > chrono::Utc::now(),
        "lockout window is in the future"
    );

    // Even the correct password is now rejected (not a 2xx) while the
    // account is locked / rate-limited.
    let blocked = portal_login(&app, "victim@acme.example", PORTAL_PASSWORD).await;
    assert!(
        !blocked.status().is_success(),
        "correct password must not succeed during lockout, got {}",
        blocked.status()
    );
}

// PMS-501: a handful of failures below the threshold does not lock, and a
// successful login clears the failed-attempt counter so a legitimate user
// is never penalised for an earlier typo.
#[sqlx::test]
async fn portal_login_success_resets_failed_counter(pool: PgPool) {
    let company = seed_company(&pool, "Acme Co").await;
    let contact = seed_portal_contact(&pool, company, "user@acme.example").await;
    let app = common::boot(pool).await;

    // Two wrong attempts: counts but does not lock (threshold is 5).
    for _ in 0..2 {
        let resp = portal_login(&app, "user@acme.example", "wrong-password").await;
        assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
    }
    let (count, locked_until) = read_lockout(&app.pool, contact).await;
    assert_eq!(count, 2, "two failures counted");
    assert!(locked_until.is_none(), "under threshold: no lockout");

    // A correct login succeeds and clears the counter.
    let ok = portal_login(&app, "user@acme.example", PORTAL_PASSWORD).await;
    assert!(ok.status().is_success(), "correct password should 2xx");
    let (count, locked_until) = read_lockout(&app.pool, contact).await;
    assert_eq!(count, 0, "successful login resets the counter");
    assert!(
        locked_until.is_none(),
        "successful login clears any lockout"
    );
}

/// PMS-693: `register_failed_login` derives the lock window in SQL from the
/// post-increment counter, so that expression is a second copy of the schedule
/// `lockout_until` defines in Rust. Pin the two together across the whole
/// documented table (`1..=12` spans below-threshold, the doubling ramp and the
/// 3600s cap) so neither can drift.
#[sqlx::test]
async fn portal_lock_seconds_sql_matches_rust_schedule(pool: PgPool) {
    let sql = format!(
        "SELECT {}",
        mokosh_server::modules::portal::lock_seconds_sql("$1::int")
    );
    let now = chrono::Utc::now();
    for n in 1..=12 {
        let sql_secs: Option<f64> = sqlx::query_scalar(&sql)
            .bind(n)
            .fetch_one(&pool)
            .await
            .expect("evaluate the SQL lockout schedule");
        let rust_secs = mokosh_server::modules::portal::lockout_until(n, now)
            .map(|until| (until - now).num_seconds());
        assert_eq!(
            sql_secs.map(|s| s as i64),
            rust_secs,
            "SQL and Rust portal lockout schedules disagree at failed_count = {n}"
        );
    }
}

// PMS-806: a contact may now link to several companies, but portal scoping is
// deliberately UNCHANGED by that PR: a portal session still resolves the
// contact's PRIMARY company only. Broadening it is a security decision tracked
// in PMS-807. This test pins the narrow scope so that decision cannot be made
// by accident.
#[sqlx::test]
async fn portal_session_for_a_two_company_contact_sees_only_the_primary_company(pool: PgPool) {
    let (admin_id, _email, _password) = common::seed_admin(&pool).await;
    let primary = seed_company(&pool, "Primary Co").await;
    let secondary = seed_company(&pool, "Secondary Co").await;
    let contact = seed_portal_contact(&pool, primary, "dual@dual.example").await;

    // Link the same contact to BOTH companies, primary first.
    for (company, is_primary) in [(primary, true), (secondary, false)] {
        sqlx::query(
            "INSERT INTO contact_companies (tenant_id, contact_id, company_id, is_primary) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(common::DEFAULT_TENANT_ID)
        .bind(contact)
        .bind(company)
        .bind(is_primary)
        .execute(&pool)
        .await
        .expect("link contact to company");
    }

    // A ticket sitting on the SECONDARY company. The portal must not surface it.
    let secondary_ticket =
        seed_ticket_for_company(&pool, secondary, admin_id, "Secondary work").await;
    let primary_ticket = seed_ticket_for_company(&pool, primary, admin_id, "Primary work").await;

    let app = common::boot(pool).await;
    let login: serde_json::Value = portal_login(&app, "dual@dual.example", PORTAL_PASSWORD)
        .await
        .json()
        .await
        .expect("portal login JSON");
    assert_eq!(
        login["contact"]["company_id"].as_str(),
        Some(primary.to_string().as_str()),
        "the session resolves the PRIMARY company, not the link set"
    );
    let token = login["access_token"]
        .as_str()
        .expect("access token")
        .to_string();

    let list: serde_json::Value = app
        .client
        .get(app.url("/api/v1/portal/tickets"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list portal tickets")
        .json()
        .await
        .expect("portal ticket list JSON");
    let ids: Vec<&str> = list["data"]
        .as_array()
        .expect("data array")
        .iter()
        .filter_map(|t| t["id"].as_str())
        .collect();
    assert!(
        ids.contains(&primary_ticket.to_string().as_str()),
        "the primary company's ticket is visible: {ids:?}"
    );
    assert!(
        !ids.contains(&secondary_ticket.to_string().as_str()),
        "the second company's ticket must NOT be visible until PMS-807 decides: {ids:?}"
    );
}

/// Seed a minimal ticket under `company_id`, reusing the tenant's first status,
/// priority and queue. Returns its id.
async fn seed_ticket_for_company(
    pool: &PgPool,
    company_id: Uuid,
    created_by: Uuid,
    title: &str,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO tickets (
            id, tenant_id, ticket_number, title, company_id,
            status_id, priority_id, queue_id, source, created_by_id
        )
        SELECT $1, $2, $3, $4, $5,
               (SELECT id FROM ticket_statuses WHERE tenant_id = $2 ORDER BY sort_order LIMIT 1),
               (SELECT id FROM ticket_priorities WHERE tenant_id = $2 ORDER BY sort_order LIMIT 1),
               (SELECT id FROM ticket_queues WHERE tenant_id = $2 ORDER BY name LIMIT 1),
               'portal', $6
        "#,
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(format!("TKT-{}", &id.to_string()[..8]))
    .bind(title)
    .bind(company_id)
    .bind(created_by)
    .execute(pool)
    .await
    .expect("seed ticket");
    id
}

/// PMS-812: deleting a company unlinks its contacts instead of deleting them,
/// so a portal contact can end up with `company_id IS NULL`. Every portal read
/// is company-scoped, so there is no session to issue - but the rejection has
/// to be an explicit 401, not the 500 the old non-null `Uuid` decode produced.
#[sqlx::test]
async fn portal_login_rejects_a_contact_whose_company_was_deleted(pool: PgPool) {
    let company = seed_company(&pool, "Doomed Co").await;
    let contact = seed_portal_contact(&pool, company, "orphan@doomed.example").await;

    sqlx::query("DELETE FROM companies WHERE id = $1")
        .bind(company)
        .execute(&pool)
        .await
        .expect("delete the contact's only company");

    // The contact survives the delete with a NULL company_id (migration 110's
    // ON DELETE SET NULL). Under the old CASCADE the row was gone, and the 401
    // below would have proved nothing.
    let company_id: Option<Option<Uuid>> =
        sqlx::query_scalar("SELECT company_id FROM contacts WHERE id = $1")
            .bind(contact)
            .fetch_optional(&pool)
            .await
            .expect("read the contact back");
    assert_eq!(
        company_id,
        Some(None),
        "the portal contact survives with no company"
    );

    let app = common::boot(pool).await;
    let resp = portal_login(&app, "orphan@doomed.example", PORTAL_PASSWORD).await;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    assert_eq!(
        status,
        reqwest::StatusCode::UNAUTHORIZED,
        "a company-less portal contact is rejected explicitly, not with a decode 500 \
         (body: {body})"
    );
}
