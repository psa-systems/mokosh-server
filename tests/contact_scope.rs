//! mokosh-contact-login prompt 008: server-side capability + scope
//! enforcement across the primary dual-plane endpoints. The prompt-008
//! scope is deliberately narrower than the full sweep: this suite pins
//! the shape matrix on ~1 endpoint per swept module (tickets, invoices,
//! quotes, and the staff-only Companies/Contacts CRM), plus one
//! stale-JWT scenario. Deferred surfaces (contracts, assets, projects,
//! time-entries, KB, forms, approvals, notifications, sub-user invite)
//! are tracked in the prompt-008 report + follow-up ticket.
//!
//! Every test names the failure mode it pins so a regression fires with
//! a message that points at the missing gate, not just "assertion left
//! != right".

mod common;

use reqwest::StatusCode;
use sqlx::PgPool;
use uuid::Uuid;

/// Seed a Company + Contact + granted portal access under
/// [`common::DEFAULT_TENANT_ID`]. `role_names` picks which built-in
/// role(s) to assign the contact (see migration 142 for the three
/// defaults: `Billing Contact` / `Support Contact` / `Read-Only`).
///
/// Returns `(company_id, contact_id, email, access_token)`. The token
/// is what a downstream test attaches as the contact-plane bearer.
async fn seed_contact_with_roles(
    app: &common::TestApp,
    pool: &PgPool,
    email_local: &str,
    role_names: &[&str],
) -> (Uuid, Uuid, String, String) {
    seed_contact_with_roles_in_tenant(
        app,
        pool,
        common::DEFAULT_TENANT_ID,
        email_local,
        role_names,
    )
    .await
}

/// Same as [`seed_contact_with_roles`] but under a caller-picked tenant so
/// cross-tenant tests can seed a Contact in an alternate tenant.
async fn seed_contact_with_roles_in_tenant(
    app: &common::TestApp,
    pool: &PgPool,
    tenant_id: Uuid,
    email_local: &str,
    role_names: &[&str],
) -> (Uuid, Uuid, String, String) {
    let email = format!("{email_local}@contact-scope.example");
    let company_id = Uuid::new_v4();
    // The MSP admin identifies portal companies by `portal_slug`; the
    // login flow rejects a company row without one, so we stamp a
    // deterministic slug per company here.
    let slug = format!("cs-{}", &Uuid::new_v4().simple().to_string()[..12]);
    sqlx::query("INSERT INTO companies (id, tenant_id, name, portal_slug) VALUES ($1, $2, $3, $4)")
        .bind(company_id)
        .bind(tenant_id)
        .bind(format!("Contact Scope Co {email_local}"))
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

    // Grant the requested portal role(s). `grant_portal_access` mints
    // the setup token + row assignment set in one go; mirrors what the
    // staff-side UI does.
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

    // Redeem the magic link, then log in, so the returned bearer is
    // the same one the SPA sees. The `setup_link` shape is
    // `{app_url}/portal/{slug}/set-password?token={contact_id}.{secret}`.
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

/// Seed one plain (non-portal) contact + company under the given
/// tenant. Used when a test needs to open a ticket for a company that
/// is NOT the caller's own Company (for the mismatched-scope case).
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

// ============================================================================
// TICKETS - contact-plane sweep
// ============================================================================

/// prompt 008 shape row 1: contact WITH cap + matching company scope ->
/// 201 (creating a ticket succeeds).
#[sqlx::test]
async fn tickets_create_with_cap_and_matching_scope_returns_ok(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (company_id, _contact_id, _email, token) =
        seed_contact_with_roles(&app, &pool, "t-create-ok", &["Support Contact"]).await;

    let resp = app
        .client
        .post(app.url("/api/v1/tickets"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "title": "printer stuck",
            // prompt 008: server MUST override this to the session's Company.
            "company_id": company_id,
            "description": "the office printer is jammed again",
            "custom_fields": {},
        }))
        .send()
        .await
        .expect("send create");
    let status = resp.status();
    let body = resp.text().await.expect("body");
    assert!(
        status.is_success(),
        "prompt 008: contact with tickets:write must create a ticket, got {status} body={body}"
    );
    let value: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(
        value["company_id"].as_str(),
        Some(company_id.to_string().as_str()),
        "prompt 008: server-stamped company_id must equal the session's own"
    );
    assert_eq!(
        value["source"].as_str(),
        Some("portal"),
        "prompt 008: contact-originated ticket must record source=portal"
    );
}

/// prompt 008 shape row 2: contact WITH cap but a mismatched
/// `company_id` in the body -> the server silently overrides to the
/// session's Company so the created ticket is still on the caller's
/// own Company. Nothing can be widened by a client-supplied field.
#[sqlx::test]
async fn tickets_create_body_company_id_is_ignored_for_contact(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (own_company, _c, _e, token) =
        seed_contact_with_roles(&app, &pool, "t-create-scope", &["Support Contact"]).await;
    let other_company = seed_plain_company(&pool, common::DEFAULT_TENANT_ID, "other-co").await;

    let resp = app
        .client
        .post(app.url("/api/v1/tickets"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "title": "cross-company probe",
            // A spoofed `company_id` MUST NOT make the ticket land on
            // another Company. The server forces the session's own.
            "company_id": other_company,
            "custom_fields": {},
        }))
        .send()
        .await
        .expect("send create");
    assert!(resp.status().is_success());
    let value: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(
        value["company_id"].as_str(),
        Some(own_company.to_string().as_str()),
        "prompt 008: contact create MUST override a spoofed body company_id \
         to the session's own"
    );
}

/// prompt 008 shape row 3: contact WITHOUT the tickets:read cap ->
/// listing tickets returns 403 even though the caller is
/// authenticated. Belt-and-braces on the DB-loaded cap set (JWT `caps`
/// is UI-only).
#[sqlx::test]
async fn tickets_list_without_cap_returns_403(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    // Billing Contact has NO tickets:* capability, so it must be
    // refused on the tickets list.
    let (_c, _cid, _e, token) =
        seed_contact_with_roles(&app, &pool, "t-list-nocap", &["Billing Contact"]).await;

    let resp = app
        .client
        .get(app.url("/api/v1/tickets"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send list");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "prompt 008: contact without tickets:read must 403 on list"
    );
}

/// prompt 008 shape row 4: staff caller on the same endpoint keeps its
/// 200. Regression pin: adding contact-plane enforcement must not
/// break the staff branch.
#[sqlx::test]
async fn tickets_list_staff_bypass_returns_200(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let staff_token = common::login(&app, &email, &password).await;
    let resp = app
        .client
        .get(app.url("/api/v1/tickets"))
        .bearer_auth(&staff_token)
        .send()
        .await
        .expect("staff list");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "prompt 008: staff callers must keep their 200 on /tickets"
    );
}

/// prompt 008: contact GET one ticket that lives on another Company in
/// the same tenant -> 404 (not 403). Enumeration-resistant.
#[sqlx::test]
async fn tickets_get_foreign_company_returns_404(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (_own_company, _c, _e, token) =
        seed_contact_with_roles(&app, &pool, "t-get-foreign", &["Support Contact"]).await;
    let other_company = seed_plain_company(&pool, common::DEFAULT_TENANT_ID, "foreign-co").await;

    // Seed a ticket on the OTHER Company directly. Requires a valid
    // staff `created_by_id` so grab one from the migration-seeded set.
    let admin_id: Uuid = {
        let (id, _e, _p) = common::seed_admin(&pool).await;
        id
    };
    let default_status: Uuid = sqlx::query_scalar(
        "SELECT id FROM ticket_statuses WHERE tenant_id = $1 AND is_default = TRUE LIMIT 1",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(&pool)
    .await
    .expect("default status");
    let default_priority: Uuid = sqlx::query_scalar(
        "SELECT id FROM ticket_priorities WHERE tenant_id = $1 AND is_default = TRUE LIMIT 1",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(&pool)
    .await
    .expect("default priority");
    let default_queue: Uuid = sqlx::query_scalar(
        "SELECT id FROM ticket_queues WHERE tenant_id = $1 AND is_default = TRUE LIMIT 1",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(&pool)
    .await
    .expect("default queue");
    let ticket_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO tickets (id, tenant_id, ticket_number, title, status_id, priority_id, \
         queue_id, source, company_id, created_by_id) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, 'internal', $8, $9)",
    )
    .bind(ticket_id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(format!("CS-{}", &ticket_id.simple().to_string()[..8]))
    .bind("foreign ticket")
    .bind(default_status)
    .bind(default_priority)
    .bind(default_queue)
    .bind(other_company)
    .bind(admin_id)
    .execute(&pool)
    .await
    .expect("seed foreign ticket");

    let resp = app
        .client
        .get(app.url(&format!("/api/v1/tickets/{ticket_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("get");
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "prompt 008: cross-Company ticket must 404, not 403 (no enumeration)"
    );
}

/// prompt 008: contact POST notes must reject `internal` note_type
/// even when the contact holds `tickets:comment`. Customer back-
/// channel notes never leak into internal agent discussion.
#[sqlx::test]
async fn tickets_add_note_contact_cannot_post_internal(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (company_id, _c, _e, token) =
        seed_contact_with_roles(&app, &pool, "t-note-internal", &["Support Contact"]).await;

    // Create a ticket first (via the contact path so ownership is
    // guaranteed).
    let create = app
        .client
        .post(app.url("/api/v1/tickets"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "title": "n-internal ticket",
            "company_id": company_id,
            "custom_fields": {},
        }))
        .send()
        .await
        .expect("create ticket");
    let created: serde_json::Value = create.json().await.expect("json");
    let ticket_id = created["id"].as_str().expect("id");

    let resp = app
        .client
        .post(app.url(&format!("/api/v1/tickets/{ticket_id}/notes")))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "note_type": "internal",
            "content": "back-channel probe",
        }))
        .send()
        .await
        .expect("post note");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "prompt 008: contact must not post `internal` notes"
    );
}

// ============================================================================
// STALE-JWT scenario: cap present in the JWT claim but the role has
// been revoked in the DB. The DB-load enforcement means the next
// request 403s even though the JWT is still valid.
// ============================================================================

#[sqlx::test]
async fn stale_jwt_after_role_revoke_returns_403(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (_company_id, contact_id, _email, token) =
        seed_contact_with_roles(&app, &pool, "stale-jwt", &["Support Contact"]).await;

    // Sanity: the fresh token can list tickets.
    let resp = app
        .client
        .get(app.url("/api/v1/tickets"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list pre-revoke");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "prompt 008: fresh token with tickets:read must 200 pre-revoke"
    );

    // Revoke the assignment directly (mirrors what
    // `PUT /api/v1/contacts/{id}/portal-roles` would do with an empty
    // role set).
    sqlx::query("DELETE FROM contact_role_assignments WHERE contact_id = $1 AND tenant_id = $2")
        .bind(contact_id)
        .bind(common::DEFAULT_TENANT_ID)
        .execute(&pool)
        .await
        .expect("revoke role");

    // Re-issue with the SAME (still-valid) access token. Because
    // `require_capability` reads `portal_roles` per request instead of
    // trusting `caps` in the JWT, the next call must 403.
    let resp = app
        .client
        .get(app.url("/api/v1/tickets"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list post-revoke");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "prompt 008: DB-load enforcement must 403 on next request after revoke, \
         not wait for the 15-min JWT TTL"
    );
}

// ============================================================================
// TENANT ISOLATION: a Contact in tenant A pointed at a row in tenant B
// must 401 - the JWT's `tid` scopes the whole request tree.
// ============================================================================

#[sqlx::test]
async fn cross_tenant_invoice_id_returns_404(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    // Contact under DEFAULT_TENANT_ID.
    let (_company_id, _c, _e, token) =
        seed_contact_with_roles(&app, &pool, "cross-tenant", &["Billing Contact"]).await;

    // An invoice that lives in another tenant. Invoices have no
    // dependent lookup rows (statuses/priorities), so this is the
    // clean cross-tenant fixture; the same scoping code path runs
    // for tickets/quotes.
    let (other_tenant, _other_admin_id, _e, _p) =
        common::seed_tenant_with_admin(&pool, "other-tenant-cs").await;
    let other_company = seed_plain_company(&pool, other_tenant, "other-tenant-co").await;
    let invoice_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO invoices (id, tenant_id, invoice_number, company_id, status, \
         invoice_date, due_date, subtotal, total, amount_paid, balance_due) \
         VALUES ($1, $2, $3, $4, 'sent', CURRENT_DATE, CURRENT_DATE + 30, \
         100, 100, 0, 100)",
    )
    .bind(invoice_id)
    .bind(other_tenant)
    .bind(format!("OT-{}", &invoice_id.simple().to_string()[..8]))
    .bind(other_company)
    .execute(&pool)
    .await
    .expect("seed cross-tenant invoice");

    let resp = app
        .client
        .get(app.url(&format!("/api/v1/invoices/{invoice_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("cross-tenant get");
    // The service scopes reads by the caller's tenant, so the row is
    // simply not visible and we get a 404. Same enumeration-resistant
    // shape as the same-tenant foreign-Company case.
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "prompt 008: cross-tenant invoice lookup MUST 404, never 200"
    );
}

// ============================================================================
// INVOICES - contact list (shape row 1 + row 2 rolled into one test)
// ============================================================================

#[sqlx::test]
async fn invoices_list_scoped_to_contact_company(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (own_company, _c, _e, token) =
        seed_contact_with_roles(&app, &pool, "inv-list", &["Billing Contact"]).await;
    let other_company = seed_plain_company(&pool, common::DEFAULT_TENANT_ID, "inv-other-co").await;

    // Seed one invoice per Company.
    for (label, cid) in [("MINE", own_company), ("THEIRS", other_company)] {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO invoices (id, tenant_id, invoice_number, company_id, status, \
             invoice_date, due_date, subtotal, total, amount_paid, balance_due) \
             VALUES ($1, $2, $3, $4, 'sent', CURRENT_DATE, CURRENT_DATE + 30, \
             100, 100, 0, 100)",
        )
        .bind(id)
        .bind(common::DEFAULT_TENANT_ID)
        .bind(format!("{label}-{}", &id.simple().to_string()[..8]))
        .bind(cid)
        .execute(&pool)
        .await
        .expect("seed invoice");
    }

    let resp = app
        .client
        .get(app.url("/api/v1/invoices"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list invoices");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "prompt 008: contact with invoices:read must 200 on /invoices"
    );
    let body: serde_json::Value = resp.json().await.expect("json");
    let items = body["data"].as_array().expect("data array");
    // Every returned row must belong to the caller's own Company; a
    // client-supplied `?company_id=...` filter cannot widen the scope
    // because the handler stamps the session's own before querying.
    for row in items {
        assert_eq!(
            row["company_id"].as_str(),
            Some(own_company.to_string().as_str()),
            "prompt 008: /invoices for a contact must only return their Company's rows"
        );
    }
    assert!(
        !items.is_empty(),
        "prompt 008: expected the seeded MINE invoice in the response"
    );
}

#[sqlx::test]
async fn invoices_list_without_cap_returns_403(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    // Support Contact has NO invoices:* cap.
    let (_c, _cid, _e, token) =
        seed_contact_with_roles(&app, &pool, "inv-nocap", &["Support Contact"]).await;
    let resp = app
        .client
        .get(app.url("/api/v1/invoices"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "prompt 008: contact without invoices:read must 403"
    );
}

/// Regression pin: dropping RequireBilling+RequireFinance from the
/// dual-plane invoice list handler must not stop the staff-side gate
/// from rejecting non-finance roles.
#[sqlx::test]
async fn invoices_staff_non_finance_still_403(pool: PgPool) {
    let (_tech_id, tech_email, tech_password) = common::seed_user(
        &pool,
        common::DEFAULT_TENANT_ID,
        "tech@cs.example",
        "technician",
    )
    .await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &tech_email, &tech_password).await;
    let resp = app
        .client
        .get(app.url("/api/v1/invoices"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("staff list");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "prompt 008: swapping RequireFinance into inline check must still 403 \
         a technician on /invoices"
    );
}

// ============================================================================
// QUOTES - accept endpoint (shape row: cap + scope + accept)
// ============================================================================

/// Seed a quote in `sent` status for `company_id` and return its id.
/// The service's `decide_quote` requires the quote to be `sent` with
/// a future (or NULL) `valid_until`.
async fn seed_sent_quote(pool: &PgPool, tenant_id: Uuid, company_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO quotes (id, tenant_id, company_id, title, status, quote_number, \
         subtotal, tax_amount, total) \
         VALUES ($1, $2, $3, $4, 'sent', $5, 100, 0, 100)",
    )
    .bind(id)
    .bind(tenant_id)
    .bind(company_id)
    .bind("sent quote")
    .bind(format!("Q-{}", &id.simple().to_string()[..8]))
    .execute(pool)
    .await
    .expect("seed sent quote");
    id
}

#[sqlx::test]
async fn quotes_contact_accept_flips_status(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (company_id, _c, _e, token) =
        seed_contact_with_roles(&app, &pool, "q-accept", &["Billing Contact"]).await;
    let quote_id = seed_sent_quote(&pool, common::DEFAULT_TENANT_ID, company_id).await;

    let resp = app
        .client
        .post(app.url(&format!("/api/v1/quotes/{quote_id}/accept")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "notes": "looks good" }))
        .send()
        .await
        .expect("accept quote");
    let status = resp.status();
    let body = resp.text().await.expect("body");
    assert!(
        status.is_success(),
        "prompt 008: contact with quotes:accept must succeed, got {status} body={body}"
    );
    let value: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(
        value["status"].as_str(),
        Some("accepted"),
        "prompt 008: accept endpoint must flip status to accepted"
    );
}

#[sqlx::test]
async fn quotes_accept_foreign_company_returns_404(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (_own_company, _c, _e, token) =
        seed_contact_with_roles(&app, &pool, "q-cross", &["Billing Contact"]).await;
    let other_company = seed_plain_company(&pool, common::DEFAULT_TENANT_ID, "q-other-co").await;
    let quote_id = seed_sent_quote(&pool, common::DEFAULT_TENANT_ID, other_company).await;

    let resp = app
        .client
        .post(app.url(&format!("/api/v1/quotes/{quote_id}/accept")))
        .bearer_auth(&token)
        .json(&serde_json::json!({}))
        .send()
        .await
        .expect("accept cross");
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "prompt 008: accepting another Company's quote must 404 (no enumeration)"
    );
}

#[sqlx::test]
async fn quotes_accept_without_cap_returns_403(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    // Support Contact has quotes:* off.
    let (company_id, _c, _e, token) =
        seed_contact_with_roles(&app, &pool, "q-nocap", &["Support Contact"]).await;
    let quote_id = seed_sent_quote(&pool, common::DEFAULT_TENANT_ID, company_id).await;
    let resp = app
        .client
        .post(app.url(&format!("/api/v1/quotes/{quote_id}/accept")))
        .bearer_auth(&token)
        .json(&serde_json::json!({}))
        .send()
        .await
        .expect("accept nocap");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "prompt 008: contact without quotes:accept must 403"
    );
}

#[sqlx::test]
async fn quotes_staff_accept_endpoint_returns_403(pool: PgPool) {
    // Staff use the internal approvals surface, not accept/decline.
    // The contact-plane endpoint must refuse a staff bearer so the
    // wire semantics stay unambiguous.
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let company_id = common::seed_company(&pool).await;
    let quote_id = seed_sent_quote(&pool, common::DEFAULT_TENANT_ID, company_id).await;

    let resp = app
        .client
        .post(app.url(&format!("/api/v1/quotes/{quote_id}/accept")))
        .bearer_auth(&token)
        .json(&serde_json::json!({}))
        .send()
        .await
        .expect("staff accept");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "prompt 008: staff must be redirected to the approvals surface"
    );
}

// ============================================================================
// COMPANIES + CONTACTS staff-only CRM - the contact plane never reaches
// these routes.
// ============================================================================

#[sqlx::test]
async fn companies_list_blocks_contact_bearer(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (_company_id, _c, _e, token) =
        seed_contact_with_roles(&app, &pool, "co-list", &["Read-Only"]).await;
    let resp = app
        .client
        .get(app.url("/api/v1/contacts/companies"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("companies list");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "prompt 008: the Companies + Contacts CRM must 403 on a contact bearer, \
         regardless of what roles the contact holds"
    );
}

#[sqlx::test]
async fn contacts_list_blocks_contact_bearer(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (_company_id, _c, _e, token) =
        seed_contact_with_roles(&app, &pool, "ct-list", &["Read-Only"]).await;
    let resp = app
        .client
        .get(app.url("/api/v1/contacts/contacts"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("contacts list");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "prompt 008: /api/v1/contacts/contacts must 403 on a contact bearer"
    );
}

#[sqlx::test]
async fn companies_list_still_allows_staff(pool: PgPool) {
    // Regression pin: the whole-router layer that rejects contacts
    // must NOT reject staff.
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let resp = app
        .client
        .get(app.url("/api/v1/contacts/companies"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("staff companies");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "prompt 008: staff callers must retain 200 on /contacts/companies"
    );
}

// ============================================================================
// UNAUTHENTICATED baseline: /tickets with no bearer stays 401. The
// prompt-008 sweep must not accidentally open a public surface.
// ============================================================================

#[sqlx::test]
async fn tickets_list_without_bearer_still_401(pool: PgPool) {
    let app = common::boot(pool).await;
    let resp = app
        .client
        .get(app.url("/api/v1/tickets"))
        .send()
        .await
        .expect("no bearer");
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "prompt 008: no bearer must still 401 on a dual-plane endpoint"
    );
}
