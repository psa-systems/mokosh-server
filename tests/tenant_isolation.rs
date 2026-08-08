//! PMS-236: org-tenant isolation integration suite.
//!
//! A user authenticated to Tenant B can never read, write, search, or
//! enumerate Tenant A's data through the API, and tenant-scoped settings and
//! users stay isolated. This is the automated form of the PMS-236 manual QA
//! plan (the issue chose automation over a one-shot manual pass).
//!
//! Relationship to the sibling isolation suites, so the coverage reads as one
//! set and this file does not duplicate them:
//!
//! - `tests/per_user_isolation.rs` (PMS-264) pins the same cross-tenant
//!   read/write denial across modules, but between two tenants whose users are
//!   `technician`. This file uses two tenants whose users are `admin`, which is
//!   the role that matters for the cross-tenant admin guard
//!   (`super_admin`-or-own-tenant): a tenant-scoped `admin` must still be
//!   denied another tenant, whereas `super_admin` is the cross-tenant system
//!   role and would mask the very isolation under test. It also adds the AC
//!   that per-user does not: search scoping, `ticket_number` per-tenant
//!   sequencing, settings/branding/module isolation, and user scoping.
//! - `tests/rls_isolation.rs` (PMS-257) pins the DB-engine face of the policy
//!   (fail-closed read on an unset GUC, `WITH CHECK` on writes) under an
//!   unprivileged `NOBYPASSRLS` role. This file adds the two-real-tenant read
//!   case (`rls_read_scoping_with_guc`): with `app.current_tenant` set to B,
//!   B's row is visible and A's is not, so the isolation does not depend on
//!   the fail-open default.
//!
//! The IDOR-correct response is 404 (existence-hiding), not 403, per the
//! issue. Cross-tenant id reads therefore assert `NOT_FOUND`; the cross-tenant
//! `tenants` admin guard is the one place that deliberately returns 403.
//!
//! Issue Background note that is now stale: it lists billing / notifications /
//! assets / KB as "routes return 501". Those modules have real handlers today
//! (the E2E suite exercises them), so there is no 501 surface left to defer;
//! tracked as a follow-up to update the issue rather than asserting 501s here.

mod common;

use mokosh_server::modules::tenants::TenantService;
use mokosh_server::Database;
use reqwest::StatusCode;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

/// One authenticated admin in their own tenant.
struct Actor {
    tenant_id: Uuid,
    /// The login admin's user id (a real `active` user with a password).
    admin_id: Uuid,
    token: String,
}

/// Stand up a real tenant with the full seeded lookup + `module_config` set
/// (so the in-tenant create paths that fill default status/priority/queue FKs
/// from the caller's tenant succeed) and an `admin` user logged in.
///
/// The tenant is provisioned via `ensure_personal_tenant`, which runs the same
/// `copy_default_config` seeding a normal tenant gets. The tenant `kind` is
/// immaterial to isolation (the boundary is `tenant_id`); the role that matters
/// for this suite is `admin` - the cross-tenant `tenants` guard is
/// super_admin-or-own-tenant, so a tenant-scoped admin must still be denied
/// another tenant. (`TenantService::create_tenant`, the org-create path, is not
/// used here: it omits the NOT-NULL `tenants.kind` column and 500s - tracked
/// separately.)
async fn provision(pool: &PgPool, app: &common::TestApp, label: &str) -> Actor {
    provision_with_email(pool, app, &format!("admin-{label}@iso.example")).await
}

/// Same as [`provision`], but the login admin's email is caller-chosen so two
/// tenants can share an email (the `UNIQUE(tenant_id, email)` user-scoping AC).
async fn provision_with_email(pool: &PgPool, app: &common::TestApp, login_email: &str) -> Actor {
    let svc = TenantService::new(Database::from_pool(pool.clone()));
    // `owner_id` only keys the tenant provisioning; the real login admin is
    // seeded separately below so it carries a password + `admin` role.
    let owner_id = Uuid::new_v4();
    let tenant_id = svc
        .ensure_personal_tenant(owner_id, None, None)
        .await
        .expect("provision tenant");

    mark_demo_seeded(pool, tenant_id).await;

    let admin_id = Uuid::new_v4();
    common::seed_user_in_tenant(pool, admin_id, tenant_id, login_email, "admin").await;
    let token = login_in_tenant(app, login_email, tenant_id).await;

    Actor {
        tenant_id,
        admin_id,
        token,
    }
}

/// Pre-empt the racy first-visit demo-seed middleware (PMS-157): on the first
/// authenticated request the router spawns a detached task that seeds a demo
/// company + contacts + tickets into a fresh tenant, which would inject
/// nondeterministic rows into the counts/lists under test. The seeder claims a
/// tenant by flipping `settings->>'demo_seeded'`, so pre-setting it makes the
/// claim a no-op. (Demo seeding has its own coverage in `tests/seed_demo.rs`.)
async fn mark_demo_seeded(pool: &PgPool, tenant_id: Uuid) {
    sqlx::query(
        r#"UPDATE tenants
           SET settings = jsonb_set(
                   COALESCE(settings, '{}'::jsonb),
                   '{demo_seeded}', 'true'::jsonb, true)
           WHERE id = $1"#,
    )
    .bind(tenant_id)
    .execute(pool)
    .await
    .expect("mark tenant demo-seeded");
}

/// `POST /auth/login` binds the lookup to `(tenant_id, email)` and falls back
/// to the default tenant when no hint is supplied (PMS-138), so a user in a
/// non-default tenant must name its tenant to be found.
async fn login_in_tenant(app: &common::TestApp, email: &str, tenant_id: Uuid) -> String {
    let resp = app
        .client
        .post(app.url("/api/v1/auth/login"))
        .json(&json!({
            "email": email,
            "password": "test-password-12345",
            "tenant_id": tenant_id,
        }))
        .send()
        .await
        .expect("send login");
    let status = resp.status();
    let text = resp.text().await.expect("login body");
    assert!(
        status.is_success(),
        "login expected 2xx, got {status} body={text}"
    );
    serde_json::from_str::<serde_json::Value>(&text).expect("login JSON")["access_token"]
        .as_str()
        .expect("login response has access_token")
        .to_string()
}

async fn post_json(
    app: &common::TestApp,
    token: &str,
    path: &str,
    body: serde_json::Value,
) -> serde_json::Value {
    let resp = app
        .client
        .post(app.url(path))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .expect("send post");
    let status = resp.status();
    let text = resp.text().await.expect("post body");
    assert!(
        status.is_success(),
        "POST {path} expected 2xx, got {status} body={text}"
    );
    serde_json::from_str(&text).expect("post JSON")
}

/// POST and return the created row's `id`.
async fn create_id(
    app: &common::TestApp,
    token: &str,
    path: &str,
    body: serde_json::Value,
) -> String {
    post_json(app, token, path, body).await["id"]
        .as_str()
        .expect("created row has id")
        .to_string()
}

async fn get_status(app: &common::TestApp, token: &str, path: &str) -> StatusCode {
    app.client
        .get(app.url(path))
        .bearer_auth(token)
        .send()
        .await
        .expect("send get")
        .status()
}

async fn put_status(
    app: &common::TestApp,
    token: &str,
    path: &str,
    body: serde_json::Value,
) -> StatusCode {
    app.client
        .put(app.url(path))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .expect("send put")
        .status()
}

async fn delete_status(app: &common::TestApp, token: &str, path: &str) -> StatusCode {
    app.client
        .delete(app.url(path))
        .bearer_auth(token)
        .send()
        .await
        .expect("send delete")
        .status()
}

async fn get_json(app: &common::TestApp, token: &str, path: &str) -> serde_json::Value {
    let resp = app
        .client
        .get(app.url(path))
        .bearer_auth(token)
        .send()
        .await
        .expect("send get json");
    assert_eq!(resp.status(), StatusCode::OK, "GET {path} expected 200");
    resp.json().await.expect("response JSON")
}

/// GET a paginated list endpoint and return the rows in `data`.
async fn list_data(app: &common::TestApp, token: &str, path: &str) -> Vec<serde_json::Value> {
    get_json(app, token, path).await["data"]
        .as_array()
        .expect("list response has a data array")
        .clone()
}

fn ids(rows: &[serde_json::Value]) -> Vec<String> {
    rows.iter()
        .filter_map(|r| r["id"].as_str().map(str::to_string))
        .collect()
}

/// Create a company + contact + site + ticket in `actor`'s tenant, returning
/// their ids `(company, contact, site, ticket)`.
async fn seed_records(
    app: &common::TestApp,
    actor: &Actor,
    prefix: &str,
) -> (String, String, String, String) {
    let company = create_id(
        app,
        &actor.token,
        "/api/v1/contacts/companies",
        json!({ "name": format!("{prefix} Co") }),
    )
    .await;
    let contact = create_id(
        app,
        &actor.token,
        "/api/v1/contacts/contacts",
        json!({
            "company_id": company,
            "first_name": prefix,
            "last_name": "Owner",
            "email": format!("owner@{prefix}.example"),
        }),
    )
    .await;
    let site = create_id(
        app,
        &actor.token,
        "/api/v1/contacts/sites",
        json!({ "company_id": company, "name": format!("{prefix} HQ") }),
    )
    .await;
    let ticket = create_id(
        app,
        &actor.token,
        "/api/v1/tickets",
        json!({ "title": format!("{prefix} ticket"), "company_id": company, "custom_fields": {} }),
    )
    .await;
    (company, contact, site, ticket)
}

/// AC #4: cross-tenant id reads return 404 (existence-hiding), not 403, for
/// every direct-by-id read surface.
#[sqlx::test]
async fn cross_tenant_idor_reads_return_404(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let a = provision(&pool, &app, "alpha").await;
    let b = provision(&pool, &app, "bravo").await;

    let (company, contact, site, ticket) = seed_records(&app, &a, "Alpha").await;

    for path in [
        format!("/api/v1/contacts/companies/{company}"),
        format!("/api/v1/contacts/contacts/{contact}"),
        format!("/api/v1/contacts/sites/{site}"),
        format!("/api/v1/tickets/{ticket}"),
    ] {
        // Owner A reads its own record (not a blanket deny).
        assert_eq!(
            get_status(&app, &a.token, &path).await,
            StatusCode::OK,
            "owner A must read its own {path}"
        );
        // Tenant B gets 404 for A's id - existence-hiding, never 403.
        assert_eq!(
            get_status(&app, &b.token, &path).await,
            StatusCode::NOT_FOUND,
            "tenant B reading A's {path} must be 404, not 403/200"
        );
    }
}

/// AC #5: the cross-tenant `tenants` admin guard. A tenant-scoped `admin`
/// (NOT super_admin) is denied another tenant's row with 403, but reads its
/// own. This is why the actors here are `admin`: super_admin would pass.
#[sqlx::test]
async fn cross_tenant_admin_cannot_read_other_tenant(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let a = provision(&pool, &app, "alpha").await;
    let b = provision(&pool, &app, "bravo").await;

    assert_eq!(
        get_status(&app, &b.token, &format!("/api/v1/tenants/{}", a.tenant_id)).await,
        StatusCode::FORBIDDEN,
        "tenant B admin must not read A's tenant row"
    );
    assert_eq!(
        get_status(&app, &a.token, &format!("/api/v1/tenants/{}", a.tenant_id)).await,
        StatusCode::OK,
        "owner A admin must read its own tenant row"
    );
}

/// AC #2 / #6: a record created in A never appears in B's list or search, and
/// the search predicate is tenant-bound (no trigram/ILIKE leak) for tickets,
/// companies, and contacts.
#[sqlx::test]
async fn search_and_list_do_not_leak_across_tenants(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let a = provision(&pool, &app, "alpha").await;
    let b = provision(&pool, &app, "bravo").await;

    // A string that exists only in A's tenant. Distinctive so a fuzzy/trigram
    // match in B would surface it if isolation were broken.
    let needle = "ZxqvueNeedle";
    let a_company = create_id(
        &app,
        &a.token,
        "/api/v1/contacts/companies",
        json!({ "name": format!("{needle} Industries") }),
    )
    .await;
    create_id(
        &app,
        &a.token,
        "/api/v1/contacts/contacts",
        json!({
            "company_id": a_company,
            "first_name": needle,
            "last_name": "Person",
            "email": "p@needle.example",
        }),
    )
    .await;
    let a_ticket = create_id(
        &app,
        &a.token,
        "/api/v1/tickets",
        json!({ "title": format!("{needle} outage"), "company_id": a_company, "custom_fields": {} }),
    )
    .await;

    // B has its own company so its lists are non-empty (proves scoping, not a
    // broken endpoint).
    let b_company = create_id(
        &app,
        &b.token,
        "/api/v1/contacts/companies",
        json!({ "name": "Bravo Co" }),
    )
    .await;

    // Full-string and partial (trigram surface) searches from B: zero hits.
    for q in [needle, &needle[0..6]] {
        for path in [
            format!("/api/v1/tickets?q={q}"),
            format!("/api/v1/contacts/companies?q={q}"),
            format!("/api/v1/contacts/contacts?q={q}"),
        ] {
            let rows = list_data(&app, &b.token, &path).await;
            assert!(
                rows.is_empty(),
                "tenant B search {path} must not leak A's data, got {rows:?}"
            );
        }
    }

    // Unfiltered lists from B never contain A's ids, and do contain B's own.
    let b_tickets = list_data(&app, &b.token, "/api/v1/tickets").await;
    assert!(
        !ids(&b_tickets).contains(&a_ticket),
        "B's ticket list must not contain A's ticket"
    );
    let b_companies = ids(&list_data(&app, &b.token, "/api/v1/contacts/companies").await);
    assert!(
        b_companies.contains(&b_company) && !b_companies.contains(&a_company),
        "B's company list is its own only, got {b_companies:?}"
    );
}

/// AC #2: `ticket_number` is sequenced per tenant, so it never leaks A's
/// volume into B. Both tenants' first ticket carries the same number; if the
/// sequence were global, B's first would be offset by A's count.
#[sqlx::test]
async fn ticket_number_sequence_is_per_tenant(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let a = provision(&pool, &app, "alpha").await;
    let b = provision(&pool, &app, "bravo").await;

    let a_company = create_id(
        &app,
        &a.token,
        "/api/v1/contacts/companies",
        json!({ "name": "A" }),
    )
    .await;
    let b_company = create_id(
        &app,
        &b.token,
        "/api/v1/contacts/companies",
        json!({ "name": "B" }),
    )
    .await;

    let make_ticket = |actor_token: String, company: String, n: u32| {
        let app = &app;
        async move {
            post_json(
                app,
                &actor_token,
                "/api/v1/tickets",
                json!({ "title": format!("t{n}"), "company_id": company, "custom_fields": {} }),
            )
            .await["ticket_number"]
                .clone()
        }
    };

    // A burns three numbers; B then creates its first.
    let a_first = ticket_seq(&make_ticket(a.token.clone(), a_company.clone(), 0).await);
    let a_second = ticket_seq(&make_ticket(a.token.clone(), a_company.clone(), 1).await);
    let _a_third = make_ticket(a.token.clone(), a_company.clone(), 2).await;
    let b_first = ticket_seq(&make_ticket(b.token.clone(), b_company.clone(), 0).await);

    assert_eq!(
        a_second,
        a_first + 1,
        "the sequence must advance by one within a tenant (a_first={a_first}, a_second={a_second})"
    );
    assert_eq!(
        b_first, a_first,
        "each tenant's first ticket_number must match (per-tenant sequence); \
         B's first must not be offset by A's volume (a_first={a_first}, b_first={b_first})"
    );
}

/// Extract the numeric sequence value from a `ticket_number`, tolerant of both
/// a bare JSON number and a prefixed string form (e.g. `"TKT-000007"` -> 7), so
/// the per-tenant-sequence assertions do not silently pass on a `null`/missing
/// field and do not break if a display prefix is added later. Panics if no
/// number is present, which is the correct (loud) failure for a broken field.
fn ticket_seq(v: &serde_json::Value) -> u64 {
    match v {
        serde_json::Value::Number(n) => {
            n.as_u64().expect("ticket_number is a non-negative integer")
        }
        serde_json::Value::String(s) => {
            let digits: String = s
                .chars()
                .rev()
                .take_while(char::is_ascii_digit)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            digits
                .parse()
                .unwrap_or_else(|_| panic!("ticket_number {s:?} has no trailing number"))
        }
        other => panic!("unexpected ticket_number JSON type: {other:?}"),
    }
}

/// AC #3: deletion is tenant-scoped. A deleting its own company leaves B's
/// equivalent row intact, and B aiming a delete at A's id never removes it.
#[sqlx::test]
async fn deletion_is_tenant_scoped(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let a = provision(&pool, &app, "alpha").await;
    let b = provision(&pool, &app, "bravo").await;

    let a_company = create_id(
        &app,
        &a.token,
        "/api/v1/contacts/companies",
        json!({ "name": "Shared Name" }),
    )
    .await;
    let b_company = create_id(
        &app,
        &b.token,
        "/api/v1/contacts/companies",
        json!({ "name": "Shared Name" }),
    )
    .await;

    // B aims a delete at A's id: must not remove A's row (cross-tenant write).
    let _ = delete_status(
        &app,
        &b.token,
        &format!("/api/v1/contacts/companies/{a_company}"),
    )
    .await;
    assert_eq!(
        get_status(
            &app,
            &a.token,
            &format!("/api/v1/contacts/companies/{a_company}")
        )
        .await,
        StatusCode::OK,
        "A's company must survive B's cross-tenant delete attempt"
    );

    // A deletes its own company: B's same-named row is untouched.
    assert_eq!(
        delete_status(
            &app,
            &a.token,
            &format!("/api/v1/contacts/companies/{a_company}")
        )
        .await,
        StatusCode::OK,
        "A deletes its own company"
    );
    assert_eq!(
        get_status(
            &app,
            &b.token,
            &format!("/api/v1/contacts/companies/{b_company}")
        )
        .await,
        StatusCode::OK,
        "B's company must be intact after A deletes its own"
    );
}

/// AC #8: tenant_settings, `tenants.branding`, and `module_config` are
/// tenant-scoped. A's writes never bleed into B's defaults.
#[sqlx::test]
async fn settings_and_branding_are_tenant_scoped(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let a = provision(&pool, &app, "alpha").await;
    let b = provision(&pool, &app, "bravo").await;

    // tenant_settings: A sets a per-key value; B has none at that key (404).
    assert_eq!(
        put_status(
            &app,
            &a.token,
            "/api/v1/settings/e2e/iso_probe",
            json!({ "value": "A-secret" })
        )
        .await,
        StatusCode::OK,
        "A upserts its own setting"
    );
    assert_eq!(
        get_status(&app, &a.token, "/api/v1/settings/e2e/iso_probe").await,
        StatusCode::OK,
        "A reads back its own setting"
    );
    assert_eq!(
        get_status(&app, &b.token, "/api/v1/settings/e2e/iso_probe").await,
        StatusCode::NOT_FOUND,
        "B must not see A's tenant_settings row"
    );

    // branding: A sets a primary colour; B's tenant branding stays at default.
    assert_eq!(
        put_status(
            &app,
            &a.token,
            &format!("/api/v1/tenants/{}", a.tenant_id),
            json!({ "branding": { "primary_color": "#A1A1A1" } }),
        )
        .await,
        StatusCode::OK,
        "A updates its own branding"
    );
    let b_tenant = get_json(&app, &b.token, &format!("/api/v1/tenants/{}", b.tenant_id)).await;
    assert_ne!(
        b_tenant["branding"]["primary_color"].as_str(),
        Some("#A1A1A1"),
        "B's branding must not inherit A's colour, got {:?}",
        b_tenant["branding"]["primary_color"]
    );

    // module_config: capture B's default, A enables a module, B's is unchanged.
    let b_before =
        get_json(&app, &b.token, "/api/v1/settings/modules/assets").await["is_enabled"].clone();
    assert_eq!(
        put_status(
            &app,
            &a.token,
            "/api/v1/settings/modules/assets",
            json!({ "is_enabled": true })
        )
        .await,
        StatusCode::OK,
        "A enables its own assets module"
    );
    // Confirm A's write actually took effect in A's own tenant. Without this the
    // B-before == B-after check below could pass vacuously: a silently no-op'd
    // write would leave both A and B unchanged, hiding a broken write (and, if
    // the module default were ever flipped to enabled, hiding a leak too).
    let a_after =
        get_json(&app, &a.token, "/api/v1/settings/modules/assets").await["is_enabled"].clone();
    assert_eq!(
        a_after,
        serde_json::Value::Bool(true),
        "A's own assets module must read back enabled after A's write"
    );
    let b_after =
        get_json(&app, &b.token, "/api/v1/settings/modules/assets").await["is_enabled"].clone();
    assert_eq!(
        b_before, b_after,
        "B's module_config must be unaffected by A enabling its own module"
    );
}

/// AC #9 (users): users are tenant-scoped. A's admin cannot list or manage B's
/// users, and the same email in both tenants yields a session scoped to
/// exactly one tenant_id.
#[sqlx::test]
async fn users_are_tenant_scoped(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    // Both tenants' login admin shares one email (allowed: UNIQUE is per
    // (tenant_id, email)). Each login names its tenant, so the session binds to
    // exactly one tenant_id.
    let shared = "shared-admin@iso.example";
    let a = provision_with_email(&pool, &app, shared).await;
    let b = provision_with_email(&pool, &app, shared).await;
    assert_ne!(a.admin_id, b.admin_id, "same email, distinct user rows");

    // A's admin user list contains A's own admin and never B's.
    let a_user_ids = ids(&list_data(&app, &a.token, "/api/v1/auth/users").await);
    assert!(
        a_user_ids.contains(&a.admin_id.to_string()),
        "A admin lists its own user, got {a_user_ids:?}"
    );
    assert!(
        !a_user_ids.contains(&b.admin_id.to_string()),
        "A admin must not list B's user, got {a_user_ids:?}"
    );

    // A's admin cannot manage B's user: tenant-scoped, so 404 (existence-hide).
    assert_eq!(
        put_status(
            &app,
            &a.token,
            &format!("/api/v1/auth/users/{}", b.admin_id),
            json!({ "first_name": "hijacked" }),
        )
        .await,
        StatusCode::NOT_FOUND,
        "A admin updating B's user must be 404"
    );

    // Same email, two sessions: each is scoped to its own tenant's data. A has
    // a company; B's session (same email) must not see it.
    let a_company = create_id(
        &app,
        &a.token,
        "/api/v1/contacts/companies",
        json!({ "name": "A-only Co" }),
    )
    .await;
    let b_companies = ids(&list_data(&app, &b.token, "/api/v1/contacts/companies").await);
    assert!(
        !b_companies.contains(&a_company),
        "the same-email session scoped to B must not see A's company, got {b_companies:?}"
    );
}

/// AC #9 (RLS confirmation): with `app.current_tenant` set via
/// `begin_with_tenant`, cross-tenant reads are scoped by the policy itself,
/// not only the service predicate - so the result does not depend on the
/// fail-open default. Observed under an unprivileged `NOBYPASSRLS` role, since
/// `#[sqlx::test]` connects as the cluster superuser (which bypasses RLS).
#[sqlx::test]
async fn rls_read_scoping_with_guc(pool: PgPool) {
    let tenant_a = Uuid::new_v4();
    let tenant_b = Uuid::new_v4();
    // tenants rows so the FK on companies.tenant_id is satisfied.
    for (id, slug) in [(tenant_a, "rls-a"), (tenant_b, "rls-b")] {
        sqlx::query("INSERT INTO tenants (id, name, slug, status, kind) VALUES ($1, $2, $3, 'active', 'org')")
            .bind(id)
            .bind(slug)
            .bind(slug)
            .execute(&pool)
            .await
            .expect("insert tenant");
    }

    let mut conn = pool.acquire().await.expect("acquire dedicated connection");

    // Seed one company in each tenant as the superuser (bypasses RLS).
    let a_company = Uuid::new_v4();
    let b_company = Uuid::new_v4();
    for (id, tenant) in [(a_company, tenant_a), (b_company, tenant_b)] {
        sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, 'probe')")
            .bind(id)
            .bind(tenant)
            .execute(&mut *conn)
            .await
            .expect("seed company");
    }

    // An unprivileged application-style role is required to observe the policy.
    let role = format!("mokosh_iso_test_{}", Uuid::new_v4().simple());
    sqlx::query(&format!(
        "CREATE ROLE {role} NOLOGIN NOSUPERUSER NOBYPASSRLS"
    ))
    .execute(&mut *conn)
    .await
    .expect("create app role");
    sqlx::query(&format!("GRANT USAGE ON SCHEMA public TO {role}"))
        .execute(&mut *conn)
        .await
        .expect("grant schema");
    sqlx::query(&format!("GRANT SELECT ON companies TO {role}"))
        .execute(&mut *conn)
        .await
        .expect("grant select");
    sqlx::query(&format!("SET ROLE {role}"))
        .execute(&mut *conn)
        .await
        .expect("set role");

    // With the GUC pinned to B, only B's company is visible; A's is hidden by
    // the policy, not merely by a missing service predicate.
    sqlx::query("SELECT set_config('app.current_tenant', $1, false)")
        .bind(tenant_b.to_string())
        .execute(&mut *conn)
        .await
        .expect("set GUC to tenant B");

    let visible: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM companies ORDER BY id")
        .fetch_all(&mut *conn)
        .await
        .expect("select companies under B GUC");
    assert_eq!(
        visible,
        vec![b_company],
        "under app.current_tenant=B only B's company is visible (A's is hidden by RLS)"
    );

    // Cleanup: shed privileges and drop the cluster-global role.
    sqlx::query("RESET ROLE")
        .execute(&mut *conn)
        .await
        .expect("reset role");
    sqlx::query(&format!("REVOKE ALL ON companies FROM {role}"))
        .execute(&mut *conn)
        .await
        .expect("revoke table");
    sqlx::query(&format!("REVOKE ALL ON SCHEMA public FROM {role}"))
        .execute(&mut *conn)
        .await
        .expect("revoke schema");
    sqlx::query(&format!("DROP ROLE {role}"))
        .execute(&mut *conn)
        .await
        .expect("drop role");
}
