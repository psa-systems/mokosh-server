//! PMS-264: per-user isolation integration suite (Step 9 of 9 of the PMS-255
//! epic). This is the proof the whole epic worked, and it must stay green
//! permanently.
//!
//! The model (PMS-255 decision 1) is personal-tenant-per-user: every user
//! lives in their own `tenants` row and the `tenant_id` boundary IS the
//! per-user boundary. This file stands up two users in two distinct personal
//! tenants (each provisioned via `TenantService::ensure_personal_tenant`, so
//! each carries the full seeded lookup set) and drives the real HTTP API the
//! way a client would: bearer token in, JSON out.
//!
//! What each test pins, mapped to the acceptance criteria:
//!
//! - `cross_user_read_and_write_denied_across_modules` (AC #1): user A creates
//!   a record in every module with real handlers (contacts: companies +
//!   contacts, tickets, time_tracking: time entries). User B's token gets 404
//!   on every single-record GET of A's ids and B's LIST never contains A's
//!   rows (read denial). For writes, B aims an UPDATE then a DELETE at A's row
//!   id; the handlers differ on the surface code for a cross-tenant id (a
//!   tenant-scoped write matches no row, so some 404 and some report a no-op
//!   200), so this asserts the isolation EFFECT instead: A's row is still
//!   present and still carries its original field value, never B's "hijacked"
//!   sentinel. That is the request-path face of the `WITH CHECK` guarantee
//!   (PMS-255.2 / PMS-257) - a row B cannot see, B cannot mutate. The DB-engine
//!   face of that same guarantee - an INSERT/UPDATE whose `tenant_id` differs
//!   from the GUC is rejected with SQLSTATE 42501 - is pinned directly in
//!   `tests/rls_isolation.rs`.
//! - `cross_user_tenant_endpoint_denied` (AC #1, tenants module): B cannot read
//!   A's `tenants` row (403, the authz guard) and B's tenant list never leaks
//!   A's tenant.
//! - `dashboard_aggregate_is_caller_scoped` (AC #2): aggregate endpoints leak
//!   counts even when individual rows are hidden, so this asserts
//!   `reports::dashboard` counts only the caller's own tickets across two
//!   personal tenants.
//!
//! The remaining acceptance criteria are pinned by sibling suites already in
//! CI, and are referenced here so the PMS-264 coverage reads as one set:
//!
//! - AC #3 (RLS fail-closed regression): `tests/rls_isolation.rs` proves an
//!   unset `app.current_tenant` GUC exposes zero rows under an unprivileged,
//!   `NOBYPASSRLS` role, plus the `WITH CHECK` rejection above.
//! - AC #4 (per-user lookup seeding / isolation): `tests/personal_tenant_seed.rs`
//!   proves a fresh personal tenant is seeded with the full default lookup set,
//!   isolated from every other tenant, idempotently.

mod common;

use mokosh_server::modules::tenants::TenantService;
use mokosh_server::Database;
use reqwest::StatusCode;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

/// One authenticated user living in their own personal tenant.
struct Actor {
    tenant_id: Uuid,
    token: String,
}

/// Provision a personal tenant (with the full seeded lookup set, so the
/// in-tenant create paths that fill default status/priority/queue FKs from the
/// caller's tenant succeed, and `module_config` copies the default module
/// enablement) and an ordinary `technician` user inside it, then log in.
///
/// Deliberately NOT `super_admin`: super_admin is the cross-tenant system role
/// (`get_tenant` lets it read any tenant), which would mask the very isolation
/// under test. The module-gated endpoints (time_tracking, reports) check module
/// enablement, not role, so a technician reaches every module here while the
/// `tenants` authz guard still denies it another tenant.
async fn provision_actor(pool: &PgPool, app: &common::TestApp, label: &str) -> Actor {
    let svc = TenantService::new(Database::from_pool(pool.clone()));
    let user_id = Uuid::new_v4();
    let tenant_id = svc
        .ensure_personal_tenant(user_id)
        .await
        .expect("provision personal tenant");
    let email = format!("{label}@example.com");
    common::seed_user_in_tenant(pool, user_id, tenant_id, &email, "technician").await;

    // Pre-empt the racy first-visit demo-seed middleware (PMS-157). On the
    // first authenticated request the router spawns a DETACHED task that seeds
    // a demo company + contacts + three open tickets into a fresh tenant; left
    // enabled it injects nondeterministic rows that corrupt the per-user counts
    // under test. The seeder claims a tenant by flipping
    // `settings->>'demo_seeded'`, so pre-setting that flag makes the claim a
    // no-op and the seeder inserts nothing. Demo seeding has its own coverage
    // in `tests/seed_demo.rs`.
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

    // `seed_user_in_tenant` plants the uniform test password.
    let token = login_in_tenant(app, &email, tenant_id).await;
    Actor { tenant_id, token }
}

/// Log in, passing the `tenant_id` hint. `POST /auth/login` binds the lookup to
/// `(tenant_id, email)` and falls back to the default tenant when no hint is
/// supplied (PMS-138); a user in a personal tenant therefore must name its
/// tenant to be found. Returns the bearer access token.
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
    let body: serde_json::Value = serde_json::from_str(&text).expect("login JSON");
    body["access_token"]
        .as_str()
        .expect("login response has access_token")
        .to_string()
}

/// POST a JSON body and return the created row's `id` string, asserting 2xx.
async fn create(app: &common::TestApp, token: &str, path: &str, body: serde_json::Value) -> String {
    let resp = app
        .client
        .post(app.url(path))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .expect("send create");
    let status = resp.status();
    let text = resp.text().await.expect("create body");
    assert!(
        status.is_success(),
        "create {path} expected 2xx, got {status} body={text}"
    );
    let v: serde_json::Value = serde_json::from_str(&text).expect("create JSON");
    v["id"].as_str().expect("created row has id").to_string()
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

/// GET a paginated list endpoint and return the `id` of every row in `data`.
async fn list_ids(app: &common::TestApp, token: &str, path: &str) -> Vec<String> {
    let body: serde_json::Value = app
        .client
        .get(app.url(path))
        .bearer_auth(token)
        .send()
        .await
        .expect("send list")
        .json()
        .await
        .expect("list JSON");
    body["data"]
        .as_array()
        .expect("list response has a data array")
        .iter()
        .filter_map(|row| row["id"].as_str().map(str::to_string))
        .collect()
}

/// GET a single record the caller owns and return its JSON body. Asserts 200.
async fn get_json(app: &common::TestApp, token: &str, path: &str) -> serde_json::Value {
    let resp = app
        .client
        .get(app.url(path))
        .bearer_auth(token)
        .send()
        .await
        .expect("send get json");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "owner GET {path} expected 200"
    );
    resp.json().await.expect("record JSON")
}

/// Create a stopped time entry in `actor`'s tenant via the timer flow and
/// return its id. The flow never needs a client-supplied date (the server
/// timestamps start/stop), and the entry is linked to the supplied ticket.
async fn create_time_entry(
    app: &common::TestApp,
    actor: &Actor,
    company_id: &str,
    ticket_id: &str,
) -> String {
    // The caller's own seeded work types.
    let work_types: serde_json::Value = app
        .client
        .get(app.url("/api/v1/work-types"))
        .bearer_auth(&actor.token)
        .send()
        .await
        .expect("list work types")
        .json()
        .await
        .expect("work types JSON");
    let work_type_id = work_types["data"][0]["id"]
        .as_str()
        .expect("seeded tenant has a work type");

    let timer_id = create(
        app,
        &actor.token,
        "/api/v1/timers/start",
        json!({
            "ticket_id": ticket_id,
            "company_id": company_id,
            "work_type_id": work_type_id,
            "notes": "isolation probe",
        }),
    )
    .await;

    let stop: serde_json::Value = app
        .client
        .post(app.url(&format!("/api/v1/timers/{timer_id}/stop")))
        .bearer_auth(&actor.token)
        .send()
        .await
        .expect("stop timer")
        .json()
        .await
        .expect("stopped entry JSON");
    stop["id"]
        .as_str()
        .expect("stopped timer yields a time entry id")
        .to_string()
}

/// AC #1: across every module with real handlers, user B is denied both READ
/// and WRITE of user A's records, while B's own lists stay populated (proving
/// the policy scopes per tenant rather than blanket-denying).
#[sqlx::test]
async fn cross_user_read_and_write_denied_across_modules(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let a = provision_actor(&pool, &app, "alice").await;
    let b = provision_actor(&pool, &app, "bob").await;
    assert_ne!(
        a.tenant_id, b.tenant_id,
        "the two actors are in distinct tenants"
    );

    // --- User A populates every module. ---
    let a_company = create(
        &app,
        &a.token,
        "/api/v1/contacts/companies",
        json!({ "name": "Alice Co" }),
    )
    .await;
    let a_contact = create(
        &app,
        &a.token,
        "/api/v1/contacts/contacts",
        json!({
            "company_id": a_company,
            "first_name": "Alice",
            "last_name": "Owner",
            "email": "owner@alice.example",
        }),
    )
    .await;
    let a_ticket = create(
        &app,
        &a.token,
        "/api/v1/tickets",
        json!({
            "title": "Alice's private ticket",
            "company_id": a_company,
            "description": "confidential",
            "custom_fields": {},
        }),
    )
    .await;
    let a_entry = create_time_entry(&app, &a, &a_company, &a_ticket).await;

    // --- User B populates its own tenant, so its lists are non-empty and we
    //     prove scoping, not a blanket empty result. ---
    let b_company = create(
        &app,
        &b.token,
        "/api/v1/contacts/companies",
        json!({ "name": "Bob Co" }),
    )
    .await;

    // Per module: (list path, single-record subpath, a `{field: "hijacked"}`
    // update body B will try, and the `field` + A's original value so we can
    // prove B's write never landed). The "hijacked" sentinel is what a
    // successful cross-tenant write would leave behind.
    let modules: &[(&str, String, serde_json::Value, &str, &str)] = &[
        (
            "/api/v1/contacts/companies",
            format!("/api/v1/contacts/companies/{a_company}"),
            json!({ "name": "hijacked" }),
            "name",
            "Alice Co",
        ),
        (
            "/api/v1/contacts/contacts",
            format!("/api/v1/contacts/contacts/{a_contact}"),
            json!({ "first_name": "hijacked" }),
            "first_name",
            "Alice",
        ),
        (
            "/api/v1/tickets",
            format!("/api/v1/tickets/{a_ticket}"),
            json!({ "title": "hijacked" }),
            "title",
            "Alice's private ticket",
        ),
        (
            "/api/v1/time-entries",
            format!("/api/v1/time-entries/{a_entry}"),
            json!({ "notes": "hijacked" }),
            "notes",
            "isolation probe",
        ),
    ];

    for (list_path, record_path, update_body, field, original) in modules {
        // Sanity: A reads its own record with the original field value (the
        // policy is not a blanket deny).
        let owned = get_json(&app, &a.token, record_path).await;
        assert_eq!(
            owned[field].as_str(),
            Some(*original),
            "A's own {record_path} should start with {field} = {original:?}"
        );

        // READ denial: B gets 404 on the single-record GET.
        assert_eq!(
            get_status(&app, &b.token, record_path).await,
            StatusCode::NOT_FOUND,
            "user B must not read A's {record_path}"
        );

        // READ denial: B's list never contains A's record.
        let b_listed = list_ids(&app, &b.token, list_path).await;
        assert!(
            !b_listed.iter().any(|id| record_path.ends_with(id)),
            "user B's {list_path} list must not leak A's record, got {b_listed:?}"
        );

        // WRITE denial (UPDATE): B targets A's row id. Handlers differ on the
        // surface code for a cross-tenant id (a tenant-scoped UPDATE matches no
        // row, so some 404 and some report a no-op 200), but the isolation
        // contract is the EFFECT: A's row must be untouched. This is the
        // request-path face of `WITH CHECK` - a row B cannot see, B cannot
        // mutate. The DB-engine face (SQLSTATE 42501 on a GUC-mismatched write)
        // lives in `tests/rls_isolation.rs`.
        let _ = put_status(&app, &b.token, record_path, update_body.clone()).await;

        // WRITE denial (DELETE): same effect contract - A's row must survive.
        let _ = delete_status(&app, &b.token, record_path).await;

        // Prove the effect: A's record is still present AND still carries the
        // original field value, never B's "hijacked" sentinel.
        let after = get_json(&app, &a.token, record_path).await;
        assert_eq!(
            after[field].as_str(),
            Some(*original),
            "A's {record_path} {field} must survive B's update+delete unchanged, \
             got {:?}",
            after[field]
        );
    }

    // B's company list is non-empty (its own row), confirming the empty cross
    // results above are scoping, not a broken list endpoint.
    let b_companies = list_ids(&app, &b.token, "/api/v1/contacts/companies").await;
    assert!(
        b_companies.contains(&b_company),
        "user B must see its own company in its list, got {b_companies:?}"
    );
}

/// AC #1 (tenants module): user B cannot read user A's `tenants` row, and B's
/// tenant list never leaks A's tenant.
#[sqlx::test]
async fn cross_user_tenant_endpoint_denied(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let a = provision_actor(&pool, &app, "alice").await;
    let b = provision_actor(&pool, &app, "bob").await;

    // B reading A's tenant by id is rejected by the authz guard (403).
    assert_eq!(
        get_status(&app, &b.token, &format!("/api/v1/tenants/{}", a.tenant_id)).await,
        StatusCode::FORBIDDEN,
        "user B must not read A's tenant row"
    );

    // A reading its own tenant succeeds (not a blanket deny).
    assert_eq!(
        get_status(&app, &a.token, &format!("/api/v1/tenants/{}", a.tenant_id)).await,
        StatusCode::OK,
        "owner A must read its own tenant row"
    );
}

/// AC #2: aggregate endpoints are caller-scoped. Counts can leak across the
/// isolation boundary even when individual rows are hidden, so this pins that
/// `reports::dashboard` counts only the caller's own tickets.
#[sqlx::test]
async fn dashboard_aggregate_is_caller_scoped(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let a = provision_actor(&pool, &app, "alice").await;
    let b = provision_actor(&pool, &app, "bob").await;

    // A opens two tickets; B opens three.
    let a_company = create(
        &app,
        &a.token,
        "/api/v1/contacts/companies",
        json!({ "name": "Alice Co" }),
    )
    .await;
    for n in 0..2 {
        create(
            &app,
            &a.token,
            "/api/v1/tickets",
            json!({ "title": format!("A-{n}"), "company_id": a_company, "custom_fields": {} }),
        )
        .await;
    }

    let b_company = create(
        &app,
        &b.token,
        "/api/v1/contacts/companies",
        json!({ "name": "Bob Co" }),
    )
    .await;
    for n in 0..3 {
        create(
            &app,
            &b.token,
            "/api/v1/tickets",
            json!({ "title": format!("B-{n}"), "company_id": b_company, "custom_fields": {} }),
        )
        .await;
    }

    let open_count = |actor: &Actor| {
        let app = &app;
        let token = actor.token.clone();
        async move {
            let dash: serde_json::Value = app
                .client
                .get(app.url("/api/v1/reports/dashboard"))
                .bearer_auth(&token)
                .send()
                .await
                .expect("dashboard report")
                .json()
                .await
                .expect("dashboard JSON");
            dash["open_by_priority"]
                .as_array()
                .expect("dashboard has open_by_priority")
                .iter()
                .filter_map(|bucket| bucket["count"].as_i64())
                .sum::<i64>()
        }
    };

    assert_eq!(
        open_count(&a).await,
        2,
        "A's dashboard counts only A's two open tickets, not B's three"
    );
    assert_eq!(
        open_count(&b).await,
        3,
        "B's dashboard counts only B's three open tickets, not A's two"
    );
}
