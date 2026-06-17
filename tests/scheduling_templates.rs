//! Integration tests for the scheduling-template CRUD story (PMS-403).
//!
//! Covers the full lifecycle of a `scheduling_templates` row through the
//! HTTP API: create -> list (filtered by `kind`) -> get -> update -> delete,
//! plus the two isolation/validation guards the service enforces:
//!   * a template created in one tenant is invisible to another tenant
//!   * a `default_ticket_id` from another tenant is rejected (400)
//!   * a non-positive `duration_minutes` is rejected (422 at the validator)
//!
//! Everything is driven through the legacy bearer-token path like the sibling
//! `tests/calendar.rs` suite. The default tenant the seed migration provisions
//! carries the ticket-lookup defaults, so a ticket can be created through the
//! API there; the second tenant is stood up via `seed_tenant_with_admin`.

mod common;

use common::{boot, login, seed_admin, seed_company, seed_tenant_with_admin, TestApp};
use sqlx::PgPool;
use uuid::Uuid;

/// Log in passing an explicit `tenant_id` hint. The shared `login` helper
/// always resolves to the default tenant (`resolve_tenant_for_login` falls
/// back to it when no hint is supplied), so a second-tenant admin must
/// disambiguate via the `tenant_id` field, mirroring `tests/auth.rs`.
async fn login_tenant(app: &TestApp, tenant_id: Uuid, email: &str, password: &str) -> String {
    let resp = app
        .client
        .post(app.url("/api/v1/auth/login"))
        .json(&serde_json::json!({
            "email": email,
            "password": password,
            "tenant_id": tenant_id,
        }))
        .send()
        .await
        .expect("send tenant login");
    assert!(
        resp.status().is_success(),
        "tenant login expected 2xx, got {}",
        resp.status()
    );
    let body: serde_json::Value = resp.json().await.expect("login JSON body");
    body["access_token"]
        .as_str()
        .expect("login response has access_token")
        .to_string()
}

/// Enable the `calendar` module for a tenant. The default tenant gets this row
/// from the seed migration (023_seed_data.sql), but a tenant stood up in-test
/// via `seed_tenant_with_admin` has no `module_config` rows, so the
/// `RequireCalendar` gate would 404 every scheduling-template request from it.
async fn enable_calendar_module(pool: &PgPool, tenant_id: Uuid) {
    sqlx::query(
        r#"INSERT INTO module_config (tenant_id, module_name, is_enabled, config)
           VALUES ($1, 'calendar', TRUE, '{}')"#,
    )
    .bind(tenant_id)
    .execute(pool)
    .await
    .expect("enable calendar module for tenant");
}

/// Full CRUD lifecycle plus `kind` filtering. Create one `dispatch` and one
/// `calendar` template, assert the list filter narrows by kind, then get,
/// update, and delete the dispatch one.
#[sqlx::test]
async fn template_crud_lifecycle_and_kind_filter(pool: PgPool) {
    let (_admin_id, email, password) = seed_admin(&pool).await;
    let app = boot(pool).await;
    let token = login(&app, &email, &password).await;

    // CREATE dispatch template (with travel buffers).
    let dispatch: serde_json::Value = app
        .client
        .post(app.url("/api/v1/scheduling-templates"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "name": "On-site visit",
            "kind": "dispatch",
            "appointment_type": "ticket",
            "duration_minutes": 120,
            "travel_before_minutes": 30,
            "travel_after_minutes": 30,
            "default_location": "Client HQ",
        }))
        .send()
        .await
        .expect("send create dispatch template")
        .json()
        .await
        .expect("create dispatch JSON");
    let dispatch_id = dispatch["id"].as_str().expect("dispatch id").to_string();
    assert_eq!(dispatch["kind"].as_str(), Some("dispatch"));
    assert_eq!(dispatch["duration_minutes"].as_i64(), Some(120));
    assert_eq!(dispatch["travel_before_minutes"].as_i64(), Some(30));
    // tenant_id is intentionally omitted from the wire shape.
    assert!(
        dispatch.get("tenant_id").is_none(),
        "tenant_id must not be serialized, got {dispatch}"
    );

    // CREATE calendar template.
    app.client
        .post(app.url("/api/v1/scheduling-templates"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "name": "New-customer interview",
            "kind": "calendar",
            "duration_minutes": 60,
        }))
        .send()
        .await
        .expect("send create calendar template")
        .error_for_status()
        .expect("calendar template created");

    // LIST filtered by kind=dispatch -> only the dispatch one.
    let list: serde_json::Value = app
        .client
        .get(app.url("/api/v1/scheduling-templates?kind=dispatch"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send list (kind=dispatch)")
        .json()
        .await
        .expect("list JSON");
    let data = list["data"].as_array().expect("list data array");
    assert_eq!(
        data.len(),
        1,
        "kind=dispatch filter must return exactly the dispatch template, got {data:?}"
    );
    assert_eq!(data[0]["kind"].as_str(), Some("dispatch"));

    // LIST unfiltered -> both.
    let all: serde_json::Value = app
        .client
        .get(app.url("/api/v1/scheduling-templates"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send list (all)")
        .json()
        .await
        .expect("list-all JSON");
    assert_eq!(
        all["data"].as_array().expect("all data array").len(),
        2,
        "unfiltered list must return both templates"
    );

    // GET the dispatch one.
    let got: serde_json::Value = app
        .client
        .get(app.url(&format!("/api/v1/scheduling-templates/{dispatch_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send get template")
        .json()
        .await
        .expect("get JSON");
    assert_eq!(got["name"].as_str(), Some("On-site visit"));

    // UPDATE: change duration and name (partial PUT).
    let updated: serde_json::Value = app
        .client
        .put(app.url(&format!("/api/v1/scheduling-templates/{dispatch_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "name": "On-site visit (long)",
            "duration_minutes": 180,
        }))
        .send()
        .await
        .expect("send update template")
        .json()
        .await
        .expect("update JSON");
    assert_eq!(updated["name"].as_str(), Some("On-site visit (long)"));
    assert_eq!(updated["duration_minutes"].as_i64(), Some(180));
    // Untouched fields keep their stored values.
    assert_eq!(updated["travel_before_minutes"].as_i64(), Some(30));
    assert_eq!(updated["kind"].as_str(), Some("dispatch"));

    // DELETE.
    let del = app
        .client
        .delete(app.url(&format!("/api/v1/scheduling-templates/{dispatch_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send delete template");
    assert!(
        del.status().is_success(),
        "delete must 2xx, got {}",
        del.status()
    );

    // GET after delete -> 404.
    let after = app
        .client
        .get(app.url(&format!("/api/v1/scheduling-templates/{dispatch_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send get-after-delete");
    assert_eq!(
        after.status().as_u16(),
        404,
        "deleted template must be gone"
    );
}

/// A template created in tenant A is invisible to tenant B. Both tenants seed
/// a template; each list returns only its own.
#[sqlx::test]
async fn templates_are_tenant_isolated(pool: PgPool) {
    let (_admin_id, email_a, password_a) = seed_admin(&pool).await;
    let (tenant_b, _user_b, email_b, password_b) = seed_tenant_with_admin(&pool, "tenant-b").await;
    enable_calendar_module(&pool, tenant_b).await;
    let app = boot(pool).await;
    let token_a = login(&app, &email_a, &password_a).await;
    let token_b = login_tenant(&app, tenant_b, &email_b, &password_b).await;

    // Tenant A creates a template.
    let created_a: serde_json::Value = app
        .client
        .post(app.url("/api/v1/scheduling-templates"))
        .bearer_auth(&token_a)
        .json(&serde_json::json!({
            "name": "A-only template",
            "kind": "calendar",
            "duration_minutes": 45,
        }))
        .send()
        .await
        .expect("send create (tenant A)")
        .json()
        .await
        .expect("create A JSON");
    let id_a = created_a["id"].as_str().expect("A template id").to_string();

    // Tenant B's list must not contain A's template.
    let list_b: serde_json::Value = app
        .client
        .get(app.url("/api/v1/scheduling-templates"))
        .bearer_auth(&token_b)
        .send()
        .await
        .expect("send list (tenant B)")
        .json()
        .await
        .expect("list B JSON");
    assert!(
        list_b["data"].as_array().expect("B data array").is_empty(),
        "tenant B must not see tenant A's template, got {list_b}"
    );

    // Tenant B cannot GET A's template by id either (404, not cross-tenant read).
    let get_b = app
        .client
        .get(app.url(&format!("/api/v1/scheduling-templates/{id_a}")))
        .bearer_auth(&token_b)
        .send()
        .await
        .expect("send get A's id as tenant B");
    assert_eq!(
        get_b.status().as_u16(),
        404,
        "tenant B fetching tenant A's template by id must 404"
    );
}

/// A `default_ticket_id` belonging to another tenant is rejected with 400.
/// Tenant A (the default, lookup-seeded tenant) owns a ticket; tenant B tries
/// to reference it from a template and is rejected by the FK-tenant guard.
#[sqlx::test]
async fn template_rejects_cross_tenant_default_ticket(pool: PgPool) {
    let (_admin_id, email_a, password_a) = seed_admin(&pool).await;
    let company_id = seed_company(&pool).await;
    let (tenant_b, _user_b, email_b, password_b) = seed_tenant_with_admin(&pool, "tenant-b").await;
    enable_calendar_module(&pool, tenant_b).await;
    let app = boot(pool).await;
    let token_a = login(&app, &email_a, &password_a).await;
    let token_b = login_tenant(&app, tenant_b, &email_b, &password_b).await;

    // Tenant A owns a ticket (created through the API; default-tenant lookups
    // are seeded by the migration).
    let ticket: serde_json::Value = app
        .client
        .post(app.url("/api/v1/tickets"))
        .bearer_auth(&token_a)
        .json(&serde_json::json!({
            "title": "Tenant A ticket",
            "company_id": company_id,
            "custom_fields": {},
        }))
        .send()
        .await
        .expect("send create ticket (tenant A)")
        .json()
        .await
        .expect("create ticket JSON");
    let ticket_id = ticket["id"].as_str().expect("ticket id").to_string();

    // Tenant B references tenant A's ticket -> 400.
    let resp = app
        .client
        .post(app.url("/api/v1/scheduling-templates"))
        .bearer_auth(&token_b)
        .json(&serde_json::json!({
            "name": "Bad ticket link",
            "kind": "dispatch",
            "duration_minutes": 60,
            "default_ticket_id": ticket_id,
        }))
        .send()
        .await
        .expect("send create with cross-tenant ticket");
    assert_eq!(
        resp.status().as_u16(),
        400,
        "a default_ticket_id from another tenant must be rejected with 400"
    );
}

/// A non-positive `duration_minutes` is rejected at the request validator
/// with 422, before reaching the DB CHECK.
#[sqlx::test]
async fn template_rejects_non_positive_duration(pool: PgPool) {
    let (_admin_id, email, password) = seed_admin(&pool).await;
    let app = boot(pool).await;
    let token = login(&app, &email, &password).await;

    let resp = app
        .client
        .post(app.url("/api/v1/scheduling-templates"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "name": "Zero duration",
            "kind": "calendar",
            "duration_minutes": 0,
        }))
        .send()
        .await
        .expect("send create with zero duration");
    assert_eq!(
        resp.status().as_u16(),
        422,
        "duration_minutes = 0 must be rejected by the validator"
    );
}

/// An unknown `kind` value is rejected at the request validator with 422.
#[sqlx::test]
async fn template_rejects_invalid_kind(pool: PgPool) {
    let (_admin_id, email, password) = seed_admin(&pool).await;
    let app = boot(pool).await;
    let token = login(&app, &email, &password).await;

    let resp = app
        .client
        .post(app.url("/api/v1/scheduling-templates"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "name": "Bad kind",
            "kind": "wat",
            "duration_minutes": 60,
        }))
        .send()
        .await
        .expect("send create with invalid kind");
    assert_eq!(
        resp.status().as_u16(),
        422,
        "an out-of-set kind must be rejected by the validator"
    );
}
