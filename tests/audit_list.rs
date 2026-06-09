//! Integration regression test for PMS-178.
//!
//! `GET /api/v1/audit-log` must return 200 for any filter combination. A bug
//! in `AuditService::list` numbered the dynamic filter placeholders so they
//! collided with `LIMIT $2 OFFSET $3` and bound more values than the prepared
//! statement declared, so the endpoint 500'd whenever a filter was supplied
//! (no-filter reads worked, which hid it). This drives the real HTTP API as a
//! seeded super-admin (passes `RequireAdmin`) and asserts each filtered read
//! succeeds. No audit rows need to exist - an empty result is still a 200; the
//! bug was at the query layer, before any row mapping.

mod common;

use sqlx::PgPool;

#[sqlx::test]
async fn audit_log_list_handles_every_filter_combination(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    // Each query string exercises a different placeholder count / ordering.
    let cases = [
        "",
        "per_page=100",
        "entity_type=companies&action=create&per_page=100",
        "entity_type=companies",
        "action=create",
        "user_id=00000000-0000-0000-0000-000000000001",
        "from=2026-01-01T00:00:00Z&to=2026-12-31T23:59:59Z&entity_type=companies&action=create",
    ];

    for qs in cases {
        let url = if qs.is_empty() {
            app.url("/api/v1/audit-log")
        } else {
            app.url(&format!("/api/v1/audit-log?{qs}"))
        };
        let resp = app
            .client
            .get(&url)
            .bearer_auth(&token)
            .send()
            .await
            .expect("audit-log request");
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        assert!(
            status.is_success(),
            "GET /api/v1/audit-log?{qs} -> {status} (body: {body})"
        );
    }
}
