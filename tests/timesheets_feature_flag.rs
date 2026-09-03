//! PMS-943: timesheets are a per-tenant feature, and on a one-person MSP they
//! do not exist.
//!
//! The interesting half is the OFF state, because "not reachable" has to mean
//! not reachable by a direct request rather than merely absent from the SPA's
//! navigation. `RequireModuleEnabled` answers 404 for exactly that reason, so a
//! probing client cannot tell a disabled feature from a route that was never
//! mounted, and these pin that answer on every one of the five routes.

mod common;

use mokosh_server::modules::audit::AuditCtx;
use mokosh_server::modules::auth::TenantId;
use mokosh_server::modules::invitations::{CreateInvitationRequest, InvitationsService};
use mokosh_server::Database;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

/// Every route the flag governs, with a request that would otherwise succeed or
/// fail on its own merits. A 404 from any of them is the flag talking.
fn gated_paths(user_id: Uuid) -> Vec<(&'static str, String)> {
    vec![
        ("GET", "/api/v1/timesheets".to_string()),
        (
            "POST",
            format!("/api/v1/timesheets/{user_id}/2026-06-15/submit"),
        ),
        (
            "POST",
            format!("/api/v1/timesheets/{user_id}/2026-06-15/withdraw"),
        ),
        (
            "POST",
            format!("/api/v1/timesheets/{user_id}/2026-06-15/approve"),
        ),
        (
            "POST",
            format!("/api/v1/timesheets/{user_id}/2026-06-15/reject"),
        ),
    ]
}

async fn set_flag(pool: &PgPool, tenant_id: Uuid, enabled: bool) {
    sqlx::query(
        "UPDATE module_config SET is_enabled = $3 \
         WHERE tenant_id = $1 AND module_name = $2",
    )
    .bind(tenant_id)
    .bind("timesheets")
    .bind(enabled)
    .execute(pool)
    .await
    .expect("set the timesheets flag");
}

async fn flag(pool: &PgPool, tenant_id: Uuid) -> Option<bool> {
    sqlx::query_scalar::<_, bool>(
        "SELECT is_enabled FROM module_config WHERE tenant_id = $1 AND module_name = 'timesheets'",
    )
    .bind(tenant_id)
    .fetch_optional(pool)
    .await
    .expect("read the timesheets flag")
}

/// With the flag off, a direct request to any timesheet route is answered the
/// way a nonexistent route is. Not hidden in the client, not 403.
#[sqlx::test]
async fn every_timesheet_route_is_gone_when_the_flag_is_off(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    set_flag(&pool, common::DEFAULT_TENANT_ID, false).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    for (method, path) in gated_paths(admin_id) {
        let request = match method {
            "GET" => app.client.get(app.url(&path)),
            _ => app.client.post(app.url(&path)).json(&json!({})),
        };
        let response = request
            .bearer_auth(&token)
            .send()
            .await
            .expect("call a gated route");
        assert_eq!(
            response.status(),
            404,
            "{method} {path} must read as a route that does not exist"
        );
    }
}

/// And with it on, the same routes behave as they did before the gate existed.
#[sqlx::test]
async fn the_routes_are_unchanged_when_the_flag_is_on(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    // The default tenant is `kind = 'org'`, so migration 120 seeds it on. Assert
    // that rather than setting it, because the seeding rule is the thing.
    assert_eq!(flag(&pool, common::DEFAULT_TENANT_ID).await, Some(true));
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let response = app
        .client
        .get(app.url("/api/v1/timesheets"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list timesheets");
    assert_eq!(response.status(), 200, "{:?}", response.text().await);
}

/// Turning timesheets off does not stop anybody working. `time_tracking` is a
/// separate module for this reason: a one-person MSP still logs time and still
/// bills for it, it just has nobody to submit a week to.
#[sqlx::test]
async fn logging_time_still_works_with_timesheets_off(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    set_flag(&pool, common::DEFAULT_TENANT_ID, false).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let work_types: serde_json::Value = app
        .client
        .get(app.url("/api/v1/work-types"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list work types")
        .json()
        .await
        .expect("work types json");
    let work_type_id = work_types["data"][0]["id"]
        .as_str()
        .expect("a seeded work type")
        .to_string();

    let response = app
        .client
        .post(app.url("/api/v1/time-entries"))
        .bearer_auth(&token)
        .json(&json!({
            "user_id": admin_id,
            "date": "2026-06-15",
            "duration_minutes": 60,
            "work_type_id": work_type_id,
            "company_id": company_id,
        }))
        .send()
        .await
        .expect("log time");
    assert_eq!(response.status(), 200, "{:?}", response.text().await);
}

/// The seeding rule, run over both tenant kinds. The statement is read out of
/// migration 120 rather than restated, so this cannot drift from the SQL that
/// actually ran on every existing database; migrations are immutable once
/// committed, which is what makes the file safe to quote.
#[sqlx::test]
async fn the_seeding_rule_follows_the_tenant_kind(pool: PgPool) {
    let personal = Uuid::new_v4();
    let org = Uuid::new_v4();
    for (id, kind) in [(personal, "personal"), (org, "org")] {
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, status, kind) VALUES ($1, $2, $2, 'active', $3)",
        )
        .bind(id)
        .bind(format!("seed-{kind}-{}", &id.simple().to_string()[..8]))
        .bind(kind)
        .execute(&pool)
        .await
        .expect("insert a tenant");
    }

    // Comments come off before the split on `;`: the paragraphs explaining the
    // statement are English and contain semicolons of their own.
    let migration = include_str!("../migrations/120_timesheets_module_flag.sql");
    let sql: String = migration
        .lines()
        .filter(|line| !line.trim_start().starts_with("--"))
        .collect::<Vec<_>>()
        .join("\n");
    let seed = sql
        .split(';')
        .map(str::trim)
        .find(|s| s.starts_with("INSERT INTO module_config"))
        .expect("the migration carries the seed")
        .to_string();
    sqlx::query(&seed)
        .execute(&pool)
        .await
        .expect("re-run the seed");

    assert_eq!(
        flag(&pool, personal).await,
        Some(false),
        "one self-signed-up person has nobody to submit a week to"
    );
    assert_eq!(flag(&pool, org).await, Some(true));
    // The default tenant already had a row from the migration proper, and the
    // re-run must not have disturbed it.
    assert_eq!(flag(&pool, common::DEFAULT_TENANT_ID).await, Some(true));
}

/// A personal tenant becomes an org the moment it invites somebody, and that is
/// the moment timesheets start to mean something. Without this the promoted
/// tenant would keep the answer it was given when it was one person: an
/// employer with staff and no timesheets, until somebody found the setting.
#[sqlx::test]
async fn the_first_invitation_turns_timesheets_on(pool: PgPool) {
    let tenant_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO tenants (id, name, slug, status, kind) \
         VALUES ($1, 'Solo', 'solo-msp', 'active', 'personal')",
    )
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("insert a personal tenant");
    sqlx::query(
        "INSERT INTO module_config (tenant_id, module_name, is_enabled, config) \
         VALUES ($1, 'timesheets', FALSE, '{}'::jsonb)",
    )
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("seed the flag off");
    assert_eq!(flag(&pool, tenant_id).await, Some(false));

    // The inviter has to be a real user in the tenant.
    let owner_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name, role, \
         status, email_verified_at) \
         VALUES ($1, $2, 'solo@example.com', 'x', 'Solo', 'Owner', 'super_admin', 'active', NOW())",
    )
    .bind(owner_id)
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("insert the owner");

    let service = InvitationsService::new(Database::from_pool(pool.clone()));
    service
        .create(
            TenantId::from_trusted(tenant_id),
            owner_id,
            &CreateInvitationRequest {
                email: "colleague@example.com".to_string(),
                role: "technician".to_string(),
            },
            &AuditCtx {
                tenant_id: Some(tenant_id),
                user_id: None,
                ip: None,
                user_agent: None,
            },
        )
        .await
        .expect("invite the first colleague");

    let kind: String = sqlx::query_scalar("SELECT kind FROM tenants WHERE id = $1")
        .bind(tenant_id)
        .fetch_one(&pool)
        .await
        .expect("read the kind");
    assert_eq!(kind, "org", "the invitation promotes the tenant");
    assert_eq!(flag(&pool, tenant_id).await, Some(true));
}

/// An established org that turned timesheets off keeps them off. The flag
/// follows the PROMOTION, not every invitation, so an operator's decision is
/// not undone by the next person they hire.
#[sqlx::test]
async fn a_later_invitation_does_not_re_enable_a_deliberate_off(pool: PgPool) {
    let (admin_id, _email, _password) = common::seed_admin(&pool).await;
    set_flag(&pool, common::DEFAULT_TENANT_ID, false).await;
    let service = InvitationsService::new(Database::from_pool(pool.clone()));
    service
        .create(
            TenantId::from_trusted(common::DEFAULT_TENANT_ID),
            admin_id,
            &CreateInvitationRequest {
                email: "second-hire@example.com".to_string(),
                role: "technician".to_string(),
            },
            &AuditCtx {
                tenant_id: Some(common::DEFAULT_TENANT_ID),
                user_id: None,
                ip: None,
                user_agent: None,
            },
        )
        .await
        .expect("invite into an established org");
    assert_eq!(flag(&pool, common::DEFAULT_TENANT_ID).await, Some(false));
}

/// Break tracking is off until an employer says otherwise, and it is a tenant
/// setting because the employee taking the break is the MSP's. PMS-950 reads it.
#[sqlx::test]
async fn break_tracking_defaults_off_and_is_settable(pool: PgPool) {
    let db = Database::from_pool(pool.clone());
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);
    assert!(
        !mokosh_server::modules::settings::read_track_breaks(&db, tenant)
            .await
            .expect("read the default")
    );

    sqlx::query(
        "INSERT INTO tenant_settings (tenant_id, category, key, value) \
         VALUES ($1, 'timesheets', 'track_breaks', 'true'::jsonb)",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .execute(&pool)
    .await
    .expect("store the setting");

    assert!(
        mokosh_server::modules::settings::read_track_breaks(&db, tenant)
            .await
            .expect("read it back")
    );
}
