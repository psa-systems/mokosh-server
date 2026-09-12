//! PMS-1162: the team-management projection guard.
//!
//! `PUT /teams/{id}` and the sibling membership writes widen the admin-only
//! gate PMS-791 shipped: an app-role admin (`super_admin | admin`) still
//! passes unconditionally, AND the row's own `manager_id` also passes so the
//! accountable owner of a team can self-manage without holding an admin
//! role at the tenant level. Every other user, including a
//! `UserRole::Manager` whose row's `manager_id` is set to somebody else, is
//! 403.
//!
//! Three shapes worth pinning end-to-end:
//!
//! 1. `admin` with no matching `manager_id` still passes.
//! 2. A `technician` who IS the row's `manager_id` passes.
//! 3. A `technician` who is NOT the row's `manager_id` is 403.
//!
//! The service-level tests in `tests/teams.rs` already pin the underlying
//! behaviour; this file pins the HTTP-layer guard.

mod common;

use reqwest::StatusCode;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

/// Convenience: seed a user with the given app role, log them in, and hand
/// back `(user_id, bearer_token)`.
async fn seed_user_and_login(
    pool: &PgPool,
    app: &common::TestApp,
    role: &str,
    email_local: &str,
) -> (Uuid, String) {
    let email = format!("{email_local}@team-mgmt.example");
    let (user_id, _email, password) =
        common::seed_user(pool, common::DEFAULT_TENANT_ID, &email, role).await;
    let token = common::login(app, &email, &password).await;
    (user_id, token)
}

#[sqlx::test]
async fn admin_can_edit_team_metadata_without_manager_binding(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (_admin_id, admin_email, admin_password) = common::seed_admin(&pool).await;
    let admin_token = common::login(&app, &admin_email, &admin_password).await;

    // Team's manager_id is NULL; admin still gets through the projection
    // guard purely on their app role.
    let team_id = common::seed_team(&pool, common::DEFAULT_TENANT_ID, "Alpha", None).await;

    let resp = app
        .client
        .put(app.url(&format!("/api/v1/teams/{team_id}")))
        .bearer_auth(&admin_token)
        .json(&json!({"name": "Alpha Renamed"}))
        .send()
        .await
        .expect("put team");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "PMS-1162: an admin passes the projection guard regardless of manager_id"
    );
}

#[sqlx::test]
async fn technician_who_is_manager_can_edit_team_metadata(pool: PgPool) {
    let app = common::boot(pool.clone()).await;

    // Seed the technician first so the team row can name them as manager.
    let (tech_id, tech_token) = seed_user_and_login(&pool, &app, "technician", "tech-mgr").await;
    let team_id = common::seed_team(&pool, common::DEFAULT_TENANT_ID, "Beta", Some(tech_id)).await;

    let resp = app
        .client
        .put(app.url(&format!("/api/v1/teams/{team_id}")))
        .bearer_auth(&tech_token)
        .json(&json!({"description": "Beta squad, updated by its own manager"}))
        .send()
        .await
        .expect("put team");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "PMS-1162: the row's own manager_id passes the projection guard even without an admin role"
    );
}

#[sqlx::test]
async fn technician_who_is_not_manager_is_403(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (_tech_id, tech_token) =
        seed_user_and_login(&pool, &app, "technician", "tech-nonmgr").await;

    // Team's manager_id is deliberately NULL so no user can claim it.
    let team_id = common::seed_team(&pool, common::DEFAULT_TENANT_ID, "Gamma", None).await;

    let resp = app
        .client
        .put(app.url(&format!("/api/v1/teams/{team_id}")))
        .bearer_auth(&tech_token)
        .json(&json!({"name": "Gamma Hijacked"}))
        .send()
        .await
        .expect("put team");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "PMS-1162: a non-admin whose id does not match manager_id is refused"
    );
}

#[sqlx::test]
async fn user_role_manager_class_does_not_auto_grant_edit(pool: PgPool) {
    let app = common::boot(pool.clone()).await;

    // A user with the app-level `Manager` role - NOT the same as being set
    // as the row's `manager_id`. The projection deliberately excludes the
    // Manager class from team-metadata edits unless they are ALSO named as
    // the accountable owner on the specific row. Two separate axes.
    let (_manager_id, manager_token) =
        seed_user_and_login(&pool, &app, "manager", "manager-cls").await;
    let team_id = common::seed_team(&pool, common::DEFAULT_TENANT_ID, "Delta", None).await;

    let resp = app
        .client
        .put(app.url(&format!("/api/v1/teams/{team_id}")))
        .bearer_auth(&manager_token)
        .json(&json!({"name": "Delta Overreach"}))
        .send()
        .await
        .expect("put team");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "PMS-1162: UserRole::Manager is not admin AND does not auto-match a row's manager_id"
    );
}

#[sqlx::test]
async fn membership_writes_share_the_same_projection_guard(pool: PgPool) {
    // The projection guard runs on add_member / update_member_role /
    // remove_member the same way it does on update_team. Pin add_member as
    // the representative case: a non-manager technician is refused, an
    // admin passes.
    let app = common::boot(pool.clone()).await;
    let (_tech_id, tech_token) =
        seed_user_and_login(&pool, &app, "technician", "add-mem-tech").await;
    let (_admin_id, admin_email, admin_password) = common::seed_admin(&pool).await;
    let admin_token = common::login(&app, &admin_email, &admin_password).await;

    let team_id = common::seed_team(&pool, common::DEFAULT_TENANT_ID, "Epsilon", None).await;
    let (member_id, _email, _password) = common::seed_user(
        &pool,
        common::DEFAULT_TENANT_ID,
        "member-target@team-mgmt.example",
        "technician",
    )
    .await;

    // Technician (non-manager) trying to add a member: 403.
    let resp = app
        .client
        .post(app.url(&format!("/api/v1/teams/{team_id}/members")))
        .bearer_auth(&tech_token)
        .json(&json!({"user_id": member_id}))
        .send()
        .await
        .expect("post member (tech)");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "PMS-1162: membership writes share the projection guard"
    );

    // Admin adding the same member: 201.
    let resp = app
        .client
        .post(app.url(&format!("/api/v1/teams/{team_id}/members")))
        .bearer_auth(&admin_token)
        .json(&json!({"user_id": member_id}))
        .send()
        .await
        .expect("post member (admin)");
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "PMS-1162: the same admin gate that clears update_team clears add_member"
    );
}
