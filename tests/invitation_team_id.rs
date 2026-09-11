//! PMS-1161: `tenant_invitations.team_id` and accept-time team enrolment.
//!
//! Four shapes pinned end-to-end:
//!
//! 1. Create invite with a valid team_id → row records it; accept adds the
//!    user to the team.
//! 2. Create invite naming a team from another tenant → 422 with a
//!    `team_id` field error.
//! 3. Soft-delete the team between create and accept → invite still
//!    accepts cleanly, no team_members row.
//! 4. Create invite with team_id = None (the pre-PMS-1161 shape) →
//!    behaviour unchanged, no team_members row.

mod common;

use sqlx::PgPool;
use uuid::Uuid;

use mokosh_server::modules::audit::AuditCtx;
use mokosh_server::modules::auth::TenantId;
use mokosh_server::modules::invitations::{CreateInvitationRequest, InvitationsService};
use mokosh_server::Database;

fn svc(pool: PgPool) -> InvitationsService {
    InvitationsService::new(Database::from_pool(pool))
}

fn ctx() -> AuditCtx {
    AuditCtx::system(common::DEFAULT_TENANT_ID)
}

fn tenant() -> TenantId {
    TenantId::from_trusted(common::DEFAULT_TENANT_ID)
}

fn req_with_team(email: &str, team_id: Option<Uuid>) -> CreateInvitationRequest {
    CreateInvitationRequest {
        email: email.to_string(),
        role: "technician".to_string(),
        team_id,
    }
}

async fn membership_exists(pool: &PgPool, team_id: Uuid, user_id: Uuid) -> bool {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM team_members WHERE team_id = $1 AND user_id = $2)",
    )
    .bind(team_id)
    .bind(user_id)
    .fetch_one(pool)
    .await
    .expect("membership_exists probe")
}

#[sqlx::test]
async fn accept_adds_user_to_the_teams_named_by_the_invite(pool: PgPool) {
    let team_id = common::seed_team(&pool, common::DEFAULT_TENANT_ID, "Alpha", None).await;
    let (admin_id, _email, _password) = common::seed_admin(&pool).await;
    let s = svc(pool.clone());

    // Create the invite naming the team.
    let inv = s
        .create(
            tenant(),
            admin_id,
            &req_with_team("joiner-team@example.com", Some(team_id)),
            &ctx(),
        )
        .await
        .expect("create invite");
    assert_eq!(
        inv.team_id,
        Some(team_id),
        "PMS-1161: response echoes team_id"
    );

    // Seed the invitee as a user of the tenant so the accept can enrol them.
    let (user_id, _email, _password) = common::seed_user(
        &pool,
        common::DEFAULT_TENANT_ID,
        "joiner-team@example.com",
        "technician",
    )
    .await;

    // Look up the pending invite (the login-driven acceptance path does this)
    // and accept.
    let found = s
        .newest_pending_for("joiner-team@example.com")
        .await
        .expect("newest_pending_for")
        .expect("a pending invite");
    assert_eq!(found.team_id, Some(team_id));
    s.accept(&found, user_id).await.expect("accept");

    assert!(
        membership_exists(&pool, team_id, user_id).await,
        "PMS-1161: accept must add the invitee to the invite's team"
    );
}

#[sqlx::test]
async fn create_refuses_a_foreign_tenant_team(pool: PgPool) {
    // Seed a second tenant with its own team, then attempt to create an
    // invite in the DEFAULT_TENANT_ID naming that foreign team.
    let (foreign_tenant_id, _admin_id, _email, _password) =
        common::seed_tenant_with_admin(&pool, "foreign").await;
    let foreign_team_id = common::seed_team(&pool, foreign_tenant_id, "Foreign", None).await;

    let (admin_id, _email, _password) = common::seed_admin(&pool).await;
    let s = svc(pool.clone());

    let err = s
        .create(
            tenant(),
            admin_id,
            &req_with_team("joiner-foreign@example.com", Some(foreign_team_id)),
            &ctx(),
        )
        .await
        .expect_err("PMS-1161: foreign-tenant team must refuse");

    let msg = format!("{err}");
    assert!(
        msg.to_ascii_lowercase().contains("team"),
        "PMS-1161: the error must name the team_id field: {msg}"
    );
}

#[sqlx::test]
async fn accept_still_succeeds_after_team_soft_delete(pool: PgPool) {
    let team_id = common::seed_team(&pool, common::DEFAULT_TENANT_ID, "Beta", None).await;
    let (admin_id, _email, _password) = common::seed_admin(&pool).await;
    let s = svc(pool.clone());

    let _inv = s
        .create(
            tenant(),
            admin_id,
            &req_with_team("late-accept@example.com", Some(team_id)),
            &ctx(),
        )
        .await
        .expect("create invite");

    // Soft-delete the team AFTER the invite lands. The `is_active = FALSE`
    // predicate on the enrolment INSERT matches zero rows, so the invite
    // still accepts cleanly but no team_members row is written.
    sqlx::query("UPDATE teams SET is_active = FALSE WHERE id = $1")
        .bind(team_id)
        .execute(&pool)
        .await
        .expect("soft-delete team");

    let (user_id, _email, _password) = common::seed_user(
        &pool,
        common::DEFAULT_TENANT_ID,
        "late-accept@example.com",
        "technician",
    )
    .await;

    let found = s
        .newest_pending_for("late-accept@example.com")
        .await
        .expect("newest_pending_for")
        .expect("a pending invite");
    s.accept(&found, user_id).await.expect("accept");

    assert!(
        !membership_exists(&pool, team_id, user_id).await,
        "PMS-1161: a soft-deleted team gets no membership row, but the invite still accepts"
    );
}

#[sqlx::test]
async fn create_without_team_id_is_unchanged_pre_pms_1161_behaviour(pool: PgPool) {
    let (admin_id, _email, _password) = common::seed_admin(&pool).await;
    let s = svc(pool.clone());

    let inv = s
        .create(
            tenant(),
            admin_id,
            &req_with_team("no-team@example.com", None),
            &ctx(),
        )
        .await
        .expect("create invite (no team)");
    assert_eq!(inv.team_id, None, "PMS-1161: None round-trips as None");

    let (user_id, _email, _password) = common::seed_user(
        &pool,
        common::DEFAULT_TENANT_ID,
        "no-team@example.com",
        "technician",
    )
    .await;
    let found = s
        .newest_pending_for("no-team@example.com")
        .await
        .expect("newest_pending_for")
        .expect("a pending invite");
    assert_eq!(found.team_id, None);
    s.accept(&found, user_id).await.expect("accept");

    // Sanity: no rogue team membership was created. The user has zero team
    // memberships in this tenant.
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM team_members WHERE tenant_id = $1 AND user_id = $2",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(user_id)
    .fetch_one(&pool)
    .await
    .expect("count memberships");
    assert_eq!(
        count, 0,
        "PMS-1161: a None invite must not enrol the user in any team"
    );
}
