//! PMS-249: end-to-end placement tests for the Bunyip SSO login path.
//!
//! Drives `place_bunyip_user` directly with stubbed userinfo (`email` /
//! `email_verified`) so the invite / self-signup / isolation / role logic is
//! exercised without a live OIDC verifier. Placement is asserted against the
//! `users` row (the source of truth) rather than `AuthState` internals.

mod common;

use std::sync::Arc;

use sqlx::PgPool;
use uuid::Uuid;

use mokosh_server::modules::auth::middleware::place_bunyip_user;
use mokosh_server::modules::auth::oidc_rs::AtClaims;
use mokosh_server::modules::auth::{AuthService, TenantId};
use mokosh_server::modules::invitations::{CreateInvitationRequest, InvitationsService};
use mokosh_server::modules::tenants::TenantService;
use mokosh_server::Database;

fn services(
    pool: &PgPool,
) -> (
    Arc<AuthService>,
    Arc<TenantService>,
    Arc<InvitationsService>,
) {
    let db = Database::from_pool(pool.clone());
    (
        Arc::new(AuthService::new(db.clone(), "test-secret".into(), vec![])),
        Arc::new(TenantService::new(db.clone())),
        Arc::new(InvitationsService::new(db)),
    )
}

fn claims(sub: Uuid, bunyip_role: Option<&str>) -> AtClaims {
    AtClaims {
        iss: "https://bunyip.test".into(),
        sub: sub.to_string(),
        aud: "https://api.mokosh.test".into(),
        client_id: "mokosh".into(),
        scope: "openid".into(),
        exp: 0,
        iat: 0,
        bunyip_role: bunyip_role.map(|s| s.to_string()),
    }
}

fn invite(email: &str, role: &str) -> CreateInvitationRequest {
    CreateInvitationRequest {
        email: email.to_string(),
        role: role.to_string(),
    }
}

async fn user_tenant_role(pool: &PgPool, sub: Uuid) -> (Uuid, String) {
    sqlx::query_as("SELECT tenant_id, role FROM users WHERE id = $1")
        .bind(sub)
        .fetch_one(pool)
        .await
        .expect("user row")
}

#[sqlx::test]
async fn invited_user_lands_in_inviting_tenant_with_invite_role(pool: PgPool) {
    let (admin_id, _e, _p) = common::seed_admin(&pool).await;
    let (auth, tenants, invitations) = services(&pool);

    // An org tenant to invite into, with a pending invite for the joiner.
    let org = tenants
        .ensure_personal_tenant(Uuid::new_v4())
        .await
        .expect("org tenant");
    invitations
        .create(
            TenantId::from_trusted(org),
            admin_id,
            &invite("Joiner@Example.com", "manager"),
        )
        .await
        .expect("invite");

    // The joiner signs in via Bunyip with that verified email; `bunyip_role`
    // is `subscriber`, which must NOT override the invite's mokosh role.
    let sub = Uuid::new_v4();
    let state = place_bunyip_user(
        &auth,
        Some(&tenants),
        Some(&invitations),
        sub,
        Some("joiner@example.com".to_string()),
        true,
        &claims(sub, Some("subscriber")),
    )
    .await;
    assert!(state.is_some(), "placement succeeded");

    let (tenant, role) = user_tenant_role(&pool, sub).await;
    assert_eq!(tenant, org, "invited user lands in the inviting tenant");
    assert_eq!(
        role, "manager",
        "invite role applied and survives the bunyip subscriber translation"
    );

    // The invite is consumed (no longer pending).
    let still_pending: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM tenant_invitations WHERE tenant_id = $1 AND status = 'pending'",
    )
    .bind(org)
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(still_pending, 0, "invite accepted on placement");
}

#[sqlx::test]
async fn uninvited_user_gets_their_own_personal_tenant(pool: PgPool) {
    let (auth, tenants, invitations) = services(&pool);

    let sub = Uuid::new_v4();
    place_bunyip_user(
        &auth,
        Some(&tenants),
        Some(&invitations),
        sub,
        Some("solo@example.com".to_string()),
        true,
        &claims(sub, None),
    )
    .await
    .expect("placed");

    let (tenant, _role) = user_tenant_role(&pool, sub).await;
    assert_ne!(
        tenant,
        common::DEFAULT_TENANT_ID,
        "self-signup user is not put in the shared default tenant"
    );
    let (kind, owner): (String, Option<Uuid>) =
        sqlx::query_as("SELECT kind, personal_owner_id FROM tenants WHERE id = $1")
            .bind(tenant)
            .fetch_one(&pool)
            .await
            .expect("tenant");
    assert_eq!(kind, "personal");
    assert_eq!(owner, Some(sub), "the personal tenant is owned by the user");
}

#[sqlx::test]
async fn two_uninvited_users_are_isolated_in_distinct_tenants(pool: PgPool) {
    let (auth, tenants, invitations) = services(&pool);

    let a = Uuid::new_v4();
    let b = Uuid::new_v4();
    for (sub, em) in [(a, "a@example.com"), (b, "b@example.com")] {
        place_bunyip_user(
            &auth,
            Some(&tenants),
            Some(&invitations),
            sub,
            Some(em.to_string()),
            true,
            &claims(sub, None),
        )
        .await
        .expect("placed");
    }

    let (ta, _) = user_tenant_role(&pool, a).await;
    let (tb, _) = user_tenant_role(&pool, b).await;
    assert_ne!(
        ta, tb,
        "two self-signup users land in separate tenants - no shared data"
    );
}

#[sqlx::test]
async fn unverified_email_does_not_consume_an_invite(pool: PgPool) {
    // PMS-248 gate, end to end: an invite is honored only for a VERIFIED email.
    let (admin_id, _e, _p) = common::seed_admin(&pool).await;
    let (auth, tenants, invitations) = services(&pool);

    let org = tenants
        .ensure_personal_tenant(Uuid::new_v4())
        .await
        .expect("org tenant");
    invitations
        .create(
            TenantId::from_trusted(org),
            admin_id,
            &invite("pending@example.com", "manager"),
        )
        .await
        .expect("invite");

    // Same email, but unverified -> the invite is ignored; the user self-signs
    // up into their own personal tenant instead of joining the org.
    let sub = Uuid::new_v4();
    place_bunyip_user(
        &auth,
        Some(&tenants),
        Some(&invitations),
        sub,
        Some("pending@example.com".to_string()),
        false,
        &claims(sub, None),
    )
    .await
    .expect("placed");

    let (tenant, _role) = user_tenant_role(&pool, sub).await;
    assert_ne!(
        tenant, org,
        "unverified email must not join the inviting tenant"
    );

    let still_pending: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM tenant_invitations WHERE tenant_id = $1 AND status = 'pending'",
    )
    .bind(org)
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(still_pending, 1, "the invite is still pending");
}
