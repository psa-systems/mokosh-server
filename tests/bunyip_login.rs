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

use mokosh_server::modules::audit::AuditCtx;
use mokosh_server::modules::auth::middleware::place_bunyip_user;
use mokosh_server::modules::auth::oidc_rs::AtClaims;
use mokosh_server::modules::auth::{AuthService, TenantId};
use mokosh_server::modules::invitations::{CreateInvitationRequest, InvitationsService};
use mokosh_server::modules::tenants::TenantService;
use mokosh_server::modules::tickets::{CreateTicketRequest, TicketService};
use mokosh_server::Database;
use serde_json::json;

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
async fn invited_user_lands_in_inviting_tenant_as_admin(pool: PgPool) {
    // MAPPS-330: every Mokosh user is an admin of their own instance, even
    // when joining a shared org tenant via an invite. The invite still
    // decides the TENANT placement, but the role floors at `admin` (PMS-458's
    // invite-respect carveout is removed).
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
            &invite("Joiner@Example.com", "manager"),
            &AuditCtx::system(org),
        )
        .await
        .expect("invite");

    let sub = Uuid::new_v4();
    let state = place_bunyip_user(
        &auth,
        Some(&tenants),
        Some(&invitations),
        sub,
        Some("joiner@example.com".to_string()),
        true,
        None,
        None,
        &claims(sub, Some("subscriber")),
    )
    .await;
    assert!(state.is_some(), "placement succeeded");

    let (tenant, role) = user_tenant_role(&pool, sub).await;
    assert_eq!(tenant, org, "invited user lands in the inviting tenant");
    assert_eq!(
        role, "admin",
        "MAPPS-330: invite role floors at admin under the subscriber translation"
    );

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
        None,
        None,
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
            None,
            None,
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
async fn non_admin_stuck_in_default_tenant_is_backfilled_out(pool: PgPool) {
    // PMS-262 AC: a non-admin Bunyip user must never RESOLVE to the default
    // tenant. A user historically parked in the shared default tenant (id 1)
    // is moved into their own personal tenant on next login (PMS-245 backfill),
    // proving the default tenant holds no normal users.
    let (auth, tenants, invitations) = services(&pool);

    // Seed the user already sitting in the default tenant with a non-admin role.
    let sub = Uuid::new_v4();
    common::seed_user_in_tenant(
        &pool,
        sub,
        common::DEFAULT_TENANT_ID,
        "stuck@example.com",
        "technician",
    )
    .await;

    place_bunyip_user(
        &auth,
        Some(&tenants),
        Some(&invitations),
        sub,
        Some("stuck@example.com".to_string()),
        true,
        None,
        None,
        &claims(sub, Some("subscriber")),
    )
    .await
    .expect("placed");

    let (tenant, _role) = user_tenant_role(&pool, sub).await;
    assert_ne!(
        tenant,
        common::DEFAULT_TENANT_ID,
        "a non-admin must be backfilled out of the shared default tenant"
    );
    let (kind, owner): (String, Option<Uuid>) =
        sqlx::query_as("SELECT kind, personal_owner_id FROM tenants WHERE id = $1")
            .bind(tenant)
            .fetch_one(&pool)
            .await
            .expect("tenant");
    assert_eq!(
        kind, "personal",
        "backfill lands the user in a personal tenant"
    );
    assert_eq!(owner, Some(sub), "the personal tenant is owned by the user");
}

#[sqlx::test]
async fn super_admin_in_default_tenant_stays(pool: PgPool) {
    // PMS-262 disposition pin: the default tenant is infra-only. A platform
    // super_admin legitimately lives there and is NOT backfilled out, so the
    // default tenant remains a valid (super_admin-only) residence.
    let (auth, tenants, invitations) = services(&pool);

    let sub = Uuid::new_v4();
    common::seed_user_in_tenant(
        &pool,
        sub,
        common::DEFAULT_TENANT_ID,
        "infra-admin@example.com",
        "super_admin",
    )
    .await;

    place_bunyip_user(
        &auth,
        Some(&tenants),
        Some(&invitations),
        sub,
        Some("infra-admin@example.com".to_string()),
        true,
        None,
        None,
        &claims(sub, None),
    )
    .await
    .expect("placed");

    let (tenant, role) = user_tenant_role(&pool, sub).await;
    assert_eq!(
        tenant,
        common::DEFAULT_TENANT_ID,
        "a platform super_admin stays in the infra/default tenant"
    );
    assert_eq!(role, "super_admin");
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
            &AuditCtx::system(org),
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
        None,
        None,
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

#[sqlx::test]
async fn placement_seeds_off_psa_target_tenant_so_tickets_create(pool: PgPool) {
    // PMS-288: a user placed in a tenant provisioned off the PSA path (here a
    // manually-created org tenant with no copy_default_config) gets it seeded on
    // placement, so ticket creation - which needs a default ticket status AND a
    // ticket_sequences row - succeeds instead of 500ing. Pre-fix, create_ticket
    // returns "No default ticket status configured".
    let (auth, tenants, invitations) = services(&pool);

    // A bare org tenant: no lookup config, no sequences.
    let tenant = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO tenants (id, name, slug, status, kind)
         VALUES ($1, 'Off-PSA Org', 'off-psa-288-place', 'active', 'org')",
    )
    .bind(tenant)
    .execute(&pool)
    .await
    .expect("insert bare tenant");

    // The user already lives there (existing placement, admin role), so the
    // placement resolves target = current = the unseeded tenant (no re-home to a
    // fresh personal tenant, which would seed via ensure_personal_tenant).
    let sub = Uuid::new_v4();
    common::seed_user_in_tenant(&pool, sub, tenant, "offpsa@example.com", "admin").await;

    place_bunyip_user(
        &auth,
        Some(&tenants),
        Some(&invitations),
        sub,
        Some("offpsa@example.com".to_string()),
        true,
        None,
        None,
        &claims(sub, Some("admin")),
    )
    .await
    .expect("placed");

    let (resolved, _role) = user_tenant_role(&pool, sub).await;
    assert_eq!(resolved, tenant, "user stays in their existing tenant");

    // A company to hang the ticket on.
    let company = Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, 'Acme')")
        .bind(company)
        .bind(tenant)
        .execute(&pool)
        .await
        .expect("insert company");

    // Ticket creation now succeeds: placement seeded the default status + the
    // ticket_sequences row.
    let tickets = TicketService::new(Database::from_pool(pool.clone()));
    let req: CreateTicketRequest = serde_json::from_value(json!({
        "title": "PMS-288 first ticket",
        "company_id": company,
    }))
    .expect("build ticket request");
    let ticket = tickets
        .create_ticket(
            TenantId::from_trusted(tenant),
            sub,
            &req,
            &AuditCtx::system(tenant),
        )
        .await
        .expect("create_ticket must succeed after placement seeded the tenant");
    assert!(
        !ticket.ticket_number.is_empty(),
        "ticket received a sequenced number"
    );
}

/// MAPPS-329: Bunyip-onboarded users (BUNYIP-206 guarantees first + last name
/// are present on every fresh signup) should not have to re-type the same name
/// on mokosh's `/onboarding/profile`. The placement now stamps
/// `profile_completed_at` when both name claims arrive non-empty, so the
/// SPA's AuthGuard sees `profile_completed = true` from `/auth/me` and lets
/// the user land directly on the dashboard.
#[sqlx::test]
async fn name_claims_stamp_profile_completed_at(pool: PgPool) {
    let (auth, tenants, invitations) = services(&pool);

    let sub = Uuid::new_v4();
    place_bunyip_user(
        &auth,
        Some(&tenants),
        Some(&invitations),
        sub,
        Some("named@example.com".to_string()),
        true,
        Some("a contributor".to_string()),
        Some("a contributor".to_string()),
        &claims(sub, None),
    )
    .await
    .expect("placed");

    let (tenant, _) = user_tenant_role(&pool, sub).await;
    let completed_at: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT profile_completed_at FROM users WHERE id = $1")
            .bind(sub)
            .fetch_one(&pool)
            .await
            .expect("read user");
    assert!(
        completed_at.is_some(),
        "name claims present -> profile_completed_at stamped on INSERT"
    );

    let _ = tenant;
}

/// MAPPS-329: the inverse - a placement with NO name claims (legacy bunyip
/// user, magic-link signup pre-BUNYIP-206, etc.) leaves `profile_completed_at`
/// NULL so the existing mokosh `/onboarding/profile` page kicks in as the
/// fallback for that user.
#[sqlx::test]
async fn missing_name_claims_leave_profile_incomplete(pool: PgPool) {
    let (auth, tenants, invitations) = services(&pool);

    let sub = Uuid::new_v4();
    place_bunyip_user(
        &auth,
        Some(&tenants),
        Some(&invitations),
        sub,
        Some("anon@example.com".to_string()),
        true,
        None,
        None,
        &claims(sub, None),
    )
    .await
    .expect("placed");

    let completed_at: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT profile_completed_at FROM users WHERE id = $1")
            .bind(sub)
            .fetch_one(&pool)
            .await
            .expect("read user");
    assert!(
        completed_at.is_none(),
        "no name claims -> profile_completed_at stays NULL, SPA still gates"
    );
}
