//! PMS-249: end-to-end placement tests for the Bunyip SSO login path.
//!
//! Drives `place_bunyip_user` directly with stubbed userinfo (`email` /
//! `email_verified`) so the invite / rejection / isolation / role logic is
//! exercised without a live OIDC verifier. Placement is asserted against the
//! `users` row (the source of truth) rather than `AuthState` internals.
//!
//! MAPPS-458 (PMS-728 slice 2) is the policy the whole file states: bunyip is
//! not an onboarding surface, so a `sub` with no `users` row and no pending
//! invitation for its VERIFIED address is refused, and the platform admin
//! (`bunyip_role = "admin"`) is the only carve-out. Every test here that needs a
//! placed user therefore seeds an invitation or a row; a first-sight identity
//! that just signs itself up is the shape PMS-1042 removed, not a shape to
//! restore.

mod common;

use std::sync::Arc;

use sqlx::PgPool;
use uuid::Uuid;

use mokosh_server::modules::audit::AuditCtx;
use mokosh_server::modules::auth::middleware::{bunyip_userinfo_needed, place_bunyip_user};
use mokosh_server::modules::auth::oidc_rs::AtClaims;
use mokosh_server::modules::auth::{AuthService, TenantId, UserRole};
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
        Arc::new(AuthService::new(db.clone(), "test-secret".into())),
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

/// PMS-512: the cached `(first_name, last_name)` bunyip owns.
async fn names(pool: &PgPool, sub: Uuid) -> (String, String) {
    sqlx::query_as("SELECT first_name, last_name FROM users WHERE id = $1")
        .bind(sub)
        .fetch_one(pool)
        .await
        .expect("user row")
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
        .ensure_personal_tenant(Uuid::new_v4(), None, None)
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

/// MAPPS-458 (PMS-728 slice 2): a Bunyip-authenticated identity with no
/// existing `users` row and no pending invitation is REJECTED. Bunyip is
/// no longer an onboarding surface: fresh users arrive via the explicit
/// invitations flow. Supersedes the pre-MAPPS-458
/// `uninvited_user_gets_their_own_personal_tenant` behavior.
#[sqlx::test]
async fn uninvited_bunyip_user_without_invite_is_rejected(pool: PgPool) {
    let (auth, tenants, invitations) = services(&pool);

    let sub = Uuid::new_v4();
    let state = place_bunyip_user(
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
    .await;

    assert!(
        state.is_none(),
        "uninvited non-platform-admin must be rejected, not silently provisioned"
    );

    // No user row exists.
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE id = $1")
        .bind(sub)
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(
        count, 0,
        "no `users` row is inserted for a rejected placement"
    );
}

/// MAPPS-458: two uninvited (non-platform-admin) Bunyip users both get
/// rejected. Neither gets a personal tenant. Supersedes the pre-MAPPS-458
/// `two_uninvited_users_are_isolated_in_distinct_tenants` behavior.
#[sqlx::test]
async fn two_uninvited_bunyip_users_are_both_rejected(pool: PgPool) {
    let (auth, tenants, invitations) = services(&pool);

    for em in ["a@example.com", "b@example.com"] {
        let sub = Uuid::new_v4();
        let state = place_bunyip_user(
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
        .await;
        assert!(state.is_none(), "uninvited user {em} must be rejected");
    }
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
        .ensure_personal_tenant(Uuid::new_v4(), None, None)
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

    // Same email, but unverified -> the invite is ignored. Pre-MAPPS-458
    // the user then self-signed up into their own personal tenant; post
    // MAPPS-458 the invite is ignored AND JIT provisioning is off, so
    // placement returns None. The invite must remain pending either way.
    let sub = Uuid::new_v4();
    let state = place_bunyip_user(
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
    .await;
    assert!(
        state.is_none(),
        "unverified email cannot consume the invite AND cannot self-signup (MAPPS-458)"
    );

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE id = $1")
        .bind(sub)
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(count, 0, "no user row is written for a rejected placement");

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

/// PMS-676 (revised for MAPPS-519): the first/bootstrap admin must still be
/// able to log in and operate with FULL admin rights on a fresh instance
/// even when email is unconfigured and the address can therefore never be
/// verified. Production authenticates the bootstrap admin through
/// bunyip-as-OP; that path does NOT gate login on `email_verified`.
/// Here `email_verified = false` stands in for the "SMTP unconfigured,
/// email can never be verified" state.
///
/// MAPPS-519 (MAPPS-518 stage B follow-up): the bunyip `admin` claim used
/// to promote the placement to `UserRole::SuperAdmin` on the tenant plane.
/// That mint path was the last remaining source of `users.role='super_admin'`
/// in production, and it silently reopened the shared-identity data surface
/// migration 133 closed. It now flattens to tenant `Admin`. The bootstrap
/// admin still authenticates + still owns their own tenant; the mokosh
/// platform super-admin persona (cross-tenant privilege) moved to
/// `platform_admins` + `/platform/login` in MAPPS-513 / MAPPS-518 and is
/// bootstrapped from `ADMIN_EMAIL` / `ADMIN_PASSWORD` (see
/// `auth::bootstrap`), not from a bunyip claim.
#[sqlx::test]
async fn bootstrap_admin_unverified_email_still_authenticates(pool: PgPool) {
    let (auth, tenants, invitations) = services(&pool);

    let sub = Uuid::new_v4();
    let state = place_bunyip_user(
        &auth,
        Some(&tenants),
        Some(&invitations),
        sub,
        Some("bootstrap-admin@example.com".to_string()),
        // email_verified = false: no SMTP, so the address is never verified.
        false,
        None,
        None,
        // Platform-admin claim (bunyip-side). Post-MAPPS-519 this no longer
        // promotes on the mokosh tenant plane; the bootstrap admin still
        // authenticates and owns their own tenant.
        &claims(sub, Some("admin")),
    )
    .await;

    let state = state.expect("bootstrap admin authenticates even with an unverified email");
    let user = state
        .require_user()
        .expect("authenticated state carries the current user");
    assert_eq!(
        user.role,
        UserRole::Admin,
        "MAPPS-519: the bunyip admin claim mints tenant Admin, not \
         SuperAdmin - platform super-admin lives in platform_admins now"
    );
    assert!(
        state.has_role(UserRole::Admin),
        "bootstrap admin has tenant-admin access on a fresh, \
         email-unconfigured instance"
    );

    let (_tenant, role) = user_tenant_role(&pool, sub).await;
    assert_eq!(
        role, "admin",
        "the persisted row is admin, so tenant-admin access survives the \
         next request; MAPPS-519 blocks the users.role='super_admin' mint \
         path so this row cannot regress on a re-login"
    );
}

/// PMS-676 companion (revised for MAPPS-519): once email IS configured
/// (address verified), the same bootstrap-admin login still lands as
/// tenant `Admin`. `email_verified = true` stands in for the "SMTP
/// configured, email verified" state. Turning email on must not regress
/// or downgrade the bootstrap admin's tenant-admin role.
///
/// Pairs with `bootstrap_admin_unverified_email_still_authenticates`
/// above; both were pinned at `SuperAdmin` pre-MAPPS-519 and flipped
/// together when the bunyip `admin` promotion was retired.
#[sqlx::test]
async fn bootstrap_admin_verified_email_still_authenticates(pool: PgPool) {
    let (auth, tenants, invitations) = services(&pool);

    let sub = Uuid::new_v4();
    let state = place_bunyip_user(
        &auth,
        Some(&tenants),
        Some(&invitations),
        sub,
        Some("bootstrap-admin@example.com".to_string()),
        // email_verified = true: SMTP configured, address verified.
        true,
        None,
        None,
        &claims(sub, Some("admin")),
    )
    .await;

    let state = state.expect("bootstrap admin authenticates with a verified email");
    let user = state
        .require_user()
        .expect("authenticated state carries the current user");
    assert_eq!(
        user.role,
        UserRole::Admin,
        "MAPPS-519: enabling email must not change what role the bunyip \
         admin claim mints (tenant Admin, not SuperAdmin)"
    );

    let (_tenant, role) = user_tenant_role(&pool, sub).await;
    assert_eq!(role, "admin");
}

/// MAPPS-329: Bunyip-onboarded users (BUNYIP-206 guarantees first + last name
/// are present on every fresh signup) should not have to re-type the same name
/// on mokosh's `/onboarding/profile`. The placement now stamps
/// `profile_completed_at` when both name claims arrive non-empty, so the
/// SPA's AuthGuard sees `profile_completed = true` from `/auth/me` and lets
/// the user land directly on the dashboard.
#[sqlx::test]
async fn name_claims_stamp_profile_completed_at(pool: PgPool) {
    // MAPPS-458: brand-new bunyip user needs an invitation to be placed
    // (JIT personal-tenant provisioning was retired). Seed one so the
    // placement path exercises the intended profile-completion logic.
    let (admin_id, _e, _p) = common::seed_admin(&pool).await;
    let (auth, tenants, invitations) = services(&pool);

    let org = tenants
        .ensure_personal_tenant(Uuid::new_v4(), None, None)
        .await
        .expect("org tenant");
    invitations
        .create(
            TenantId::from_trusted(org),
            admin_id,
            &invite("named@example.com", "manager"),
            &AuditCtx::system(org),
        )
        .await
        .expect("invite");

    let sub = Uuid::new_v4();
    place_bunyip_user(
        &auth,
        Some(&tenants),
        Some(&invitations),
        sub,
        Some("named@example.com".to_string()),
        true,
        Some("Alex".to_string()),
        Some("Doe".to_string()),
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
    // MAPPS-458: seed an invitation so placement succeeds; the point of
    // this test is the name-claims -> profile-completed-at bookkeeping,
    // not the pre-458 self-signup path.
    let (admin_id, _e, _p) = common::seed_admin(&pool).await;
    let (auth, tenants, invitations) = services(&pool);

    let org = tenants
        .ensure_personal_tenant(Uuid::new_v4(), None, None)
        .await
        .expect("org tenant");
    invitations
        .create(
            TenantId::from_trusted(org),
            admin_id,
            &invite("anon@example.com", "manager"),
            &AuditCtx::system(org),
        )
        .await
        .expect("invite");

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

/// PMS-752: a user whose bunyip claims carried no names lands on the SPA's
/// onboarding screen, and until now could not leave it. The screen's
/// `PUT /auth/me` cannot set names (PMS-512 gave those to bunyip), so nothing
/// stamped `profile_completed_at` and the AuthGuard sent the user straight
/// back. `POST /auth/me/complete-onboarding` is what lets the screen finish.
#[sqlx::test]
async fn complete_onboarding_stamps_the_profile_once(pool: PgPool) {
    // MAPPS-458: seed an invitation so placement succeeds; this test's
    // point is `mark_profile_completed`, not the pre-458 self-signup.
    let (admin_id, _e, _p) = common::seed_admin(&pool).await;
    let (auth, tenants, invitations) = services(&pool);

    let org = tenants
        .ensure_personal_tenant(Uuid::new_v4(), None, None)
        .await
        .expect("org tenant");
    invitations
        .create(
            TenantId::from_trusted(org),
            admin_id,
            &invite("nameless@example.com", "manager"),
            &AuditCtx::system(org),
        )
        .await
        .expect("invite");

    let sub = Uuid::new_v4();
    place_bunyip_user(
        &auth,
        Some(&tenants),
        Some(&invitations),
        sub,
        Some("nameless@example.com".to_string()),
        true,
        None,
        None,
        &claims(sub, None),
    )
    .await
    .expect("placed");

    let (tenant, _) = user_tenant_role(&pool, sub).await;
    let before: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT profile_completed_at FROM users WHERE id = $1")
            .bind(sub)
            .fetch_one(&pool)
            .await
            .expect("read user");
    assert!(
        before.is_none(),
        "no name claims, so the SPA gates this user"
    );

    let user = auth
        .mark_profile_completed(tenant, sub, None, None)
        .await
        .expect("complete onboarding");
    assert!(
        user.profile_completed_at.is_some(),
        "the screen must be able to complete itself"
    );

    // Idempotent: a double submit records when onboarding was finished, not
    // when it was last re-submitted.
    let stamped = user.profile_completed_at;
    let again = auth
        .mark_profile_completed(tenant, sub, None, None)
        .await
        .expect("second call");
    assert_eq!(again.profile_completed_at, stamped);
}

/// Regression: the onboarding screen collects a first + last name for a
/// user whose bunyip claims did not carry them. Pre-fix the screen
/// PUT /auth/me those two fields and the server dropped them silently
/// (PMS-512 removed name fields from UpdateUserRequest so bunyip stays
/// authoritative on the OIDC path). The correct plumbing is a
/// name-carrying body on `POST /auth/me/complete-onboarding` that
/// writes ONLY on first completion (guarded by
/// `WHERE profile_completed_at IS NULL`) so a later bunyip-refreshed
/// name is not clobbered by a replay of the endpoint.
#[sqlx::test]
async fn complete_onboarding_persists_names_on_first_call_and_locks_thereafter(pool: PgPool) {
    let (admin_id, _e, _p) = common::seed_admin(&pool).await;
    let (auth, tenants, invitations) = services(&pool);

    let org = tenants
        .ensure_personal_tenant(Uuid::new_v4(), None, None)
        .await
        .expect("org tenant");
    invitations
        .create(
            TenantId::from_trusted(org),
            admin_id,
            &invite("nameless2@example.com", "manager"),
            &AuditCtx::system(org),
        )
        .await
        .expect("invite");

    let sub = Uuid::new_v4();
    place_bunyip_user(
        &auth,
        Some(&tenants),
        Some(&invitations),
        sub,
        Some("nameless2@example.com".to_string()),
        true,
        None,
        None,
        &claims(sub, None),
    )
    .await
    .expect("placed");

    let (tenant, _) = user_tenant_role(&pool, sub).await;
    // First submit: names carried from the SPA land on the row + the
    // profile stamps. This is the ONLY moment the endpoint can write
    // names; the guard clause locks them after.
    let user = auth
        .mark_profile_completed(tenant, sub, Some("Wanda"), Some("Vasquez"))
        .await
        .expect("first complete");
    assert!(
        user.profile_completed_at.is_some(),
        "must stamp the profile"
    );
    assert_eq!(user.first_name, "Wanda", "first submit persists first_name");
    assert_eq!(user.last_name, "Vasquez", "first submit persists last_name");

    // Replay with a DIFFERENT name payload: the guard clause blocks the
    // write. Names stay at their original values; timestamp stays
    // COALESCE-frozen too. This is what prevents a stolen access token
    // from silently renaming a user through the onboarding endpoint.
    let stamped = user.profile_completed_at;
    let again = auth
        .mark_profile_completed(tenant, sub, Some("Attacker"), Some("Impersonator"))
        .await
        .expect("replay");
    assert_eq!(
        again.first_name, "Wanda",
        "post-onboarding replay must not overwrite the first_name (bunyip stays authoritative)"
    );
    assert_eq!(
        again.last_name, "Vasquez",
        "post-onboarding replay must not overwrite the last_name (bunyip stays authoritative)"
    );
    assert_eq!(
        again.profile_completed_at, stamped,
        "timestamp still frozen"
    );
}

/// PMS-512: bunyip owns the profile names, so the local columns are a
/// read-only cache refreshed on EVERY login, not just the JIT one. A rename in
/// bunyip lands in `users.first_name` / `last_name` on the next placement.
#[sqlx::test]
async fn name_claims_refresh_on_every_login(pool: PgPool) {
    // MAPPS-458: seed an invitation so the first placement succeeds;
    // the subsequent calls see the user as already-placed and exercise
    // the refresh branch.
    let (admin_id, _e, _p) = common::seed_admin(&pool).await;
    let (auth, tenants, invitations) = services(&pool);

    let org = tenants
        .ensure_personal_tenant(Uuid::new_v4(), None, None)
        .await
        .expect("org tenant");
    invitations
        .create(
            TenantId::from_trusted(org),
            admin_id,
            &invite("renamed@example.com", "manager"),
            &AuditCtx::system(org),
        )
        .await
        .expect("invite");

    let sub = Uuid::new_v4();
    let place = |first: Option<&str>, last: Option<&str>| {
        let (auth, tenants, invitations) = (auth.clone(), tenants.clone(), invitations.clone());
        let (first, last) = (first.map(str::to_string), last.map(str::to_string));
        async move {
            place_bunyip_user(
                &auth,
                Some(&tenants),
                Some(&invitations),
                sub,
                Some("renamed@example.com".to_string()),
                true,
                first,
                last,
                &claims(sub, None),
            )
            .await
            .expect("placed")
        }
    };

    place(Some("Alex"), Some("Doe")).await;
    assert_eq!(names(&pool, sub).await, ("Alex".into(), "Doe".into()));

    // Second login with the bunyip-side rename: both columns follow.
    place(Some("Alexandra"), Some("Roe")).await;
    assert_eq!(
        names(&pool, sub).await,
        ("Alexandra".into(), "Roe".into()),
        "a later login must overwrite the cached names from the claims"
    );
}

/// PMS-512: the same overwrite-not-seed contract on `upsert_user_from_oidc`
/// itself, so the `ON CONFLICT DO UPDATE` branch is pinned independently of
/// which caller reaches it. A re-run with fresh hints overwrites; a re-run
/// with no hints keeps the stored values (the synthetic `EXCLUDED` fallback
/// must never clobber a real name).
#[sqlx::test]
async fn upsert_on_conflict_overwrites_names_only_from_non_empty_hints(pool: PgPool) {
    let (auth, _tenants, _invitations) = services(&pool);
    let tenant = common::DEFAULT_TENANT_ID;
    let sub = Uuid::new_v4();

    auth.upsert_user_from_oidc(
        sub,
        tenant,
        "upsert@example.com",
        UserRole::Admin,
        Some("Alex"),
        Some("Doe"),
        true,
    )
    .await
    .expect("insert");
    assert_eq!(names(&pool, sub).await, ("Alex".into(), "Doe".into()));

    auth.upsert_user_from_oidc(
        sub,
        tenant,
        "upsert@example.com",
        UserRole::Admin,
        Some("Alexandra"),
        Some("Roe"),
        true,
    )
    .await
    .expect("conflict update");
    assert_eq!(
        names(&pool, sub).await,
        ("Alexandra".into(), "Roe".into()),
        "the ON CONFLICT branch overwrites from the hints"
    );

    auth.upsert_user_from_oidc(
        sub,
        tenant,
        "upsert@example.com",
        UserRole::Admin,
        None,
        Some("   "),
        true,
    )
    .await
    .expect("conflict update without hints");
    assert_eq!(
        names(&pool, sub).await,
        ("Alexandra".into(), "Roe".into()),
        "absent / empty hints must not write the synthetic placeholder"
    );
}

/// PMS-512: `users.first_name` / `last_name` are `NOT NULL`, so a login whose
/// claims are absent (scope not granted) or empty (whitespace-only) must leave
/// the cached values intact rather than blanking the columns.
#[sqlx::test]
async fn absent_or_empty_name_claims_leave_cached_names_intact(pool: PgPool) {
    // MAPPS-458: seed an invitation so the first placement succeeds.
    let (admin_id, _e, _p) = common::seed_admin(&pool).await;
    let (auth, tenants, invitations) = services(&pool);

    let org = tenants
        .ensure_personal_tenant(Uuid::new_v4(), None, None)
        .await
        .expect("org tenant");
    invitations
        .create(
            TenantId::from_trusted(org),
            admin_id,
            &invite("keeper@example.com", "manager"),
            &AuditCtx::system(org),
        )
        .await
        .expect("invite");

    let sub = Uuid::new_v4();
    let place = |first: Option<&str>, last: Option<&str>| {
        let (auth, tenants, invitations) = (auth.clone(), tenants.clone(), invitations.clone());
        let (first, last) = (first.map(str::to_string), last.map(str::to_string));
        async move {
            place_bunyip_user(
                &auth,
                Some(&tenants),
                Some(&invitations),
                sub,
                Some("keeper@example.com".to_string()),
                true,
                first,
                last,
                &claims(sub, None),
            )
            .await
            .expect("placed")
        }
    };

    place(Some("Alex"), Some("Doe")).await;

    // Claims absent entirely.
    place(None, None).await;
    assert_eq!(
        names(&pool, sub).await,
        ("Alex".into(), "Doe".into()),
        "absent claims must not blank the NOT NULL columns"
    );

    // Claims present but empty / whitespace-only.
    place(Some("  "), Some("")).await;
    assert_eq!(
        names(&pool, sub).await,
        ("Alex".into(), "Doe".into()),
        "empty claims must not blank the NOT NULL columns"
    );

    // One side present, the other empty: only the present side moves.
    place(Some("Sam"), None).await;
    assert_eq!(
        names(&pool, sub).await,
        ("Sam".into(), "Doe".into()),
        "an absent family_name must leave last_name alone"
    );
}

// PMS-713: the Bunyip RS path fetched `/oauth2/userinfo` (a network hop) on
// EVERY authenticated request, so a page that fires several API calls (the
// dashboard) stalled for seconds waiting on Bunyip. `bunyip_userinfo_needed`
// gates that hop: it is fetched only to provision / re-place a user, and skipped
// for an already-placed user with no pending invite, who is resolved from local
// state.

#[sqlx::test]
async fn userinfo_is_fetched_for_a_first_sight_user(pool: PgPool) {
    // No local placement yet -> userinfo IS needed to JIT-provision the user.
    let (auth, _tenants, invitations) = services(&pool);
    let sub = Uuid::new_v4();
    assert!(
        bunyip_userinfo_needed(&auth, Some(&invitations), sub).await,
        "a first-sight user needs userinfo to be provisioned"
    );
}

#[sqlx::test]
async fn userinfo_is_skipped_for_an_existing_placed_user(pool: PgPool) {
    // The perf fix: an already-provisioned user in their own tenant with no
    // pending invite is resolved locally, so the per-request userinfo hop is
    // skipped.
    // MAPPS-458: seed an invitation so the first placement succeeds
    // (JIT self-signup was retired).
    let (admin_id, _e, _p) = common::seed_admin(&pool).await;
    let (auth, tenants, invitations) = services(&pool);

    let org = tenants
        .ensure_personal_tenant(Uuid::new_v4(), None, None)
        .await
        .expect("org tenant");
    invitations
        .create(
            TenantId::from_trusted(org),
            admin_id,
            &invite("placed@example.com", "manager"),
            &AuditCtx::system(org),
        )
        .await
        .expect("invite");

    let sub = Uuid::new_v4();
    place_bunyip_user(
        &auth,
        Some(&tenants),
        Some(&invitations),
        sub,
        Some("placed@example.com".to_string()),
        true,
        None,
        None,
        &claims(sub, None),
    )
    .await
    .expect("first placement");

    assert!(
        !bunyip_userinfo_needed(&auth, Some(&invitations), sub).await,
        "an existing placed user with no invite must not trigger a userinfo fetch"
    );
}

#[sqlx::test]
async fn userinfo_is_fetched_when_a_pending_invite_matches(pool: PgPool) {
    // Invites still work: an existing user with a pending invite for their
    // verified email goes through the full (userinfo) path so it is honored.
    // MAPPS-458: seed a first invitation so the initial placement lands the
    // user in an org, then add a NEW pending invite to a different tenant to
    // exercise the userinfo-needed guard.
    let (admin_id, _e, _p) = common::seed_admin(&pool).await;
    let (auth, tenants, invitations) = services(&pool);

    let seed_org = tenants
        .ensure_personal_tenant(Uuid::new_v4(), None, None)
        .await
        .expect("seed org tenant");
    invitations
        .create(
            TenantId::from_trusted(seed_org),
            admin_id,
            &invite("invitee@example.com", "manager"),
            &AuditCtx::system(seed_org),
        )
        .await
        .expect("seed invite");

    let sub = Uuid::new_v4();
    place_bunyip_user(
        &auth,
        Some(&tenants),
        Some(&invitations),
        sub,
        Some("invitee@example.com".to_string()),
        true,
        None,
        None,
        &claims(sub, None),
    )
    .await
    .expect("first placement");

    let org = tenants
        .ensure_personal_tenant(Uuid::new_v4(), None, None)
        .await
        .expect("org tenant");
    invitations
        .create(
            TenantId::from_trusted(org),
            admin_id,
            &invite("invitee@example.com", "manager"),
            &AuditCtx::system(org),
        )
        .await
        .expect("invite");

    assert!(
        bunyip_userinfo_needed(&auth, Some(&invitations), sub).await,
        "a pending invite for the user's verified email must trigger the userinfo path"
    );
}

#[sqlx::test]
async fn existing_user_resolves_with_no_userinfo(pool: PgPool) {
    // The fast path end to end: once provisioned, a user is resolved by
    // place_bunyip_user with NO email/name (the values the middleware passes when
    // it skips userinfo), staying in their tenant and keeping their cached name.
    // MAPPS-458: seed an invitation so the first placement succeeds.
    let (admin_id, _e, _p) = common::seed_admin(&pool).await;
    let (auth, tenants, invitations) = services(&pool);

    let org = tenants
        .ensure_personal_tenant(Uuid::new_v4(), None, None)
        .await
        .expect("org tenant");
    invitations
        .create(
            TenantId::from_trusted(org),
            admin_id,
            &invite("fastpath@example.com", "manager"),
            &AuditCtx::system(org),
        )
        .await
        .expect("invite");

    let sub = Uuid::new_v4();
    place_bunyip_user(
        &auth,
        Some(&tenants),
        Some(&invitations),
        sub,
        Some("fastpath@example.com".to_string()),
        true,
        Some("Fast".to_string()),
        Some("Path".to_string()),
        &claims(sub, None),
    )
    .await
    .expect("first placement");
    let (tenant, _) = user_tenant_role(&pool, sub).await;

    let state = place_bunyip_user(
        &auth,
        Some(&tenants),
        Some(&invitations),
        sub,
        None,
        false,
        None,
        None,
        &claims(sub, None),
    )
    .await;
    assert!(
        state.is_some(),
        "an existing user resolves with no userinfo (the skipped-hop fast path)"
    );
    let (tenant2, _) = user_tenant_role(&pool, sub).await;
    assert_eq!(
        tenant, tenant2,
        "the user stays in their tenant on the no-userinfo fast path"
    );
    assert_eq!(
        names(&pool, sub).await,
        ("Fast".into(), "Path".into()),
        "cached names are untouched when no name hints are supplied"
    );
}

/// PMS-698 AC1: a user whose `users.status` is not `active` is not placed, so
/// the bunyip branch of `auth_middleware` never authenticates them.
#[sqlx::test]
async fn inactive_user_is_not_placed(pool: PgPool) {
    let (admin_id, _e, _p) = common::seed_admin(&pool).await;
    let (auth, tenants, invitations) = services(&pool);

    let placed = place_bunyip_user(
        &auth,
        Some(&tenants),
        Some(&invitations),
        admin_id,
        Some("test-admin@example.com".to_string()),
        true,
        None,
        None,
        &claims(admin_id, Some("admin")),
    )
    .await;
    assert!(placed.is_some(), "active user places normally");

    sqlx::query("UPDATE users SET status = 'inactive' WHERE id = $1")
        .bind(admin_id)
        .execute(&pool)
        .await
        .expect("deactivate user");

    let placed = place_bunyip_user(
        &auth,
        Some(&tenants),
        Some(&invitations),
        admin_id,
        Some("test-admin@example.com".to_string()),
        true,
        None,
        None,
        &claims(admin_id, Some("admin")),
    )
    .await;
    assert!(
        placed.is_none(),
        "inactive user is rejected on the bunyip path"
    );
}

/// PMS-698 AC2: a placement whose resolved tenant is not `active` is rejected,
/// so a tenant suspension stops data access on the bunyip path too.
///
/// MAPPS-519 note: pre-MAPPS-519 this test used `common::seed_admin`,
/// which parks a `users.role='super_admin'` row in `DEFAULT_TENANT_ID`;
/// the old `is_stuck_in_default` exemption for `super_admin` meant the
/// placement stayed pinned to DEFAULT and suspending DEFAULT rejected
/// the next call. Post-519 the bunyip `admin` claim mints tenant `Admin`
/// (not `SuperAdmin`), and `Admin` in the default tenant IS re-homed to
/// a personal tenant on the next placement, so suspending DEFAULT would
/// let the second placement re-home out and succeed. The test uses a
/// fresh sub with no seeded row so the first placement JITs the user
/// into a personal tenant of their own; we read that tenant and suspend
/// it, and the second placement then hits AC2's rejection cleanly.
#[sqlx::test]
async fn suspended_tenant_is_not_placed(pool: PgPool) {
    let (auth, tenants, invitations) = services(&pool);
    let sub = Uuid::new_v4();

    let placed = place_bunyip_user(
        &auth,
        Some(&tenants),
        Some(&invitations),
        sub,
        Some("suspended-tenant-probe@example.com".to_string()),
        true,
        None,
        None,
        &claims(sub, Some("admin")),
    )
    .await;
    assert!(placed.is_some(), "active tenant places normally");

    // MAPPS-519: read the personal tenant the JIT placement provisioned
    // and suspend that so the AC2 rejection has something real to gate
    // on (not the shared default tenant, which the re-home would leave
    // for a personal one on the second call).
    let (landed_tenant, _role) = user_tenant_role(&pool, sub).await;
    assert_ne!(
        landed_tenant,
        common::DEFAULT_TENANT_ID,
        "MAPPS-519 sanity: a bunyip admin with no seeded row must JIT \
         into a personal tenant, not the shared default"
    );
    sqlx::query("UPDATE tenants SET status = 'suspended' WHERE id = $1")
        .bind(landed_tenant)
        .execute(&pool)
        .await
        .expect("suspend tenant");

    let placed = place_bunyip_user(
        &auth,
        Some(&tenants),
        Some(&invitations),
        sub,
        Some("suspended-tenant-probe@example.com".to_string()),
        true,
        None,
        None,
        &claims(sub, Some("admin")),
    )
    .await;
    assert!(
        placed.is_none(),
        "suspended tenant is rejected on the bunyip path"
    );
}

// PMS-635: a user JIT-mirrored before bunyip verified their email lands under
// the `{sub}@unresolved.invalid` placeholder. `upsert_user_from_oidc` runs on
// first sight ONLY, so that placeholder used to be permanent: every mokosh-side
// email to the user was addressed to a reserved non-routable domain (guaranteed
// bounce, rejected outright by Google Workspace) and `email_verified_at` stayed
// NULL so no invite could ever match. The row now repairs itself on the first
// request after bunyip reports the address verified.
//
// MAPPS-458 (PMS-728 slice 2) removed the way such a row comes to exist: an
// unverified first sight matches no invitation (the gate is
// `(Some(invs), Some(em)) if email_verified`), so it is now rejected outright
// and NO NEW row can hold the placeholder. The repair is still needed and still
// correct for the rows already sitting on deployed databases, so the tests below
// place the user legitimately - invited, verified - and then set the row to the
// legacy placeholder shape with SQL. Do not restore the old first-sight setup:
// it asserts the self-signup MAPPS-458 abolished.

/// The row's stored `(email, email_verified_at IS NOT NULL)`.
async fn email_state(pool: &PgPool, sub: Uuid) -> (String, bool) {
    sqlx::query_as("SELECT email, email_verified_at IS NOT NULL FROM users WHERE id = $1")
        .bind(sub)
        .fetch_one(pool)
        .await
        .expect("user row")
}

/// MAPPS-458: a pending invitation is the only way a `users` row comes into
/// existence on the bunyip path, so every test below that needs a placed user
/// seeds one first. Returns the tenant the invited address will land in.
async fn invite_into_new_org(
    tenants: &Arc<TenantService>,
    invitations: &Arc<InvitationsService>,
    admin_id: Uuid,
    email: &str,
) -> Uuid {
    let org = tenants
        .ensure_personal_tenant(Uuid::new_v4(), None, None)
        .await
        .expect("org tenant");
    invitations
        .create(
            TenantId::from_trusted(org),
            admin_id,
            &invite(email, "manager"),
            &AuditCtx::system(org),
        )
        .await
        .expect("invite");
    org
}

/// Put a legitimately-placed row back into the legacy placeholder shape:
/// `{sub}@unresolved.invalid` with no `email_verified_at`. That is exactly what
/// a pre-MAPPS-458 unverified first sight left behind, and the only way such a
/// row can still be met - on a database that was migrated from that era.
async fn degrade_to_placeholder(pool: &PgPool, sub: Uuid) {
    let affected = sqlx::query(
        "UPDATE users SET email = $2, email_verified_at = NULL, updated_at = NOW() WHERE id = $1",
    )
    .bind(sub)
    .bind(format!("{sub}@unresolved.invalid"))
    .execute(pool)
    .await
    .expect("degrade the row to the placeholder shape")
    .rows_affected();
    assert_eq!(
        affected, 1,
        "the user must already be placed before the row is degraded"
    );
}

/// MAPPS-458: the inverse of the pre-MAPPS-458
/// `unverified_first_sight_user_is_mirrored_under_the_placeholder`, which this
/// test replaces. Mirroring an unverified first sight under the placeholder is
/// how those rows came to exist; that path is now a rejection, so the address is
/// refused placement and writes no `users` row at all.
///
/// The remaining cell of the matrix:
/// `uninvited_bunyip_user_without_invite_is_rejected` covers verified and
/// uninvited, `unverified_email_does_not_consume_an_invite` covers unverified
/// with an invitation pending, and this one covers unverified AND uninvited.
#[sqlx::test]
async fn unverified_uninvited_first_sight_is_refused_placement(pool: PgPool) {
    let (auth, tenants, invitations) = services(&pool);
    let sub = Uuid::new_v4();
    let state = place_bunyip_user(
        &auth,
        Some(&tenants),
        Some(&invitations),
        sub,
        Some("david@example.com".to_string()),
        false,
        None,
        None,
        &claims(sub, None),
    )
    .await;

    assert!(
        state.is_none(),
        "an unverified, uninvited first sight is rejected, not mirrored (MAPPS-458)"
    );

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE id = $1")
        .bind(sub)
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(
        count, 0,
        "no `users` row is written, so no new row can hold the unresolved-email placeholder"
    );
}

#[sqlx::test]
async fn userinfo_is_fetched_while_the_row_holds_a_placeholder_email(pool: PgPool) {
    // The PMS-713 hop is skipped for placed users, which is what made the
    // placeholder permanent. A placeholder row must keep fetching userinfo:
    // nothing else can tell mokosh the address was verified since.
    //
    // MAPPS-458: the row is placed by invitation and then degraded, because an
    // unverified first sight no longer produces one.
    let (admin_id, _e, _p) = common::seed_admin(&pool).await;
    let (auth, tenants, invitations) = services(&pool);
    let sub = Uuid::new_v4();
    invite_into_new_org(&tenants, &invitations, admin_id, "david@example.com").await;
    place_bunyip_user(
        &auth,
        Some(&tenants),
        Some(&invitations),
        sub,
        Some("david@example.com".to_string()),
        true,
        None,
        None,
        &claims(sub, None),
    )
    .await
    .expect("placed");
    degrade_to_placeholder(&pool, sub).await;

    assert!(
        bunyip_userinfo_needed(&auth, Some(&invitations), sub).await,
        "a placeholder row must keep fetching userinfo until it is repaired"
    );
}

#[sqlx::test]
async fn placeholder_email_is_repaired_once_bunyip_verifies_it(pool: PgPool) {
    // MAPPS-458: the row is placed by invitation and then degraded to the legacy
    // placeholder shape. Before MAPPS-458 an unverified first sight wrote that
    // row directly; today it is rejected instead.
    let (admin_id, _e, _p) = common::seed_admin(&pool).await;
    let (auth, tenants, invitations) = services(&pool);
    let sub = Uuid::new_v4();
    let org = invite_into_new_org(&tenants, &invitations, admin_id, "david@example.com").await;
    place_bunyip_user(
        &auth,
        Some(&tenants),
        Some(&invitations),
        sub,
        Some("david@example.com".to_string()),
        true,
        None,
        None,
        &claims(sub, None),
    )
    .await
    .expect("first placement");
    degrade_to_placeholder(&pool, sub).await;
    let (tenant, _) = user_tenant_role(&pool, sub).await;
    assert_eq!(tenant, org, "the invited user lands in the inviting tenant");

    // Next request after the user verifies in bunyip -> the row is repaired.
    place_bunyip_user(
        &auth,
        Some(&tenants),
        Some(&invitations),
        sub,
        Some("david@example.com".to_string()),
        true,
        None,
        None,
        &claims(sub, None),
    )
    .await
    .expect("second placement");

    let (email, verified) = email_state(&pool, sub).await;
    assert_eq!(email, "david@example.com", "the real address is persisted");
    assert!(verified, "email_verified_at is stamped on repair");
    let (tenant2, _) = user_tenant_role(&pool, sub).await;
    assert_eq!(tenant, tenant2, "the repair does not move the user");
    assert!(
        !bunyip_userinfo_needed(&auth, Some(&invitations), sub).await,
        "a repaired row falls back to the no-userinfo fast path"
    );
}

#[sqlx::test]
async fn a_real_address_is_never_overwritten_by_the_repair(pool: PgPool) {
    // The repair only ever replaces the placeholder. A verified user whose
    // userinfo later reports a different address keeps the stored one (bunyip
    // address changes are out of scope here) and an unverified userinfo response
    // cannot clobber a verified row.
    //
    // MAPPS-458: the invitation is what lets the first placement happen at all;
    // the assertions below are unchanged. The address is verified here, so
    // seeding the invite is the whole adaptation.
    let (admin_id, _e, _p) = common::seed_admin(&pool).await;
    let (auth, tenants, invitations) = services(&pool);
    let sub = Uuid::new_v4();
    invite_into_new_org(&tenants, &invitations, admin_id, "real@example.com").await;
    place_bunyip_user(
        &auth,
        Some(&tenants),
        Some(&invitations),
        sub,
        Some("real@example.com".to_string()),
        true,
        None,
        None,
        &claims(sub, None),
    )
    .await
    .expect("first placement");

    for (email, verified) in [("other@example.com", true), ("attacker@example.com", false)] {
        place_bunyip_user(
            &auth,
            Some(&tenants),
            Some(&invitations),
            sub,
            Some(email.to_string()),
            verified,
            None,
            None,
            &claims(sub, None),
        )
        .await
        .expect("re-placement");
        let (stored, stored_verified) = email_state(&pool, sub).await;
        assert_eq!(stored, "real@example.com", "stored address is untouched");
        assert!(stored_verified, "verified_at stays stamped");
    }
}

#[sqlx::test]
async fn a_repaired_user_can_then_consume_a_pending_invite(pool: PgPool) {
    // The downstream consequence of the placeholder: `email_verified_at IS NULL`
    // plus a placeholder address means the invite gate can never open. After the
    // repair the invite for the real address is honored.
    //
    // MAPPS-458: the placeholder row is reached by placing the user through a
    // FIRST invitation and degrading the row, not by an unverified first sight.
    // A second org then invites the same address, which is the invite the repair
    // has to make consumable.
    let (admin_id, _e, _p) = common::seed_admin(&pool).await;
    let (auth, tenants, invitations) = services(&pool);

    let sub = Uuid::new_v4();
    let home = invite_into_new_org(&tenants, &invitations, admin_id, "invited@example.com").await;
    place_bunyip_user(
        &auth,
        Some(&tenants),
        Some(&invitations),
        sub,
        Some("invited@example.com".to_string()),
        true,
        None,
        None,
        &claims(sub, None),
    )
    .await
    .expect("first placement");
    degrade_to_placeholder(&pool, sub).await;
    let (before, _) = user_tenant_role(&pool, sub).await;
    assert_eq!(before, home, "the first invitation placed the user");

    let org = invite_into_new_org(&tenants, &invitations, admin_id, "invited@example.com").await;

    place_bunyip_user(
        &auth,
        Some(&tenants),
        Some(&invitations),
        sub,
        Some("invited@example.com".to_string()),
        true,
        None,
        None,
        &claims(sub, None),
    )
    .await
    .expect("second placement");

    let (tenant, _role) = user_tenant_role(&pool, sub).await;
    assert_eq!(tenant, org, "the repaired user joins the inviting tenant");
    let (email, verified) = email_state(&pool, sub).await;
    assert_eq!(email, "invited@example.com");
    assert!(verified);
}
