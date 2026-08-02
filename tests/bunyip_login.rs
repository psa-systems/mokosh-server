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

/// PMS-676: the first/bootstrap admin must be able to log in and operate with
/// FULL admin rights on a fresh instance even when email is unconfigured and
/// the address can therefore never be verified. Production authenticates the
/// bootstrap admin through bunyip-as-OP: the platform-admin claim
/// (`bunyip_role = "admin"`) maps to mokosh `super_admin` in `place_bunyip_user`,
/// and that path does NOT gate login on `email_verified`. Here `email_verified
/// = false` stands in for the "SMTP unconfigured, email can never be verified"
/// state: the admin still authenticates and still lands as `super_admin`.
#[sqlx::test]
async fn bootstrap_admin_unverified_email_still_gets_super_admin(pool: PgPool) {
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
        // Platform-admin claim -> the bootstrap admin.
        &claims(sub, Some("admin")),
    )
    .await;

    let state = state.expect("bootstrap admin authenticates even with an unverified email");
    let user = state
        .require_user()
        .expect("authenticated state carries the current user");
    assert_eq!(
        user.role,
        UserRole::SuperAdmin,
        "the platform-admin claim grants super_admin regardless of email verification"
    );
    assert!(
        state.has_role(UserRole::SuperAdmin),
        "bootstrap admin has super_admin access on a fresh, email-unconfigured instance"
    );

    let (_tenant, role) = user_tenant_role(&pool, sub).await;
    assert_eq!(
        role, "super_admin",
        "the persisted row is super_admin, so admin access survives the next request"
    );
}

/// PMS-676 companion: once email IS configured (address verified), the same
/// bootstrap-admin login still yields `super_admin` - i.e. turning email on does
/// not regress or downgrade the bootstrap admin. `email_verified = true` stands
/// in for the "SMTP configured, email verified" state.
#[sqlx::test]
async fn bootstrap_admin_verified_email_still_gets_super_admin(pool: PgPool) {
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
        UserRole::SuperAdmin,
        "enabling email must not downgrade the bootstrap admin"
    );

    let (_tenant, role) = user_tenant_role(&pool, sub).await;
    assert_eq!(role, "super_admin");
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

/// PMS-512: bunyip owns the profile names, so the local columns are a
/// read-only cache refreshed on EVERY login, not just the JIT one. A rename in
/// bunyip lands in `users.first_name` / `last_name` on the next placement.
#[sqlx::test]
async fn name_claims_refresh_on_every_login(pool: PgPool) {
    let (auth, tenants, invitations) = services(&pool);

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
    let (auth, tenants, invitations) = services(&pool);

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
#[sqlx::test]
async fn suspended_tenant_is_not_placed(pool: PgPool) {
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
    assert!(placed.is_some(), "active tenant places normally");

    sqlx::query("UPDATE tenants SET status = 'suspended' WHERE id = $1")
        .bind(common::DEFAULT_TENANT_ID)
        .execute(&pool)
        .await
        .expect("suspend tenant");

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
        "suspended tenant is rejected on the bunyip path"
    );
}
