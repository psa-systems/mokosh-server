//! Integration tests for the `invitations` module (PMS-244).

mod common;

use sqlx::PgPool;

use mokosh_server::modules::audit::AuditCtx;
use mokosh_server::modules::auth::TenantId;
use mokosh_server::modules::invitations::{CreateInvitationRequest, InvitationsService};
use mokosh_server::utils::pagination::PaginationParams;
use mokosh_server::Database;

fn svc(pool: &PgPool) -> InvitationsService {
    InvitationsService::new(Database::from_pool(pool.clone()))
}

// PMS-318 sweep: create now writes a Create audit row, so it takes an AuditCtx.
fn actx() -> AuditCtx {
    AuditCtx {
        tenant_id: Some(common::DEFAULT_TENANT_ID),
        user_id: None,
        ip: None,
        user_agent: None,
    }
}

fn page() -> PaginationParams {
    PaginationParams {
        page: 1,
        per_page: 25,
        sort: None,
        sort_dir: "desc".to_string(),
    }
}

fn req(email: &str, role: &str) -> CreateInvitationRequest {
    CreateInvitationRequest {
        email: email.to_string(),
        role: role.to_string(),
    }
}

#[sqlx::test]
async fn create_list_revoke_roundtrip(pool: PgPool) {
    let (admin_id, _email, _password) = common::seed_admin(&pool).await;
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);
    let s = svc(&pool);

    let inv = s
        .create(
            tenant,
            admin_id,
            &req("Tech@Example.com", "technician"),
            &actx(),
        )
        .await
        .expect("create invite");
    assert_eq!(inv.email, "tech@example.com", "email is lowercased");
    assert_eq!(inv.role, "technician");
    assert_eq!(inv.status, "pending");

    let (items, total) = s.list_pending(tenant, &page()).await.expect("list");
    assert_eq!(total, 1);
    assert_eq!(items.len(), 1);

    s.revoke(tenant, inv.id).await.expect("revoke");
    let (_items, total) = s
        .list_pending(tenant, &page())
        .await
        .expect("list after revoke");
    assert_eq!(total, 0, "revoked invite no longer pending");

    // Revoking again 404s (no live invite).
    assert!(s.revoke(tenant, inv.id).await.is_err());
}

#[sqlx::test]
async fn reinvite_same_email_upserts(pool: PgPool) {
    let (admin_id, _e, _p) = common::seed_admin(&pool).await;
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);
    let s = svc(&pool);

    let first = s
        .create(
            tenant,
            admin_id,
            &req("dup@example.com", "technician"),
            &actx(),
        )
        .await
        .expect("first");
    let second = s
        .create(
            tenant,
            admin_id,
            &req("dup@example.com", "manager"),
            &actx(),
        )
        .await
        .expect("re-invite");

    assert_eq!(first.id, second.id, "same live invite, refreshed");
    assert_eq!(second.role, "manager", "role updated on re-invite");

    let (_items, total) = s.list_pending(tenant, &page()).await.expect("list");
    assert_eq!(total, 1, "no duplicate pending invite");
}

#[sqlx::test]
async fn rejects_non_invitable_role(pool: PgPool) {
    let (admin_id, _e, _p) = common::seed_admin(&pool).await;
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);

    let err = svc(&pool)
        .create(
            tenant,
            admin_id,
            &req("x@example.com", "super_admin"),
            &actx(),
        )
        .await;
    assert!(err.is_err(), "super_admin is not invitable");
}

#[sqlx::test]
async fn create_with_app_url_enqueues_invite_email(pool: PgPool) {
    // PMS-246: with a SPA URL configured, creating an invite enqueues an email
    // notification (channel=email, recipient=invitee) for the worker to deliver.
    let (admin_id, _e, _p) = common::seed_admin(&pool).await;
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);
    let s = InvitationsService::new(Database::from_pool(pool.clone()))
        .with_app_url("https://app.example.test".to_string());

    s.create(
        tenant,
        admin_id,
        &req("Invitee@Example.com", "technician"),
        &actx(),
    )
    .await
    .expect("create invite");

    let row: Option<(String, Option<String>, String)> = sqlx::query_as(
        "SELECT channel_type, recipient, body FROM notifications
         WHERE tenant_id = $1 AND channel_type = 'email' AND recipient = $2",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind("invitee@example.com")
    .fetch_optional(&pool)
    .await
    .expect("query notification");

    let (channel, recipient, body) = row.expect("an invite email was enqueued");
    assert_eq!(channel, "email");
    assert_eq!(recipient.as_deref(), Some("invitee@example.com"));
    assert!(
        body.contains("https://app.example.test"),
        "body carries the accept link"
    );

    // Without a SPA URL, no email is enqueued (tests / unconfigured deploys).
    let s2 = InvitationsService::new(Database::from_pool(pool.clone()));
    s2.create(
        tenant,
        admin_id,
        &req("noemail@example.com", "technician"),
        &actx(),
    )
    .await
    .expect("create invite without email");
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM notifications WHERE recipient = 'noemail@example.com'",
    )
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(count, 0, "no email enqueued when app_url is unset");
}

#[sqlx::test]
async fn newest_pending_lookup_then_accept(pool: PgPool) {
    // The login path's building blocks (PMS-244 phase 2): resolve the newest
    // live invite for an email, then mark it accepted so it stops resolving.
    let (admin_id, _e, _p) = common::seed_admin(&pool).await;
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);
    let s = svc(&pool);

    let inv = s
        .create(
            tenant,
            admin_id,
            &req("Joiner@Example.com", "manager"),
            &actx(),
        )
        .await
        .expect("invite");

    let found = s
        .newest_pending_for("joiner@example.com")
        .await
        .expect("lookup")
        .expect("a pending invite");
    assert_eq!(found.id, inv.id);
    assert_eq!(found.tenant_id, common::DEFAULT_TENANT_ID);
    assert_eq!(found.role, "manager");

    s.accept(inv.id, admin_id).await.expect("accept");

    assert!(
        s.newest_pending_for("joiner@example.com")
            .await
            .expect("lookup after accept")
            .is_none(),
        "accepted invite no longer resolves"
    );
    let status: String = sqlx::query_scalar("SELECT status FROM tenant_invitations WHERE id = $1")
        .bind(inv.id)
        .fetch_one(&pool)
        .await
        .expect("status");
    assert_eq!(status, "accepted");
}

#[sqlx::test]
async fn first_invite_promotes_personal_tenant_to_org(pool: PgPool) {
    let (admin_id, _e, _p) = common::seed_admin(&pool).await;
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);

    sqlx::query("UPDATE tenants SET kind = 'personal' WHERE id = $1")
        .bind(common::DEFAULT_TENANT_ID)
        .execute(&pool)
        .await
        .expect("make tenant personal");

    svc(&pool)
        .create(
            tenant,
            admin_id,
            &req("colleague@example.com", "technician"),
            &actx(),
        )
        .await
        .expect("invite");

    let kind: String = sqlx::query_scalar("SELECT kind FROM tenants WHERE id = $1")
        .bind(common::DEFAULT_TENANT_ID)
        .fetch_one(&pool)
        .await
        .expect("read kind");
    assert_eq!(kind, "org", "inviting promotes a personal tenant to org");
}
