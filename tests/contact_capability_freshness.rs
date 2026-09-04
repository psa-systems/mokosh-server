//! PMS-985: a portal role assigned or revoked in the staff admin takes
//! effect for the contact on their very next request.
//!
//! The reported symptom was that the change only appeared after the
//! server was restarted. The cause is one step upstream of that: the
//! effective capability set was minted into the contact's JWT at login,
//! and the contact-plane dashboard was reading that snapshot rather than
//! the database. A restart forces every SPA to sign in again, which
//! re-mints the token, which is why restarting looked like the fix.
//!
//! What these tests pin is the contract in
//! `contact_portal::capabilities`: there is no cache, so there is
//! nothing to invalidate, and the answer is read for the request being
//! served. Every assertion below re-uses the SAME access token across
//! the admin's write, because a test that logged in again afterwards
//! would pass against the very bug being fixed.

mod common;

use reqwest::StatusCode;
use sqlx::PgPool;
use uuid::Uuid;

use mokosh_server::utils::deployment::DeploymentMode;

/// Seed a Company + Contact under [`common::DEFAULT_TENANT_ID`], grant
/// portal access with the named built-in role(s), and return
/// `(company_id, contact_id, access_token)`.
///
/// Lifted from `tests/contact_scope.rs`: the token has to come from a
/// real login so it carries the `caps` claim the fix stops trusting.
async fn seed_portal_contact(
    app: &common::TestApp,
    pool: &PgPool,
    email_local: &str,
    role_names: &[&str],
) -> (Uuid, Uuid, String) {
    let email = format!("{email_local}@cap-freshness.example");
    let company_id = Uuid::new_v4();
    let slug = format!("cf-{}", &Uuid::new_v4().simple().to_string()[..12]);
    sqlx::query("INSERT INTO companies (id, tenant_id, name, portal_slug) VALUES ($1, $2, $3, $4)")
        .bind(company_id)
        .bind(common::DEFAULT_TENANT_ID)
        .bind(format!("Cap Freshness Co {email_local}"))
        .bind(&slug)
        .execute(pool)
        .await
        .expect("seed company");

    let contact_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO contacts (id, tenant_id, company_id, first_name, last_name, email) \
         VALUES ($1, $2, $3, 'Cap', 'Freshness', $4)",
    )
    .bind(contact_id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company_id)
    .bind(&email)
    .execute(pool)
    .await
    .expect("seed contact");

    let db = mokosh_server::Database::from_pool(pool.clone());
    let contact_svc = mokosh_server::modules::contacts::ContactService::new(db);
    let role_ids = role_ids_for(pool, role_names).await;
    let outcome = contact_svc
        .grant_portal_access(
            mokosh_server::modules::auth::TenantId::from_trusted(common::DEFAULT_TENANT_ID),
            contact_id,
            &role_ids,
            &mokosh_server::modules::audit::AuditCtx::system(common::DEFAULT_TENANT_ID),
        )
        .await
        .expect("grant_portal_access");

    let prefix = format!("/portal/{}/set-password?token=", outcome.portal_slug);
    let setup_token = outcome
        .setup_link
        .split(&prefix)
        .nth(1)
        .expect("token in setup_link")
        .to_string();
    let password = "Kq7$mZ2n#PxR9wLf";
    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/set-password"))
        .json(&serde_json::json!({ "token": setup_token, "password": password }))
        .send()
        .await
        .expect("set-password");
    assert_eq!(resp.status(), StatusCode::NO_CONTENT, "set-password 204");

    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/login"))
        .json(&serde_json::json!({
            "slug": outcome.portal_slug,
            "email": email,
            "password": password,
        }))
        .send()
        .await
        .expect("contact login");
    assert_eq!(resp.status(), StatusCode::OK, "contact login 200");
    let body: serde_json::Value = resp.json().await.expect("login JSON");
    let access = body["access_token"]
        .as_str()
        .expect("access_token in login response")
        .to_string();
    (company_id, contact_id, access)
}

/// Resolve the built-in role names seeded by migration 142 to ids.
async fn role_ids_for(pool: &PgPool, names: &[&str]) -> Vec<Uuid> {
    let mut ids = Vec::new();
    for name in names {
        let id: Uuid =
            sqlx::query_scalar("SELECT id FROM portal_roles WHERE tenant_id = $1 AND name = $2")
                .bind(common::DEFAULT_TENANT_ID)
                .bind(name)
                .fetch_one(pool)
                .await
                .unwrap_or_else(|e| panic!("read portal_role {name}: {e}"));
        ids.push(id);
    }
    ids
}

/// Do what the MSP admin does in the UI: `PUT
/// /api/v1/contacts/contacts/{id}/portal-roles` with the new role set
/// (the contacts router owns several top-level prefixes, so it is
/// nested under `/contacts` and the contact routes repeat the segment).
/// Going through the real staff endpoint rather than an `INSERT` is the
/// point - the issue is about a change made in admin.
async fn set_roles_as_admin(
    app: &common::TestApp,
    pool: &PgPool,
    staff_token: &str,
    contact_id: Uuid,
    role_names: &[&str],
) {
    let role_ids = role_ids_for(pool, role_names).await;
    let resp = app
        .client
        .put(app.url(&format!(
            "/api/v1/contacts/contacts/{contact_id}/portal-roles"
        )))
        .bearer_auth(staff_token)
        .json(&serde_json::json!({ "role_ids": role_ids }))
        .send()
        .await
        .expect("admin sets portal roles");
    assert_eq!(
        resp.status(),
        StatusCode::NO_CONTENT,
        "admin role write must 204, got {}",
        resp.status()
    );
}

async fn ticket_list_status(app: &common::TestApp, token: &str) -> StatusCode {
    app.client
        .get(app.url("/api/v1/tickets"))
        .bearer_auth(token)
        .send()
        .await
        .expect("contact lists tickets")
        .status()
}

async fn dashboard_open_tickets(app: &common::TestApp, token: &str) -> i64 {
    let body: serde_json::Value = app
        .client
        .get(app.url("/api/v1/contact/dashboard/summary"))
        .bearer_auth(token)
        .send()
        .await
        .expect("contact reads dashboard")
        .json()
        .await
        .expect("dashboard JSON");
    body["open_tickets"].as_i64().expect("open_tickets")
}

async fn seed_open_tickets(pool: &PgPool, company_id: Uuid, admin_id: Uuid, n: i64) {
    let tenant_id = common::DEFAULT_TENANT_ID;
    let status: Uuid = sqlx::query_scalar(
        "SELECT id FROM ticket_statuses \
         WHERE tenant_id = $1 AND is_closed = FALSE ORDER BY sort_order LIMIT 1",
    )
    .bind(tenant_id)
    .fetch_one(pool)
    .await
    .expect("open status");
    let priority: Uuid = sqlx::query_scalar(
        "SELECT id FROM ticket_priorities WHERE tenant_id = $1 AND is_default = TRUE LIMIT 1",
    )
    .bind(tenant_id)
    .fetch_one(pool)
    .await
    .expect("default priority");
    let queue: Uuid = sqlx::query_scalar(
        "SELECT id FROM ticket_queues WHERE tenant_id = $1 AND is_default = TRUE LIMIT 1",
    )
    .bind(tenant_id)
    .fetch_one(pool)
    .await
    .expect("default queue");
    for i in 0..n {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO tickets (id, tenant_id, ticket_number, title, status_id, priority_id, \
             queue_id, source, company_id, created_by_id) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, 'internal', $8, $9)",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(format!("CF-{}-{i}", &id.simple().to_string()[..6]))
        .bind(format!("cap freshness ticket {i}"))
        .bind(status)
        .bind(priority)
        .bind(queue)
        .bind(company_id)
        .bind(admin_id)
        .execute(pool)
        .await
        .expect("seed ticket");
    }
}

/// AC1: assigning a role takes effect without a restart.
///
/// The contact starts on Billing Contact, which holds no `tickets:*`
/// capability at all, so the ticket list is refused. The admin adds
/// Support Contact; the SAME still-valid access token must be served on
/// the next call.
#[sqlx::test]
async fn assigning_a_role_lands_on_the_contacts_next_request(pool: PgPool) {
    let (admin_id, admin_email, admin_password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let staff_token = common::login(&app, &admin_email, &admin_password).await;
    let _ = admin_id;

    let (_company, contact_id, token) =
        seed_portal_contact(&app, &pool, "assign", &["Billing Contact"]).await;

    assert_eq!(
        ticket_list_status(&app, &token).await,
        StatusCode::FORBIDDEN,
        "Billing Contact holds no tickets:read, so the list must be refused first"
    );

    set_roles_as_admin(
        &app,
        &pool,
        &staff_token,
        contact_id,
        &["Billing Contact", "Support Contact"],
    )
    .await;

    assert_eq!(
        ticket_list_status(&app, &token).await,
        StatusCode::OK,
        "PMS-985: the role the admin just assigned must apply to the very next request \
         on the same token, with no restart and no re-login"
    );
}

/// AC2: removing a role likewise takes effect without a restart.
#[sqlx::test]
async fn revoking_a_role_lands_on_the_contacts_next_request(pool: PgPool) {
    let (_admin_id, admin_email, admin_password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let staff_token = common::login(&app, &admin_email, &admin_password).await;

    let (_company, contact_id, token) =
        seed_portal_contact(&app, &pool, "revoke", &["Support Contact"]).await;

    assert_eq!(
        ticket_list_status(&app, &token).await,
        StatusCode::OK,
        "Support Contact holds tickets:read, so the list must be served first"
    );

    // The admin swaps the roles rather than clearing them, which is the
    // ordinary shape of the action and leaves the contact a working
    // portal login with a different permission set.
    set_roles_as_admin(&app, &pool, &staff_token, contact_id, &["Billing Contact"]).await;

    assert_eq!(
        ticket_list_status(&app, &token).await,
        StatusCode::FORBIDDEN,
        "PMS-985: the role the admin just removed must stop applying on the very next \
         request, not after the 15-minute access-token TTL"
    );
}

/// The dashboard is the site PMS-985 actually fixed.
///
/// `GET /contact/dashboard/summary` gates each tile on the caller's
/// capabilities (MAPPS-705). It used to read them from the JWT, so the
/// first screen a contact lands on kept reporting zero open tickets
/// after the admin had granted `tickets:read` - the exact "I gave them
/// the role and they still cannot see anything" report.
#[sqlx::test]
async fn the_dashboard_counts_what_the_role_grants_right_now(pool: PgPool) {
    let (admin_id, admin_email, admin_password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let staff_token = common::login(&app, &admin_email, &admin_password).await;

    let (company_id, contact_id, token) =
        seed_portal_contact(&app, &pool, "dash", &["Billing Contact"]).await;
    seed_open_tickets(&pool, company_id, admin_id, 4).await;

    assert_eq!(
        dashboard_open_tickets(&app, &token).await,
        0,
        "a contact without tickets:read must not be told how many tickets exist"
    );

    set_roles_as_admin(
        &app,
        &pool,
        &staff_token,
        contact_id,
        &["Billing Contact", "Support Contact"],
    )
    .await;
    assert_eq!(
        dashboard_open_tickets(&app, &token).await,
        4,
        "PMS-985: the tile must fill on the next request after the grant, on the same token"
    );

    set_roles_as_admin(&app, &pool, &staff_token, contact_id, &["Billing Contact"]).await;
    assert_eq!(
        dashboard_open_tickets(&app, &token).await,
        0,
        "PMS-985: and it must empty again on the next request after the revoke"
    );
}

/// AC4: the standalone (self-hosted) deployment is covered too.
///
/// The concern raised with the issue is that standalone gets less
/// coverage than SaaS and this class of bug lands there first. Two
/// facts together settle it, and both are asserted rather than assumed:
///
/// 1. This whole suite runs standalone. Nothing here sets
///    `MOKOSH_DEPLOYMENT_MODE`, so the process is on the `self-hosted`
///    default and the three tests above ARE the standalone runs.
/// 2. The read path cannot behave differently in the other mode,
///    because no file on it can even ask which mode it is. That is
///    already enforced globally by
///    `deployment_mode_email::only_the_auth_service_and_the_startup_wiring_know_the_deployment_mode`;
///    this narrower scan names the capability-path files so a
///    deployment-mode branch introduced there fails against PMS-985's
///    own suite rather than only against PMS-904's.
#[test]
fn the_capability_read_path_is_deployment_mode_independent() {
    assert_eq!(
        DeploymentMode::from_env(),
        DeploymentMode::SelfHosted,
        "this suite must run as a standalone deployment; something set \
         MOKOSH_DEPLOYMENT_MODE and the assign/revoke tests above are no longer the \
         standalone evidence they are cited as"
    );

    let on_the_path = [
        "src/modules/auth/caller_context.rs",
        "src/modules/contact_portal/capabilities.rs",
        "src/modules/contact_portal/middleware.rs",
        "src/modules/contact_portal/routes.rs",
        "src/modules/contact_portal/service.rs",
        "src/modules/portal_roles/service.rs",
    ];
    for path in on_the_path {
        let src = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
        assert!(
            !src.contains("DeploymentMode") && !src.contains("MOKOSH_DEPLOYMENT_MODE"),
            "{path} consults the deployment mode. What a contact may do is the same \
             question in every deployment; a branch here means standalone and SaaS can \
             disagree about it, which is precisely what PMS-985 was asked to rule out."
        );
    }
}

/// The structural half of the fix: a contact session carries no
/// capability set, so a handler cannot read a stale one by accident.
///
/// The compiler already enforces this (the field is gone), but the
/// reason it is gone is worth pinning: re-adding it is a one-line
/// change that silently reopens the defect at whichever call site
/// reaches for it next.
#[test]
fn a_contact_session_carries_no_capability_snapshot() {
    let src = std::fs::read_to_string("src/modules/contact_portal/models.rs")
        .expect("read contact_portal models");
    let session = src
        .split("pub struct ContactSession {")
        .nth(1)
        .and_then(|rest| rest.split('}').next())
        .expect("ContactSession struct body");
    assert!(
        !session.contains("caps"),
        "PMS-985: ContactSession must not carry a capability set. It would be the set as \
         it stood when the token was minted, and an admin can change the assignment a \
         second later; every decision reads `portal_roles` for the request instead."
    );
}
