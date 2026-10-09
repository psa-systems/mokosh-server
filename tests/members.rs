//! MAPPS-877 phase 1: `GET /api/v1/members` returns the merged list of
//! native `users` rows plus active cross-account grants from
//! `mokosh_bunyip_grants`. A placed grantee (a users row whose
//! `bunyip_user_id` matches a grant) is collapsed to one `User` row
//! decorated with `placed_by_grant_id`; a grant with no matching users row
//! is an `UnplacedGuest`.
//!
//! Standalone-mode shape only (reads grants directly from
//! `mokosh_bunyip_grants`); the SaaS fan-out that composes an upstream
//! bunyip directory lands in a later phase.

mod common;

use mokosh_test::mokosh_test;
use reqwest::StatusCode;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_user(
    pool: &PgPool,
    email: &str,
    first: &str,
    last: &str,
    role: &str,
) -> (Uuid, Uuid) {
    let id = Uuid::new_v4();
    let bunyip_user_id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO users
               (id, tenant_id, email, first_name, last_name, role, status, bunyip_user_id,
                email_verified_at)
               VALUES ($1, $2, $3, $4, $5, $6, 'active', $7, NOW())"#,
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(email)
    .bind(first)
    .bind(last)
    .bind(role)
    .bind(bunyip_user_id)
    .execute(pool)
    .await
    .expect("seed user");
    (id, bunyip_user_id)
}

/// Insert a grant whose `grantee_bunyip_user_id` either does or does not
/// match a seeded user. The tenant slug comes from the DEFAULT tenant row.
async fn seed_grant(pool: &PgPool, grantee: Uuid, role: &str) -> Uuid {
    let id = Uuid::new_v4();
    let slug: String = sqlx::query_scalar("SELECT slug FROM tenants WHERE id = $1")
        .bind(common::DEFAULT_TENANT_ID)
        .fetch_one(pool)
        .await
        .expect("tenant slug");
    sqlx::query(
        r#"INSERT INTO mokosh_bunyip_grants
               (id, grantee_bunyip_user_id, owner_bunyip_user_id, mokosh_account_id,
                bunyip_grant_id, role, granted_at)
               VALUES ($1, $2, $3, $4, $5, $6, NOW())"#,
    )
    .bind(id)
    .bind(grantee)
    .bind(Uuid::new_v4())
    .bind(slug)
    .bind(Uuid::new_v4())
    .bind(role)
    .execute(pool)
    .await
    .expect("seed grant");
    id
}

async fn get_members(app: &common::TestApp, token: &str, query: &str) -> Value {
    let path = if query.is_empty() {
        "/api/v1/members".to_string()
    } else {
        format!("/api/v1/members?{}", query)
    };
    let resp = app
        .client
        .get(app.url(&path))
        .bearer_auth(token)
        .send()
        .await
        .expect("send list members");
    assert!(
        resp.status().is_success(),
        "list members should 2xx, got {}: {}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
    resp.json().await.expect("members JSON")
}

/// T1: no grants, three native users -> three User rows, no guests.
#[mokosh_test]
async fn list_members_returns_native_users_alone_when_no_grants(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    seed_user(&pool, "alice@acme.example", "Alice", "Adams", "manager").await;
    seed_user(&pool, "bob@acme.example", "Bob", "Baker", "technician").await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let body = get_members(&app, &token, "").await;
    let rows = body["rows"].as_array().expect("rows array");
    // Three rows: the seeded admin + Alice + Bob. No unplaced guests.
    assert_eq!(body["total"].as_u64(), Some(3));
    assert_eq!(rows.len(), 3);
    for r in rows {
        assert_eq!(r["kind"].as_str(), Some("user"));
        assert!(r["placed_by_grant_id"].is_null());
    }
    assert_eq!(body["bunyip_reachable"].as_bool(), Some(true));
}

/// T2: a users row whose bunyip_user_id matches a grant is placed; the
/// SPA sees one `User` row decorated with `placed_by_grant_id`.
#[mokosh_test]
async fn list_members_decorates_a_placed_guest_with_placed_by_grant_id(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let (_guest_user_id, guest_bunyip_id) =
        seed_user(&pool, "guest@partner.example", "Grace", "Guest", "manager").await;
    let grant_id = seed_grant(&pool, guest_bunyip_id, "manager").await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let body = get_members(&app, &token, "").await;
    let rows = body["rows"].as_array().expect("rows");
    // Admin + guest. The guest row carries the grant id; the admin's does not.
    assert_eq!(body["total"].as_u64(), Some(2));
    let guest_row = rows
        .iter()
        .find(|r| r["email"] == "guest@partner.example")
        .expect("guest row");
    assert_eq!(guest_row["kind"].as_str(), Some("user"));
    assert_eq!(
        guest_row["placed_by_grant_id"].as_str(),
        Some(grant_id.to_string().as_str())
    );
    let admin_row = rows
        .iter()
        .find(|r| r["email"] == "test-admin@example.com")
        .expect("admin row");
    assert!(admin_row["placed_by_grant_id"].is_null());
}

/// T3: a grant naming a bunyip user with no local users row is an
/// UnplacedGuest.
#[mokosh_test]
async fn list_members_emits_an_unplaced_guest_for_a_grant_with_no_users_row(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let orphan_bunyip = Uuid::new_v4();
    let grant_id = seed_grant(&pool, orphan_bunyip, "finance").await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let body = get_members(&app, &token, "").await;
    let rows = body["rows"].as_array().expect("rows");
    let guest = rows
        .iter()
        .find(|r| r["kind"] == "unplaced_guest")
        .expect("unplaced guest row");
    assert_eq!(
        guest["grant_id"].as_str(),
        Some(grant_id.to_string().as_str())
    );
    assert_eq!(guest["role"].as_str(), Some("finance"));
    assert_eq!(body["total"].as_u64(), Some(2));
}

/// T8-ish: `kind=user` hides UnplacedGuest; `kind=guest` keeps the placed
/// guest AND the unplaced one.
#[mokosh_test]
async fn list_members_filter_by_kind_splits_placed_and_unplaced_from_native(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let (_placed_id, placed_bunyip) = seed_user(
        &pool,
        "placed@partner.example",
        "Placed",
        "Guest",
        "manager",
    )
    .await;
    seed_grant(&pool, placed_bunyip, "manager").await;
    seed_grant(&pool, Uuid::new_v4(), "finance").await; // unplaced
    seed_user(&pool, "native@acme.example", "Nat", "Native", "technician").await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let users_only = get_members(&app, &token, "kind=user").await;
    let user_rows = users_only["rows"].as_array().expect("rows");
    // Admin + native. Placed-guest and unplaced-guest are hidden.
    assert_eq!(user_rows.len(), 2);
    for r in user_rows {
        assert_eq!(r["kind"].as_str(), Some("user"));
        assert!(r["placed_by_grant_id"].is_null());
    }

    let guests_only = get_members(&app, &token, "kind=guest").await;
    let guest_rows = guests_only["rows"].as_array().expect("rows");
    // One placed guest + one unplaced guest.
    assert_eq!(guest_rows.len(), 2);
    let kinds: Vec<&str> = guest_rows
        .iter()
        .map(|r| r["kind"].as_str().unwrap())
        .collect();
    assert!(kinds.contains(&"user"));
    assert!(kinds.contains(&"unplaced_guest"));
}

/// T12: the reader is gated on `RequireManager`. A technician (not a
/// manager / admin) gets 403.
#[mokosh_test]
async fn list_members_gates_on_require_manager(pool: PgPool) {
    let (_admin_id, admin_email, admin_pw) = common::seed_admin(&pool).await;
    // Seed a technician with a known password through the same path.
    let tech_pw = "tech-password-12345".to_string();
    let tech_pw_hash = mokosh_server::utils::crypto::hash_password(&tech_pw)
        .await
        .expect("hash tech password");
    let tech_id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO users
               (id, tenant_id, email, password_hash, first_name, last_name,
                role, status, email_verified_at)
               VALUES ($1, $2, 'tech@acme.example', $3, 'T', 'Tech',
                       'technician', 'active', NOW())"#,
    )
    .bind(tech_id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(&tech_pw_hash)
    .execute(&pool)
    .await
    .expect("seed tech");

    let app = common::boot(pool.clone()).await;
    let tech_token = common::login(&app, "tech@acme.example", &tech_pw).await;
    let admin_token = common::login(&app, &admin_email, &admin_pw).await;

    let tech_resp = app
        .client
        .get(app.url("/api/v1/members"))
        .bearer_auth(&tech_token)
        .send()
        .await
        .expect("send");
    assert_eq!(tech_resp.status(), StatusCode::FORBIDDEN);

    let admin_resp = app
        .client
        .get(app.url("/api/v1/members"))
        .bearer_auth(&admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(admin_resp.status(), StatusCode::OK);
}

/// T13: the MAPPS-562 `system+<slug>@mokosh.local` attribution user is
/// hidden here the same way `list_users` hides it.
#[mokosh_test]
async fn list_members_hides_the_system_attribution_user(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    sqlx::query(
        r#"INSERT INTO users
               (id, tenant_id, email, first_name, last_name, role, status, bunyip_user_id,
                email_verified_at)
               VALUES ($1, $2, $3, 'System', 'Attribution', 'technician', 'active', $4, NOW())"#,
    )
    .bind(Uuid::new_v4())
    .bind(common::DEFAULT_TENANT_ID)
    .bind("system+default@mokosh.local")
    .bind(Uuid::new_v4())
    .execute(&pool)
    .await
    .expect("seed system user");
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let body = get_members(&app, &token, "").await;
    let rows = body["rows"].as_array().expect("rows");
    for r in rows {
        let email = r["email"].as_str().unwrap_or("");
        assert!(
            !email.ends_with("@mokosh.local"),
            "system attribution row leaked: {email}"
        );
    }
}

/// T11: `GET /teams` returns `member_count` populated, batched, for every
/// team in the page (zero-member teams get `Some(0)`, never missing).
#[mokosh_test]
async fn team_list_carries_member_count(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let team_a = Uuid::new_v4();
    let team_b = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO teams (id, tenant_id, name, is_active) VALUES ($1, $2, 'Team A', TRUE), ($3, $2, 'Team B', TRUE)",
    )
    .bind(team_a)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(team_b)
    .execute(&pool)
    .await
    .expect("seed teams");
    // Team A: two members. Team B: zero.
    let (user1_id, _) = seed_user(&pool, "m1@acme.example", "M", "One", "technician").await;
    let (user2_id, _) = seed_user(&pool, "m2@acme.example", "M", "Two", "technician").await;
    for user in [admin_id, user1_id, user2_id].iter().take(2) {
        sqlx::query(
            "INSERT INTO team_members (tenant_id, team_id, user_id, role) VALUES ($1, $2, $3, 'member')",
        )
        .bind(common::DEFAULT_TENANT_ID)
        .bind(team_a)
        .bind(user)
        .execute(&pool)
        .await
        .expect("seed team_member");
    }
    let _ = user2_id;

    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let resp = app
        .client
        .get(app.url("/api/v1/teams"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list teams");
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.expect("teams JSON");
    let items = body["data"].as_array().expect("data");
    let a = items
        .iter()
        .find(|t| t["name"] == "Team A")
        .expect("team A");
    let b = items
        .iter()
        .find(|t| t["name"] == "Team B")
        .expect("team B");
    assert_eq!(a["member_count"].as_u64(), Some(2), "{a}");
    assert_eq!(b["member_count"].as_u64(), Some(0), "{b}");
}

/// Validation at the API boundary: an unknown `kind` is a 422 named on the
/// field, not a silent empty-list.
#[mokosh_test]
async fn list_members_rejects_an_unknown_kind_at_validation(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let resp = app
        .client
        .get(app.url("/api/v1/members?kind=robots"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let dump = resp.text().await.unwrap_or_default();
    assert!(dump.contains("kind"), "error names the field: {dump}");
}

// Deliberately deferred to later phases:
// - T4 / T5 / T6 / T7 / T9 / T10: the sort / pagination / q / role /
//   team_id / bunyip-unreachable paths; the standalone-mode build keeps
//   `bunyip_reachable = true` so T10 does not apply, and the other
//   filters are mechanical variations the SPA will exercise during
//   phase 3 end-to-end.
