//! PMS-921: `GET /api/v1/auth/directory` is the minimum needed to name a
//! colleague, readable by any authenticated user of the tenant.
//!
//! The two things worth pinning are what it lets through and what it does not.
//! It exists because MAPPS-578 resolved `@handle` against the manager-gated
//! `GET /auth/users`, so a Technician saw every mention as plain text. The fix
//! must not be a wider `/users`: that response carries role, status, MFA state,
//! login history and phone numbers, and relaxing it would hand a technician a
//! colleague's security posture to solve a name lookup.

mod common;

use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

/// `GET /auth/directory` as `token`, returning `(status, body)`.
async fn get_directory(app: &common::TestApp, token: &str) -> (u16, Value) {
    let resp = app
        .client
        .get(app.url("/api/v1/auth/directory"))
        .bearer_auth(token)
        .send()
        .await
        .expect("directory request");
    let status = resp.status().as_u16();
    let body: Value = resp.json().await.unwrap_or(Value::Null);
    (status, body)
}

fn names(body: &Value) -> Vec<String> {
    body["data"]
        .as_array()
        .map(|rows| {
            rows.iter()
                .map(|r| r["name"].as_str().unwrap_or_default().to_string())
                .collect()
        })
        .unwrap_or_default()
}

/// AC1: a Technician can read it. This is the whole reason it exists, so it is
/// asserted against the role that was refused before.
#[sqlx::test]
async fn a_technician_can_read_the_directory(pool: PgPool) {
    common::seed_user(
        &pool,
        common::DEFAULT_TENANT_ID,
        "tech@example.test",
        "technician",
    )
    .await;
    let app = common::boot(pool).await;
    let token = common::login(&app, "tech@example.test", "test-password-12345").await;

    let (status, body) = get_directory(&app, &token).await;
    assert_eq!(status, 200, "a technician must be able to name a colleague");
    assert!(
        !names(&body).is_empty(),
        "and must actually see somebody: {body}"
    );
}

/// AC1 and AC7: the projection. Three fields, and nothing that belongs to user
/// management. Asserted by walking the keys rather than by naming the ones we
/// do not want, so a field added to the query fails here instead of shipping.
#[sqlx::test]
async fn the_directory_exposes_three_fields_and_no_more(pool: PgPool) {
    common::seed_user(
        &pool,
        common::DEFAULT_TENANT_ID,
        "tech@example.test",
        "technician",
    )
    .await;
    let app = common::boot(pool).await;
    let token = common::login(&app, "tech@example.test", "test-password-12345").await;

    let (_, body) = get_directory(&app, &token).await;
    let rows = body["data"].as_array().expect("a data array").clone();
    assert!(!rows.is_empty(), "{body}");

    for row in &rows {
        let obj = row.as_object().expect("an object");
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            ["handle", "id", "name"],
            "the directory is a fixed, minimal projection. Anything else here is \
             something an unprivileged caller can now read about a colleague."
        );
    }
}

/// The handle is the local part of the address, not the address. A technician
/// can already see a colleague's display name all over the app; a contactable
/// address is a disclosure this endpoint deliberately does not make.
#[sqlx::test]
async fn the_handle_is_the_local_part_and_the_address_never_appears(pool: PgPool) {
    common::seed_user(
        &pool,
        common::DEFAULT_TENANT_ID,
        "Dana.Scully@Example.Test",
        "technician",
    )
    .await;
    let app = common::boot(pool).await;
    let token = common::login(&app, "Dana.Scully@Example.Test", "test-password-12345").await;

    let (_, body) = get_directory(&app, &token).await;
    let raw = body.to_string();

    assert!(
        raw.contains("dana.scully"),
        "the handle is the lowercased local part: {raw}"
    );
    assert!(
        !raw.to_lowercase().contains("example.test"),
        "the domain must not appear anywhere, or the response reconstructs the \
         address it was designed not to carry: {raw}"
    );
    assert!(!raw.contains('@'), "no address in the response: {raw}");
}

/// AC3: a deactivated colleague is not in the directory. A mention of somebody
/// who has left then renders as the plain text it always was, which is a
/// truthful signal rather than a broken one.
#[sqlx::test]
async fn a_deactivated_user_is_not_in_the_directory(pool: PgPool) {
    common::seed_user(
        &pool,
        common::DEFAULT_TENANT_ID,
        "tech@example.test",
        "technician",
    )
    .await;
    let (gone_id, _, _) = common::seed_user(
        &pool,
        common::DEFAULT_TENANT_ID,
        "departed@example.test",
        "technician",
    )
    .await;
    sqlx::query("UPDATE users SET status = 'inactive' WHERE id = $1")
        .bind(gone_id)
        .execute(&pool)
        .await
        .expect("deactivate");

    let app = common::boot(pool).await;
    let token = common::login(&app, "tech@example.test", "test-password-12345").await;

    let (_, body) = get_directory(&app, &token).await;
    assert!(
        !body.to_string().contains("departed"),
        "a deactivated user must not be listed: {body}"
    );
}

/// AC2: tenant scoping. The read goes through `begin_with_tenant` like every
/// other serving read, so another tenant's staff are invisible.
#[sqlx::test]
async fn the_directory_never_shows_another_tenants_staff(pool: PgPool) {
    let (other_tenant, _, _, _) = common::seed_tenant_with_admin(&pool, "other-msp").await;
    common::seed_user(&pool, other_tenant, "outsider@other.test", "technician").await;
    common::seed_user(
        &pool,
        common::DEFAULT_TENANT_ID,
        "insider@example.test",
        "technician",
    )
    .await;

    let app = common::boot(pool).await;
    let token = common::login(&app, "insider@example.test", "test-password-12345").await;

    let (_, body) = get_directory(&app, &token).await;
    let raw = body.to_string();
    assert!(raw.contains("insider"), "own tenant is visible: {raw}");
    assert!(
        !raw.contains("outsider") && !raw.contains("other"),
        "another tenant's staff must never appear: {raw}"
    );
}

/// AC6: nothing about user management was relaxed. The endpoint this replaces
/// as a mention source still refuses a Technician.
#[sqlx::test]
async fn user_management_is_still_manager_gated(pool: PgPool) {
    common::seed_user(
        &pool,
        common::DEFAULT_TENANT_ID,
        "tech@example.test",
        "technician",
    )
    .await;
    let app = common::boot(pool).await;
    let token = common::login(&app, "tech@example.test", "test-password-12345").await;

    let resp = app
        .client
        .get(app.url("/api/v1/auth/users"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("users request");
    assert_eq!(
        resp.status().as_u16(),
        403,
        "PMS-921 adds a directory; it does not widen user management"
    );
}

/// AC4: the standard paginated envelope, and paging that covers every row once.
///
/// This does NOT prove the `id` tiebreak is load-bearing. Removing it and
/// re-running this test still passes, because Postgres happens to return a
/// deterministic order for a set this small; the guarantee is absent, not the
/// behaviour. The tiebreak is asserted on the query itself below, and this test
/// covers what it can actually observe: that paging the endpoint yields each
/// row exactly once.
#[sqlx::test]
async fn paging_is_the_standard_envelope_and_covers_every_row_once(pool: PgPool) {
    common::seed_user(
        &pool,
        common::DEFAULT_TENANT_ID,
        "reader@example.test",
        "technician",
    )
    .await;
    // Several users sharing one display name, which is exactly the case an
    // unstable sort gets wrong. `seed_user` names every row "Test User".
    for i in 0..6 {
        common::seed_user(
            &pool,
            common::DEFAULT_TENANT_ID,
            &format!("dup{i}@example.test"),
            "technician",
        )
        .await;
    }

    let app = common::boot(pool).await;
    let token = common::login(&app, "reader@example.test", "test-password-12345").await;

    let (_, first) = get_directory(&app, &token).await;
    let total = first["meta"]["total"].as_u64().expect("a total");
    assert!(total >= 7, "every seeded user is counted: {first}");

    let mut seen: Vec<String> = Vec::new();
    for page in 1..=4 {
        let resp = app
            .client
            .get(app.url(&format!("/api/v1/auth/directory?page={page}&per_page=2")))
            .bearer_auth(&token)
            .send()
            .await
            .expect("paged directory request");
        let body: Value = resp.json().await.expect("json");
        for row in body["data"].as_array().expect("data").iter() {
            seen.push(row["id"].as_str().unwrap_or_default().to_string());
        }
    }

    let mut unique = seen.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(
        unique.len(),
        seen.len(),
        "paging must not repeat a row. Saw: {seen:?}"
    );
    // Four pages of two covers the whole directory here, or the first eight
    // rows of a larger one. Derived from `total` rather than hardcoded, so
    // adding a seeded user to the fixture does not turn this into a failure
    // about arithmetic instead of about paging.
    assert_eq!(
        seen.len(),
        (total as usize).min(8),
        "paging must not skip a row either: {seen:?} of {total}"
    );
}

/// An unauthenticated caller gets nothing. The gate moved from
/// `RequireManager` to `RequireAuth`, not to nothing at all.
#[sqlx::test]
async fn the_directory_still_needs_a_session(pool: PgPool) {
    let app = common::boot(pool).await;
    let resp = app
        .client
        .get(app.url("/api/v1/auth/directory"))
        .send()
        .await
        .expect("anonymous directory request");
    assert_eq!(resp.status().as_u16(), 401, "no session, no directory");
}

/// The id is a real user id, so a client can key on it.
#[sqlx::test]
async fn the_id_identifies_the_user(pool: PgPool) {
    let (uid, email, password) = common::seed_user(
        &pool,
        common::DEFAULT_TENANT_ID,
        "keyed@example.test",
        "technician",
    )
    .await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let (_, body) = get_directory(&app, &token).await;
    let ids: Vec<Uuid> = body["data"]
        .as_array()
        .expect("data")
        .iter()
        .filter_map(|r| r["id"].as_str().and_then(|s| s.parse().ok()))
        .collect();
    assert!(ids.contains(&uid), "{body}");
}

/// AC5, asserted on the query rather than on a response.
///
/// `name` is not unique: `seed_user` gives every fixture row the same display
/// name, and a real tenant can easily hold two people called the same thing.
/// An `ORDER BY` on a non-unique key alone leaves the order of ties undefined,
/// so a row can land on both sides of a page boundary, or on neither.
///
/// A behavioural test cannot pin this. Postgres is free to return ties in any
/// order and, for a set that fits in one sort, reliably returns them in the
/// same one; dropping the tiebreak and re-running the paging test above still
/// passes. What is being pinned is therefore the guarantee, which lives in the
/// SQL.
#[test]
fn the_directory_sort_carries_a_unique_tiebreak() {
    const SRC: &str = include_str!("../src/modules/auth/service.rs");
    let start = SRC
        .find("pub async fn list_directory")
        .expect("list_directory is defined here");
    let body = &SRC[start..];
    let end = body.find("pub async fn list_users").unwrap_or(body.len());
    let body = &body[..end];

    assert!(
        body.contains("ORDER BY name, id"),
        "the directory's ORDER BY must carry `id` after `name`. Without it the \
         order of two people sharing a display name is undefined, and paging can \
         repeat or skip one."
    );
}
