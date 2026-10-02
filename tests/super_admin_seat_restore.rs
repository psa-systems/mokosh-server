//! PMS-1425: migration 260 gives back the tenant seat migration 162 took.
//!
//! 162 retired `users.role = 'super_admin'` by deactivating the row and
//! clearing its credentials, which preserved ticket attribution and also took
//! away the person's only seat in their tenant: `ensure_principal_usable`
//! refuses a row whose `status <> 'active'`, so every API call answered 403
//! "Account is not active" for everyone who had ever been a super-admin. It hit
//! nc-01 on the first upgrade past 162 and five rows went with it.
//!
//! What this suite pins is the migration's REACH, which is the part a deployment
//! depends on and the part a careless guard gets wrong in both directions: too
//! narrow and the lockout survives the upgrade, too wide and it reactivates
//! somebody an admin deliberately switched off.
//!
//! Rows are seeded AFTER the migration has run, which is the only way to have
//! "pre-upgrade" rows in a template-cloned database, and the statement is then
//! applied from the migration file itself (`include_str!`) so the thing under
//! test is the shipped text rather than a copy of it.

mod common;

use mokosh_test::mokosh_test;
use sqlx::PgPool;
use uuid::Uuid;

const MIGRATION: &str = include_str!("../migrations/260_restore_retired_super_admin_seats.sql");

/// Seed one `users` row, in whatever state the case needs.
///
/// Returns the id, because "the row keeps its id" is half of what makes this a
/// restore rather than a re-provision: a new row would split the person's ticket
/// and note attribution across two seats, which is the alternative PMS-1425
/// rejected.
async fn seed_user(
    pool: &PgPool,
    email: &str,
    role: &str,
    status: &str,
    password_hash: Option<&str>,
    mfa_secret: Option<&str>,
) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO users \
             (tenant_id, email, first_name, last_name, role, status, password_hash, mfa_secret) \
         VALUES ($1, $2, 'Seat', 'Holder', $3, $4, $5, $6) \
         RETURNING id",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(email)
    .bind(role)
    .bind(status)
    .bind(password_hash)
    .bind(mfa_secret)
    .fetch_one(pool)
    .await
    .expect("seed a users row")
}

/// Read back the two columns the migration writes.
async fn state_of(pool: &PgPool, id: Uuid) -> (String, String) {
    sqlx::query_as("SELECT role, status FROM users WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("the row is still there")
}

/// A row in exactly the shape 162 leaves comes back as an active tenant admin,
/// keeping its id.
#[mokosh_test]
async fn a_retired_super_admin_gets_its_seat_back(pool: PgPool) {
    let id = seed_user(
        &pool,
        "pms1425-retired@example.com",
        "super_admin",
        "inactive",
        None,
        None,
    )
    .await;

    sqlx::raw_sql(MIGRATION)
        .execute(&pool)
        .await
        .expect("run the restore");

    assert_eq!(
        state_of(&pool, id).await,
        ("admin".to_string(), "active".to_string()),
        "the seat has to come back as a usable tenant admin, which is what the hand repair on \
         nc-01 chose and what the person needs to use their own tenant"
    );
    // The credentials stay NULL: bunyip is the only sign-in path for these
    // people, and a NULL hash is what keeps MAPPS-498's identity mirror
    // fail-closed rather than accepting a mirrored write from a sibling tenant.
    let (hash, secret): (Option<String>, Option<String>) =
        sqlx::query_as("SELECT password_hash, mfa_secret FROM users WHERE id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .expect("read the credential columns");
    assert_eq!((hash, secret), (None, None), "no credential is restored");
}

/// Three rows the migration must not touch, in one pass.
///
/// Each is a different way of being deliberately off, and each would be a real
/// incident if reactivated: an account somebody deactivated by hand, a role that
/// was never part of this, and an active super-admin on a database where 162
/// has not run yet.
#[mokosh_test]
async fn rows_that_were_not_retired_by_162_are_left_alone(pool: PgPool) {
    let deactivated_by_hand = seed_user(
        &pool,
        "pms1425-by-hand@example.com",
        "super_admin",
        "inactive",
        Some("$argon2id$v=19$m=19456,t=2,p=1$notarealhash"),
        None,
    )
    .await;
    let mfa_still_set = seed_user(
        &pool,
        "pms1425-mfa@example.com",
        "super_admin",
        "inactive",
        None,
        Some("JBSWY3DPEHPK3PXP"),
    )
    .await;
    let another_role = seed_user(
        &pool,
        "pms1425-technician@example.com",
        "technician",
        "inactive",
        None,
        None,
    )
    .await;

    sqlx::raw_sql(MIGRATION)
        .execute(&pool)
        .await
        .expect("run the restore");

    for (id, what) in [
        (
            deactivated_by_hand,
            "a row with a password hash was switched off by a person",
        ),
        (
            mfa_still_set,
            "a row that still holds an MFA secret was not stripped by 162",
        ),
        (
            another_role,
            "a role other than super_admin was never part of this",
        ),
    ] {
        let (role, status) = state_of(&pool, id).await;
        assert_eq!(status, "inactive", "{what}, so it stays inactive");
        assert_ne!(role, "admin", "{what}, so its role is untouched");
    }
}

/// Running it twice restores nothing the second time.
///
/// Not a throwaway: migrations run on every boot, so a statement that kept
/// finding rows would keep reactivating an account an admin had just switched
/// off, once per restart, and nobody would connect the two.
#[mokosh_test]
async fn a_second_run_restores_nothing(pool: PgPool) {
    let id = seed_user(
        &pool,
        "pms1425-twice@example.com",
        "super_admin",
        "inactive",
        None,
        None,
    )
    .await;

    sqlx::raw_sql(MIGRATION)
        .execute(&pool)
        .await
        .expect("first");
    // Switch it off the way an admin would after the upgrade, which is the
    // follow-up the migration's own header asks for.
    sqlx::query("UPDATE users SET status = 'inactive' WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await
        .expect("an admin deactivates a departed colleague");

    sqlx::raw_sql(MIGRATION)
        .execute(&pool)
        .await
        .expect("second");

    let (role, status) = state_of(&pool, id).await;
    assert_eq!(
        (role.as_str(), status.as_str()),
        ("admin", "inactive"),
        "the role moved on the first run and the guard no longer matches, so a later boot cannot \
         undo an admin's decision"
    );
}
