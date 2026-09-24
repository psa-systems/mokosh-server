//! PMS-1120: the `users` <-> `identities` mirror had a lock-order cycle.
//!
//! Two triggers, two orders. `sync_user_to_identity_and_membership` locked the
//! `users` row, then `tenant_memberships`, then `identities`;
//! `sync_identity_to_users` locked the `identities` row, then `users`. Two
//! transactions writing one person on opposite planes at the same instant took
//! the two row locks in opposite orders, and Postgres killed one with
//! `40P01 deadlock detected`, which reaches the caller as a 500.
//!
//! The test below drives that interleaving deterministically. It fails on the
//! tree before this change and passes after it, and what makes it pass is that
//! there is now only one direction: nothing reaches `users` from a write to
//! `identities`, so no transaction can want the two locks in the other order.
//!
//! The deterministic shape stands in for the real race rather than replacing
//! it. In production both acquisitions happen inside one statement, so the
//! window is the microseconds between a row lock and its trigger's cross-plane
//! UPDATE; holding the first lock explicitly is how a test makes that window
//! wide enough to observe every run.

mod common;

use sqlx::PgPool;
use std::time::Duration;
use uuid::Uuid;

async fn seed_person(pool: &PgPool, email: &str) -> (Uuid, Uuid) {
    let user_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name, role, status) \
         VALUES ($1, $2, $3, 'hash', 'First', 'Last', 'admin', 'active')",
    )
    .bind(user_id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(email)
    .execute(pool)
    .await
    .expect("insert users row");

    // The forward mirror creates the identity, which is the point: one person,
    // two planes.
    let identity_id: Uuid =
        sqlx::query_scalar("SELECT id FROM identities WHERE lower(email) = lower($1)")
            .bind(email)
            .fetch_one(pool)
            .await
            .expect("the forward mirror created an identity");
    (user_id, identity_id)
}

/// The residual case PMS-1114 left behind: one transaction changing a mirrored
/// column on each plane, for the same person, at the same time.
///
/// Both must commit. A `40P01` here is the cycle, whichever transaction loses
/// it: the loser rolled back cleanly, but its caller saw a 500 on an ordinary
/// profile edit or an ordinary sign-in.
#[sqlx::test]
async fn two_mirrored_writes_on_opposite_planes_do_not_deadlock(pool: PgPool) {
    let (user_id, identity_id) = seed_person(&pool, "cycle@example.test").await;

    // Two connections from the test's own pool, because `#[sqlx::test]` runs
    // against a database it created for this test alone; `DATABASE_URL` names
    // the cluster that database was created in, not the database.
    let mut a = pool.acquire().await.expect("connection a");
    let mut b_conn = pool.acquire().await.expect("connection b");

    // A takes the `users` row first, which is the order the forward mirror
    // imposes on every writer of that plane.
    sqlx::query("BEGIN")
        .execute(&mut *a)
        .await
        .expect("begin a");
    sqlx::query("SELECT id FROM users WHERE id = $1 FOR UPDATE")
        .bind(user_id)
        .execute(&mut *a)
        .await
        .expect("a locks the users row");

    // B writes the identity plane. On the old tree its trigger then wants the
    // `users` row A is holding, so it blocks here and the cycle is armed; with
    // one direction it simply commits.
    let b = tokio::spawn(async move {
        sqlx::query("BEGIN")
            .execute(&mut *b_conn)
            .await
            .expect("begin b");
        let wrote = sqlx::query(
            "UPDATE identities SET last_login_at = NOW(), updated_at = NOW() WHERE id = $1",
        )
        .bind(identity_id)
        .execute(&mut *b_conn)
        .await;
        let committed = sqlx::query("COMMIT").execute(&mut *b_conn).await;
        (wrote.map(|_| ()), committed.map(|_| ()))
    });

    // Give B time to reach its trigger's cross-plane UPDATE and block on A.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // A now writes its own plane. Its forward trigger wants the identity row B
    // is holding: the second half of the cycle.
    let a_wrote =
        sqlx::query("UPDATE users SET first_name = 'Edited', updated_at = NOW() WHERE id = $1")
            .bind(user_id)
            .execute(&mut *a)
            .await;
    let a_committed = sqlx::query("COMMIT").execute(&mut *a).await;

    let (b_wrote, b_committed) = b.await.expect("join b");

    for (label, outcome) in [
        ("A's profile edit", a_wrote.map(|_| ())),
        ("A's commit", a_committed.map(|_| ())),
        ("B's sign-in stamp", b_wrote),
        ("B's commit", b_committed),
    ] {
        if let Err(e) = outcome {
            let code = e
                .as_database_error()
                .and_then(|d| d.code())
                .unwrap_or_default()
                .to_string();
            panic!(
                "{label} failed with {code}: {e}. A deadlock here is the \
                 users <-> identities lock-order cycle (PMS-1120)."
            );
        }
    }

    // And the write landed, so this is not passing by doing nothing.
    let first_name: String = sqlx::query_scalar("SELECT first_name FROM identities WHERE id = $1")
        .bind(identity_id)
        .fetch_one(&pool)
        .await
        .expect("identity row");
    assert_eq!(
        first_name, "Edited",
        "the profile edit reached the identity"
    );

    // B's stamp is deliberately not asserted. It wrote `identities` directly,
    // and A's forward mirror then copied its own `users` row over the same
    // columns, so whichever commits last wins. That is what a one-way mirror
    // means, and it is why `update_last_login` writes `users` rather than
    // `identities`: the plane that is written is the plane that wins.
}
