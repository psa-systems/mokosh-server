//! PMS-1441: the write `provider-set` performs, against a real database.
//!
//! The unit tests in `src/cli/providers.rs` drive every refusal and the
//! read-back contract with in-memory providers, which is the right place for
//! the decisions. What they cannot establish is the claim the read-back design
//! rests on, because it is a claim about two handles and a row: the database
//! app-secret provider caches the plaintext on a successful write, so reading
//! the handle just written to would prove the cache agrees with itself and say
//! nothing about what the next boot will load.
//!
//! So this pins both halves of that claim. A freshly loaded provider sees the
//! row, which is what makes the re-build an honest read-back. And a provider
//! loaded BEFORE the write does not, which is what makes re-reading the same
//! handle worthless and is the reason the CLI pays for a second build.

mod common;

use mokosh_server::app_secrets::{AppSecretProvider, DatabaseProvider, GovernedSecret};
use mokosh_server::db::Database;
use mokosh_test::mokosh_test;
use sqlx::PgPool;

/// The zero key `common::boot_*` wires into the router, so a row written here
/// decrypts the way the application would decrypt it.
const TEST_KEY: [u8; 32] = [0u8; 32];

const ID: GovernedSecret = GovernedSecret::GoogleContactsClientId;

async fn load(pool: &PgPool) -> DatabaseProvider {
    DatabaseProvider::load(&Database::from_pool(pool.clone()), TEST_KEY)
        .await
        .expect("load the app-tier database provider")
}

/// A write lands in the row, and a provider built afterwards serves it.
///
/// This is `provider-set`'s whole contract in one assertion: the value the
/// operator handed the command is what the NEXT process will read, and the
/// ciphertext in between is not something the test has to know the shape of.
#[mokosh_test]
async fn a_written_secret_is_served_by_the_next_load(pool: PgPool) {
    let before = load(&pool).await;
    assert_eq!(
        before.get(ID),
        None,
        "the fixture must start without this secret or the test proves nothing"
    );

    let client_id = "pms1441.apps.googleusercontent.com";
    load(&pool)
        .await
        .set(ID, client_id)
        .await
        .expect("write the governed secret");

    assert_eq!(
        load(&pool).await.get(ID),
        Some(client_id.to_string()),
        "a provider built after the write must serve it, or a restart would lose the value"
    );

    // The row is what carries it, not the process: the value is encrypted, so
    // the column cannot be compared to the plaintext, but it has to be there
    // and it has to not BE the plaintext.
    let ciphertext: Vec<u8> =
        sqlx::query_scalar("SELECT ciphertext FROM app_secrets WHERE name = $1")
            .bind(ID.name())
            .fetch_one(&pool)
            .await
            .expect("the row exists");
    assert!(!ciphertext.is_empty(), "the row holds no ciphertext");
    assert_ne!(
        String::from_utf8_lossy(&ciphertext),
        client_id,
        "the value is stored in the clear"
    );

    // Same key, so the plaintext survives a rewrite rather than accumulating a
    // second row: the upsert is keyed by name.
    load(&pool)
        .await
        .set(ID, "second.apps.googleusercontent.com")
        .await
        .expect("overwrite the governed secret");
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM app_secrets WHERE name = $1")
        .bind(ID.name())
        .fetch_one(&pool)
        .await
        .expect("count the rows");
    assert_eq!(
        rows, 1,
        "a second write added a row instead of replacing one"
    );
    assert_eq!(
        load(&pool).await.get(ID),
        Some("second.apps.googleusercontent.com".to_string())
    );
}

/// A provider loaded before the write does NOT see it, which is why the CLI's
/// read-back builds a new one.
///
/// Stated as a test rather than a comment because it is the reason for a cost:
/// `provider-set` pays for a second provider build on every call, and a future
/// reader looking to remove that would otherwise have to rediscover why reading
/// the handle back is not enough.
#[mokosh_test]
async fn a_provider_loaded_before_the_write_does_not_see_it(pool: PgPool) {
    let stale = load(&pool).await;

    load(&pool)
        .await
        .set(ID, "pms1441.apps.googleusercontent.com")
        .await
        .expect("write through a different handle");

    assert_eq!(
        stale.get(ID),
        None,
        "the handle caches at load, so a read-back through the writer's own handle proves nothing \
         about the row"
    );
}
