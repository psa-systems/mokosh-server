//! PMS-967: the database backend of the secret store, against a real database.
//!
//! The unit tests in `src/secrets/mod.rs` cover the key and the backend rule
//! without a database. What needs Postgres is the part where being wrong is
//! expensive: that a stored secret round-trips through AES-256-GCM, that an
//! absent one is `None` rather than an error, and above all that RLS confines
//! the read, because this is the one table where a tenant leak is every
//! tenant's credentials at once.

mod common;

use mokosh_server::db::Database;
use mokosh_server::secrets::{DatabaseSecretStore, SecretKey, SecretStore};
use sqlx::PgPool;
use uuid::Uuid;

/// The zero key `common::boot_*` wires into the router, so a value written here
/// decrypts the way the app would decrypt it.
const TEST_KEY: [u8; 32] = [0u8; 32];

fn store(pool: &PgPool) -> DatabaseSecretStore {
    DatabaseSecretStore::new(Database::from_pool(pool.clone()), TEST_KEY)
}

/// A store whose serving connection is the unprivileged NOBYPASSRLS role, which
/// is the production posture and the only way RLS is actually exercised.
async fn rls_store(pool: &PgPool) -> DatabaseSecretStore {
    let app_pool = common::build_app_role_pool(pool).await;
    DatabaseSecretStore::new(Database::from_pools(app_pool, pool.clone()), TEST_KEY)
}

#[sqlx::test]
async fn a_secret_round_trips(pool: PgPool) {
    let store = store(&pool);
    let key = SecretKey::payment_gateway(common::DEFAULT_TENANT_ID, "stripe");

    store.put(&key, "sk_test_value").await.expect("put");
    let read = store.get(&key).await.expect("get");
    assert_eq!(read.as_deref(), Some("sk_test_value"));
}

/// The value is not sitting in the table in the clear. The column is what an
/// operator with a database dump sees.
#[sqlx::test]
async fn the_stored_column_is_not_the_plaintext(pool: PgPool) {
    let store = store(&pool);
    let key = SecretKey::payment_gateway(common::DEFAULT_TENANT_ID, "stripe");
    store.put(&key, "sk_test_value").await.expect("put");

    let stored: String = sqlx::query_scalar("SELECT value_encrypted FROM secrets WHERE name = $1")
        .bind(key.name().unwrap())
        .fetch_one(&pool)
        .await
        .expect("read column");
    assert!(
        !stored.contains("sk_test_value"),
        "the secret must not be readable from the column"
    );
}

/// Writing twice replaces rather than accumulating: a reconnected integration
/// has one current credential, and two rows would make "which one" a question.
#[sqlx::test]
async fn writing_twice_replaces_the_value(pool: PgPool) {
    let store = store(&pool);
    let key = SecretKey::payment_gateway(common::DEFAULT_TENANT_ID, "stripe");

    store.put(&key, "first").await.expect("first put");
    store.put(&key, "second").await.expect("second put");

    assert_eq!(
        store.get(&key).await.expect("get").as_deref(),
        Some("second")
    );
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM secrets WHERE name = $1")
        .bind(key.name().unwrap())
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(rows, 1, "a replace must not leave the old row behind");
}

/// An unconfigured integration is `None`, not an error. Every caller has to
/// handle it, and making it an error would push that handling into each of
/// them differently.
#[sqlx::test]
async fn an_absent_secret_is_none(pool: PgPool) {
    let store = store(&pool);
    let key = SecretKey::payment_gateway(common::DEFAULT_TENANT_ID, "stripe");
    assert!(store.get(&key).await.expect("get").is_none());
}

/// Deleting something that is not there is success, matching `ObjectStore` and
/// for the same reason: the caller has already removed the row that pointed at
/// it, so a missing secret says the same thing as a deleted one.
#[sqlx::test]
async fn deleting_is_idempotent(pool: PgPool) {
    let store = store(&pool);
    let key = SecretKey::payment_gateway(common::DEFAULT_TENANT_ID, "stripe");

    store.put(&key, "value").await.expect("put");
    store.delete(&key).await.expect("first delete");
    store
        .delete(&key)
        .await
        .expect("second delete must succeed");
    assert!(store.get(&key).await.expect("get").is_none());
}

/// Two tenants store a secret for the same integration and each still reads its
/// own. This is the store's API doing its job, and it is NOT a test of RLS:
/// every read here sets the GUC from its own key, so it would pass with the
/// policy dropped. `rls_confines_the_table_to_the_tenant_in_the_guc` below is
/// the one that exercises the policy.
#[sqlx::test]
async fn each_tenants_key_resolves_to_its_own_value(pool: PgPool) {
    let (other_tenant, _u, _e, _p) = common::seed_tenant_with_admin(&pool, "othertenant").await;
    let store = rls_store(&pool).await;

    let mine = SecretKey::payment_gateway(common::DEFAULT_TENANT_ID, "stripe");
    let theirs = SecretKey::payment_gateway(other_tenant, "stripe");

    store.put(&mine, "mine-value").await.expect("put mine");
    store
        .put(&theirs, "theirs-value")
        .await
        .expect("put theirs");

    assert_eq!(
        store.get(&mine).await.expect("get mine").as_deref(),
        Some("mine-value")
    );
    assert_eq!(
        store.get(&theirs).await.expect("get theirs").as_deref(),
        Some("theirs-value")
    );

    let names: Vec<String> = sqlx::query_scalar("SELECT name FROM secrets ORDER BY name")
        .fetch_all(&pool)
        .await
        .expect("list names");
    assert_eq!(names.len(), 2, "each tenant has its own row");
    assert_ne!(names[0], names[1], "and its own name");
}

/// The one that matters, and the reason this table is worth a policy at all: a
/// leak here is every tenant's credentials at once.
///
/// The store always sets the GUC from the key it was given, so no call through
/// its API can ask this question. It is asked directly, on a connection as the
/// unprivileged NOBYPASSRLS role production serves with, because a superuser
/// bypasses RLS unconditionally and the assertion would hold with the policy
/// removed.
#[sqlx::test]
async fn rls_confines_the_table_to_the_tenant_in_the_guc(pool: PgPool) {
    let (other_tenant, _u, _e, _p) = common::seed_tenant_with_admin(&pool, "othertenant").await;
    let store = rls_store(&pool).await;

    store
        .put(
            &SecretKey::payment_gateway(common::DEFAULT_TENANT_ID, "stripe"),
            "mine-value",
        )
        .await
        .expect("put mine");
    store
        .put(
            &SecretKey::payment_gateway(other_tenant, "stripe"),
            "theirs-value",
        )
        .await
        .expect("put theirs");

    let app_pool = common::build_app_role_pool(&pool).await;
    let mut conn = app_pool.acquire().await.expect("app-role connection");

    // Fail-closed: no GUC set means no rows, not every row (038_rls_fail_closed).
    let unset: i64 = sqlx::query_scalar("SELECT count(*) FROM secrets")
        .fetch_one(&mut *conn)
        .await
        .expect("count with no GUC");
    assert_eq!(unset, 0, "an unset tenant GUC must see no secrets at all");

    sqlx::query("SELECT set_config('app.current_tenant', $1, false)")
        .bind(common::DEFAULT_TENANT_ID.to_string())
        .execute(&mut *conn)
        .await
        .expect("set GUC to tenant A");

    let visible: Vec<Uuid> = sqlx::query_scalar("SELECT tenant_id FROM secrets")
        .fetch_all(&mut *conn)
        .await
        .expect("select with tenant A GUC");
    assert_eq!(
        visible,
        vec![common::DEFAULT_TENANT_ID],
        "only the GUC tenant's secrets are readable"
    );

    // WITH CHECK: a write naming another tenant is refused, so a mis-scoped
    // INSERT cannot plant a row under someone else.
    let planted =
        sqlx::query("INSERT INTO secrets (tenant_id, name, value_encrypted) VALUES ($1, 'X', 'Y')")
            .bind(other_tenant)
            .execute(&mut *conn)
            .await;
    assert!(
        planted.is_err(),
        "writing a secret for another tenant must be refused by the policy"
    );
}

/// A key whose discriminator would not survive being a name is refused before
/// anything touches the database, so a bad key can never write a row.
#[sqlx::test]
async fn a_malformed_key_never_reaches_the_table(pool: PgPool) {
    let store = store(&pool);
    let key = SecretKey::payment_gateway(Uuid::new_v4(), "../escape");

    assert!(store.put(&key, "value").await.is_err());
    assert!(store.get(&key).await.is_err());
    assert!(store.delete(&key).await.is_err());

    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM secrets")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(rows, 0, "a refused key must write nothing");
}
