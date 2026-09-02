//! PMS-968: gateway credentials move into the secret store, and a move that
//! cannot finish changes nothing.
//!
//! The interesting cases are all about partial failure. A credential that moves
//! is easy; what PMS-912 asked for, after the Bunyip secrets migration wrote
//! blanks, is that a credential which CANNOT move leaves its row exactly as it
//! was. So the failing store below is not a mock for convenience: it is the
//! only way to reach the branch that matters.

mod common;

use std::sync::Arc;

use async_trait::async_trait;
use mokosh_server::db::Database;
use mokosh_server::modules::billing::GatewayCredentialMover;
use mokosh_server::secrets::{DatabaseSecretStore, SecretKey, SecretStore};
use mokosh_server::utils::error::{AppError, AppResult};
use sqlx::PgPool;
use uuid::Uuid;

const TEST_KEY: [u8; 32] = [0u8; 32];

/// A store that accepts every write and returns nothing, which is the silent
/// failure the mover's read-back exists to catch.
struct ForgetfulStore;

#[async_trait]
impl SecretStore for ForgetfulStore {
    async fn get(&self, _key: &SecretKey) -> AppResult<Option<String>> {
        Ok(None)
    }
    async fn put(&self, _key: &SecretKey, _value: &str) -> AppResult<()> {
        Ok(())
    }
    async fn delete(&self, _key: &SecretKey) -> AppResult<()> {
        Ok(())
    }
}

/// A store that refuses every write, which is what an outage looks like.
struct UnreachableStore;

#[async_trait]
impl SecretStore for UnreachableStore {
    async fn get(&self, _key: &SecretKey) -> AppResult<Option<String>> {
        Err(AppError::external_service("Infisical", "unreachable"))
    }
    async fn put(&self, _key: &SecretKey, _value: &str) -> AppResult<()> {
        Err(AppError::external_service("Infisical", "unreachable"))
    }
    async fn delete(&self, _key: &SecretKey) -> AppResult<()> {
        Ok(())
    }
}

/// Seed a pre-PMS-968 row: credential in the column, nothing in the store.
async fn seed_legacy_gateway(pool: &PgPool, tenant_id: Uuid, provider: &str, secret_key: &str) {
    let plaintext = serde_json::json!({
        "secret_key": secret_key,
        "webhook_secret": "whsec_test",
    })
    .to_string();
    let encrypted = mokosh_server::utils::crypto::encrypt(&plaintext, &TEST_KEY).unwrap();
    sqlx::query(
        "INSERT INTO payment_gateway_configs \
         (tenant_id, provider, is_active, is_test_mode, config_encrypted) \
         VALUES ($1, $2, TRUE, TRUE, $3)",
    )
    .bind(tenant_id)
    .bind(provider)
    .bind(encrypted)
    .execute(pool)
    .await
    .expect("seed gateway");
}

async fn column_for(pool: &PgPool, tenant_id: Uuid, provider: &str) -> Option<String> {
    sqlx::query_scalar(
        "SELECT config_encrypted FROM payment_gateway_configs \
         WHERE tenant_id = $1 AND provider = $2",
    )
    .bind(tenant_id)
    .bind(provider)
    .fetch_one(pool)
    .await
    .expect("read column")
}

fn mover(pool: &PgPool, store: Arc<dyn SecretStore>) -> GatewayCredentialMover {
    GatewayCredentialMover::new(Database::from_pool(pool.clone()), store, TEST_KEY)
}

fn working_store(pool: &PgPool) -> Arc<dyn SecretStore> {
    Arc::new(DatabaseSecretStore::new(
        Database::from_pool(pool.clone()),
        TEST_KEY,
    ))
}

#[sqlx::test]
async fn a_credential_moves_and_the_column_is_cleared(pool: PgPool) {
    let tenant = common::DEFAULT_TENANT_ID;
    seed_legacy_gateway(&pool, tenant, "stripe", "sk_test_moved").await;

    let store = working_store(&pool);
    let outcome = mover(&pool, store.clone()).run_tick().await.expect("tick");
    assert_eq!(outcome.moved, 1);
    assert_eq!(outcome.failed, 0);

    assert!(
        column_for(&pool, tenant, "stripe").await.is_none(),
        "the column must be cleared once the store holds it"
    );
    let stored = store
        .get(&SecretKey::payment_gateway(tenant, "stripe"))
        .await
        .expect("read store")
        .expect("the store holds the credential");
    assert!(stored.contains("sk_test_moved"));
}

/// The pass is one query returning no rows once everything has moved, and a
/// second run must not undo or re-do anything.
#[sqlx::test]
async fn a_second_pass_finds_nothing_to_do(pool: PgPool) {
    seed_legacy_gateway(&pool, common::DEFAULT_TENANT_ID, "stripe", "sk_test_x").await;
    let mover = mover(&pool, working_store(&pool));

    assert_eq!(mover.run_tick().await.expect("first").moved, 1);
    let second = mover.run_tick().await.expect("second");
    assert_eq!(second.moved, 0);
    assert_eq!(second.failed, 0);
}

/// An outage leaves the row exactly as it was, so the gateway keeps working off
/// its column and the next tick retries.
#[sqlx::test]
async fn an_unreachable_store_changes_nothing(pool: PgPool) {
    let tenant = common::DEFAULT_TENANT_ID;
    seed_legacy_gateway(&pool, tenant, "stripe", "sk_test_kept").await;
    let before = column_for(&pool, tenant, "stripe").await;

    let outcome = mover(&pool, Arc::new(UnreachableStore))
        .run_tick()
        .await
        .expect("a failing credential must not fail the tick");
    assert_eq!(outcome.moved, 0);
    assert_eq!(outcome.failed, 1);

    assert_eq!(
        column_for(&pool, tenant, "stripe").await,
        before,
        "a failed move must leave the ciphertext untouched"
    );
}

/// The failure the read-back exists to catch: a store that reports success and
/// does not have the value. Clearing the column here would destroy the only
/// remaining copy of a live API key.
#[sqlx::test]
async fn a_store_that_forgets_the_write_does_not_clear_the_column(pool: PgPool) {
    let tenant = common::DEFAULT_TENANT_ID;
    seed_legacy_gateway(&pool, tenant, "stripe", "sk_test_survives").await;
    let before = column_for(&pool, tenant, "stripe").await;

    let outcome = mover(&pool, Arc::new(ForgetfulStore))
        .run_tick()
        .await
        .expect("tick");
    assert_eq!(outcome.moved, 0);
    assert_eq!(outcome.failed, 1);
    assert_eq!(
        column_for(&pool, tenant, "stripe").await,
        before,
        "an unverified write must never clear the column"
    );
}

/// A credential this deployment's key cannot decrypt is reported and left, not
/// replaced with a blank. This is the shape of the failure PMS-912 named.
#[sqlx::test]
async fn a_credential_that_cannot_be_decrypted_is_left_alone(pool: PgPool) {
    let tenant = common::DEFAULT_TENANT_ID;
    sqlx::query(
        "INSERT INTO payment_gateway_configs \
         (tenant_id, provider, is_active, is_test_mode, config_encrypted) \
         VALUES ($1, 'stripe', TRUE, TRUE, 'not-valid-ciphertext')",
    )
    .bind(tenant)
    .execute(&pool)
    .await
    .expect("seed undecryptable row");

    let outcome = mover(&pool, working_store(&pool))
        .run_tick()
        .await
        .expect("tick");
    assert_eq!(outcome.failed, 1);
    assert_eq!(
        column_for(&pool, tenant, "stripe").await.as_deref(),
        Some("not-valid-ciphertext"),
        "an undecryptable credential is kept, never blanked"
    );
}

/// One tenant's failure does not stop another tenant's move.
#[sqlx::test]
async fn a_failing_row_does_not_block_the_rest(pool: PgPool) {
    let (other, _u, _e, _p) = common::seed_tenant_with_admin(&pool, "movertenant").await;
    sqlx::query(
        "INSERT INTO payment_gateway_configs \
         (tenant_id, provider, is_active, is_test_mode, config_encrypted) \
         VALUES ($1, 'stripe', TRUE, TRUE, 'not-valid-ciphertext')",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .execute(&pool)
    .await
    .expect("seed bad row");
    seed_legacy_gateway(&pool, other, "stripe", "sk_test_good").await;

    let outcome = mover(&pool, working_store(&pool))
        .run_tick()
        .await
        .expect("tick");
    assert_eq!(outcome.moved, 1, "the healthy row still moves");
    assert_eq!(outcome.failed, 1, "and the broken one is reported");
    assert!(column_for(&pool, other, "stripe").await.is_none());
}

/// The acceptance criterion that spans the whole change: after the move, the
/// pre-auth webhook verifies against a credential that is no longer in the row.
///
/// `tests/pms711_stripe_pay_now.rs` proves the same route still works from a
/// column, because it seeds one and never moves it. This is the other half, and
/// it is the one that would break silently: the webhook fetches the very secret
/// it needs to check the signature, so a credential the store cannot return is
/// a 401 and a payment that never reconciles.
#[sqlx::test]
async fn a_moved_credential_still_serves_the_webhook(pool: PgPool) {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use std::time::{SystemTime, UNIX_EPOCH};

    let tenant = common::DEFAULT_TENANT_ID;
    seed_legacy_gateway(&pool, tenant, "stripe", "sk_test_webhook").await;

    let outcome = mover(&pool, working_store(&pool))
        .run_tick()
        .await
        .expect("tick");
    assert_eq!(outcome.moved, 1);
    assert!(
        column_for(&pool, tenant, "stripe").await.is_none(),
        "the credential is only in the store now"
    );

    let app = common::boot_rls(pool.clone()).await;
    let body = serde_json::json!({
        "id": "evt_moved",
        "type": "checkout.session.expired",
        "data": {"object": {"id": "cs_moved"}},
    })
    .to_string();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(b"whsec_test").unwrap();
    mac.update(format!("{timestamp}.").as_bytes());
    mac.update(body.as_bytes());
    let digest: String = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    let resp = app
        .client
        .post(app.url(&format!("/api/v1/stripe/webhooks/{tenant}")))
        .header("Stripe-Signature", format!("t={timestamp},v1={digest}"))
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
        .expect("post webhook");

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "the signature must verify against the credential in the store"
    );
}
