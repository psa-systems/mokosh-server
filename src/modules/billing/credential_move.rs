//! PMS-968: move every gateway credential into the secret store, once.
//!
//! Before this, a tenant's payment-provider credential was AES-256-GCM
//! ciphertext in `payment_gateway_configs.config_encrypted`. PMS-967 built
//! `crate::secrets` so the location is a deployment choice, migration 132 made
//! the column nullable so a row can say "mine is in the store", and the write
//! path now puts new credentials there. This is what walks the existing ones
//! over.
//!
//! ## Why a job and not a migration
//!
//! Migrations here are plain SQL embedded by `sqlx::migrate!` and run at
//! startup. Writing to the secret store is a network call when the backend is
//! Infisical, which no SQL file can make. [`Scheduler`](crate::scheduler::Scheduler)
//! fires every registered job once immediately at startup and then on its
//! interval, which gives the one-shot behaviour with no maintenance window and
//! makes a transient failure self-healing rather than waiting for a restart.
//! Nothing about the API needs the move to have finished, because
//! `gateway_plaintext` reads either state.
//!
//! ## What it does about failure
//!
//! Loudly, and by leaving the row exactly as it was. This is the requirement
//! PMS-912 named after the Bunyip secrets migration: fail on a credential it
//! cannot move rather than writing a blank.
//!
//! Three things can go wrong and none of them may half-finish a row. The
//! ciphertext might not decrypt, which means the deployment's `ENCRYPTION_KEY`
//! is not the one that wrote it and no amount of retrying will help. The store
//! write might fail, which is usually an outage and is worth retrying next
//! tick. Or the write might report success and the read-back not match, which
//! is the one that would be invisible without checking, so it is checked: the
//! secret is written, read back and compared before the column is cleared.
//!
//! In every failing case the column keeps its ciphertext, so the gateway goes
//! on working off the old path and the next tick tries again. The only ordering
//! that can lie is clearing the column before the store has the value, and that
//! ordering does not exist here.

use async_trait::async_trait;
use uuid::Uuid;

use crate::db::Database;
use crate::scheduler::Job;
use crate::secrets::{SecretKey, SecretStore};
use crate::utils::error::AppResult;

/// What one tick did, for the log line and for tests.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CredentialMoveOutcome {
    /// Credentials written to the store and cleared from the column.
    pub moved: usize,
    /// Left exactly as they were, with the reason logged.
    pub failed: usize,
}

impl CredentialMoveOutcome {
    fn considered(&self) -> usize {
        self.moved + self.failed
    }
}

/// Walks pre-PMS-968 gateway credentials into the configured secret store.
#[derive(Clone)]
pub struct GatewayCredentialMover {
    db: Database,
    secrets: std::sync::Arc<dyn SecretStore>,
    encryption_key: [u8; 32],
}

impl GatewayCredentialMover {
    pub fn new(
        db: Database,
        secrets: std::sync::Arc<dyn SecretStore>,
        encryption_key: [u8; 32],
    ) -> Self {
        Self {
            db,
            secrets,
            encryption_key,
        }
    }

    /// One pass over every credential still in a column.
    ///
    /// No batch cap. The rows selected are only the unmoved ones, so the set
    /// shrinks to nothing after the first successful pass, and a payment
    /// gateway is one row per provider per tenant rather than a bulk table.
    pub async fn run_tick(&self) -> AppResult<CredentialMoveOutcome> {
        // SAFETY (PMS-285): this runs on the BYPASSRLS migrator pool because it
        // is a cross-tenant sweep with no `app.current_tenant` to set - the
        // same shape as the calendar, SLA and billing workers. Every write
        // below re-derives its tenant from the row it just read, and the secret
        // key is built from that same tenant id.
        let pending: Vec<(Uuid, String, String)> = sqlx::query_as(
            r#"
            SELECT tenant_id, provider, config_encrypted
            FROM payment_gateway_configs
            WHERE config_encrypted IS NOT NULL
            ORDER BY created_at
            "#,
        )
        .fetch_all(self.db.migrator_pool())
        .await?;

        let mut outcome = CredentialMoveOutcome::default();
        for (tenant_id, provider, ciphertext) in pending {
            match self.move_one(tenant_id, &provider, &ciphertext).await {
                Ok(()) => outcome.moved += 1,
                Err(e) => {
                    outcome.failed += 1;
                    // The tenant and provider, never the credential. `warn` and
                    // not `error` because the next tick retries and the gateway
                    // is still working off its column in the meantime.
                    tracing::warn!(
                        target: "mokosh_server.billing",
                        tenant_id = %tenant_id,
                        provider = %provider,
                        error = %e,
                        "gateway_credential_move: left in place, will retry"
                    );
                }
            }
        }

        if outcome.considered() > 0 {
            tracing::info!(
                target: "mokosh_server.billing",
                moved = outcome.moved,
                failed = outcome.failed,
                "gateway_credential_move: pass complete"
            );
        }
        Ok(outcome)
    }

    /// Write, read back, compare, and only then clear the column.
    ///
    /// Any error leaves the row untouched, which is what makes a failed move
    /// indistinguishable from one that never started.
    async fn move_one(&self, tenant_id: Uuid, provider: &str, ciphertext: &str) -> AppResult<()> {
        let plaintext = crate::utils::crypto::decrypt(ciphertext, &self.encryption_key)?;
        let key = SecretKey::payment_gateway(tenant_id, provider);

        self.secrets.put(&key, &plaintext).await?;

        // The read-back is the whole point of doing this in code rather than in
        // SQL. A store that accepted the write and does not return it is the
        // one failure that would otherwise be silent, and clearing the column
        // on it destroys the only remaining copy.
        let stored = self.secrets.get(&key).await?;
        if stored.as_deref() != Some(plaintext.as_str()) {
            return Err(crate::utils::error::AppError::Configuration(format!(
                "secret store did not return the credential just written for provider {provider:?}"
            )));
        }

        // `IS NOT NULL` makes the clear idempotent and makes a concurrent write
        // through the API the winner: if `upsert_payment_gateway` has already
        // stored a newer credential and NULLed this row, there is nothing here
        // to clear and nothing to undo.
        sqlx::query(
            "UPDATE payment_gateway_configs SET config_encrypted = NULL \
             WHERE tenant_id = $1 AND provider = $2 AND config_encrypted IS NOT NULL",
        )
        .bind(tenant_id)
        .bind(provider)
        .execute(self.db.migrator_pool())
        .await?;
        Ok(())
    }
}

#[async_trait]
impl Job for GatewayCredentialMover {
    fn name(&self) -> &'static str {
        "gateway_credential_move"
    }

    async fn run(&self) -> AppResult<()> {
        self.run_tick().await.map(|_| ())
    }
}
