//! PMS-968: move every gateway credential into the secret provider, once.
//!
//! Before this, a tenant's payment-provider credential was AES-256-GCM
//! ciphertext in `payment_gateway_configs.config_encrypted`. PMS-967 built
//! `crate::secrets` so the location is a deployment choice, migration 132 made
//! the column nullable so a row can say "mine is in the store", and the write
//! path now puts new credentials there. This is what walks the existing ones
//! over.
//!
//! ## Why a one-shot and not a migration
//!
//! Migrations here are plain SQL embedded by `sqlx::migrate!` and run at
//! startup. Writing to the secret provider is a network call when the provider
//! is Infisical, which no SQL file can make.
//!
//! It ran as an hourly [`Job`](crate::scheduler::Job) until PMS-1320, because
//! [`Scheduler`](crate::scheduler::Scheduler) fires every registered job once
//! immediately at startup and the interval came free with that. It is a
//! one-time move either way, so it now goes through
//! [`crate::scheduler::one_shot::spawn_once`], which runs it once per process
//! start and names it as the correction it is. Nothing about the API needs it
//! to have finished, because `gateway_plaintext` reads either state.
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
//! write might fail, which is usually an outage and is worth retrying at the
//! next restart. Or the write might report success and the read-back not match, which
//! is the one that would be invisible without checking, so it is checked: the
//! secret is written, read back and compared before the column is cleared.
//!
//! In every failing case the column keeps its ciphertext, so the gateway goes
//! on working off the old path and the next restart tries again. The only ordering
//! that can lie is clearing the column before the store has the value, and that
//! ordering does not exist here.

use uuid::Uuid;

use crate::db::Database;
use crate::secrets::{SecretKey, SecretProvider};
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

/// Walks pre-PMS-968 gateway credentials into the configured secret provider.
#[derive(Clone)]
pub struct GatewayCredentialMover {
    db: Database,
    secrets: std::sync::Arc<dyn SecretProvider>,
    encryption_key: [u8; 32],
}

impl GatewayCredentialMover {
    pub fn new(
        db: Database,
        secrets: std::sync::Arc<dyn SecretProvider>,
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
                    // not `error` because the next restart retries and the gateway
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

        // PMS-1235: `put_if_absent`, not `put`. `upsert_payment_gateway` writes
        // a fresh credential to this same address with no DB row lock in
        // common with this job (its own store write happens before it touches
        // the row), so between `run_tick`'s SELECT and this call a concurrent
        // save can already have claimed this address with newer data. An
        // unconditional `put` would silently revert it to what this legacy
        // column held; the compare-and-set means whichever write reaches the
        // store first wins, and the store is the one place both paths agree
        // to check.
        let claimed = self.secrets.put_if_absent(&key, &plaintext).await?;
        if !claimed {
            // Something is already at this address: either a concurrent save
            // won the race, or an earlier tick already moved it and this
            // column's clear failed to commit for an unrelated reason. Either
            // way, the store is not ours to overwrite, and the column is safe
            // to clear below: the address has a real credential now, and this
            // legacy copy is redundant.
            return self.clear_column(tenant_id, provider).await;
        }

        // The read-back is the whole point of doing this in code rather than in
        // SQL. A store that accepted the write and does not return it is the
        // one failure that would otherwise be silent, and clearing the column
        // on it destroys the only remaining copy.
        let stored = self.secrets.get(&key).await?;
        if stored.as_deref() != Some(plaintext.as_str()) {
            return Err(crate::utils::error::AppError::Configuration(format!(
                "secret provider did not return the credential just written for gateway {provider:?}"
            )));
        }

        self.clear_column(tenant_id, provider).await
    }

    /// `IS NOT NULL` makes this idempotent and makes a concurrent write
    /// through the API the winner: if `upsert_payment_gateway` has already
    /// stored a newer credential and NULLed this row, there is nothing here
    /// to clear and nothing to undo.
    async fn clear_column(&self, tenant_id: Uuid, provider: &str) -> AppResult<()> {
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

impl GatewayCredentialMover {
    /// The name this pass is logged under, and the only thing left of the
    /// `Job` impl it used to carry (PMS-1320). It is handed to
    /// [`crate::scheduler::one_shot::spawn_once`] at boot rather than
    /// registered on the scheduler: this corrects history once and never
    /// becomes due again, so an hourly interval was a recurring job doing a
    /// one-time job's work.
    pub const ONE_SHOT_NAME: &'static str = "gateway_credential_move";
}
