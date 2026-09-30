//! PMS-1430: remove the per-tenant Google OAuth client secrets, once.
//!
//! The Google client is the host's now, held as a pair of governed
//! application-tier secrets (`src/app_secrets/`). Migration 258 deletes the
//! stored client ids from `tenant_settings`; this removes the secrets that sat
//! beside them under [`SecretKind::OauthClient`](crate::secrets::SecretKind).
//!
//! ## Why this is not part of the migration
//!
//! A migration is SQL running inside Postgres. These secrets live in whichever
//! [`SecretProvider`](crate::secrets::SecretProvider) the deployment declared,
//! which on the hosted one is Infisical over the network, so no SQL file can
//! reach them. That is the same reason `billing::credential_move` and the two
//! storage movers are one-shots (PMS-1320), and the same ordering applies: this
//! runs once per process start rather than on an interval, because it is a
//! correction that completes.
//!
//! ## Why the secrets go at all
//!
//! An id row left behind would be read by nothing after this release. A SECRET
//! left behind is different: it is a live Google client secret, for an
//! application the product no longer connects as, sitting in a store where
//! nothing in the UI can show it and nobody will think to look. Leaving it is
//! the sort of residue an audit finds years later.
//!
//! ## What it deliberately does not touch
//!
//! A tenant's contact-sync refresh token, under
//! [`SecretKind::ContactSync`](crate::secrets::SecretKind). That is the tenant's
//! own grant and belongs to them. It will stop working, because Google binds a
//! refresh token to the client that issued it and the host client is a different
//! application, but the connection row and its token are what let
//! `contact_sync::runs` report `reconnect_required` and tell the admin why. A
//! sweep that deleted them would turn an explainable failure into a silent one.

use crate::db::Database;
use crate::secrets::{SecretKey, SecretProvider};
use crate::utils::error::AppResult;
use std::sync::Arc;
use uuid::Uuid;

/// The provider discriminator these secrets were keyed by.
const GOOGLE: &str = "google";

/// Removes each tenant's stored Google client secret.
pub struct ClientSecretCleanup {
    db: Database,
    secrets: Arc<dyn SecretProvider>,
}

impl ClientSecretCleanup {
    /// The name `one_shot::spawn_once` logs this pass under.
    pub const ONE_SHOT_NAME: &'static str = "contact_sync_client_secret_cleanup";

    pub fn new(db: Database, secrets: Arc<dyn SecretProvider>) -> Self {
        Self { db, secrets }
    }

    /// Delete the `OauthClient` secret for every tenant.
    ///
    /// Addressed per tenant rather than by listing the store, because
    /// `SecretProvider` has no list operation and adding one for a one-time
    /// correction would widen a trait every provider implements. `delete` on a
    /// key nothing holds is not an error in any provider, so a tenant that never
    /// registered a client costs one no-op.
    ///
    /// A failure on one tenant does not stop the rest: the pass runs again at
    /// the next restart, and the alternative is one unreachable secret blocking
    /// the cleanup of every other.
    pub async fn run_tick(&self) -> AppResult<CleanupOutcome> {
        // SAFETY (PMS-285): a cross-tenant sweep with no `app.current_tenant` to
        // set, the shape every mover and worker here uses. It reads ids only.
        let tenants: Vec<(Uuid,)> = sqlx::query_as("SELECT id FROM tenants")
            .fetch_all(self.db.migrator_pool())
            .await?;

        let mut outcome = CleanupOutcome::default();
        for (tenant_id,) in tenants {
            let key = SecretKey::oauth_client(tenant_id, GOOGLE);
            match self.secrets.delete(&key).await {
                Ok(()) => outcome.cleared += 1,
                Err(e) => {
                    outcome.failed += 1;
                    tracing::warn!(
                        tenant_id = %tenant_id,
                        error = %e,
                        "contact sync: could not remove a stored Google client secret; it is \
                         retried at the next restart"
                    );
                }
            }
        }
        if outcome.cleared > 0 || outcome.failed > 0 {
            tracing::info!(
                cleared = outcome.cleared,
                failed = outcome.failed,
                "contact sync: removed the per-tenant Google client secrets (PMS-1430)"
            );
        }
        Ok(outcome)
    }
}

/// What one pass did. Counts tenants addressed, not secrets that existed: the
/// provider does not say whether a delete removed anything.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CleanupOutcome {
    pub cleared: u64,
    pub failed: u64,
}
