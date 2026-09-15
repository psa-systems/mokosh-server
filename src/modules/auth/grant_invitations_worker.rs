//! PMS-1208: hourly expiry sweep for the grant-invitations table.
//!
//! Every tick moves pending rows past their `expires_at` to the
//! `expired` state. The service also lazily checks expiry on every
//! read, accept, and decline path, so a late request between sweeps
//! still answers correctly; this job is what removes stale rows
//! from the owner outbox and the grantee inbox so a UI listing them
//! does not need per-request date arithmetic on the client.
//!
//! Interval matches the parent ticket: 1 hour. A shorter cadence
//! is fine but self-defeating (the invite TTL is 7 days, so the
//! sweep never lags observably); a longer cadence would leave
//! expired rows visible for longer than a customer would call
//! reasonable.

use std::sync::Arc;
use std::time::Duration as StdDuration;

use async_trait::async_trait;
use sqlx::PgPool;

use super::grant_invitations::GrantInvitationsService;
use crate::scheduler::Job;
use crate::utils::error::AppResult;

pub const GRANT_INVITATIONS_SWEEP_INTERVAL: StdDuration = StdDuration::from_secs(3600);

pub struct GrantInvitationsExpirySweep {
    pool: Arc<PgPool>,
}

impl GrantInvitationsExpirySweep {
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl Job for GrantInvitationsExpirySweep {
    fn name(&self) -> &'static str {
        "grant_invitations_expiry_sweep"
    }

    async fn run(&self) -> AppResult<()> {
        let expired = GrantInvitationsService::expire_stale(&self.pool).await?;
        if expired > 0 {
            tracing::info!(
                expired,
                "grant_invitations: swept pending rows past expires_at"
            );
        }
        Ok(())
    }
}
