//! Contract lifecycle worker (PMS-64).
//!
//! Sweeps `active` contracts whose `end_date` has passed and either
//! renews them (when `auto_renew`) or marks them `expired`, by delegating
//! to [`ContractsService::expire_due_contracts`]. Cross-tenant, like the
//! notifications dispatcher: the worker owns the cadence, the service owns
//! the per-row transition.
//!
//! Implements the shared [`Job`](crate::scheduler::Job) trait so it can be
//! registered on the [`Scheduler`](crate::scheduler::Scheduler). The spawn
//! site is `src/main.rs`. A daily-ish tick is enough since contract
//! end_dates are day-granular; the registered interval in `main.rs` sets
//! the real cadence.

use async_trait::async_trait;

use crate::scheduler::Job;
use crate::utils::error::AppResult;

use super::service::ContractsService;

/// Worker handle. Clone is cheap (the service wraps an `Arc`-backed
/// `Database`).
#[derive(Clone)]
pub struct ContractLifecycleWorker {
    service: ContractsService,
}

impl ContractLifecycleWorker {
    pub fn new(service: ContractsService) -> Self {
        Self { service }
    }
}

#[async_trait]
impl Job for ContractLifecycleWorker {
    fn name(&self) -> &'static str {
        "contract_lifecycle"
    }

    async fn run(&self) -> AppResult<()> {
        let (renewed, expired) = self
            .service
            .expire_due_contracts(chrono::Utc::now())
            .await?;
        if renewed > 0 || expired > 0 {
            tracing::info!(renewed, expired, "contract lifecycle sweep");
        }
        Ok(())
    }
}
