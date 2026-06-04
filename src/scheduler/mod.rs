//! Shared scheduler for background jobs (PMS-135).
//!
//! Replaces ad-hoc `tokio::spawn(worker.run_forever(interval))` sites
//! in `main.rs` with a single registry. Each registered [`Job`] runs
//! on its own tokio task at a fixed interval, with
//! [`MissedTickBehavior::Skip`] so slow ticks do not stack up. Tick
//! errors are logged at `warn` and the loop continues; per-job retry
//! semantics (e.g. the notifications dispatcher's backoff ladder)
//! stay inside the `Job::run` implementation.
//!
//! Usage from `main.rs`:
//! ```ignore
//! let mut scheduler = Scheduler::new();
//! scheduler.register(notif_worker, Duration::from_secs(5));
//! scheduler.register(rmm_worker, Duration::from_secs(60));
//! scheduler.start();
//! ```
//!
//! Existing workers (`DispatcherWorker`, `RmmSyncWorker`) keep their
//! current `run_forever(interval)` entry points; migration to the
//! [`Job`] trait happens in follow-up PRs so each diff stays small.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::time::MissedTickBehavior;

use crate::utils::error::AppResult;

/// A background job that the scheduler ticks at a fixed interval.
///
/// Implementations are owned by the scheduler after [`Scheduler::register`]
/// so they must be `Send + Sync + 'static`. Errors returned from
/// [`run`](Self::run) are logged at `warn` and discarded; the next
/// tick fires on schedule.
#[async_trait]
pub trait Job: Send + Sync + 'static {
    /// Stable identifier used in span fields and log lines, e.g.
    /// `notifications_dispatcher` or `rmm_sync`. Should match the
    /// owning module's worker name for grep-ability.
    fn name(&self) -> &'static str;

    /// One tick of work. Returning `Err` logs the error and skips the
    /// tick; the loop continues. Implementations that need richer
    /// retry semantics (backoff, dedupe) keep that logic inside
    /// `run`; the scheduler does not retry.
    async fn run(&self) -> AppResult<()>;
}

/// A single registered job + the interval at which the scheduler
/// will tick it. Cheap to clone; `Arc<dyn Job>` is two pointers.
struct Entry {
    job: Arc<dyn Job>,
    interval: Duration,
}

/// Registry of background jobs. Build via [`Scheduler::new`], add
/// jobs with [`Scheduler::register`], then call [`Scheduler::start`]
/// to spawn one tokio task per job. The scheduler does not own a
/// runtime handle; it relies on the surrounding `#[tokio::main]`.
pub struct Scheduler {
    entries: Vec<Entry>,
}

impl Scheduler {
    pub fn new() -> Self {
        Self { entries: vec![] }
    }

    /// Queue a job to spawn at [`start`](Self::start) time. The job
    /// is moved into an `Arc` so the spawn closure can carry it
    /// without lifetimes.
    pub fn register<J: Job>(&mut self, job: J, interval: Duration) {
        self.entries.push(Entry {
            job: Arc::new(job),
            interval,
        });
    }

    /// Consume the scheduler and spawn one tokio task per registered
    /// job. Returns immediately; the spawned tasks run until the
    /// surrounding runtime shuts down.
    pub fn start(self) {
        for Entry { job, interval } in self.entries {
            let name = job.name();
            tracing::info!(
                job = name,
                interval_secs = interval.as_secs(),
                "scheduler: spawning job"
            );
            tokio::spawn(run_job_loop(job, interval));
        }
    }
}

impl Default for Scheduler {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-job loop. Pulled out of `Scheduler::start` so each spawn site
/// has a clean async fn (cleaner tracing spans + easier to reason
/// about in profiles than a nested closure).
async fn run_job_loop(job: Arc<dyn Job>, interval: Duration) {
    let name = job.name();
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        let span = tracing::info_span!("scheduler_tick", job = name);
        let _enter = span.enter();
        if let Err(e) = job.run().await {
            tracing::warn!(
                job = name,
                error = ?e,
                "scheduler tick failed; will retry on next interval"
            );
        }
    }
}
