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
//! Tokio's `interval(d)` fires its first tick IMMEDIATELY, then
//! every `d`. That means every registered job runs once at process
//! startup with no warmup delay; jobs that need a warmup should
//! sleep inside `run` on first invocation.
//!
//! Usage from `main.rs`:
//! ```ignore
//! let mut scheduler = Scheduler::new();
//! scheduler.register(notif_worker, Duration::from_secs(5));
//! scheduler.register(rmm_worker, Duration::from_secs(60));
//! let _handles = scheduler.start();
//! ```
//!
//! `start` returns the spawned task handles. They are usually
//! dropped (fire-and-forget daemon semantics, same as the old
//! ad-hoc spawn sites) but the caller MAY keep them for graceful
//! shutdown / `abort()` on signal.
//!
//! Every background worker now implements [`Job`] and is registered here:
//! `DispatcherWorker` and `RmmSyncWorker` were migrated off their raw
//! `tokio::spawn(run_forever(..))` sites in PMS-198, joining the contract /
//! recurring-invoicing / SLA / calendar-reminder jobs already on the
//! Scheduler. Workers expose a `run_tick`-style method for deterministic
//! tests; the `Job::run` impl is a thin wrapper the Scheduler ticks.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;
use tracing::Instrument;

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
    /// owning module's worker name for grep-ability. Must be unique
    /// across every job registered on the same [`Scheduler`];
    /// [`Scheduler::register`] panics on duplicates so cross-job
    /// trace fields stay unambiguous.
    fn name(&self) -> &'static str;

    /// One tick of work. Returning `Err` logs the error and skips the
    /// tick; the loop continues. Implementations that need richer
    /// retry semantics (backoff, dedupe) keep that logic inside
    /// `run`; the scheduler does not retry.
    async fn run(&self) -> AppResult<()>;
}

/// A single registered job + the interval at which the scheduler
/// will tick it.
struct Entry {
    job: Arc<dyn Job>,
    interval: Duration,
}

/// Registry of background jobs. Build via [`Scheduler::new`], add
/// jobs with [`Scheduler::register`], then call [`Scheduler::start`]
/// to spawn one tokio task per job. The scheduler does not own a
/// runtime handle; it relies on the surrounding `#[tokio::main]`.
#[must_use = "a Scheduler does nothing until you call .start()"]
pub struct Scheduler {
    entries: Vec<Entry>,
}

impl Scheduler {
    pub fn new() -> Self {
        Self { entries: vec![] }
    }

    /// Queue a job to spawn at [`start`](Self::start) time. Panics
    /// if a job with the same [`Job::name`] was already registered
    /// on this scheduler: identical span field values would make
    /// per-job trace filtering ambiguous, and silently dropping the
    /// second registration would mask a real misconfiguration.
    pub fn register<J: Job>(&mut self, job: J, interval: Duration) {
        let name = job.name();
        if self.entries.iter().any(|e| e.job.name() == name) {
            panic!("scheduler: duplicate job name {name:?}");
        }
        self.entries.push(Entry {
            job: Arc::new(job),
            interval,
        });
    }

    /// Consume the scheduler and spawn one tokio task per registered
    /// job. Returns the `JoinHandle`s in registration order; the
    /// caller may drop them for fire-and-forget daemon semantics or
    /// keep them for graceful-shutdown coordination.
    pub fn start(self) -> Vec<JoinHandle<()>> {
        // Defence in depth: the registry already guards against
        // duplicates at `register` time, but verify once more here
        // so any future bypass (e.g. construction via Default +
        // direct entries mutation in a refactor) still fails loud.
        let mut seen: HashSet<&'static str> = HashSet::new();
        for e in &self.entries {
            if !seen.insert(e.job.name()) {
                panic!("scheduler: duplicate job name {:?} at start", e.job.name());
            }
        }

        self.entries
            .into_iter()
            .map(|Entry { job, interval }| {
                let name = job.name();
                tracing::info!(
                    job = name,
                    interval_secs = interval.as_secs(),
                    "scheduler: spawning job"
                );
                tokio::spawn(run_job_loop(job, interval))
            })
            .collect()
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
        // Use `Instrument` so the span stays attached to the future
        // even if the tokio scheduler moves this task between
        // threads mid-await. A bare `span.enter()` guard held across
        // `.await` ties the span to the current OS thread and the
        // log lines drift off the wrong context once the task
        // resumes elsewhere.
        let result = job.run().instrument(span).await;
        if let Err(e) = result {
            tracing::warn!(
                job = name,
                error = ?e,
                "scheduler tick failed; will retry on next interval"
            );
        }
    }
}
