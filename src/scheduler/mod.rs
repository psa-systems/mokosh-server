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
//! That immediate first tick is also what used to make this the wrong home for
//! work with no cadence at all. Registering a one-time correction at an hour
//! got it run at boot, and the interval was only ever a free retry, so the
//! process ended up carrying three recurring jobs that existed to fix
//! something once (PMS-1320). Such work now goes through
//! [`one_shot::spawn_once`] and says so; a [`Job`] is for work that becomes
//! due again.
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

// PMS-1320: work that happens once per process start rather than on an
// interval. Three "one-shot in effect" jobs used to sit on this scheduler at an
// hour, which is a recurring job doing a one-time correction; see the module
// doc for why that is not the same thing and why it is not a migration either.
pub mod one_shot;

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::Notify;
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

/// A single registered job, the interval at which the scheduler will tick it,
/// and an optional handle that runs it sooner.
struct Entry {
    job: Arc<dyn Job>,
    interval: Duration,
    wake: Option<Arc<Notify>>,
}

/// A handle that runs a registered job NOW rather than at its next tick
/// (PMS-1429).
///
/// The interval is the cadence of the work nobody is watching. A person who
/// presses a button IS watching, and the gap between the two is the whole
/// problem this closes: a Google Contacts import queued by hand waited up to a
/// full minute before anything started, for six contacts, because the request
/// only inserted a row and the worker slept.
///
/// What it deliberately does NOT do is run the work in the request. PMS-1215
/// made the request insert a row precisely so a closed tab cannot stop an
/// import, and that stays true: the worker still owns execution, it just does
/// not sleep first.
///
/// [`Notify::notify_one`] holds one permit when nobody is waiting, so a wake
/// that arrives WHILE the job is running is not lost: the loop's next
/// `notified()` returns immediately and the work is picked up on the spot.
/// Extra wakes collapse into that one permit, so a person pressing a button
/// twice costs one extra tick rather than one per press.
///
/// It reaches only the jobs in THIS process. A deployment running several
/// replicas wakes the one whose API served the request; another replica's
/// claim is unaffected, and the run is claimed by whoever gets there first
/// (`FOR UPDATE SKIP LOCKED`), so the worst case is the old behaviour rather
/// than a wrong one.
#[derive(Clone, Default)]
pub struct JobWake(Arc<Notify>);

impl JobWake {
    pub fn new() -> Self {
        Self::default()
    }

    /// Run the job this handle was registered with as soon as it is free.
    pub fn wake(&self) {
        self.0.notify_one();
    }

    /// Resolve once this handle has been woken.
    ///
    /// The symmetric half of [`wake`](Self::wake), and what the loop awaits. A
    /// test that wants to prove some code path wakes the worker awaits this
    /// rather than sleeping and hoping, which is the only way to assert the
    /// wake without standing a whole scheduler up beside it.
    pub async fn woken(&self) {
        self.0.notified().await;
    }
}

impl std::fmt::Debug for JobWake {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("JobWake")
    }
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
        self.push(Arc::new(job), interval, None);
    }

    /// Register a job that can also be run on demand through [`JobWake`]
    /// (PMS-1429), keeping its interval for the cadence nobody watches.
    pub fn register_wakeable<J: Job>(&mut self, job: J, interval: Duration, wake: &JobWake) {
        self.push(Arc::new(job), interval, Some(Arc::clone(&wake.0)));
    }

    fn push(&mut self, job: Arc<dyn Job>, interval: Duration, wake: Option<Arc<Notify>>) {
        let name = job.name();
        if self.entries.iter().any(|e| e.job.name() == name) {
            panic!("scheduler: duplicate job name {name:?}");
        }
        self.entries.push(Entry {
            job,
            interval,
            wake,
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
            .map(
                |Entry {
                     job,
                     interval,
                     wake,
                 }| {
                    let name = job.name();
                    tracing::info!(
                        job = name,
                        interval_secs = interval.as_secs(),
                        wakeable = wake.is_some(),
                        "scheduler: spawning job"
                    );
                    tokio::spawn(run_job_loop(job, interval, wake))
                },
            )
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
async fn run_job_loop(job: Arc<dyn Job>, interval: Duration, wake: Option<Arc<Notify>>) {
    let name = job.name();
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        // PMS-1429: whichever comes first. `select!` drops the loser's future,
        // which is safe for both halves here: `tick()` holds no state outside
        // the ticker, and a `notify_one` that raced the drop left its permit
        // behind for the next `notified()`.
        match &wake {
            Some(wake) => {
                tokio::select! {
                    _ = ticker.tick() => {}
                    _ = wake.notified() => {
                        // The interval keeps its own schedule, so a woken run
                        // does not shift the cadence; `MissedTickBehavior::Skip`
                        // then drops a tick this wake has already covered.
                        tracing::debug!(job = name, "scheduler: woken on demand");
                    }
                }
            }
            None => {
                ticker.tick().await;
            }
        }
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

#[cfg(test)]
mod pms1429_wake {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Counts its ticks and tells the test when the first one has happened.
    struct Counter {
        ticks: Arc<AtomicUsize>,
        ran: Arc<Notify>,
    }

    #[async_trait]
    impl Job for Counter {
        fn name(&self) -> &'static str {
            "pms1429_counter"
        }

        async fn run(&self) -> AppResult<()> {
            self.ticks.fetch_add(1, Ordering::SeqCst);
            self.ran.notify_one();
            Ok(())
        }
    }

    fn counter() -> (Counter, Arc<AtomicUsize>, Arc<Notify>) {
        let ticks = Arc::new(AtomicUsize::new(0));
        let ran = Arc::new(Notify::new());
        (
            Counter {
                ticks: Arc::clone(&ticks),
                ran: Arc::clone(&ran),
            },
            ticks,
            ran,
        )
    }

    /// The property PMS-1429 is about: a job on a long interval runs when it is
    /// woken, rather than when its interval next comes round.
    ///
    /// The interval is an hour, so the wake is the only thing that can produce
    /// the second tick inside the timeout. (The first is tokio's immediate one:
    /// `interval` fires at once and then every period, which the module header
    /// says and every registered job already relies on.)
    #[tokio::test]
    async fn a_woken_job_runs_without_waiting_out_its_interval() {
        let (job, ticks, ran) = counter();
        let wake = JobWake::new();
        let mut scheduler = Scheduler::new();
        scheduler.register_wakeable(job, Duration::from_secs(3600), &wake);
        let _handles = scheduler.start();

        // The immediate first tick.
        tokio::time::timeout(Duration::from_secs(5), ran.notified())
            .await
            .expect("the job runs once at startup");
        assert_eq!(ticks.load(Ordering::SeqCst), 1);

        wake.wake();
        tokio::time::timeout(Duration::from_secs(5), ran.notified())
            .await
            .expect("a woken job runs without waiting out its hour");
        assert_eq!(ticks.load(Ordering::SeqCst), 2);
    }

    /// A wake that arrives while the job is between runs is not lost, which is
    /// what makes pressing a button twice safe: `notify_one` leaves a permit
    /// when nobody is waiting, so the next `notified()` returns at once.
    #[tokio::test]
    async fn a_wake_that_arrives_early_is_not_lost() {
        let (job, ticks, ran) = counter();
        let wake = JobWake::new();
        // Woken before the scheduler even starts.
        wake.wake();
        let mut scheduler = Scheduler::new();
        scheduler.register_wakeable(job, Duration::from_secs(3600), &wake);
        let _handles = scheduler.start();

        for expected in [1, 2] {
            tokio::time::timeout(Duration::from_secs(5), ran.notified())
                .await
                .unwrap_or_else(|_| panic!("run {expected} never happened"));
        }
        assert_eq!(ticks.load(Ordering::SeqCst), 2);
    }

    /// A job registered the plain way keeps the plain loop, so nothing that was
    /// not asked to be wakeable gains a second way to be run.
    #[tokio::test]
    async fn an_unwoken_job_ticks_on_its_interval_alone() {
        let (job, ticks, ran) = counter();
        let mut scheduler = Scheduler::new();
        scheduler.register(job, Duration::from_secs(3600));
        let _handles = scheduler.start();

        tokio::time::timeout(Duration::from_secs(5), ran.notified())
            .await
            .expect("the job runs once at startup");
        // Nothing else can make it run: there is no handle to wake it with.
        assert!(
            tokio::time::timeout(Duration::from_millis(200), ran.notified())
                .await
                .is_err(),
            "an unwakeable job ran a second time inside its interval"
        );
        assert_eq!(ticks.load(Ordering::SeqCst), 1);
    }
}
