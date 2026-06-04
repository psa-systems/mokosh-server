//! Smoke test for the shared scheduler (PMS-135).
//!
//! Pins the per-job spawn + interval semantics that follow-up
//! migration PRs (notifications dispatcher, RMM sync worker, future
//! reminder/breach/renewal jobs) all rely on:
//!
//! - Each registered `Job` runs on its own tokio task.
//! - Ticks fire at the configured interval (no missed-tick backlog).
//! - An error returned by `run` is logged + swallowed; the next tick
//!   still fires.
//!
//! The test uses an `AtomicUsize` shared between the test body and
//! the job closure so the assertion is wall-clock driven (we wait
//! N intervals + slack, then read the counter). No DB needed.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use mokosh_server::scheduler::{Job, Scheduler};
use mokosh_server::utils::error::{AppError, AppResult};

struct CountingJob {
    counter: Arc<AtomicUsize>,
    fail_every: usize,
}

#[async_trait]
impl Job for CountingJob {
    fn name(&self) -> &'static str {
        "counting_job"
    }

    async fn run(&self) -> AppResult<()> {
        let n = self.counter.fetch_add(1, Ordering::SeqCst) + 1;
        if self.fail_every > 0 && n.is_multiple_of(self.fail_every) {
            return Err(AppError::Internal("intentional smoke-test failure".into()));
        }
        Ok(())
    }
}

#[tokio::test]
async fn registered_job_ticks_at_interval() {
    let counter = Arc::new(AtomicUsize::new(0));
    let mut sched = Scheduler::new();
    sched.register(
        CountingJob {
            counter: counter.clone(),
            fail_every: 0,
        },
        Duration::from_millis(50),
    );
    sched.start();

    // First tick of `tokio::time::interval` fires immediately, then
    // every 50ms. Wait 240ms so we expect ~5 ticks (1 + 4) but assert
    // a conservative >= 3 to absorb scheduler jitter on a loaded CI
    // runner.
    tokio::time::sleep(Duration::from_millis(240)).await;
    let n = counter.load(Ordering::SeqCst);
    assert!(
        n >= 3,
        "expected at least 3 ticks in 240ms at 50ms interval, got {n}"
    );
}

#[tokio::test]
async fn tick_errors_do_not_kill_the_loop() {
    let counter = Arc::new(AtomicUsize::new(0));
    let mut sched = Scheduler::new();
    // Every other tick returns Err; the scheduler must still keep
    // ticking. After 240ms the counter should advance past
    // `fail_every` (otherwise an error would have aborted the loop
    // and the counter would freeze at the first failing tick).
    sched.register(
        CountingJob {
            counter: counter.clone(),
            fail_every: 2,
        },
        Duration::from_millis(50),
    );
    sched.start();

    tokio::time::sleep(Duration::from_millis(240)).await;
    let n = counter.load(Ordering::SeqCst);
    assert!(
        n >= 4,
        "loop should survive periodic Err; want >= 4 ticks, got {n}"
    );
}
