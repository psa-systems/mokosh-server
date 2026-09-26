//! PMS-1320: work that has to happen once, not on an interval.
//!
//! A layout change leaves the objects already on a customer's volume where the
//! old code put them, and something has to walk them over. That something is
//! not a job: it has no cadence, it does not become due again, and once it has
//! run against a deployment there is nothing left for it to do ever again.
//!
//! It was written as a [`Job`](super::Job) at an hour anyway, three times over
//! (KB attachments, the tenant logo, gateway credentials), because
//! [`Scheduler`](super::Scheduler) fires every registered job once immediately
//! at startup and the hourly interval came free with that. What it bought was a
//! retry after a transient failure. What it cost was a recurring job whose
//! whole purpose was a one-time correction, which reads to anyone looking at
//! the process as ongoing maintenance the design still depends on, and which
//! has to be explained every time somebody asks what runs every hour and why.
//! David asked that question and it is a fair one.
//!
//! So a one-shot says so. It runs once per process start and never again, and
//! the retry it gives up is the difference between a failure being corrected an
//! hour later and being corrected at the next restart, against a `WARN` line
//! naming the pass either way.
//!
//! # Why this is not a migration
//!
//! The obvious shape is a `migrations/*.sql` that does the move once and is
//! then recorded in `_sqlx_migrations` forever. It is not available: a
//! migration runs inside Postgres, and what these passes move is BYTES in
//! `crate::storage`, on a local volume or in an S3 bucket that Postgres cannot
//! reach. Only the `files` ledger row is SQL, and rewriting a ledger row
//! without moving the file it names is the one ordering that can lie (PMS-957).
//!
//! # Why not an operator command
//!
//! A `mokosh-server move-kb-attachments` an operator runs once is the shape the
//! Infisical secret move took, and it is the most honest one-time story there
//! is. It was declined here for one reason: a deployment nobody tells keeps
//! serving those files off the legacy read fallback indefinitely, so the
//! fallback can never be removed and the correction never actually completes.
//! Running at boot means every deployment that takes the upgrade completes it.

use std::future::Future;

use tokio::task::JoinHandle;
use tracing::Instrument;

use crate::utils::error::AppResult;

/// Run `task` once, in the background, naming it in the log either way.
///
/// Spawned rather than awaited because the caller is `main` on its way to
/// binding a port: a pass over a volume of unknown size must not decide how
/// long the API takes to come up, and nothing about serving a request needs the
/// pass to have finished. Every one of these has a read-side fallback to the
/// old location for exactly that window.
///
/// A failure is a `WARN` and nothing else. These passes correct history, so a
/// failed one leaves the deployment where it already was rather than breaking
/// it, and taking the process down over it would turn a cosmetic layout debt
/// into an outage.
///
/// The returned handle is usually dropped, the same fire-and-forget the
/// scheduler's handles get; a caller that wants to await or abort the pass can
/// keep it.
pub fn spawn_once<F>(name: &'static str, task: F) -> JoinHandle<()>
where
    F: Future<Output = AppResult<()>> + Send + 'static,
{
    let span = tracing::info_span!("one_shot", job = name);
    tokio::spawn(
        async move {
            match task.await {
                Ok(()) => tracing::debug!("one-shot pass complete"),
                // Named in the message as well as the span, because a span
                // field is lost the moment this line is grepped out of a log.
                Err(e) => tracing::warn!(error = %e, "one-shot pass {name} failed; it runs again at the next restart"),
            }
        }
        .instrument(span),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::error::AppError;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// Once means once. The whole point of the change is that nothing re-arms
    /// it, so the assertion is on the count after giving the runtime every
    /// chance to tick something.
    #[tokio::test]
    async fn the_task_runs_exactly_once() {
        let runs = Arc::new(AtomicUsize::new(0));
        let counter = runs.clone();
        let handle = spawn_once("test_pass", async move {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });
        handle.await.expect("the pass ran");
        tokio::task::yield_now().await;
        assert_eq!(runs.load(Ordering::SeqCst), 1);
    }

    /// A failed pass must not take the process with it: these correct history,
    /// so failing leaves the deployment where it already was.
    #[tokio::test]
    async fn a_failing_task_is_logged_and_swallowed() {
        let handle = spawn_once("test_pass", async {
            Err(AppError::Internal("the store was unreachable".into()))
        });
        handle
            .await
            .expect("a failing pass does not panic the task");
    }

    /// PMS-1320: a mover is not a job, and nothing quietly makes it one again.
    ///
    /// The three passes were on the scheduler at an hour precisely because
    /// registering them there was the easiest way to get them run at boot, so
    /// the pull toward doing it again is real and the comment saying not to is
    /// not enough. This reads `main.rs` back: no `scheduler.register` line may
    /// name a mover, and every mover must be spawned as a one-shot.
    ///
    /// Keyed on the `_mover` variable suffix rather than on the three type
    /// names, so a fourth pass added later is covered by the convention
    /// instead of needing an edit here.
    #[test]
    fn no_mover_is_registered_on_the_scheduler() {
        let main = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("src")
                .join("main.rs"),
        )
        .expect("read src/main.rs");

        let registered: Vec<&str> = main
            .lines()
            .map(str::trim)
            .filter(|line| !line.starts_with("//"))
            .filter(|line| line.contains("scheduler.register") && line.contains("_mover"))
            .collect();
        assert!(
            registered.is_empty(),
            "a one-time correction is not a recurring job (PMS-1320); these put              one back on the scheduler: {registered:#?}"
        );

        // And the complement: a mover that is constructed and then spawned by
        // nothing would be dead code that reads as wiring.
        let constructed = main.matches("_mover =").count();
        let spawned = main.matches("ONE_SHOT_NAME").count();
        assert_eq!(
            constructed, spawned,
            "{constructed} mover(s) are built in main.rs but {spawned} are              handed to spawn_once"
        );
    }
}
