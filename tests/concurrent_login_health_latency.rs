//! PMS-1245 acceptance criterion 2: a concurrent-login latency test shows
//! `/health` p99 does not regress under a concurrent Argon2 burst.
//!
//! `/api/v1/health` is a trivial, DB-free handler, so its responsiveness is a
//! clean probe for whether the async worker is stalled. This drives a burst
//! of real `/api/v1/auth/login` requests (each one an Argon2 verify,
//! PMS-1245's `verify_password`, plus an Argon2 hash per seeded user) while
//! a `/health` poller runs concurrently, and asserts the poller's p99 delay
//! stays low. Before PMS-1245 those hashes ran inline on the Tokio worker
//! handling the request; on `spawn_blocking` they run on the blocking pool
//! instead, so `/health` is unaffected by how many logins are in flight.
//!
//! The poller is driven by a fixed `tokio::time::sleep_until` tick rather
//! than "sleep, then time the request": timing only the request misses the
//! queueing delay caused by a blocking task ahead of it in line, because the
//! clock in that approach cannot start until this task is already running
//! again. Measuring how late each tick actually fires against its scheduled
//! time is what makes worker starvation visible. Confirmed against this
//! file's own regression: temporarily removing the `spawn_blocking` wrap in
//! `src/utils/crypto.rs` pushed this test's measured p99 to ~128ms; with it
//! restored p99 stays under a millisecond.
//!
//! 15 distinct users keep the burst under `/auth/login`'s per-IP rate limit
//! (20/min, `AuthRateLimiter::new(20, 5)` in `src/modules/auth/routes.rs`)
//! while each user's own 5/min cap is spent once.
//!
//! ## Why the bound is relative (PMS-1426)
//!
//! This asserted `p99 < 30ms` outright and it was 9 of the 10 integration
//! failures on pull requests between PMS-1398 and PMS-1426, every one of them
//! on a change that could not have affected it. 119ms was the observed figure
//! on a loaded runner, against ~128ms for the regression this test exists to
//! catch: on shared CI the noise and the signal are the same size, so no
//! absolute threshold can separate them. PMS-1283 had already tried the
//! obvious mitigation, reserving the whole nextest thread budget for this case
//! (`.config/nextest.toml`), which does nothing about the other WORKFLOWS
//! running on the same runner.
//!
//! So the test now measures `/health` with the same poller while NOTHING is in
//! flight, and requires the burst's p99 to stay within a multiple of that
//! baseline. A machine that is merely slow raises both numbers together and
//! the ratio holds; hashing on the async worker raises only the burst, by two
//! orders of magnitude. That is the difference the assertion is about, and it
//! is the one a shared runner cannot erase.

mod common;

use mokosh_test::mokosh_test;
use sqlx::PgPool;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const CONCURRENT_LOGINS: usize = 15;

/// The poller's tick. Short enough that a 15-login burst is covered by tens of
/// samples.
const TICK: Duration = Duration::from_millis(2);

/// How long the idle baseline runs. Enough samples for a p99 to mean something
/// at a 2ms tick, and short enough not to lengthen the suite noticeably.
const BASELINE_WINDOW: Duration = Duration::from_millis(300);

/// How far above the idle baseline the burst's p99 may sit.
///
/// The regression is two orders of magnitude (sub-millisecond to ~128ms), and a
/// loaded runner moves both figures together, so the gap between "tolerate a
/// slow machine" and "catch inline hashing" is wide. 10 sits in it with room on
/// both sides.
const MAX_BURST_RATIO: f64 = 10.0;

/// The smallest bound worth asserting, whatever the baseline says.
///
/// An idle p99 under a millisecond is normal on a quiet machine, and ten times
/// nothing is still nothing: without a floor the test would fail on scheduling
/// noise it has no opinion about.
const JITTER_FLOOR: Duration = Duration::from_millis(30);

#[mokosh_test]
async fn health_p99_does_not_regress_under_concurrent_argon2_burst(pool: PgPool) {
    let app = Arc::new(common::boot(pool.clone()).await);

    let password = "test-password-12345";
    let seed_handles: Vec<_> = (0..CONCURRENT_LOGINS)
        .map(|i| {
            let pool = pool.clone();
            let email = format!("burst-user-{i}@example.com");
            tokio::spawn(async move {
                seed_active_user(&pool, &email, password).await;
                email
            })
        })
        .collect();
    let mut emails = Vec::with_capacity(CONCURRENT_LOGINS);
    for handle in seed_handles {
        emails.push(handle.await.expect("seed task panicked"));
    }

    // The baseline: the same poller, on this machine, with nothing in flight.
    // Taken BEFORE the burst rather than after, so a runner that gets busier
    // during the run makes the test more tolerant rather than less.
    let idle_p99 = {
        let stop = Arc::new(AtomicBool::new(false));
        let poller = spawn_health_poller(&app, stop.clone());
        tokio::time::sleep(BASELINE_WINDOW).await;
        stop.store(true, Ordering::Relaxed);
        let mut latencies = poller.await.expect("baseline poller task panicked");
        latencies.sort();
        p99_of(&latencies).expect("the baseline poller recorded no samples")
    };

    let stop = Arc::new(AtomicBool::new(false));
    let poller = spawn_health_poller(&app, stop.clone());

    let login_handles: Vec<_> = emails
        .into_iter()
        .map(|email| {
            let app = app.clone();
            let password = password.to_string();
            tokio::spawn(async move { common::login(&app, &email, &password).await })
        })
        .collect();
    for handle in login_handles {
        handle.await.expect("login task panicked");
    }

    stop.store(true, Ordering::Relaxed);
    let mut latencies = poller.await.expect("health poller task panicked");
    latencies.sort();

    let sample_count = latencies.len();
    let p99 = p99_of(&latencies).expect("health poller recorded no samples during the burst");

    // A single Argon2 hash/verify takes roughly 10ms in a debug build. Inline
    // on the worker, the 15 logins here serialize into well over 100ms of
    // `/health` delay (~128ms observed with the `spawn_blocking` wrap removed
    // as a check); on the blocking pool the burst is invisible to `/health`
    // and p99 stays near the idle figure.
    //
    // The bound is therefore the idle p99 times [`MAX_BURST_RATIO`], plus
    // [`JITTER_FLOOR`] so a machine fast enough to measure a sub-millisecond
    // baseline does not get a bound too tight to be meaningful. Both halves
    // are needed: the floor alone is what used to fail on a loaded runner, and
    // the ratio alone would be unusable where the baseline rounds to nothing.
    let bound = idle_p99.mul_f64(MAX_BURST_RATIO).max(JITTER_FLOOR);
    assert!(
        p99 < bound,
        "/health p99 was {:?} across {} samples during a {}-login Argon2 burst, against an idle \
         baseline of {:?} on this machine (bound {:?}); expected hash_password/verify_password to \
         stay off the async worker via spawn_blocking",
        p99,
        sample_count,
        CONCURRENT_LOGINS,
        idle_p99,
        bound,
    );
}

/// Poll `/health` on a fixed tick until `stop`, returning each sample's delay.
///
/// Driven by `sleep_until` against a scheduled tick rather than "sleep, then
/// time the request", for the reason in the module docs: timing only the
/// request cannot see the queueing delay caused by a blocking task ahead of it,
/// because the clock does not start until this task is already running again.
fn spawn_health_poller(
    app: &Arc<common::TestApp>,
    stop: Arc<AtomicBool>,
) -> tokio::task::JoinHandle<Vec<Duration>> {
    let client = app.client.clone();
    let url = app.url("/api/v1/health");
    tokio::spawn(async move {
        let mut latencies = Vec::new();
        let mut next_tick = tokio::time::Instant::now();
        while !stop.load(Ordering::Relaxed) {
            next_tick += TICK;
            tokio::time::sleep_until(next_tick).await;
            let scheduling_delay = tokio::time::Instant::now().saturating_duration_since(next_tick);

            let started = Instant::now();
            let resp = client.get(&url).send().await;
            let request_elapsed = started.elapsed();

            if resp.is_ok() {
                latencies.push(scheduling_delay + request_elapsed);
            }
        }
        latencies
    })
}

/// The p99 of a SORTED slice, or `None` when it is empty.
fn p99_of(sorted: &[Duration]) -> Option<Duration> {
    if sorted.is_empty() {
        return None;
    }
    let idx = ((sorted.len() as f64) * 0.99) as usize;
    Some(sorted[idx.min(sorted.len() - 1)])
}

async fn seed_active_user(pool: &PgPool, email: &str, password: &str) {
    let password_hash = mokosh_server::utils::crypto::hash_password(password)
        .await
        .expect("hash burst user password");
    sqlx::query(
        r#"
        INSERT INTO users (
            id, tenant_id, email, password_hash,
            first_name, last_name, role, status, email_verified_at
        )
        VALUES ($1, $2, $3, $4, 'Burst', 'User', 'technician', 'active', NOW())
        "#,
    )
    .bind(uuid::Uuid::new_v4())
    .bind(common::DEFAULT_TENANT_ID)
    .bind(email)
    .bind(&password_hash)
    .execute(pool)
    .await
    .expect("insert burst user");
}
