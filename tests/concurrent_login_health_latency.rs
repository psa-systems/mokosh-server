//! PMS-1245 acceptance criterion 2: a concurrent-login latency test shows
//! `/health` stays responsive under a concurrent Argon2 burst.
//!
//! `/api/v1/health` is a trivial, DB-free handler, so a gap in its
//! completions is a clean signal that the async worker is stalled. This
//! drives a burst of real `/api/v1/auth/login` requests (each one an Argon2
//! verify, PMS-1245's `verify_password`, plus an Argon2 hash per seeded
//! user) while a `/health` poller runs concurrently, and asserts the longest
//! gap between consecutive successful `/health` completions stays short.
//! Before PMS-1245 those hashes ran inline on the Tokio worker handling the
//! request; on `spawn_blocking` they run on the blocking pool instead, so
//! `/health` is unaffected by how many logins are in flight.
//!
//! 15 distinct users keep the burst under `/auth/login`'s per-IP rate limit
//! (20/min, `AuthRateLimiter::new(20, 5)` in `src/modules/auth/routes.rs`)
//! while each user's own 5/min cap is spent once.
//!
//! ## Why max-gap and not p99 (PMS-1283, PMS-1426, [the retry])
//!
//! The previous forms asserted on p99 of per-sample latencies. That metric
//! turned out to be unable to separate the two scenarios on a shared CI
//! runner: 119ms was the observed p99 under CI noise with hashing correctly
//! on the blocking pool; 128ms is the p99 with inline hashing (the real
//! regression). The signal and the noise are the same size at the tail, so
//! no threshold on p99 can distinguish them: a tight bound flakes under
//! load, a loose bound misses the regression.
//!
//! The structural difference the test exists to catch is not "tail is high"
//! but "the worker was blocked for a 150-ish-ms stretch while 15 serial
//! hashes ran inline". That stretch shows up as a continuous GAP in the
//! `/health` poller's completion stream, because the worker that runs the
//! poller is the same one the hashes are blocking. Independent CI jitter,
//! by contrast, delays INDIVIDUAL samples; the next tick after a jitter
//! spike completes within one tick of its predecessor.
//!
//! So the test now measures `max_gap`: the longest wall-clock distance
//! between two consecutive successful `/health` completions during the
//! burst. Under inline hashing the metric is ~100-150ms (the length of the
//! starvation stretch). Under the blocking-pool path with CI load the
//! metric stays in the single-digit-ms-to-30ms band regardless of how slow
//! individual samples got, because the gaps between samples are bounded by
//! the tick, not by the slowest sample. A relative bound against the idle
//! baseline's own max_gap plus a 70ms floor keeps the test tolerant of
//! loaded runners while a two-order-of-magnitude signal still fails
//! cleanly.

mod common;

use mokosh_test::mokosh_test;
use sqlx::PgPool;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const CONCURRENT_LOGINS: usize = 15;

/// The poller's tick. Short enough that a 15-login burst is covered by tens
/// of samples, so the longest gap under a stall is many ticks wide (easy to
/// see) rather than one tick (indistinguishable from scheduling jitter).
const TICK: Duration = Duration::from_millis(2);

/// How long the idle baseline runs. Enough samples that the baseline
/// `max_gap` captures the runner's natural scheduling-noise ceiling, short
/// enough not to lengthen the suite noticeably.
const BASELINE_WINDOW: Duration = Duration::from_millis(300);

/// How far above the idle baseline the burst's `max_gap` may sit.
///
/// Independent per-sample CI jitter affects which TICKS fire late, not the
/// WALL-CLOCK distance between successive completions: a late sample is
/// immediately followed by a catch-up one close behind it. So the burst's
/// `max_gap` only grows when the worker is blocked for a continuous
/// stretch. A 3x ceiling easily tolerates a loaded runner while leaving a
/// large gap between the top of CI jitter (~20-30ms) and the bottom of
/// inline-hash starvation (~100-150ms).
const MAX_BURST_RATIO: f64 = 3.0;

/// The smallest bound worth asserting, whatever the baseline says.
///
/// A sub-TICK baseline on a quiet runner would yield a tight ratio bound
/// that could trip on single-sample CI jitter spikes that happen to
/// coincide with a boundary. 70ms is a comfortable floor well above
/// expected CI gap noise (<30ms is the common ceiling) and well below the
/// ~100-150ms band an inline-hash stretch produces.
const JITTER_FLOOR: Duration = Duration::from_millis(70);

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
    let idle_max_gap = {
        let stop = Arc::new(AtomicBool::new(false));
        let poller = spawn_health_poller(&app, stop.clone());
        tokio::time::sleep(BASELINE_WINDOW).await;
        stop.store(true, Ordering::Relaxed);
        let completions = poller.await.expect("baseline poller task panicked");
        max_gap(&completions).expect("the baseline poller recorded fewer than two samples")
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
    let completions = poller.await.expect("health poller task panicked");
    let sample_count = completions.len();
    let burst_max_gap =
        max_gap(&completions).expect("health poller recorded fewer than two samples");

    // A single Argon2 hash/verify takes roughly 10ms in a debug build. Inline
    // on the worker, the 15 logins here serialize into a ~100-150ms continuous
    // worker stall; `/health` completions fall silent for the length of the
    // stall and `burst_max_gap` lands in that band. On the blocking pool the
    // burst is invisible to `/health` and `burst_max_gap` stays close to
    // `idle_max_gap`, bounded by scheduling jitter rather than by the hash
    // duration.
    //
    // Bound is `idle_max_gap * MAX_BURST_RATIO` with a `JITTER_FLOOR`, so a
    // machine fast enough to measure a near-TICK idle gap does not get a
    // bound tight enough to trip on single-tick CI noise.
    let bound = idle_max_gap.mul_f64(MAX_BURST_RATIO).max(JITTER_FLOOR);
    assert!(
        burst_max_gap < bound,
        "/health max completion gap was {:?} across {} samples during a {}-login Argon2 burst, \
         against an idle baseline max_gap of {:?} on this machine (bound {:?}); expected \
         hash_password/verify_password to stay off the async worker via spawn_blocking",
        burst_max_gap,
        sample_count,
        CONCURRENT_LOGINS,
        idle_max_gap,
        bound,
    );
}

/// Poll `/health` on a fixed tick until `stop`, returning each successful
/// completion's wall-clock timestamp.
///
/// Driven by `sleep_until` against a scheduled tick so the poller catches
/// back up after a stall rather than drifting. The returned sequence is
/// strictly increasing, so successive differences are the wall-clock gaps
/// between completions: a worker stall shows up as one unusually large
/// difference, independent CI scheduling noise shows up as a cluster of
/// small ones.
fn spawn_health_poller(
    app: &Arc<common::TestApp>,
    stop: Arc<AtomicBool>,
) -> tokio::task::JoinHandle<Vec<Instant>> {
    let client = app.client.clone();
    let url = app.url("/api/v1/health");
    tokio::spawn(async move {
        let mut completions = Vec::new();
        let mut next_tick = tokio::time::Instant::now();
        while !stop.load(Ordering::Relaxed) {
            next_tick += TICK;
            tokio::time::sleep_until(next_tick).await;
            let resp = client.get(&url).send().await;
            if resp.is_ok() {
                completions.push(Instant::now());
            }
        }
        completions
    })
}

/// The largest wall-clock gap between consecutive entries, or `None` when
/// there are fewer than two.
fn max_gap(completions: &[Instant]) -> Option<Duration> {
    completions.windows(2).map(|w| w[1] - w[0]).max()
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
