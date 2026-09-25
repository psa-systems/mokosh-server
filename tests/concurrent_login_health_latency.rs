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

mod common;

use mokosh_test::mokosh_test;
use sqlx::PgPool;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const CONCURRENT_LOGINS: usize = 15;

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

    let stop = Arc::new(AtomicBool::new(false));
    let health_client = app.client.clone();
    let health_url = app.url("/api/v1/health");
    let poller_stop = stop.clone();
    let poller = tokio::spawn(async move {
        let mut latencies = Vec::new();
        let mut next_tick = tokio::time::Instant::now();
        while !poller_stop.load(Ordering::Relaxed) {
            next_tick += Duration::from_millis(2);
            tokio::time::sleep_until(next_tick).await;
            let scheduling_delay = tokio::time::Instant::now().saturating_duration_since(next_tick);

            let started = Instant::now();
            let resp = health_client.get(&health_url).send().await;
            let request_elapsed = started.elapsed();

            if resp.is_ok() {
                latencies.push(scheduling_delay + request_elapsed);
            }
        }
        latencies
    });

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
    assert!(
        sample_count > 0,
        "health poller recorded no samples during the burst"
    );
    let idx = ((sample_count as f64) * 0.99) as usize;
    let p99 = latencies[idx.min(sample_count - 1)];

    // A single Argon2 hash/verify takes roughly 10ms in a debug build. If it
    // ran inline on the worker instead of on the blocking pool, the 15
    // logins in this burst would serialize into well over 100ms of `/health`
    // delay (observed ~128ms with the `spawn_blocking` wrap removed as a
    // check). A 30ms bound is generous against ordinary test-environment
    // jitter (observed well under 2ms with the fix in place) while still
    // failing loudly on that regression.
    assert!(
        p99 < Duration::from_millis(30),
        "/health p99 was {:?} across {} samples during a {}-login Argon2 \
         burst; expected hash_password/verify_password to stay off the \
         async worker via spawn_blocking",
        p99,
        sample_count,
        CONCURRENT_LOGINS,
    );
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
