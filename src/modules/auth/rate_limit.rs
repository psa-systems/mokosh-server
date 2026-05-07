//! Per-IP rate limiting for auth endpoints (currently `/login`).
//!
//! Audit F2 (P0). The login endpoint had no rate limiting, leaving it
//! open to credential stuffing / brute force. Caps a single IP at 5
//! attempts/minute; over-quota requests get HTTP 429.
//!
//! In-memory state only; will not survive a server restart and does
//! not coordinate across replicas. Acceptable for the single-process
//! dev/single-tenant deployment; for horizontal scale, swap the store
//! for Redis (the `governor` ecosystem has a redis backend).

use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
use std::sync::Arc;

use axum::extract::{ConnectInfo, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::Response;
use governor::clock::DefaultClock;
use governor::state::keyed::DefaultKeyedStateStore;
use governor::{Quota, RateLimiter};

/// Per-IP keyed rate limiter for `/auth/login`. 5 attempts per minute.
pub type LoginLimiter = RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, DefaultClock>;

/// Build the limiter; share the resulting `Arc` with the middleware via
/// `axum::middleware::from_fn_with_state`.
pub fn login_limiter() -> Arc<LoginLimiter> {
    let quota = Quota::per_minute(
        NonZeroU32::new(5).expect("5 is non-zero"),
    );
    Arc::new(RateLimiter::keyed(quota))
}

/// Axum middleware. Returns 429 when the caller's IP is over quota.
pub async fn login_rate_limit(
    State(limiter): State<Arc<LoginLimiter>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if limiter.check_key(&addr.ip()).is_err() {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    Ok(next.run(request).await)
}
