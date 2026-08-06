//! PMS-730: the unauthenticated client-facing surface for request forms.
//!
//! Mounted OUTSIDE `AuthMiddleware` and outside the portal tree: the caller is
//! a client with no session at all, and the only identity they present is the
//! magic-link token. That token is the primary control (it is scoped to one
//! company and one form, is single-use, and expires); the rate limiter below
//! is the backstop against someone grinding at the token space.

use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
use std::sync::Arc;

use axum::{
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, StatusCode},
    routing::get,
    Json, Router,
};
use governor::clock::{Clock, DefaultClock};
use governor::state::keyed::DefaultKeyedStateStore;
use governor::{Quota, RateLimiter};

use super::models::{PublicFormResponse, PublicSubmissionReceipt, SubmitFormRequest};
use super::service::FormsService;
use crate::utils::client_ip::{extract_client_ip, trusted_proxies};
use crate::utils::error::{AppError, AppResult};

type IpLimiter = RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, DefaultClock>;

/// Per-IP limiter for the public request-form surface.
///
/// In-memory only: it does not survive a restart and does not coordinate
/// across replicas, exactly like `PortalLoginLimiter`. That is acceptable here
/// because it is explicitly the SECOND line of defence. A token is a 64
/// character random secret behind an Argon2 verify, so the limiter exists to
/// make grinding expensive and noisy rather than to be the thing that stops it.
pub struct RequestFormLimiter {
    by_ip: IpLimiter,
    clock: DefaultClock,
}

impl RequestFormLimiter {
    pub fn new() -> Arc<Self> {
        // Deliberately looser than the portal's 5/min account bucket: a real
        // client opening a form, fixing two validation errors and resubmitting
        // is several requests in a minute, and a false 429 on a client-facing
        // form is a support call. 30/min still cuts a grinder to a rate at
        // which the token space is unreachable.
        let quota = Quota::per_minute(NonZeroU32::new(30).expect("30 is non-zero"));
        Arc::new(Self {
            by_ip: RateLimiter::keyed(quota),
            clock: DefaultClock::default(),
        })
    }

    /// `Ok(())` when the caller may proceed, `Err(retry_after_seconds)` when
    /// they are over quota.
    pub fn check(&self, ip: IpAddr) -> Result<(), u64> {
        match self.by_ip.check_key(&ip) {
            Ok(()) => Ok(()),
            Err(not_until) => Err(not_until.wait_time_from(self.clock.now()).as_secs().max(1)),
        }
    }
}

impl Default for RequestFormLimiter {
    fn default() -> Self {
        // `new` returns the Arc callers actually want; this exists only to
        // satisfy the lint that pairs `new()` with `Default`.
        Arc::try_unwrap(Self::new()).unwrap_or_else(|_| unreachable!("freshly created Arc"))
    }
}

#[derive(Clone)]
struct PublicFormsState {
    service: Arc<FormsService>,
    limiter: Arc<RequestFormLimiter>,
}

/// Mounted by the caller under `/api/v1/public`.
pub fn public_form_routes(service: FormsService) -> Router {
    let state = PublicFormsState {
        service: Arc::new(service),
        limiter: RequestFormLimiter::new(),
    };
    Router::new()
        .route(
            "/request-forms/{token}",
            get(get_public_form).post(submit_public_form),
        )
        .with_state(state)
}

fn client_ip(addr: SocketAddr, headers: &HeaderMap) -> IpAddr {
    extract_client_ip(addr.ip(), headers, trusted_proxies())
}

fn rate_limited(retry_after: u64) -> AppError {
    tracing::warn!(retry_after, "public request-form surface rate limited");
    let _ = retry_after;
    AppError::RateLimited
}

/// Render the form behind a link. Resolving is what validates the token, so a
/// used, expired or guessed link fails here with the same generic message a
/// malformed one gets.
async fn get_public_form(
    State(s): State<PublicFormsState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> AppResult<Json<PublicFormResponse>> {
    s.limiter
        .check(client_ip(addr, &headers))
        .map_err(rate_limited)?;
    let resolved = s.service.resolve_request_token(&token).await?;
    Ok(Json(s.service.public_form_for_token(&resolved).await?))
}

/// Submit the form behind a link: validate, store, create the ticket, burn the
/// link. Returns the ticket number so the client has something to quote.
async fn submit_public_form(
    State(s): State<PublicFormsState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(token): Path<String>,
    Json(body): Json<SubmitFormRequest>,
) -> AppResult<(StatusCode, Json<PublicSubmissionReceipt>)> {
    s.limiter
        .check(client_ip(addr, &headers))
        .map_err(rate_limited)?;
    let resolved = s.service.resolve_request_token(&token).await?;
    let receipt = s
        .service
        .submit_via_request_link(&resolved, &body.payload)
        .await?;
    Ok((StatusCode::CREATED, Json(receipt)))
}
