//! PMS-998: OIDC Back-Channel Logout receiver.
//!
//! mokosh-server is a Resource Server on the bunyip-as-OP path: it verifies
//! `at+jwt` bearers against bunyip's JWKS and holds no session state of its
//! own there. Verification is stateless by design, so a token stays
//! acceptable until its `exp` - 600 seconds for the mokosh-apps client - and
//! a session the user ended at the OP kept working against the API for the
//! remainder of that window. This closes it the standard way: the OP notifies
//! the RP's back end, and the RP refuses the session's tokens from then on.
//!
//! The browser-side relying party is the mokosh-apps SPA, which has no back
//! end of its own, so this server receives the notification on its behalf.
//! That is the ordinary arrangement for an SPA plus Resource Server pair.
//!
//! Route: `POST /api/v1/bunyip/oauth2/backchannel-logout`, form-encoded
//! `logout_token`, mounted in the same nest as the HMAC webhooks and outside
//! the auth chain. What authenticates it is the token's own signature over
//! the OP's key, which is why it needs no shared secret of its own.
//!
//! Three things are worth knowing before changing this.
//!
//! **The audience is the CLIENT id, not `OIDC_AUDIENCE`.** Bunyip mints a
//! logout token with `aud = client_id` (`mint_logout_token`), while the
//! access token carries `aud = client.audience`, which is what `OIDC_AUDIENCE`
//! is set to. Asserting the configured audience here would reject every
//! genuine token, so the expected audience is its own key,
//! `OIDC_BACKCHANNEL_CLIENT_ID`. With it unset this receiver refuses
//! everything: it cannot tell a token addressed to this deployment from one
//! addressed to another client of the same OP, and accepting either would let
//! any RP's logout end sessions here.
//!
//! **There is no `exp`.** The spec does not give a logout token one and
//! bunyip does not mint one, so freshness is an `iat` window instead. Without
//! it, a logout token captured once would revoke its session forever, on
//! every replay, including after the user signed back in.
//!
//! **The revoked set is in memory and bounded.** It only has to cover the
//! residual life of tokens minted before the logout, so entries expire after
//! the maximum access-token lifetime. A restart empties it, which is correct
//! rather than a gap: every in-flight token was minted against a process that
//! is gone, and nothing about them survives either.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
use std::sync::Arc;

use axum::{
    extract::{ConnectInfo, Form, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Duration, Utc};
use governor::clock::{Clock, DefaultClock};
use governor::state::keyed::DefaultKeyedStateStore;
use governor::{Quota, RateLimiter};
use serde::Deserialize;
use tokio::sync::RwLock;

use super::oidc_rs::{LogoutClaims, Verifier};
use crate::utils::client_ip::{extract_client_ip, trusted_proxies};
use crate::utils::error::rate_limited_response;

/// The event URI a back-channel logout token must carry, spec section 2.4.
pub const BACKCHANNEL_LOGOUT_EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";

/// How long a revoked `sid` is remembered. Nothing minted before the logout
/// can outlive the access token's own lifetime, so remembering it for longer
/// only grows the map; remembering it for less would let a token minted just
/// before the logout slip through at the end of the window. Bunyip's
/// mokosh-apps client mints 600-second access tokens; this is that with room
/// for clock skew between the two hosts.
const REVOKED_TTL_SECS: i64 = 900;

/// Hard cap on the set. A bounded map cannot be turned into a memory sink by
/// an OP that ends a great many sessions at once, and the eviction it forces
/// is the oldest entry, which is the one closest to expiring anyway.
const MAX_REVOKED: usize = 50_000;

/// How far out of date an `iat` may be. Generous relative to the delivery
/// itself (bunyip posts immediately) because the two hosts' clocks are the
/// thing being compared, not the network.
const MAX_IAT_AGE_SECS: i64 = 300;

/// Sessions the OP has ended, with the instant each stops mattering.
///
/// Cheap to clone; the map is shared. Reads take the lock for the length of
/// one `HashMap::get`, on the authenticated-request path, so the map stays a
/// plain `HashMap` behind an `RwLock` rather than anything cleverer: it is
/// empty in the overwhelmingly common case.
#[derive(Clone, Default)]
pub struct RevokedSessions {
    inner: Arc<RwLock<HashMap<String, DateTime<Utc>>>>,
}

impl RevokedSessions {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `sid` as ended. Idempotent: a replayed logout token refreshes
    /// the expiry and changes nothing else.
    pub async fn revoke(&self, sid: &str, now: DateTime<Utc>) {
        let mut map = self.inner.write().await;
        map.retain(|_, expires| *expires > now);
        if map.len() >= MAX_REVOKED && !map.contains_key(sid) {
            // Evict the entry closest to expiring. Doing nothing instead
            // would silently stop recording logouts once the cap is reached,
            // which is the failure mode this whole module exists to prevent.
            if let Some(oldest) = map
                .iter()
                .min_by_key(|(_, expires)| **expires)
                .map(|(k, _)| k.clone())
            {
                map.remove(&oldest);
            }
        }
        map.insert(sid.to_string(), now + Duration::seconds(REVOKED_TTL_SECS));
    }

    /// Whether a token carrying this `sid` must be refused. An entry past its
    /// expiry answers `false` and is left for the next `revoke` to sweep,
    /// because the read path holds only a read lock.
    pub async fn is_revoked(&self, sid: &str, now: DateTime<Utc>) -> bool {
        let map = self.inner.read().await;
        map.get(sid).is_some_and(|expires| *expires > now)
    }

    #[cfg(test)]
    async fn len(&self) -> usize {
        self.inner.read().await.len()
    }
}

/// Why a logout token was refused. Each variant is one validation step of
/// spec section 2.6, so a test can name the step it covers.
#[derive(Debug, PartialEq, Eq)]
pub enum LogoutRejection {
    /// `iss` is not the configured issuer.
    Issuer,
    /// `aud` is not the configured client id.
    Audience,
    /// The `events` claim does not carry the back-channel logout URI.
    Event,
    /// No `sid`, so the token names no session to end.
    NoSession,
    /// A `nonce` is present, which means an ID token is being replayed here.
    NoncePresent,
    /// `iat` is too old or too far in the future.
    Stale,
    /// The deployment has no configured client id, so no audience can match.
    NotConfigured,
}

impl LogoutRejection {
    /// One line for the operator, logged at `error`. A receiver that discards
    /// what it could not verify is indistinguishable from one that was never
    /// called, so every refusal says which step failed.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Issuer => "iss does not match the configured OIDC_ISSUER",
            Self::Audience => "aud does not match OIDC_BACKCHANNEL_CLIENT_ID",
            Self::Event => "events does not carry the back-channel logout event",
            Self::NoSession => "no sid claim, so the token names no session",
            Self::NoncePresent => "a nonce is present, which a logout token must not carry",
            Self::Stale => "iat is outside the accepted freshness window",
            Self::NotConfigured => {
                "OIDC_BACKCHANNEL_CLIENT_ID is unset, so no audience can be accepted"
            }
        }
    }
}

/// Spec section 2.6 over already-verified claims: everything that does not
/// need the signing key. Pure, so each rejection is testable without a JWKS.
///
/// Returns the `sid` to revoke.
pub fn validate_logout_claims<'a>(
    claims: &'a LogoutClaims,
    issuer: &str,
    client_id: Option<&str>,
    now: DateTime<Utc>,
) -> Result<&'a str, LogoutRejection> {
    if claims.iss != issuer {
        return Err(LogoutRejection::Issuer);
    }
    let Some(client_id) = client_id.map(str::trim).filter(|c| !c.is_empty()) else {
        return Err(LogoutRejection::NotConfigured);
    };
    if claims.aud != client_id {
        return Err(LogoutRejection::Audience);
    }
    // The event set is an object whose KEY is the event URI; its value is an
    // empty object by the spec, so only the key is asserted.
    let has_event = claims
        .events
        .as_object()
        .is_some_and(|events| events.contains_key(BACKCHANNEL_LOGOUT_EVENT));
    if !has_event {
        return Err(LogoutRejection::Event);
    }
    if claims.nonce.is_some() {
        return Err(LogoutRejection::NoncePresent);
    }
    let age = now.timestamp() - claims.iat;
    if !(-MAX_IAT_AGE_SECS..=MAX_IAT_AGE_SECS).contains(&age) {
        return Err(LogoutRejection::Stale);
    }
    let sid = claims
        .sid
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or(LogoutRejection::NoSession)?;
    Ok(sid)
}

type IpLimiter = RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, DefaultClock>;

/// Per-IP limiter, the `RequestFormLimiter` shape. This endpoint is
/// unauthenticated in the session sense and every call costs a signature
/// verification, so the limiter is what stops an anonymous caller spending
/// this server's CPU on junk tokens. Loose enough that a real OP fanning out
/// several sessions at once is never throttled.
pub struct BackchannelLogoutLimiter {
    by_ip: IpLimiter,
    clock: DefaultClock,
}

impl BackchannelLogoutLimiter {
    pub fn new() -> Arc<Self> {
        let quota = Quota::per_minute(NonZeroU32::new(60).expect("60 is non-zero"));
        Arc::new(Self {
            by_ip: RateLimiter::keyed(quota),
            clock: DefaultClock::default(),
        })
    }

    pub fn check(&self, ip: IpAddr) -> Result<(), u64> {
        match self.by_ip.check_key(&ip) {
            Ok(()) => Ok(()),
            Err(not_until) => Err(not_until.wait_time_from(self.clock.now()).as_secs().max(1)),
        }
    }
}

impl Default for BackchannelLogoutLimiter {
    fn default() -> Self {
        let quota = Quota::per_minute(NonZeroU32::new(60).expect("60 is non-zero"));
        Self {
            by_ip: RateLimiter::keyed(quota),
            clock: DefaultClock::default(),
        }
    }
}

/// What the receiver needs: the verifier that already holds the OP's JWKS,
/// the set it records into, the client id it accepts tokens for, and the
/// limiter.
#[derive(Clone)]
pub struct BackchannelLogoutState {
    pub verifier: Verifier,
    pub revoked: RevokedSessions,
    pub client_id: Option<String>,
    pub limiter: Arc<BackchannelLogoutLimiter>,
}

#[derive(Debug, Deserialize)]
pub struct LogoutTokenForm {
    pub logout_token: String,
}

/// `POST /api/v1/bunyip/oauth2/backchannel-logout`.
///
/// 200 when the session is now revoked, including on a replay. 400 for
/// anything that did not verify, with the cause logged at `error`: the OP
/// treats a non-2xx as a delivery failure and this server must not answer 200
/// to something it did not act on.
pub async fn backchannel_logout(
    State(state): State<Arc<BackchannelLogoutState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(form): Form<LogoutTokenForm>,
) -> Response {
    let ip = extract_client_ip(addr.ip(), &headers, trusted_proxies());
    if let Err(retry_after) = state.limiter.check(ip) {
        return rate_limited_response(retry_after, "Too many logout notifications");
    }

    let claims = match state.verifier.verify_logout_token(&form.logout_token).await {
        Ok(claims) => claims,
        Err(e) => {
            tracing::error!(error = %e, "back-channel logout token did not verify");
            return (StatusCode::BAD_REQUEST, "invalid logout token").into_response();
        }
    };

    let now = Utc::now();
    let sid = match validate_logout_claims(
        &claims,
        &state.verifier.config.issuer,
        state.client_id.as_deref(),
        now,
    ) {
        Ok(sid) => sid,
        Err(rejection) => {
            tracing::error!(
                reason = rejection.reason(),
                jti = ?claims.jti,
                "back-channel logout token refused"
            );
            return (StatusCode::BAD_REQUEST, "invalid logout token").into_response();
        }
    };

    state.revoked.revoke(sid, now).await;
    tracing::info!(
        sub = ?claims.sub,
        jti = ?claims.jti,
        "back-channel logout accepted; session refused until its tokens expire"
    );
    StatusCode::OK.into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ISSUER: &str = "https://bunyip.example";
    const CLIENT: &str = "11111111-2222-3333-4444-555555555555";

    fn claims() -> LogoutClaims {
        serde_json::from_value(serde_json::json!({
            "iss": ISSUER,
            "aud": CLIENT,
            "iat": Utc::now().timestamp(),
            "jti": "01234567-89ab-cdef-0123-456789abcdef",
            "sub": "99999999-8888-7777-6666-555555555555",
            "sid": "session-abc",
            "events": { BACKCHANNEL_LOGOUT_EVENT: {} },
        }))
        .expect("claims fixture")
    }

    fn validate(c: &LogoutClaims) -> Result<&str, LogoutRejection> {
        validate_logout_claims(c, ISSUER, Some(CLIENT), Utc::now())
    }

    #[test]
    fn a_well_formed_token_names_its_session() {
        assert_eq!(validate(&claims()), Ok("session-abc"));
    }

    /// One rejection per validation step, which is what the issue asks for.
    #[test]
    fn each_validation_step_has_its_own_refusal() {
        let mut c = claims();
        c.iss = "https://elsewhere.example".to_string();
        assert_eq!(validate(&c), Err(LogoutRejection::Issuer));

        // The audience is the CLIENT id. A token addressed to the RESOURCE
        // audience is exactly the mistake the issue's own plan would have
        // made, so it is pinned here.
        let mut c = claims();
        c.aud = "https://mokosh-api.example".to_string();
        assert_eq!(validate(&c), Err(LogoutRejection::Audience));

        let mut c = claims();
        c.events = serde_json::json!({ "http://schemas.openid.net/event/something-else": {} });
        assert_eq!(validate(&c), Err(LogoutRejection::Event));

        let mut c = claims();
        c.events = serde_json::Value::Null;
        assert_eq!(validate(&c), Err(LogoutRejection::Event));

        let mut c = claims();
        c.nonce = Some("n-0S6_WzA2Mj".to_string());
        assert_eq!(validate(&c), Err(LogoutRejection::NoncePresent));

        let mut c = claims();
        c.sid = None;
        assert_eq!(validate(&c), Err(LogoutRejection::NoSession));
        c.sid = Some("   ".to_string());
        assert_eq!(validate(&c), Err(LogoutRejection::NoSession));

        // Both directions of the freshness window: a captured token replayed
        // tomorrow, and one minted by a host whose clock runs fast.
        let mut c = claims();
        c.iat = Utc::now().timestamp() - (MAX_IAT_AGE_SECS + 60);
        assert_eq!(validate(&c), Err(LogoutRejection::Stale));
        c.iat = Utc::now().timestamp() + (MAX_IAT_AGE_SECS + 60);
        assert_eq!(validate(&c), Err(LogoutRejection::Stale));
    }

    /// With no client id configured nothing is accepted, because there is no
    /// audience to compare against and accepting any would let another
    /// client's logout end sessions here.
    #[test]
    fn an_unconfigured_deployment_accepts_nothing() {
        let c = claims();
        assert_eq!(
            validate_logout_claims(&c, ISSUER, None, Utc::now()),
            Err(LogoutRejection::NotConfigured)
        );
        assert_eq!(
            validate_logout_claims(&c, ISSUER, Some("  "), Utc::now()),
            Err(LogoutRejection::NotConfigured)
        );
    }

    #[tokio::test]
    async fn a_revoked_session_is_refused_until_it_expires() {
        let revoked = RevokedSessions::new();
        let now = Utc::now();
        assert!(!revoked.is_revoked("s1", now).await);

        revoked.revoke("s1", now).await;
        assert!(revoked.is_revoked("s1", now).await);
        assert!(
            !revoked.is_revoked("s2", now).await,
            "only the named session"
        );

        // Past the window the entry stops mattering, because no token minted
        // before the logout can still be valid.
        let later = now + Duration::seconds(REVOKED_TTL_SECS + 1);
        assert!(!revoked.is_revoked("s1", later).await);
    }

    #[tokio::test]
    async fn a_replay_is_idempotent_and_expired_entries_are_swept() {
        let revoked = RevokedSessions::new();
        let now = Utc::now();
        revoked.revoke("s1", now).await;
        revoked.revoke("s1", now).await;
        assert_eq!(revoked.len().await, 1, "a replay records one session");

        // A later revoke sweeps what has expired rather than growing forever.
        let later = now + Duration::seconds(REVOKED_TTL_SECS + 1);
        revoked.revoke("s2", later).await;
        assert_eq!(revoked.len().await, 1);
        assert!(revoked.is_revoked("s2", later).await);
    }
}
