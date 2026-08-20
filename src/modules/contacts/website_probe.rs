//! PMS-805: resolve a company website on demand and report what answered.
//!
//! The product stores whatever the user typed. Nothing until now ever asked the
//! origin whether that value actually resolves, whether it answers on http or
//! https, or whether it redirects to a `www` host. This module makes the server
//! ask, because the browser cannot: CORS hides a cross-origin status code and
//! redirect chain from the SPA, and an https-served page may not issue an http
//! request at all.
//!
//! SSRF is the whole risk surface here: an authenticated user names a host and
//! the server connects to it. The mitigation is [`crate::utils::net::is_non_public_ip`]
//! applied to every resolved address BEFORE the connect, and again for every
//! redirect hop, plus a port allowlist of 80/443, a 5-hop cap, a 5s per-scheme
//! timeout, and never reading a response body. The residual is stated rather
//! than hidden: a DNS rebinding attack that changes the answer between the
//! check and the connect is not covered without an IP-pinned connector. What it
//! could yield even then is a status code and a final URL.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde::Serialize;
use url::Url;

use crate::utils::error::AppError;
use crate::utils::net::is_non_public_ip;

/// Redirect hops followed before the probe gives up.
const MAX_HOPS: usize = 5;

/// Wall-clock budget for one scheme's attempt, redirects included.
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);

/// How long a host's probe result is reused. A form that re-probes on every
/// blur must not re-hit the origin each time.
const CACHE_TTL: Duration = Duration::from_secs(15 * 60);

/// Ports the probe will ever connect on. Anything else is rejected at input
/// (400) or refused at a redirect hop (`blocked_host`).
const ALLOWED_PORTS: [u16; 2] = [80, 443];

// ============================================================================
// WIRE TYPES
// ============================================================================

/// Whether resolving the site added or removed a `www.` prefix on the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WwwChange {
    Added,
    Removed,
    None,
}

/// Machine-readable cause behind `reachable: false`. Deliberately coarse: it is
/// what a form can act on, not a diagnostic dump of the origin's failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnreachableReason {
    Dns,
    Timeout,
    Tls,
    Refused,
    BlockedHost,
}

/// The probe result as the client sees it. Both the reachable and the
/// unreachable case are 200s: determining that a site does not answer is a
/// successful probe, not a server error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WebsiteProbe {
    /// Echoed back verbatim so a client that fired several probes can match
    /// this response to the field the user typed in.
    pub input: String,
    pub reachable: bool,
    pub canonical_url: Option<String>,
    pub https_ok: bool,
    pub http_ok: bool,
    pub http_redirects_to_https: bool,
    pub www_change: WwwChange,
    pub final_status: Option<u16>,
    pub unreachable_reason: Option<UnreachableReason>,
}

// ============================================================================
// INTERNAL OUTCOMES
// ============================================================================

/// What one scheme's attempt produced. `Failed` always carries a reason, so a
/// failure can never reach `classify` as a bare `false` with no cause.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Reached { final_url: Url, status: u16 },
    Failed(UnreachableReason),
}

impl Outcome {
    /// Named `reached`, not `ok`: this is a state test on the outcome, not a
    /// `Result::ok` that would drop the failure. The failure is preserved by
    /// [`Outcome::reason`] and always reaches the response.
    fn reached(&self) -> bool {
        matches!(self, Outcome::Reached { .. })
    }

    fn reason(&self) -> Option<UnreachableReason> {
        match self {
            Outcome::Reached { .. } => None,
            Outcome::Failed(r) => Some(*r),
        }
    }
}

/// One response, no redirect following: the status and, when it is a redirect,
/// the raw `Location` value. The body is never touched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HopResponse {
    pub status: u16,
    pub location: Option<String>,
}

/// Why a single request failed, before it is folded into an
/// [`UnreachableReason`]. Kept separate so the fetcher never has to decide what
/// the client is told.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchError {
    Timeout,
    Tls,
    Refused,
    /// Anything else the transport reported; the message is logged, never
    /// returned, because it is the origin's text and not ours.
    Other(String),
}

impl FetchError {
    fn reason(&self) -> UnreachableReason {
        match self {
            FetchError::Timeout => UnreachableReason::Timeout,
            FetchError::Tls => UnreachableReason::Tls,
            FetchError::Refused | FetchError::Other(_) => UnreachableReason::Refused,
        }
    }
}

/// The network, injected. Splitting it out is what lets every classification
/// rule below be unit tested without an outbound request.
#[async_trait]
pub trait WebsiteFetcher: Send + Sync {
    /// Resolve a host to its addresses. The error is the DNS failure itself; it
    /// is logged by the caller before becoming `unreachable_reason: "dns"`.
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<IpAddr>, String>;

    /// Issue ONE request and return its status plus `Location`. Implementations
    /// must not follow redirects (the probe follows them itself so it can
    /// re-check every hop) and must not read the body.
    async fn head_or_get(&self, url: &Url) -> Result<HopResponse, FetchError>;
}

// ============================================================================
// INPUT PARSING
// ============================================================================

/// A validated probe target. Reaching this type means the input is a plain
/// http(s) URL on port 80 or 443 with no credentials and no control characters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeTarget {
    /// What the caller typed, echoed into the response.
    pub input: String,
    /// Lower-cased host, and the in-process cache key.
    pub host: String,
}

/// Parse and validate probe input. Anything that cannot be a website at all is
/// a 400 with a field message, never a silently "unreachable" 200: the two mean
/// different things to the form showing the result.
pub fn parse_target(input: &str) -> Result<ProbeTarget, AppError> {
    let raw = input.trim();
    if raw.is_empty() {
        return Err(AppError::BadRequest(
            "The url parameter is required.".into(),
        ));
    }
    if raw.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(AppError::BadRequest(
            "The url parameter must not contain spaces or control characters.".into(),
        ));
    }

    // Same rule as `de_website_opt`, so what the probe resolves is what a save
    // would store. A value the normalizer declines to touch still has to parse
    // as an http(s) URL below, which is where the rejection happens.
    let normalized = mokosh_types::contacts::normalize_website(raw)
        .ok_or_else(|| AppError::BadRequest("The url parameter is required.".into()))?;

    let url = Url::parse(&normalized).map_err(|e| {
        AppError::BadRequest(format!(
            "The url parameter is not a valid web address: {e}."
        ))
    })?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(AppError::BadRequest(
            "The url parameter must use http or https.".into(),
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(AppError::BadRequest(
            "The url parameter must not contain credentials.".into(),
        ));
    }
    // `Host`'s Display re-brackets an IPv6 literal, so the stored value can be
    // pasted straight back into a URL; `host_str` (used by the resolver) gives
    // the same value unbracketed.
    let host = url
        .host()
        .map(|h| h.to_string().to_ascii_lowercase())
        .filter(|h| !h.is_empty())
        .ok_or_else(|| AppError::BadRequest("The url parameter must contain a host.".into()))?;
    if let Some(port) = url.port() {
        if !ALLOWED_PORTS.contains(&port) {
            return Err(AppError::BadRequest(
                "The url parameter must use port 80 or 443.".into(),
            ));
        }
    }

    Ok(ProbeTarget {
        input: raw.to_string(),
        host,
    })
}

// ============================================================================
// CLASSIFICATION (pure)
// ============================================================================

/// Fold the two per-scheme outcomes into the response body. Pure: every rule
/// the client depends on is decided here and is unit tested without a socket.
pub fn classify(
    input: &str,
    requested_host: &str,
    https: &Outcome,
    http: &Outcome,
) -> WebsiteProbe {
    let https_ok = https.reached();
    let http_ok = http.reached();

    // https is canonical when it answers; http is the fallback, so a site that
    // only serves plaintext still reports a usable URL.
    let canonical = match (https, http) {
        (Outcome::Reached { final_url, status }, _) => Some((final_url.clone(), *status)),
        (_, Outcome::Reached { final_url, status }) => Some((final_url.clone(), *status)),
        _ => None,
    };

    let http_redirects_to_https = match http {
        Outcome::Reached { final_url, .. } => final_url.scheme() == "https",
        Outcome::Failed(_) => false,
    };

    let www_change = match canonical.as_ref() {
        // A reached URL always carries a host (it was built from a guarded one),
        // so the empty fallback is unreachable and would only report "no change".
        Some((final_url, _)) => {
            www_change(requested_host, final_url.host_str().unwrap_or_default())
        }
        None => WwwChange::None,
    };

    // An unreachable result always names a cause. https is asked first because
    // it is the scheme the product wants; http's cause only surfaces when https
    // produced none, which cannot happen today but keeps the field total.
    let unreachable_reason = if https_ok || http_ok {
        None
    } else {
        https.reason().or_else(|| http.reason())
    };

    WebsiteProbe {
        input: input.to_string(),
        reachable: https_ok || http_ok,
        canonical_url: canonical.as_ref().map(|(u, _)| u.to_string()),
        https_ok,
        http_ok,
        http_redirects_to_https,
        www_change,
        final_status: canonical.as_ref().map(|(_, s)| *s),
        unreachable_reason,
    }
}

/// Compare the host asked for against the host that answered, ignoring one
/// leading `www.` label.
fn www_change(requested: &str, final_host: &str) -> WwwChange {
    let requested_www = requested.starts_with("www.");
    let final_www = final_host.starts_with("www.");
    match (requested_www, final_www) {
        (false, true) => WwwChange::Added,
        (true, false) => WwwChange::Removed,
        _ => WwwChange::None,
    }
}

// ============================================================================
// PROBE
// ============================================================================

/// Run both scheme attempts against `target` and classify the pair.
pub async fn probe<F: WebsiteFetcher + ?Sized>(fetcher: &F, target: &ProbeTarget) -> WebsiteProbe {
    let https = timed_attempt(fetcher, &target.host, "https").await;
    let http = timed_attempt(fetcher, &target.host, "http").await;
    classify(&target.input, &target.host, &https, &http)
}

/// One scheme, hard-capped at [`ATTEMPT_TIMEOUT`] end to end. The client's
/// own timeout bounds a single request; this bounds the whole redirect chain,
/// so five slow hops cannot add up past the budget.
async fn timed_attempt<F: WebsiteFetcher + ?Sized>(
    fetcher: &F,
    host: &str,
    scheme: &str,
) -> Outcome {
    match tokio::time::timeout(ATTEMPT_TIMEOUT, attempt(fetcher, host, scheme)).await {
        Ok(outcome) => outcome,
        Err(_) => {
            tracing::warn!(
                host,
                scheme,
                timeout_secs = ATTEMPT_TIMEOUT.as_secs(),
                "website probe attempt exceeded its budget"
            );
            Outcome::Failed(UnreachableReason::Timeout)
        }
    }
}

/// One scheme's attempt: guard the host, request, follow up to [`MAX_HOPS`]
/// redirects, re-guarding each hop.
async fn attempt<F: WebsiteFetcher + ?Sized>(fetcher: &F, host: &str, scheme: &str) -> Outcome {
    let Ok(mut url) = Url::parse(&format!("{scheme}://{host}/")) else {
        tracing::warn!(host, scheme, "website probe could not build a start URL");
        return Outcome::Failed(UnreachableReason::Refused);
    };

    for hop in 0..=MAX_HOPS {
        if let Err(reason) = guard_url(fetcher, &url).await {
            return Outcome::Failed(reason);
        }

        let response = match fetcher.head_or_get(&url).await {
            Ok(r) => r,
            Err(e) => {
                // Logged with the underlying cause before it is flattened into
                // the coarse wire reason, so a probe failure is never a bare
                // `false` with no record of why.
                tracing::warn!(
                    host,
                    scheme,
                    hop,
                    url = %url,
                    error = ?e,
                    "website probe request failed"
                );
                return Outcome::Failed(e.reason());
            }
        };

        let redirect = (300..400).contains(&response.status);
        if !redirect {
            return Outcome::Reached {
                final_url: url,
                status: response.status,
            };
        }

        let Some(location) = response.location.as_deref() else {
            // A 3xx with no Location is where the chain ends; report the
            // redirect itself rather than inventing a failure.
            return Outcome::Reached {
                final_url: url,
                status: response.status,
            };
        };
        match url.join(location) {
            Ok(next) => url = next,
            Err(e) => {
                tracing::warn!(
                    host,
                    scheme,
                    hop,
                    location,
                    error = %e,
                    "website probe got an unusable redirect target"
                );
                return Outcome::Failed(UnreachableReason::Refused);
            }
        }
    }

    tracing::warn!(host, scheme, "website probe exceeded {MAX_HOPS} redirects");
    Outcome::Failed(UnreachableReason::Refused)
}

/// The SSRF gate, applied before the first connect and again for every hop:
/// http(s) only, port 80/443 only, and no resolved address that is off the
/// public internet.
async fn guard_url<F: WebsiteFetcher + ?Sized>(
    fetcher: &F,
    url: &Url,
) -> Result<(), UnreachableReason> {
    if !matches!(url.scheme(), "http" | "https") {
        tracing::warn!(url = %url, "website probe refused a non-http(s) hop");
        return Err(UnreachableReason::BlockedHost);
    }
    let port = url.port_or_known_default().unwrap_or(0);
    if !ALLOWED_PORTS.contains(&port) {
        tracing::warn!(url = %url, port, "website probe refused a hop on a disallowed port");
        return Err(UnreachableReason::BlockedHost);
    }
    let Some(host) = url.host_str().filter(|h| !h.is_empty()) else {
        tracing::warn!(url = %url, "website probe refused a hop with no host");
        return Err(UnreachableReason::BlockedHost);
    };

    let addresses = match fetcher.resolve(host, port).await {
        Ok(a) => a,
        Err(e) => {
            tracing::warn!(host, error = %e, "website probe could not resolve host");
            return Err(UnreachableReason::Dns);
        }
    };
    if addresses.is_empty() {
        tracing::warn!(host, "website probe resolved host to no addresses");
        return Err(UnreachableReason::Dns);
    }
    // ANY non-public answer blocks: a name resolving to both a public and a
    // private address is exactly the shape an SSRF attempt takes.
    if let Some(blocked) = addresses.iter().find(|ip| is_non_public_ip(ip)) {
        tracing::warn!(
            host,
            address = %blocked,
            "website probe refused a host resolving off the public internet"
        );
        return Err(UnreachableReason::BlockedHost);
    }
    Ok(())
}

// ============================================================================
// LIVE FETCHER
// ============================================================================

/// The real network. Mirrors `AutomationEngine::build`'s client construction:
/// an explicit timeout and a named user agent, so an origin operator can see
/// who is asking.
pub struct ReqwestFetcher {
    client: reqwest::Client,
}

impl ReqwestFetcher {
    pub fn new() -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder()
            .timeout(ATTEMPT_TIMEOUT)
            .user_agent("mokosh-server/website-probe")
            // The probe follows redirects itself so it can re-run the SSRF
            // guard on every hop; reqwest must not do it silently underneath.
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self { client })
    }
}

#[async_trait]
impl WebsiteFetcher for ReqwestFetcher {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<IpAddr>, String> {
        // A bracketed IPv6 literal reaches us with the brackets stripped by
        // `Url::host_str`, so it parses directly and needs no resolver.
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        let addresses = tokio::net::lookup_host((host, port))
            .await
            .map_err(|e| e.to_string())?;
        Ok(addresses.map(|a| a.ip()).collect())
    }

    async fn head_or_get(&self, url: &Url) -> Result<HopResponse, FetchError> {
        let head = self.send(reqwest::Method::HEAD, url).await?;
        // Some origins answer HEAD with "not allowed" and serve the same
        // resource on GET. Only then is a second request worth making.
        if matches!(head.status, 405 | 501) {
            return self.send(reqwest::Method::GET, url).await;
        }
        Ok(head)
    }
}

impl ReqwestFetcher {
    async fn send(&self, method: reqwest::Method, url: &Url) -> Result<HopResponse, FetchError> {
        let response = self
            .client
            .request(method, url.clone())
            .send()
            .await
            .map_err(classify_transport_error)?;
        let status = response.status().as_u16();
        let location = match response
            .headers()
            .get(reqwest::header::LOCATION)
            .map(|v| v.to_str())
        {
            Some(Ok(value)) => Some(value.to_string()),
            // A Location the transport cannot read as text is not silently a
            // "no redirect": say so, then let the caller end the chain here.
            Some(Err(e)) => {
                tracing::warn!(url = %url, error = %e, "website probe got an unreadable Location header");
                None
            }
            None => None,
        };
        // The body is never read: `response` is dropped here, which closes it.
        Ok(HopResponse { status, location })
    }
}

fn classify_transport_error(e: reqwest::Error) -> FetchError {
    if e.is_timeout() {
        FetchError::Timeout
    } else if e.is_connect() {
        // reqwest folds TLS handshake failures into connect errors, so the
        // message is the only signal that separates "bad certificate" from
        // "nothing listening". Both are actionable and distinct to the user.
        let text = format!("{e:?}").to_ascii_lowercase();
        if text.contains("tls") || text.contains("certificate") || text.contains("handshake") {
            FetchError::Tls
        } else {
            FetchError::Refused
        }
    } else {
        FetchError::Other(e.to_string())
    }
}

// ============================================================================
// SERVICE
// ============================================================================

/// Owns the client and the per-host result cache.
pub struct WebsiteProbeService {
    fetcher: Arc<dyn WebsiteFetcher>,
    cache: moka::future::Cache<String, WebsiteProbe>,
}

impl WebsiteProbeService {
    pub fn new(fetcher: Arc<dyn WebsiteFetcher>) -> Arc<Self> {
        Arc::new(Self {
            fetcher,
            cache: moka::future::Cache::builder()
                .max_capacity(10_000)
                .time_to_live(CACHE_TTL)
                .build(),
        })
    }

    /// The live service. A client that cannot be built is a configuration
    /// failure, not something to paper over with a "site unreachable".
    pub fn live() -> Result<Arc<Self>, AppError> {
        let fetcher = ReqwestFetcher::new().map_err(|e| {
            tracing::error!(error = %e, "could not build the website-probe HTTP client");
            AppError::Configuration(format!("website probe client: {e}"))
        })?;
        Ok(Self::new(Arc::new(fetcher)))
    }

    /// Probe `input`, serving a cached result for the same host when one is
    /// still fresh. The cache is keyed on the host, so the echoed `input` is
    /// re-stamped from this call rather than served from the earlier one.
    pub async fn probe_input(&self, input: &str) -> Result<WebsiteProbe, AppError> {
        let target = parse_target(input)?;
        if let Some(mut cached) = self.cache.get(&target.host).await {
            cached.input = target.input.clone();
            return Ok(cached);
        }
        let result = probe(self.fetcher.as_ref(), &target).await;
        self.cache.insert(target.host.clone(), result.clone()).await;
        Ok(result)
    }
}

// ============================================================================
// RATE LIMIT
// ============================================================================

type TenantLimiter = governor::RateLimiter<
    uuid::Uuid,
    governor::state::keyed::DefaultKeyedStateStore<uuid::Uuid>,
    governor::clock::DefaultClock,
>;

/// Per-tenant limiter, modelled on `RequestFormLimiter`.
///
/// The endpoint makes the server fetch a user-named host, so the cap is what
/// stops it being driven as a scanner. 30/minute is well above a form probing
/// on blur and well below anything useful for enumeration. In-memory only: it
/// does not survive a restart and does not coordinate across replicas, which is
/// acceptable because the endpoint is authenticated and the SSRF guard, not the
/// limiter, is what bounds where it can connect.
pub struct WebsiteProbeLimiter {
    by_tenant: TenantLimiter,
    clock: governor::clock::DefaultClock,
}

impl WebsiteProbeLimiter {
    pub fn new() -> Arc<Self> {
        let quota = governor::Quota::per_minute(
            std::num::NonZeroU32::new(30).expect("30 probes per minute is non-zero"),
        );
        Arc::new(Self {
            by_tenant: governor::RateLimiter::keyed(quota),
            clock: governor::clock::DefaultClock::default(),
        })
    }

    /// `Ok(())` when the caller may proceed, `Err(retry_after_seconds)` when
    /// they are over quota.
    pub fn check(&self, tenant: uuid::Uuid) -> Result<(), u64> {
        use governor::clock::Clock;
        match self.by_tenant.check_key(&tenant) {
            Ok(()) => Ok(()),
            Err(not_until) => Err(not_until.wait_time_from(self.clock.now()).as_secs().max(1)),
        }
    }
}

impl Default for WebsiteProbeLimiter {
    fn default() -> Self {
        // `new` returns the Arc callers actually want; this exists only to
        // satisfy the lint that pairs `new()` with `Default`.
        Arc::try_unwrap(Self::new()).unwrap_or_else(|_| unreachable!("freshly created Arc"))
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    fn url(s: &str) -> Url {
        Url::parse(s).expect("test URL parses")
    }

    fn reached(u: &str, status: u16) -> Outcome {
        Outcome::Reached {
            final_url: url(u),
            status,
        }
    }

    // ---- classify ----

    #[test]
    fn classify_reports_www_added() {
        let p = classify(
            "DentalArtsPractice.com",
            "dentalartspractice.com",
            &reached("https://www.dentalartspractice.com/", 200),
            &reached("https://www.dentalartspractice.com/", 200),
        );
        assert_eq!(p.www_change, WwwChange::Added);
        assert!(p.reachable);
        assert!(p.https_ok && p.http_ok);
        assert!(p.http_redirects_to_https);
        assert_eq!(
            p.canonical_url.as_deref(),
            Some("https://www.dentalartspractice.com/")
        );
        assert_eq!(p.final_status, Some(200));
        assert_eq!(p.unreachable_reason, None);
        assert_eq!(p.input, "DentalArtsPractice.com");
    }

    #[test]
    fn classify_reports_www_removed() {
        let p = classify(
            "www.example.com",
            "www.example.com",
            &reached("https://example.com/", 200),
            &Outcome::Failed(UnreachableReason::Refused),
        );
        assert_eq!(p.www_change, WwwChange::Removed);
        assert!(p.https_ok && !p.http_ok);
    }

    #[test]
    fn classify_reports_no_www_change() {
        for (requested, final_url) in [
            ("example.com", "https://example.com/"),
            ("www.example.com", "https://www.example.com/"),
        ] {
            let p = classify(
                requested,
                requested,
                &reached(final_url, 200),
                &reached(final_url, 200),
            );
            assert_eq!(p.www_change, WwwChange::None, "{requested} -> {final_url}");
        }
    }

    #[test]
    fn classify_detects_http_redirecting_to_https() {
        let plain = classify(
            "example.com",
            "example.com",
            &reached("https://example.com/", 200),
            &reached("http://example.com/", 200),
        );
        assert!(!plain.http_redirects_to_https);

        let upgraded = classify(
            "example.com",
            "example.com",
            &reached("https://example.com/", 200),
            &reached("https://example.com/", 200),
        );
        assert!(upgraded.http_redirects_to_https);
    }

    #[test]
    fn classify_falls_back_to_http_when_https_fails() {
        let p = classify(
            "example.com",
            "example.com",
            &Outcome::Failed(UnreachableReason::Tls),
            &reached("http://example.com/home", 301),
        );
        assert!(p.reachable);
        assert!(!p.https_ok);
        assert!(p.http_ok);
        assert_eq!(p.canonical_url.as_deref(), Some("http://example.com/home"));
        assert_eq!(p.final_status, Some(301));
        assert_eq!(p.unreachable_reason, None);
    }

    #[test]
    fn classify_reports_both_schemes_failing() {
        let p = classify(
            "example.com",
            "example.com",
            &Outcome::Failed(UnreachableReason::Dns),
            &Outcome::Failed(UnreachableReason::Dns),
        );
        assert!(!p.reachable);
        assert!(!p.https_ok && !p.http_ok);
        assert!(!p.http_redirects_to_https);
        assert_eq!(p.canonical_url, None);
        assert_eq!(p.final_status, None);
        assert_eq!(p.www_change, WwwChange::None);
        assert_eq!(p.unreachable_reason, Some(UnreachableReason::Dns));
    }

    #[test]
    fn probe_body_serializes_with_the_documented_field_names() {
        let p = classify(
            "DentalArtsPractice.com",
            "dentalartspractice.com",
            &reached("https://www.dentalartspractice.com/", 200),
            &reached("https://www.dentalartspractice.com/", 200),
        );
        let json = serde_json::to_value(&p).expect("probe serializes");
        assert_eq!(json["www_change"], "added");
        assert_eq!(json["reachable"], true);
        assert_eq!(json["unreachable_reason"], serde_json::Value::Null);

        let blocked = classify(
            "127.0.0.1",
            "127.0.0.1",
            &Outcome::Failed(UnreachableReason::BlockedHost),
            &Outcome::Failed(UnreachableReason::BlockedHost),
        );
        let json = serde_json::to_value(&blocked).expect("probe serializes");
        assert_eq!(json["unreachable_reason"], "blocked_host");
    }

    // ---- parse_target ----

    #[test]
    fn parse_target_normalizes_a_bare_host() {
        let t = parse_target(" DentalArtsPractice.com ").expect("bare host is accepted");
        assert_eq!(t.host, "dentalartspractice.com");
        assert_eq!(t.input, "DentalArtsPractice.com");
    }

    #[test]
    fn parse_target_rejects_input_that_cannot_be_a_website() {
        for bad in [
            "",
            "   ",
            "exa mple.com",
            "example\u{7}.com",
            "javascript:alert(1)",
            "data:text/html,<script>",
            "ftp://example.com",
            "http://user:pass@example.com",
            "https://example.com:8080",
            "http://",
        ] {
            assert!(
                parse_target(bad).is_err(),
                "{bad:?} should be a 400, not a probe"
            );
        }
    }

    #[test]
    fn parse_target_accepts_the_allowed_ports() {
        for good in ["http://example.com:80", "https://example.com:443"] {
            assert!(parse_target(good).is_ok(), "{good} should be accepted");
        }
    }

    // ---- probe, over a scripted fetcher (no network) ----

    /// Scripted network: every resolution and every response is declared by the
    /// test, so nothing here opens a socket.
    struct FakeFetcher {
        addresses: HashMap<String, Result<Vec<IpAddr>, String>>,
        responses: HashMap<String, Result<HopResponse, FetchError>>,
        requested: Mutex<Vec<String>>,
    }

    impl FakeFetcher {
        fn new() -> Self {
            Self {
                addresses: HashMap::new(),
                responses: HashMap::new(),
                requested: Mutex::new(Vec::new()),
            }
        }

        fn resolving(mut self, host: &str, ip: &str) -> Self {
            self.addresses.insert(
                host.to_string(),
                Ok(vec![ip.parse().expect("test IP parses")]),
            );
            self
        }

        fn answering(mut self, url: &str, status: u16, location: Option<&str>) -> Self {
            self.responses.insert(
                url.to_string(),
                Ok(HopResponse {
                    status,
                    location: location.map(str::to_string),
                }),
            );
            self
        }

        fn failing(mut self, url: &str, error: FetchError) -> Self {
            self.responses.insert(url.to_string(), Err(error));
            self
        }

        fn requested(&self) -> Vec<String> {
            self.requested.lock().expect("lock is not poisoned").clone()
        }
    }

    #[async_trait]
    impl WebsiteFetcher for FakeFetcher {
        async fn resolve(&self, host: &str, _port: u16) -> Result<Vec<IpAddr>, String> {
            self.addresses
                .get(host)
                .cloned()
                .unwrap_or_else(|| Err(format!("no scripted answer for {host}")))
        }

        async fn head_or_get(&self, url: &Url) -> Result<HopResponse, FetchError> {
            self.requested
                .lock()
                .expect("lock is not poisoned")
                .push(url.to_string());
            self.responses
                .get(url.as_str())
                .cloned()
                .unwrap_or(Err(FetchError::Refused))
        }
    }

    fn target(host: &str) -> ProbeTarget {
        parse_target(host).expect("test target parses")
    }

    #[tokio::test]
    async fn probe_follows_a_redirect_to_www_and_reports_it() {
        let fetcher = FakeFetcher::new()
            .resolving("example.com", "93.184.216.34")
            .resolving("www.example.com", "93.184.216.34")
            .answering(
                "https://example.com/",
                301,
                Some("https://www.example.com/"),
            )
            .answering("https://www.example.com/", 200, None)
            .answering("http://example.com/", 301, Some("https://www.example.com/"))
            .answering("http://www.example.com/", 200, None);

        let p = probe(&fetcher, &target("example.com")).await;
        assert!(p.reachable);
        assert_eq!(p.www_change, WwwChange::Added);
        assert!(p.http_redirects_to_https);
        assert_eq!(p.canonical_url.as_deref(), Some("https://www.example.com/"));
        assert_eq!(p.final_status, Some(200));
    }

    #[tokio::test]
    async fn probe_refuses_a_host_on_the_private_network() {
        let fetcher = FakeFetcher::new()
            .resolving("internal.example.com", "10.1.2.3")
            .answering("https://internal.example.com/", 200, None);

        let p = probe(&fetcher, &target("internal.example.com")).await;
        assert!(!p.reachable);
        assert_eq!(p.unreachable_reason, Some(UnreachableReason::BlockedHost));
        // The guard runs BEFORE the connect, so no request was ever issued.
        assert!(fetcher.requested().is_empty());
    }

    #[tokio::test]
    async fn probe_refuses_a_redirect_into_the_private_network() {
        let fetcher = FakeFetcher::new()
            .resolving("example.com", "93.184.216.34")
            .resolving("internal.example.com", "127.0.0.1")
            .answering(
                "https://example.com/",
                302,
                Some("https://internal.example.com/"),
            )
            .answering(
                "http://example.com/",
                302,
                Some("https://internal.example.com/"),
            );

        let p = probe(&fetcher, &target("example.com")).await;
        assert!(!p.reachable);
        assert_eq!(p.unreachable_reason, Some(UnreachableReason::BlockedHost));
        // The first hop was fetched; the private second hop never was.
        assert!(!fetcher
            .requested()
            .iter()
            .any(|u| u.contains("internal.example.com")));
    }

    #[tokio::test]
    async fn probe_refuses_a_redirect_to_a_disallowed_port() {
        let fetcher = FakeFetcher::new()
            .resolving("example.com", "93.184.216.34")
            .answering(
                "https://example.com/",
                302,
                Some("https://example.com:8443/"),
            )
            .answering(
                "http://example.com/",
                302,
                Some("https://example.com:8443/"),
            );

        let p = probe(&fetcher, &target("example.com")).await;
        assert_eq!(p.unreachable_reason, Some(UnreachableReason::BlockedHost));
        assert!(!fetcher.requested().iter().any(|u| u.contains("8443")));
    }

    #[tokio::test]
    async fn probe_stops_after_five_redirect_hops() {
        let mut fetcher = FakeFetcher::new().resolving("example.com", "93.184.216.34");
        for scheme in ["https", "http"] {
            fetcher = fetcher.answering(
                &format!("{scheme}://example.com/"),
                302,
                Some(&format!("{scheme}://example.com/1")),
            );
            for hop in 1..20 {
                fetcher = fetcher.answering(
                    &format!("{scheme}://example.com/{hop}"),
                    302,
                    Some(&format!("{scheme}://example.com/{}", hop + 1)),
                );
            }
        }

        let p = probe(&fetcher, &target("example.com")).await;
        assert!(!p.reachable);
        // MAX_HOPS redirects followed means MAX_HOPS + 1 requests per scheme.
        let https_requests = fetcher
            .requested()
            .iter()
            .filter(|u| u.starts_with("https://"))
            .count();
        assert_eq!(https_requests, MAX_HOPS + 1);
    }

    #[tokio::test]
    async fn probe_reports_dns_failure() {
        let fetcher = FakeFetcher::new();
        let p = probe(&fetcher, &target("nx.example.com")).await;
        assert!(!p.reachable);
        assert_eq!(p.unreachable_reason, Some(UnreachableReason::Dns));
    }

    #[tokio::test]
    async fn probe_reports_a_tls_failure_with_http_still_answering() {
        let fetcher = FakeFetcher::new()
            .resolving("example.com", "93.184.216.34")
            .failing("https://example.com/", FetchError::Tls)
            .answering("http://example.com/", 200, None);

        let p = probe(&fetcher, &target("example.com")).await;
        assert!(p.reachable);
        assert!(!p.https_ok);
        assert!(p.http_ok);
        assert!(!p.http_redirects_to_https);
        assert_eq!(p.canonical_url.as_deref(), Some("http://example.com/"));
    }

    #[tokio::test]
    async fn probe_reports_a_timeout_on_both_schemes() {
        let fetcher = FakeFetcher::new()
            .resolving("example.com", "93.184.216.34")
            .failing("https://example.com/", FetchError::Timeout)
            .failing("http://example.com/", FetchError::Timeout);

        let p = probe(&fetcher, &target("example.com")).await;
        assert_eq!(p.unreachable_reason, Some(UnreachableReason::Timeout));
    }

    #[tokio::test]
    async fn service_caches_by_host_and_restamps_the_echoed_input() {
        let fetcher = Arc::new(
            FakeFetcher::new()
                .resolving("example.com", "93.184.216.34")
                .answering("https://example.com/", 200, None)
                .answering("http://example.com/", 200, None),
        );
        let service = WebsiteProbeService::new(fetcher.clone());

        let first = service.probe_input("Example.com").await.expect("probes");
        let count = fetcher.requested().len();
        let second = service.probe_input("EXAMPLE.com").await.expect("probes");

        assert_eq!(fetcher.requested().len(), count, "second probe hit the net");
        assert_eq!(first.canonical_url, second.canonical_url);
        assert_eq!(second.input, "EXAMPLE.com", "echoed input came from cache");
    }
}
