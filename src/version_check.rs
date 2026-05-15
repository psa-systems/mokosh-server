//! Operator-facing update check.
//!
//! Queries a configurable release-info URL (Forgejo / GitHub style, must
//! return JSON with a `tag_name` field) and reports whether the latest
//! published tag is newer than the running version. The endpoint is
//! strictly informational - applying an update is a deliberate operator
//! action (`docker compose pull && docker compose up --detach`).

use std::sync::Arc;
use std::time::Duration;

use moka::future::Cache;
use serde::{Deserialize, Serialize};
use tracing::warn;

const CACHE_TTL: Duration = Duration::from_secs(600);
const HTTP_TIMEOUT: Duration = Duration::from_secs(5);
const CACHE_KEY: &str = "latest";

/// JSON returned by `GET /api/v1/version/check`.
#[derive(Debug, Clone, Serialize)]
pub struct VersionCheckResponse {
    /// True when `UPDATE_CHECK_URL` is set and the endpoint will attempt
    /// a remote lookup. False means update checking is disabled.
    pub enabled: bool,
    /// `CARGO_PKG_VERSION` of the running binary.
    pub running: String,
    /// Latest published release tag (`tag_name` from the feed). `None`
    /// when checking is disabled or the lookup failed.
    pub latest: Option<String>,
    /// True when the latest tag is strictly greater than the running
    /// version. `None` when checking is disabled or the lookup failed.
    pub update_available: Option<bool>,
    /// The URL the latest tag came from. Useful when the operator wants
    /// to confirm which release feed is being polled.
    pub source_url: Option<String>,
    /// Error string when the remote lookup failed. `None` on success or
    /// when checking is disabled.
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ReleaseFeed {
    tag_name: String,
}

/// Update-check service. Cheap to clone; the inner HTTP client and
/// cache are shared via `Arc`. `from_env` returns a disabled instance
/// when `UPDATE_CHECK_URL` is unset.
#[derive(Clone)]
pub struct VersionChecker {
    inner: Option<Arc<Inner>>,
}

struct Inner {
    url: String,
    http: reqwest::Client,
    cache: Cache<&'static str, String>,
}

impl VersionChecker {
    pub fn from_env() -> Self {
        let url = std::env::var("UPDATE_CHECK_URL")
            .ok()
            .filter(|s| !s.is_empty());
        let Some(url) = url else {
            return Self { inner: None };
        };
        let http = reqwest::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .user_agent(concat!("mokosh-server/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("build update-check HTTP client");
        let cache = Cache::builder()
            .time_to_live(CACHE_TTL)
            .max_capacity(4)
            .build();
        Self {
            inner: Some(Arc::new(Inner { url, http, cache })),
        }
    }

    pub async fn check(&self) -> VersionCheckResponse {
        let running = env!("CARGO_PKG_VERSION").to_string();
        let Some(inner) = &self.inner else {
            return VersionCheckResponse {
                enabled: false,
                running,
                latest: None,
                update_available: None,
                source_url: None,
                error: None,
            };
        };

        match inner.fetch_latest().await {
            Ok(latest) => {
                let update_available = is_newer(&running, &latest);
                VersionCheckResponse {
                    enabled: true,
                    running,
                    latest: Some(latest),
                    update_available: Some(update_available),
                    source_url: Some(inner.url.clone()),
                    error: None,
                }
            }
            Err(e) => {
                warn!("update check failed: {e}");
                VersionCheckResponse {
                    enabled: true,
                    running,
                    latest: None,
                    update_available: None,
                    source_url: Some(inner.url.clone()),
                    error: Some(e.to_string()),
                }
            }
        }
    }
}

impl Inner {
    async fn fetch_latest(&self) -> Result<String, anyhow::Error> {
        if let Some(v) = self.cache.get(CACHE_KEY).await {
            return Ok(v);
        }
        let feed: ReleaseFeed = self
            .http
            .get(&self.url)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        self.cache.insert(CACHE_KEY, feed.tag_name.clone()).await;
        Ok(feed.tag_name)
    }
}

/// Strip a leading `v` and compare X.Y.Z numeric components. Returns
/// true when `latest` is strictly greater than `running`. Falls back to
/// raw string inequality if either side fails to parse - that way an
/// unexpected tag shape ("v0.2.0-rc1") still signals "different from
/// running" instead of silently swallowing the update.
fn is_newer(running: &str, latest: &str) -> bool {
    fn parse(s: &str) -> Option<(u32, u32, u32)> {
        let s = s.trim_start_matches('v');
        let parts: Vec<u32> = s.split('.').take(3).filter_map(|p| p.parse().ok()).collect();
        if parts.len() != 3 {
            return None;
        }
        Some((parts[0], parts[1], parts[2]))
    }
    match (parse(running), parse(latest)) {
        (Some(r), Some(l)) => l > r,
        _ => latest != running,
    }
}

#[cfg(test)]
mod tests {
    use super::is_newer;

    #[test]
    fn newer_patch() {
        assert!(is_newer("0.1.0", "v0.1.1"));
    }

    #[test]
    fn newer_minor() {
        assert!(is_newer("v0.1.5", "v0.2.0"));
    }

    #[test]
    fn same_version() {
        assert!(!is_newer("0.1.0", "v0.1.0"));
    }

    #[test]
    fn older_remote() {
        assert!(!is_newer("v0.2.0", "v0.1.9"));
    }

    #[test]
    fn unparseable_tag_signals_difference() {
        assert!(is_newer("0.1.0", "v0.2.0-rc1"));
        assert!(!is_newer("0.1.0", "0.1.0"));
    }
}
