//! Self-hosted update check (PMS-238).
//!
//! Self-hosted operators can opt in to an update check by setting
//! `MOKOSH_UPDATE_CHECK_URL` to a JSON manifest endpoint that publishes the
//! latest released version. The `/api/v1/version/check` endpoint fetches that
//! manifest, compares the advertised version against the running build, and
//! reports whether an upgrade is available.
//!
//! When the env var is unset the check reports `disabled` and never makes an
//! outbound request, so a stock install stays fully offline. The probe config
//! and its `reqwest::Client` are cached in a `OnceLock` (same shape as the
//! `/ready` Infisical probe) so repeated polling reuses one connection pool
//! instead of leaking file descriptors.
//!
//! The remote manifest is expected to look like:
//!
//! ```json
//! { "version": "0.2.0", "release_url": "https://example.com/releases/0.2.0" }
//! ```

use axum::{http::header, response::IntoResponse};
use serde::{Deserialize, Serialize};

use crate::version::PACKAGE_VERSION;

/// Result of an update check, serialised as the `/version/check` body. The
/// `status` discriminator tells the operator (or a calling dashboard) which
/// branch was taken without inspecting which optional fields are present.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum UpdateCheck {
    /// `MOKOSH_UPDATE_CHECK_URL` is unset: the operator has not opted in.
    Disabled { current_version: &'static str },
    /// Manifest fetched; the running build is already the latest release.
    UpToDate {
        current_version: &'static str,
        latest_version: String,
    },
    /// Manifest fetched; a newer release is available.
    UpdateAvailable {
        current_version: &'static str,
        latest_version: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        release_url: Option<String>,
    },
    /// The check was configured but failed (DNS, TCP, non-2xx, parse error,
    /// or timeout). The message references only the sanitised display URL so
    /// any credentials embedded in the env var stay out of the response body.
    Error {
        current_version: &'static str,
        message: String,
    },
}

/// Shape of the remote manifest. Extra fields are ignored so the publishing
/// side can add metadata without breaking older self-hosted installs.
#[derive(Debug, Deserialize)]
struct Manifest {
    version: String,
    #[serde(default)]
    release_url: Option<String>,
}

/// Captured-at-first-use update-check probe state. Mirrors the `/ready`
/// Infisical probe: parse the env var once, pre-build the HTTP client, and
/// pre-sanitise the display URL so the hot path is allocation-light.
struct UpdateCheckProbe {
    /// Manifest URL to GET, with any trailing slash on the configured value
    /// stripped.
    url: String,
    /// Scheme + host[:port] only (no userinfo, query, or fragment), used in
    /// error strings so credentials in the env var are never echoed back.
    display: String,
    client: reqwest::Client,
}

static UPDATE_CHECK_PROBE: std::sync::OnceLock<Option<UpdateCheckProbe>> =
    std::sync::OnceLock::new();

fn update_check_probe() -> Option<&'static UpdateCheckProbe> {
    UPDATE_CHECK_PROBE
        .get_or_init(|| {
            let configured = std::env::var("MOKOSH_UPDATE_CHECK_URL").ok()?;
            let trimmed = configured.trim().trim_end_matches('/').to_string();
            if trimmed.is_empty() {
                return None;
            }
            // Best-effort credential scrub for error strings, identical to the
            // Infisical probe. A value that does not parse as a URL has no
            // leak path, but stay defensive and fall back to the literal.
            let display = match url::Url::parse(&trimmed) {
                Ok(mut u) => {
                    let _ = u.set_username("");
                    let _ = u.set_password(None);
                    u.set_query(None);
                    u.set_fragment(None);
                    u.to_string().trim_end_matches('/').to_string()
                }
                Err(_) => trimmed.clone(),
            };
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .ok()?;
            Some(UpdateCheckProbe {
                url: trimmed,
                display,
                client,
            })
        })
        .as_ref()
}

/// Run the update check. Pure async logic split out from the handler so it can
/// be unit-tested without spinning up the Axum stack.
async fn run_update_check() -> UpdateCheck {
    let Some(probe) = update_check_probe() else {
        return UpdateCheck::Disabled {
            current_version: PACKAGE_VERSION,
        };
    };

    let resp = match probe.client.get(&probe.url).send().await {
        Ok(resp) => resp,
        Err(e) => {
            return UpdateCheck::Error {
                current_version: PACKAGE_VERSION,
                message: format!("{}: request failed: {e}", probe.display),
            };
        }
    };
    if !resp.status().is_success() {
        return UpdateCheck::Error {
            current_version: PACKAGE_VERSION,
            message: format!("{}: status {}", probe.display, resp.status()),
        };
    }
    let manifest: Manifest = match resp.json().await {
        Ok(m) => m,
        Err(e) => {
            return UpdateCheck::Error {
                current_version: PACKAGE_VERSION,
                message: format!("{}: invalid manifest: {e}", probe.display),
            };
        }
    };

    if is_newer(&manifest.version, PACKAGE_VERSION) {
        UpdateCheck::UpdateAvailable {
            current_version: PACKAGE_VERSION,
            latest_version: manifest.version,
            release_url: manifest.release_url,
        }
    } else {
        UpdateCheck::UpToDate {
            current_version: PACKAGE_VERSION,
            latest_version: manifest.version,
        }
    }
}

/// `GET /api/v1/version/check`. Returns 200 with the check result, except a
/// failed remote check returns 502 Bad Gateway (the upstream manifest server,
/// not this server, is at fault). A disabled check is a normal 200.
pub async fn version_check() -> impl IntoResponse {
    let result = run_update_check().await;
    let status = match result {
        UpdateCheck::Error { .. } => axum::http::StatusCode::BAD_GATEWAY,
        _ => axum::http::StatusCode::OK,
    };
    (
        status,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        axum::Json(result),
    )
}

/// Parse a version string into numeric release components, dropping a leading
/// `v` and any pre-release/build metadata after the first `-` or `+`. A
/// non-numeric component degrades to `0` rather than failing the whole check.
fn parse_version(v: &str) -> Vec<u64> {
    let core = v.trim().trim_start_matches('v');
    let core = core.split(['-', '+']).next().unwrap_or(core);
    core.split('.')
        .map(|p| p.parse::<u64>().unwrap_or(0))
        .collect()
}

/// True when `latest` is a strictly higher release than `current`. Missing
/// trailing components compare as `0`, so `0.2` ranks equal to `0.2.0`.
fn is_newer(latest: &str, current: &str) -> bool {
    let l = parse_version(latest);
    let c = parse_version(current);
    let n = l.len().max(c.len());
    for i in 0..n {
        let lv = l.get(i).copied().unwrap_or(0);
        let cv = c.get(i).copied().unwrap_or(0);
        if lv != cv {
            return lv > cv;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_a_newer_release() {
        assert!(is_newer("0.2.0", "0.1.0"));
        assert!(is_newer("1.0.0", "0.9.9"));
        assert!(is_newer("0.1.1", "0.1.0"));
        assert!(is_newer("0.10.0", "0.9.0"));
    }

    #[test]
    fn ignores_equal_or_older_releases() {
        assert!(!is_newer("0.1.0", "0.1.0"));
        assert!(!is_newer("0.1.0", "0.2.0"));
        assert!(!is_newer("0.9.0", "1.0.0"));
    }

    #[test]
    fn tolerates_v_prefix_and_prerelease_metadata() {
        assert!(is_newer("v0.2.0", "0.1.0"));
        // Pre-release/build metadata is stripped before comparison, so the
        // numeric cores `0.2.0` vs `0.1.0` decide the result.
        assert!(is_newer("0.2.0-rc1", "0.1.0"));
        assert!(!is_newer("0.1.0+build.7", "0.1.0"));
    }

    #[test]
    fn missing_trailing_components_default_to_zero() {
        assert!(!is_newer("0.2", "0.2.0"));
        assert!(is_newer("0.2.1", "0.2"));
    }
}
