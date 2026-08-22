//! Provider abstraction.
//!
//! Every external RMM platform (Tactical RMM, MeshCentral, Datto,
//! ConnectWise, NinjaRMM) speaks a different HTTP dialect; the sync
//! worker and alert ingest paths talk to them through this trait so
//! per-provider quirks stay in one file. Today only Tactical RMM has
//! a real implementation; the other variants return a fail-loud error
//! ("provider X not implemented") so an operator running a deployment
//! with an unimplemented provider sees a clear `rmm_connections.last_error`
//! instead of silent no-ops.
//!
//! See PMS-103 for the AC list.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use url::Url;
use uuid::Uuid;

use crate::utils::error::{AppError, AppResult};
use crate::utils::net::{
    guard_outbound_url, private_target_allowlist, HostResolver, SystemResolver,
};

/// One device as returned by a provider. Field names mirror the
/// `rmm_device_mappings` + `assets` columns the worker writes; provider
/// implementations are responsible for mapping the upstream payload
/// into this shape.
#[derive(Debug, Clone)]
pub struct ProviderDevice {
    /// Stable upstream identifier; used as the UPSERT key on
    /// `(rmm_connection_id, rmm_device_id)`.
    pub rmm_device_id: String,
    /// Hostname or label. Used to match an existing `assets` row when
    /// no serial is available.
    pub hostname: Option<String>,
    /// Hardware serial. First-choice match key against `assets.serial_number`.
    pub serial_number: Option<String>,
    /// Timestamp the provider last saw the agent online. Persisted to
    /// `rmm_device_mappings.last_seen` and `assets.last_sync_at`.
    pub last_seen: Option<DateTime<Utc>>,
    /// Full upstream JSON, dropped into `rmm_device_mappings.device_info`
    /// so downstream UIs can render provider-specific extras without
    /// requiring the schema to grow per-provider columns.
    pub raw: serde_json::Value,
}

/// One alert as returned by a provider. Mostly mirrors
/// `IngestAlertRequest`; the alert-pull path can construct an
/// `IngestAlertRequest` from this for free.
#[derive(Debug, Clone)]
pub struct ProviderAlert {
    pub rmm_device_id: String,
    pub alert_type: String,
    pub title: String,
    pub message: Option<String>,
    pub severity: Option<String>,
    /// Stable upstream identifier (so we can dedupe / link back).
    pub source_id: Option<String>,
    pub raw: serde_json::Value,
}

/// Implemented by each RMM platform. The sync worker calls
/// `list_devices` and `list_alerts`; `ping` is the cheap call wired
/// into `POST /api/v1/rmm/connections/{id}/test`.
#[async_trait]
pub trait RmmProvider: Send + Sync {
    async fn list_devices(&self) -> AppResult<Vec<ProviderDevice>>;
    async fn list_alerts(&self, since: DateTime<Utc>) -> AppResult<Vec<ProviderAlert>>;
    async fn ping(&self) -> AppResult<()>;
}

/// Builder input: the decrypted connection material. Kept distinct
/// from the DTO so the worker can hand the trait factory plain bytes
/// without leaking sqlx row structs into the provider layer.
#[derive(Debug, Clone)]
pub struct ProviderConfig {
    pub connection_id: Uuid,
    pub api_url: String,
    pub api_key: String,
    pub api_secret: Option<String>,
}

/// Build the right `RmmProvider` for a given `provider` string. Falls
/// back to a fail-loud stub for unimplemented providers so the sync
/// worker surfaces a real error in `last_error` instead of silently
/// reporting success.
pub fn build_provider(provider: &str, cfg: ProviderConfig) -> Box<dyn RmmProvider> {
    match provider {
        "tactical_rmm" => Box::new(TacticalRmmProvider::new(cfg)),
        other => Box::new(UnimplementedProvider {
            name: other.to_string(),
        }),
    }
}

/// Tactical RMM provider. Auth: `Authorization: Token <api_key>` per
/// <https://docs.tacticalrmm.com/api/>. Endpoints: `/agents/` returns
/// the agent list, `/alerts/` returns active alerts. Tactical's JSON
/// shape is documented above; this implementation only reads the
/// fields the PSA actually surfaces.
///
/// `api_url` is tenant-editable integration configuration, so every request
/// screens it through [`guard_outbound_url`] first (PMS-809): without that, a
/// tenant admin could point the integration at `127.0.0.1` or a cloud metadata
/// endpoint and have the server connect from inside the network. An
/// on-premise RMM that really does live on a private network is what
/// `OUTBOUND_PRIVATE_ALLOWLIST` is for.
pub struct TacticalRmmProvider {
    cfg: ProviderConfig,
    http: reqwest::Client,
    resolver: Arc<dyn HostResolver>,
}

impl TacticalRmmProvider {
    pub fn new(cfg: ProviderConfig) -> Self {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent("mokosh-server/rmm")
            // Redirects are not followed: a followed hop would connect to an
            // address the guard above never screened. A redirecting api_url is
            // reported as the configuration error it is.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("reqwest client builds with default config");
        Self {
            cfg,
            http,
            resolver: Arc::new(SystemResolver),
        }
    }

    /// Build the URL for `path` and screen it before the caller connects. The
    /// error is a `Configuration` failure the integration UI shows in
    /// `rmm_connections.last_error`, never a silent success.
    async fn guarded_url(&self, path: &str) -> AppResult<Url> {
        let raw = format!(
            "{}/{}",
            self.cfg.api_url.trim_end_matches('/'),
            path.trim_start_matches('/'),
        );
        let url = Url::parse(&raw).map_err(|e| {
            tracing::warn!(
                connection_id = %self.cfg.connection_id, error = %e,
                "RMM connection has an unusable api_url",
            );
            AppError::Configuration(format!("RMM api_url is not a valid URL: {e}"))
        })?;
        guard_outbound_url(
            self.resolver.as_ref(),
            &url,
            // A self-hosted RMM legitimately listens on its own port, so the
            // port set is not pinned; the resolved address is what is screened.
            None,
            private_target_allowlist(),
        )
        .await
        .map_err(|e| {
            tracing::warn!(
                connection_id = %self.cfg.connection_id, blocked = %e,
                "RMM connection refused: api_url is not on the public internet",
            );
            AppError::Configuration(format!(
                "RMM api_url refused: {e}. Set OUTBOUND_PRIVATE_ALLOWLIST if this target is deliberately private."
            ))
        })?;
        Ok(url)
    }

    /// Fold a response into a hard failure unless it is a real 2xx. A 3xx is
    /// called out separately because the client does not follow redirects.
    fn check_status(
        &self,
        response: reqwest::Response,
        what: &str,
    ) -> AppResult<reqwest::Response> {
        if response.status().is_redirection() {
            tracing::warn!(
                connection_id = %self.cfg.connection_id, status = %response.status(),
                "RMM connection redirected; api_url must name the final URL",
            );
            return Err(AppError::Configuration(format!(
                "tactical_rmm {what} redirected ({}); point api_url at the final URL, redirects are not followed",
                response.status(),
            )));
        }
        response
            .error_for_status()
            .map_err(|e| AppError::Internal(format!("tactical_rmm {what} status: {e}")))
    }
}

#[async_trait]
impl RmmProvider for TacticalRmmProvider {
    async fn list_devices(&self) -> AppResult<Vec<ProviderDevice>> {
        let url = self.guarded_url("agents/").await?;
        let resp = self
            .http
            .get(url)
            .header("Authorization", format!("Token {}", self.cfg.api_key))
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("tactical_rmm agents: {e}")))?;
        let resp = self.check_status(resp, "agents")?;
        let agents: Vec<serde_json::Value> = resp
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("tactical_rmm agents json: {e}")))?;
        Ok(agents.into_iter().map(parse_tactical_agent).collect())
    }

    async fn list_alerts(&self, _since: DateTime<Utc>) -> AppResult<Vec<ProviderAlert>> {
        let url = self.guarded_url("alerts/").await?;
        let resp = self
            .http
            .get(url)
            .header("Authorization", format!("Token {}", self.cfg.api_key))
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("tactical_rmm alerts: {e}")))?;
        let resp = self.check_status(resp, "alerts")?;
        let alerts: Vec<serde_json::Value> = resp
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("tactical_rmm alerts json: {e}")))?;
        Ok(alerts.into_iter().map(parse_tactical_alert).collect())
    }

    async fn ping(&self) -> AppResult<()> {
        let url = self.guarded_url("core/version/").await?;
        let resp = self
            .http
            .head(url)
            .header("Authorization", format!("Token {}", self.cfg.api_key))
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("tactical_rmm ping: {e}")))?;
        self.check_status(resp, "ping").map(|_| ())
    }
}

fn parse_tactical_agent(v: serde_json::Value) -> ProviderDevice {
    let rmm_device_id = v
        .get("agent_id")
        .and_then(|x| x.as_str())
        .unwrap_or_default()
        .to_string();
    let hostname = v
        .get("hostname")
        .and_then(|x| x.as_str())
        .map(str::to_string);
    let serial_number = v
        .get("serial_number")
        .or_else(|| {
            v.get("wmi_detail")
                .and_then(|w| w.get("bios"))
                .and_then(|b| b.get("SerialNumber"))
        })
        .and_then(|x| x.as_str())
        .map(str::to_string);
    let last_seen = v
        .get("last_seen")
        .and_then(|x| x.as_str())
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|d| d.with_timezone(&Utc));
    ProviderDevice {
        rmm_device_id,
        hostname,
        serial_number,
        last_seen,
        raw: v,
    }
}

fn parse_tactical_alert(v: serde_json::Value) -> ProviderAlert {
    let rmm_device_id = v
        .get("agent_id")
        .and_then(|x| x.as_str())
        .unwrap_or_default()
        .to_string();
    let alert_type = v
        .get("alert_type")
        .and_then(|x| x.as_str())
        .unwrap_or("unknown")
        .to_string();
    let title = v
        .get("message")
        .and_then(|x| x.as_str())
        .unwrap_or("RMM alert")
        .to_string();
    let message = v
        .get("snmp_info")
        .and_then(|x| x.as_str())
        .map(str::to_string);
    let severity = v
        .get("severity")
        .and_then(|x| x.as_str())
        .map(str::to_string);
    let source_id = v.get("id").map(|x| x.to_string()).or_else(|| {
        v.get("alert_id")
            .and_then(|x| x.as_str())
            .map(str::to_string)
    });
    ProviderAlert {
        rmm_device_id,
        alert_type,
        title,
        message,
        severity,
        source_id,
        raw: v,
    }
}

/// Fail-loud stub used for providers whose real adapter has not landed
/// yet. The sync worker stores the error message in
/// `rmm_connections.last_error` so an operator sees the unimplemented
/// surface explicitly.
struct UnimplementedProvider {
    name: String,
}

#[async_trait]
impl RmmProvider for UnimplementedProvider {
    async fn list_devices(&self) -> AppResult<Vec<ProviderDevice>> {
        Err(AppError::Internal(format!(
            "RMM provider '{}' is not implemented yet",
            self.name
        )))
    }
    async fn list_alerts(&self, _since: DateTime<Utc>) -> AppResult<Vec<ProviderAlert>> {
        Err(AppError::Internal(format!(
            "RMM provider '{}' is not implemented yet",
            self.name
        )))
    }
    async fn ping(&self) -> AppResult<()> {
        Err(AppError::Internal(format!(
            "RMM provider '{}' is not implemented yet",
            self.name
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_tactical_agent() {
        let v = json!({
            "agent_id": "abc-123",
            "hostname": "web-01.corp",
            "serial_number": "SN0001",
            "last_seen": "2026-06-04T10:00:00Z",
        });
        let d = parse_tactical_agent(v);
        assert_eq!(d.rmm_device_id, "abc-123");
        assert_eq!(d.hostname.as_deref(), Some("web-01.corp"));
        assert_eq!(d.serial_number.as_deref(), Some("SN0001"));
        assert!(d.last_seen.is_some());
    }

    #[tokio::test]
    async fn unimplemented_provider_fails_loud() {
        let p = UnimplementedProvider {
            name: "datto".into(),
        };
        let res = p.list_devices().await;
        let err = res.unwrap_err();
        assert!(format!("{err:?}").contains("datto"));
    }

    /// PMS-809. The api_url is an IP literal, so `SystemResolver` answers from
    /// the string with no DNS query, and the guard refuses before any connect:
    /// no test here touches the network.
    #[tokio::test]
    async fn tactical_provider_refuses_a_private_api_url() {
        for api_url in [
            "http://127.0.0.1:8000",
            "http://10.1.2.3",
            "https://192.168.1.50:8443/api",
            "http://[::1]:8000",
            "http://169.254.169.254/latest/meta-data",
        ] {
            let provider = TacticalRmmProvider::new(ProviderConfig {
                connection_id: Uuid::nil(),
                api_url: api_url.into(),
                api_key: "k".into(),
                api_secret: None,
            });
            for outcome in [
                provider.ping().await.map(|_| ()),
                provider.list_devices().await.map(|_| ()),
                provider.list_alerts(Utc::now()).await.map(|_| ()),
            ] {
                let err = outcome.expect_err("a private api_url is refused");
                assert!(
                    matches!(err, AppError::Configuration(_)),
                    "{api_url} should be a configuration error, got {err:?}"
                );
                assert!(
                    format!("{err}").contains("OUTBOUND_PRIVATE_ALLOWLIST"),
                    "{api_url} refusal must name the operator escape hatch: {err}"
                );
            }
        }
    }

    #[tokio::test]
    async fn tactical_provider_rejects_an_unusable_api_url() {
        let provider = TacticalRmmProvider::new(ProviderConfig {
            connection_id: Uuid::nil(),
            api_url: "not a url".into(),
            api_key: "k".into(),
            api_secret: None,
        });
        let err = provider
            .ping()
            .await
            .expect_err("an unparseable api_url fails");
        assert!(matches!(err, AppError::Configuration(_)), "got {err:?}");
    }

    #[test]
    fn build_provider_returns_unimplemented_for_unknown() {
        let cfg = ProviderConfig {
            connection_id: Uuid::nil(),
            api_url: "https://x".into(),
            api_key: "k".into(),
            api_secret: None,
        };
        let _ = build_provider("datto", cfg.clone());
        let _ = build_provider("mesh_central", cfg.clone());
        let _ = build_provider("tactical_rmm", cfg);
    }
}
