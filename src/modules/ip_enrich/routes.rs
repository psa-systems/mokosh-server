//! Routes for the admin IP enrichment lookup (BUNYIP-475).

use std::net::IpAddr;
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};
use dunite_ipenrich::{IpEnrichService, IpEnrichment};
use serde::{Deserialize, Serialize};

use crate::modules::auth::middleware::{RequireAdmin, RequireAuth};
use crate::utils::error::{AppError, AppResult};

/// Router state: the optional enrichment service. `None` when
/// `IP2PROXY_DB_PATH` is unset or the `.BIN` failed to load, in which case the
/// endpoint reports "no enrichment" rather than erroring.
#[derive(Clone)]
pub struct IpEnrichRouterState {
    pub service: Option<Arc<IpEnrichService>>,
}

/// `GET /api/v1/ip-enrichment?ip=<addr>` (admin-gated).
pub fn ip_enrich_routes(service: Option<Arc<IpEnrichService>>) -> Router {
    Router::new()
        .route("/ip-enrichment", get(ip_enrichment))
        .with_state(IpEnrichRouterState { service })
}

#[derive(Debug, Deserialize)]
pub struct IpEnrichmentQuery {
    pub ip: String,
}

/// The advisory enrichment of one address. `category` and `vpn` are the stable
/// lowercase labels of the classified enums, `is_anonymizing` is the one-bit
/// "looks like a VPN / proxy" summary, and `advisory` is always `true` - a
/// reminder in the payload that this is context, not a verdict.
#[derive(Debug, Serialize)]
pub struct IpEnrichmentResponse {
    pub ip: String,
    pub asn: Option<String>,
    pub organization: Option<String>,
    pub isp: Option<String>,
    pub category: String,
    pub vpn: String,
    pub is_anonymizing: bool,
    pub proxy_type: Option<String>,
    pub provider: Option<String>,
    pub threat: Option<String>,
    pub advisory: bool,
}

impl IpEnrichmentResponse {
    fn from_enrichment(ip: &str, e: &IpEnrichment) -> Self {
        Self {
            ip: ip.to_string(),
            asn: e.asn.clone(),
            organization: e.organization.clone(),
            isp: e.isp.clone(),
            category: e.category.label().to_string(),
            vpn: e.vpn.label().to_string(),
            is_anonymizing: e.vpn.is_anonymizing(),
            proxy_type: e.proxy_type.clone(),
            provider: e.provider.clone(),
            threat: e.threat.clone(),
            advisory: true,
        }
    }
}

/// Resolve `ip` to its advisory ASN / VPN enrichment, or `null` when there is
/// nothing to report (no dataset configured, a private/reserved address, or an
/// address the dataset does not know). Only a malformed IP is a client error.
async fn ip_enrichment(
    State(s): State<IpEnrichRouterState>,
    RequireAuth(_u): RequireAuth,
    _admin: RequireAdmin,
    Query(q): Query<IpEnrichmentQuery>,
) -> AppResult<Json<Option<IpEnrichmentResponse>>> {
    let ip: IpAddr =
        q.ip.trim()
            .parse()
            .map_err(|_| AppError::BadRequest("Invalid IP address".to_string()))?;

    let Some(svc) = s.service.as_ref() else {
        return Ok(Json(None));
    };

    Ok(Json(svc.enrich(ip).map(|e| {
        IpEnrichmentResponse::from_enrichment(q.ip.trim(), &e)
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use dunite_ipenrich::{NetworkCategory, VpnLikelihood};

    #[test]
    fn response_maps_labels_and_is_always_advisory() {
        let e = IpEnrichment {
            asn: Some("15169".into()),
            organization: Some("Google LLC".into()),
            isp: None,
            category: NetworkCategory::Hosting,
            vpn: VpnLikelihood::Vpn,
            proxy_type: Some("VPN".into()),
            provider: Some("NordVPN".into()),
            threat: None,
        };
        let r = IpEnrichmentResponse::from_enrichment("203.0.113.7", &e);
        assert_eq!(r.category, "hosting");
        assert_eq!(r.vpn, "vpn");
        assert!(r.is_anonymizing);
        assert!(r.advisory, "the response always marks itself advisory");
        assert_eq!(r.organization.as_deref(), Some("Google LLC"));
        assert_eq!(r.isp, None);
    }

    #[test]
    fn data_center_is_shown_but_not_flagged_anonymizing() {
        let e = IpEnrichment {
            asn: Some("16509".into()),
            organization: Some("Amazon.com".into()),
            isp: None,
            category: NetworkCategory::Hosting,
            vpn: VpnLikelihood::DataCenter,
            proxy_type: Some("DCH".into()),
            provider: None,
            threat: None,
        };
        let r = IpEnrichmentResponse::from_enrichment("203.0.113.9", &e);
        assert_eq!(r.vpn, "data-center");
        assert!(!r.is_anonymizing);
    }
}
