//! The feature-toggle surfaces (PMS-1414): the operator's list and flip, and the
//! public probe every client reads.
//!
//! parity record 2026-10-02: no route in this file has an SPA caller yet. The
//! admin page is MAPPS-955 and the client half of the public probe is the same
//! issue; this module is what they read. The note covers every route here and
//! comes off with the first one the client calls, the way PMS-1310's did when
//! MAPPS-971 shipped.
//!
//! ## Why `/settings/feature-toggles` and not `/admin/feature-toggles`
//!
//! PMS-1414 says to match bunyip's `/v1/admin/feature-toggles` and to revise only
//! if mokosh's route conventions differ. They do. mokosh has no `/admin` nest:
//! its deployment-wide settings live under `/settings/*` behind
//! [`DeploymentOperator`] (PMS-1280), which is where the email relay and the
//! product name already are, and a feature toggle is the same kind of thing. A
//! second convention for one tier of settings is the drift this repository spends
//! its guards avoiding.
//!
//! ## Why the operator gate and not `RequireAdmin`
//!
//! Bunyip lets any admin LIST and only a super admin flip. In mokosh the
//! equivalent of "super admin" for deployment-wide settings is
//! [`DeploymentOperator`], and `RequireAdmin` is satisfied by an admin of ANY
//! organisation on the deployment. A customer's admin reading which unfinished
//! features exist is a minor leak; a customer's admin flipping one is not minor
//! at all, and the two gates have to agree or the list becomes a map of what to
//! try next. So both are operator-only.
//!
//! ## The public probe
//!
//! `GET /api/v1/public/config` is new. Bunyip could hang its `features` map on
//! `/v1/auth/setup/status`; mokosh's public nest holds OAuth callbacks, logos and
//! images and nothing a client asks about the deployment. It is PUBLIC because a
//! client needs flags BEFORE it has a session: a feature that gates part of the
//! sign-in path could never be gated by a map that requires signing in first.
//!
//! What that costs: the key, label and state of every registered feature are
//! world-readable. That is accepted on the same terms as bunyip, and it is why
//! [`Feature::help`] is written for an admin rather than describing anything
//! confidential, and why the probe carries no row metadata, no `updated_by` and
//! no label text.

use std::sync::Arc;

use axum::{extract::Path, extract::State, routing::get, routing::put, Router};
use serde::{Deserialize, Serialize};

use super::registry::Feature;
use super::service::{self, FeatureSnapshot};
use crate::db::Database;
use crate::modules::audit::AuditCtx;
use crate::modules::tenants::DeploymentOperator;
use crate::utils::error::{AppError, AppResult};
use crate::utils::json::Json;

#[derive(Clone)]
pub struct FeatureRouterState {
    pub db: Database,
    pub snapshot: FeatureSnapshot,
}

/// One row of the admin list: the registry's half joined to the stored half.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct FeatureView {
    pub key: &'static str,
    pub label: &'static str,
    pub help: &'static str,
    pub issue: &'static str,
    pub enabled: bool,
    /// `None` for a feature nobody has ever flipped, which is the normal state
    /// and is why the list is built from the registry rather than the table.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<uuid::Uuid>,
}

#[derive(Debug, Deserialize)]
pub struct SetFeatureRequest {
    pub enabled: bool,
}

/// `GET /api/v1/public/config`: what a client needs before it has a session.
#[derive(Debug, Serialize)]
pub struct PublicConfig {
    /// Every registered feature and its state, keyed by the registry's own key.
    ///
    /// Built from the registry, so a feature with no row reads `false` rather
    /// than being absent and a client never has to tell the two apart.
    pub features: std::collections::BTreeMap<&'static str, bool>,
}

/// The operator surface, mounted under `/api/v1`.
pub fn feature_routes(db: Database, snapshot: FeatureSnapshot) -> Router {
    Router::new()
        .route("/settings/feature-toggles", get(list_features))
        .route("/settings/feature-toggles/{key}", put(set_feature))
        .with_state(FeatureRouterState { db, snapshot })
}

/// The public probe, mounted under `/api/v1/public`.
pub fn public_config_routes(snapshot: FeatureSnapshot) -> Router {
    Router::new()
        .route("/config", get(public_config))
        .with_state(snapshot)
}

/// Every registered feature with its stored state, in registry order.
async fn list_features(
    State(s): State<FeatureRouterState>,
    _operator: DeploymentOperator,
) -> AppResult<Json<Vec<FeatureView>>> {
    let rows = service::all_rows(&s.db).await?;
    let views = Feature::ALL
        .iter()
        .map(|feature| {
            let row = rows.iter().find(|r| r.key == feature.key());
            FeatureView {
                key: feature.key(),
                label: feature.label(),
                help: feature.help(),
                issue: feature.issue(),
                enabled: row.map(|r| r.enabled).unwrap_or(false),
                updated_at: row.map(|r| r.updated_at),
                updated_by: row.and_then(|r| r.updated_by),
            }
        })
        .collect();
    Ok(Json(views))
}

/// Flip one feature.
///
/// 404 on a key no variant matches, which is the whole reason the path takes a
/// key and the service takes a [`Feature`]: an unknown key cannot reach the
/// upsert, so the table cannot grow a row for a feature that does not exist. A
/// 400 would be wrong here: the client named a resource, and the resource is not
/// there.
async fn set_feature(
    State(s): State<FeatureRouterState>,
    _operator: DeploymentOperator,
    Path(key): Path<String>,
    ctx: AuditCtx,
    Json(request): Json<SetFeatureRequest>,
) -> AppResult<Json<FeatureView>> {
    let feature = Feature::from_key(&key).ok_or_else(|| {
        AppError::NotFound(format!(
            "no feature named {key}; this build registers {}",
            Feature::ALL
                .iter()
                .map(|f| f.key())
                .collect::<Vec<_>>()
                .join(", ")
        ))
    })?;

    let row = service::set(&s.db, feature, request.enabled, &ctx).await?;

    // Swap this process's snapshot now rather than waiting for the refresh, so
    // the admin who flipped it sees the effect on their next request. A sibling
    // container still picks it up on its own tick, which the module docs state.
    s.snapshot.swap(service::load(&s.db).await?);

    Ok(Json(FeatureView {
        key: feature.key(),
        label: feature.label(),
        help: feature.help(),
        issue: feature.issue(),
        enabled: row.enabled,
        updated_at: Some(row.updated_at),
        updated_by: row.updated_by,
    }))
}

/// The unauthenticated probe. Reads the snapshot, never the database: it is on
/// the public path and a probe that queried per request would be a free way to
/// make the deployment do work.
async fn public_config(State(snapshot): State<FeatureSnapshot>) -> Json<PublicConfig> {
    Json(PublicConfig {
        features: snapshot.current().as_map(),
    })
}

/// So the router can hold the state in an `Arc` without a second type.
impl axum::extract::FromRef<FeatureRouterState> for FeatureSnapshot {
    fn from_ref(state: &FeatureRouterState) -> Self {
        state.snapshot.clone()
    }
}

/// Unused today; kept so a future caller can share one `Arc` rather than cloning
/// the snapshot per router.
pub type SharedFeatureSnapshot = Arc<FeatureSnapshot>;
