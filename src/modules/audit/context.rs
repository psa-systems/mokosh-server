//! Request-derived audit context + in-transaction write helper (PMS-117).
//!
//! The middleware in [`super::middleware`] records a coarse, post-response
//! row per mutating request but has no access to the entity's before/after
//! state and writes outside the mutation's transaction. This module is the
//! AC1 path: service mutations build an [`AuditCtx`] from the request (actor,
//! ip, user-agent) and call [`audit_write`] with `&mut *tx` so the audit row
//! lands in the SAME transaction as the change, carrying JSONB before/after
//! snapshots. If the mutation rolls back, so does its audit row.

use std::net::SocketAddr;

use crate::modules::auth::TenantId;
use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::request::Parts;
use serde_json::Value;
use uuid::Uuid;

use crate::modules::auth::AuthState;
use crate::utils::error::AppResult;

/// Actor + request metadata captured for an audit entry.
///
/// Built from the request via [`FromRequestParts`] and threaded into the
/// service mutation so the audit row is written inside the same
/// transaction as the change it records. `tenant_id`/`user_id` are
/// `Option` because an anonymous request (e.g. a failed login) still
/// needs ip/user-agent captured.
#[derive(Clone, Debug, Default)]
pub struct AuditCtx {
    pub tenant_id: Option<Uuid>,
    pub user_id: Option<Uuid>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
}

impl AuditCtx {
    /// Construct a context for a non-request caller (background jobs,
    /// tests). Actor is unset; ip/user-agent are absent.
    pub fn system(tenant_id: Uuid) -> Self {
        Self {
            tenant_id: Some(tenant_id),
            user_id: None,
            ip: None,
            user_agent: None,
        }
    }
}

impl<S> FromRequestParts<S> for AuditCtx
where
    S: Send + Sync,
{
    // Always succeeds: an unauthenticated request yields an empty actor
    // rather than rejecting, so handlers can capture failed attempts too.
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let auth = parts
            .extensions
            .get::<AuthState>()
            .cloned()
            .unwrap_or_default();
        let ip = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0.ip().to_string());
        let user_agent = parts
            .headers
            .get(axum::http::header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        Ok(Self {
            tenant_id: auth.tenant_id,
            user_id: auth.user.as_ref().map(|u| u.id),
            ip,
            user_agent,
        })
    }
}

/// Audit action verbs, matching the `audit_log` CHECK constraint
/// (`migrations/015_audit.sql`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditAction {
    Create,
    Update,
    Delete,
    View,
    Login,
    Logout,
    Export,
    Import,
}

impl AuditAction {
    pub fn as_str(self) -> &'static str {
        match self {
            AuditAction::Create => "create",
            AuditAction::Update => "update",
            AuditAction::Delete => "delete",
            AuditAction::View => "view",
            AuditAction::Login => "login",
            AuditAction::Logout => "logout",
            AuditAction::Export => "export",
            AuditAction::Import => "import",
        }
    }
}

/// Write an audit row using the supplied executor.
///
/// Pass a transaction handle (`&mut *tx`) to record the change in the
/// SAME transaction as the mutation it audits (AC1); pass `db.pool()`
/// for out-of-band events. `tenant_id` is explicit (the mutation's
/// tenant scope) so the NOT NULL column is always populated even when
/// the actor is anonymous. Actor / ip / user-agent come from `ctx`.
///
/// PMS-139: `tenant_id` is the typed [`TenantId`], so a swept service hands
/// its scope straight through. Callers that still hold a bare `Uuid` - the
/// `auth` and `tickets` modules (not yet swept), the `tenants` create path
/// (a freshly minted id), and the `audit_auth_event` helper - bridge via
/// `TenantId::from_trusted(..)`; those bridges disappear as each is swept.
///
/// Usage from a service mutation:
/// ```ignore
/// let mut tx = self.db.pool().begin().await?;
/// let before = sqlx::query_as::<_, Row>("SELECT ... FOR UPDATE")
///     .bind(id).fetch_one(&mut *tx).await?;
/// // ... perform the UPDATE on &mut *tx, producing `after` ...
/// audit_write(&mut *tx, tenant_id, ctx, AuditAction::Update, "invoices",
///             Some(id), Some(json!(before)), Some(json!(after))).await?;
/// tx.commit().await?;
/// ```
#[allow(clippy::too_many_arguments)]
pub async fn audit_write<'e, E>(
    exec: E,
    tenant_id: TenantId,
    ctx: &AuditCtx,
    action: AuditAction,
    entity_type: &str,
    entity_id: Option<Uuid>,
    old_values: Option<Value>,
    new_values: Option<Value>,
) -> AppResult<()>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query(
        r#"INSERT INTO audit_log
           (tenant_id, user_id, action, entity_type, entity_id,
            old_values, new_values, ip_address, user_agent)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"#,
    )
    .bind(tenant_id)
    .bind(ctx.user_id)
    .bind(action.as_str())
    .bind(entity_type)
    .bind(entity_id)
    .bind(old_values)
    .bind(new_values)
    .bind(ctx.ip.as_deref())
    .bind(ctx.user_agent.as_deref())
    .execute(exec)
    .await?;
    Ok(())
}

/// Record an authentication event (login / logout / failed login).
///
/// Convenience wrapper over [`audit_write`] for the auth module, which
/// has no entity row to diff. Recorded against the `auth` entity_type
/// with the acting user (when known) as `entity_id`.
pub async fn audit_auth_event<'e, E>(
    exec: E,
    tenant_id: Uuid,
    user_id: Option<Uuid>,
    action: AuditAction,
    ip: Option<String>,
    user_agent: Option<String>,
) -> AppResult<()>
where
    E: sqlx::PgExecutor<'e>,
{
    let ctx = AuditCtx {
        tenant_id: Some(tenant_id),
        user_id,
        ip,
        user_agent,
    };
    audit_write(
        exec,
        // SAFETY (PMS-285): `tenant_id` is the caller's own authenticated tenant,
        // threaded in by the auth flow recording this event; the audit row is
        // written under the same scope, so bridging the bare Uuid is sound.
        TenantId::from_trusted(tenant_id),
        &ctx,
        action,
        "auth",
        user_id,
        None,
        None,
    )
    .await
}
