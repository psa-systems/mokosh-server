//! Postgres-backed `AuditLogger`. Append-only.

use async_trait::async_trait;
use mokosh_auth_core::{AuditEvent, AuditLogger, AuthError, TenantId, UserId};

use crate::conv::{db_err, ip_to_inet};
use crate::pool::AuthPool;

pub struct PgAuditLogger {
    pool: AuthPool,
}

impl PgAuditLogger {
    pub fn new(pool: AuthPool) -> Self {
        Self { pool }
    }
}

/// Discriminant of [`AuditEvent`] used for the indexed `event_kind` column.
fn event_kind(e: &AuditEvent) -> &'static str {
    use AuditEvent::*;
    match e {
        LoginSuccess { .. } => "login_success",
        LoginFailed { .. } => "login_failed",
        LogoutSuccess { .. } => "logout_success",
        PasswordChanged { .. } => "password_changed",
        PasswordResetRequested { .. } => "password_reset_requested",
        PasswordResetCompleted { .. } => "password_reset_completed",
        MagicLinkRequested { .. } => "magic_link_requested",
        MagicLinkUsed { .. } => "magic_link_used",
        TokenIssued { .. } => "token_issued",
        TokenRefreshed { .. } => "token_refreshed",
        RefreshReuseDetected { .. } => "refresh_reuse_detected",
        SessionRevoked { .. } => "session_revoked",
        ClientCreated { .. } => "client_created",
        ClientDisabled { .. } => "client_disabled",
        KeyRotated { .. } => "key_rotated",
        SuspiciousActivity { .. } => "suspicious_activity",
        AdminAction { .. } => "admin_action",
    }
}

#[async_trait]
impl AuditLogger for PgAuditLogger {
    async fn record(
        &self,
        tenant_id: Option<TenantId>,
        actor: Option<UserId>,
        ip: Option<std::net::IpAddr>,
        event: AuditEvent,
    ) -> Result<(), AuthError> {
        let kind = event_kind(&event);
        let severity = event.severity().as_str();
        let metadata = serde_json::to_value(&event).unwrap_or_else(|_| serde_json::json!({}));

        sqlx::query(
            "INSERT INTO mokosh_auth.audit_logs
                (tenant_id, actor_id, event_kind, severity, ip, metadata)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(tenant_id.map(|t| t.0))
        .bind(actor.map(|a| a.0))
        .bind(kind)
        .bind(severity)
        .bind(ip_to_inet(ip))
        .bind(metadata)
        .execute(self.pool.pg())
        .await
        .map_err(db_err)?;

        // Surface critical events to the structured log so an alerting
        // pipeline can pick them up without polling the DB.
        if matches!(severity, "critical") {
            tracing::warn!(target: "mokosh_auth.audit", kind, ?event, "critical audit event");
        }
        Ok(())
    }
}
