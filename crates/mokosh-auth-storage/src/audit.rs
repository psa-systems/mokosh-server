//! Postgres-backed `AuditLogger`. Append-only.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use ipnetwork::IpNetwork;
use mokosh_auth_core::{
    AuditEntry, AuditEvent, AuditListFilter, AuditLogger, AuthError, TenantId, UserId,
};
use uuid::Uuid;

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
        InviteIssued { .. } => "invite_issued",
        InviteRevoked { .. } => "invite_revoked",
        InviteAccepted { .. } => "invite_accepted",
        InviteAttemptFailed { .. } => "invite_attempt_failed",
        SignupRequested { .. } => "signup_requested",
        SignupCompleted { .. } => "signup_completed",
        SignupAttemptFailed { .. } => "signup_attempt_failed",
        PasswordResetAttemptFailed { .. } => "password_reset_attempt_failed",
        TotpEnrollmentStarted { .. } => "totp_enrollment_started",
        TotpEnrolled { .. } => "totp_enrolled",
        TotpDisenrolled { .. } => "totp_disenrolled",
        MfaChallengeIssued { .. } => "mfa_challenge_issued",
        MfaChallengeConsumed { .. } => "mfa_challenge_consumed",
        MfaVerifyFailed { .. } => "mfa_verify_failed",
        StepUpIssued { .. } => "step_up_issued",
        StepUpConsumed { .. } => "step_up_consumed",
        RecoveryCodesIssued { .. } => "recovery_codes_issued",
        RecoveryCodesRegenerated { .. } => "recovery_codes_regenerated",
        RecoveryCodeUsed { .. } => "recovery_code_used",
        AccountLockoutHit { .. } => "account_lockout_hit",
        AccountLocked { .. } => "account_locked",
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

    async fn list_recent(
        &self,
        tenant_id: TenantId,
        kind: Option<&str>,
        actor_id: Option<UserId>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<AuditEntry>, AuthError> {
        // Legacy thin wrapper around list_filtered for callers that
        // haven't migrated to the filter struct.
        self.list_filtered(
            tenant_id,
            AuditListFilter {
                kind: kind.map(str::to_string),
                actor_id,
                limit,
                offset,
                ..Default::default()
            },
        )
        .await
    }

    async fn list_filtered(
        &self,
        tenant_id: TenantId,
        filter: AuditListFilter,
    ) -> Result<Vec<AuditEntry>, AuthError> {
        let limit = filter.limit.clamp(1, 10_000); // CSV path passes up to 10k; UI path clamps lower in the handler.
        let offset = filter.offset.max(0);

        #[derive(sqlx::FromRow)]
        struct Row {
            id: Uuid,
            tenant_id: Option<Uuid>,
            actor_id: Option<Uuid>,
            actor_email: Option<String>,
            event_kind: String,
            severity: String,
            ip: Option<IpNetwork>,
            metadata: serde_json::Value,
            created_at: DateTime<Utc>,
        }

        let search_pattern = filter
            .search
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| format!("%{s}%"));

        let severity = filter
            .severity
            .as_deref()
            .map(str::trim)
            .filter(|s| matches!(*s, "info" | "warning" | "critical"));

        let rows: Vec<Row> = sqlx::query_as(
            r#"
            SELECT a.id,
                   a.tenant_id,
                   a.actor_id,
                   u.email AS actor_email,
                   a.event_kind,
                   a.severity,
                   a.ip,
                   a.metadata,
                   a.created_at
            FROM mokosh_auth.audit_logs a
            LEFT JOIN mokosh_auth.users u ON u.id = a.actor_id
            WHERE a.tenant_id = $1
              AND ($2::TEXT      IS NULL OR a.event_kind = $2)
              AND ($3::UUID      IS NULL OR a.actor_id   = $3)
              AND ($4::TEXT      IS NULL OR a.metadata::text ILIKE $4)
              AND ($5::TEXT      IS NULL OR a.severity   = $5)
              AND ($6::TIMESTAMPTZ IS NULL OR a.created_at >= $6)
              AND ($7::TIMESTAMPTZ IS NULL OR a.created_at <= $7)
            ORDER BY a.created_at DESC
            LIMIT $8 OFFSET $9
            "#,
        )
        .bind(tenant_id.0)
        .bind(filter.kind.as_deref())
        .bind(filter.actor_id.map(|a| a.0))
        .bind(&search_pattern)
        .bind(severity)
        .bind(filter.date_from)
        .bind(filter.date_to)
        .bind(limit)
        .bind(offset)
        .fetch_all(self.pool.pg())
        .await
        .map_err(db_err)?;

        Ok(rows
            .into_iter()
            .map(|r| AuditEntry {
                id: r.id,
                tenant_id: r.tenant_id.map(TenantId),
                actor_id: r.actor_id.map(UserId),
                actor_email: r.actor_email,
                event_kind: r.event_kind,
                severity: r.severity,
                ip: r.ip.map(|n| n.ip()),
                metadata: r.metadata,
                created_at: r.created_at,
            })
            .collect())
    }
}
