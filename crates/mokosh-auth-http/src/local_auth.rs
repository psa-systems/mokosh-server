//! Local password authentication for the OP's own login UI.
//!
//! Distinct from `mokosh-auth-oidc`: that crate deals with the OIDC
//! protocol surface (authorize/token/userinfo). This module is what
//! happens when a user types email + password into our login form.
//! Successful login creates an OP session whose `sid` becomes the cookie
//! value the browser then carries on every subsequent request.

use chrono::Duration;
use mokosh_auth_core::{
    AuditEvent, AuthError, OpSession, OpSessionRepository, TenantId, UserRepository, UserStatus,
};
use mokosh_auth_crypto::password::verify_password;
use serde::Deserialize;
use std::sync::Arc;

#[derive(Debug, Clone, Deserialize)]
pub struct LocalLoginRequest {
    pub tenant_id: uuid::Uuid,
    pub email: String,
    pub password: String,
}

pub struct LocalAuth {
    pub users: Arc<dyn UserRepository>,
    pub sessions: Arc<dyn OpSessionRepository>,
    pub audit: Arc<dyn mokosh_auth_core::AuditLogger>,
    pub op_session_ttl: Duration,
}

impl LocalAuth {
    pub async fn login(
        &self,
        req: LocalLoginRequest,
        ip: Option<std::net::IpAddr>,
        user_agent: Option<&str>,
    ) -> Result<OpSession, AuthError> {
        let tenant_id = TenantId(req.tenant_id);

        // Always do a password verification, even when the user does not
        // exist, to avoid a username-enumeration timing oracle. We use a
        // fixed dummy hash known to never match.
        const DUMMY_HASH: &str =
            "$argon2id$v=19$m=65536,t=3,p=4$ZHVtbXkxMjM0NTY3OA$\
             SGEgaGEgdGhpcyBpcyBub3QgcmVhbCBoYXNoIGxlbmd0aA";

        let maybe_user = self.users.find_by_email(tenant_id, &req.email).await?;
        let user = match maybe_user {
            Some(u) => u,
            None => {
                let _ = verify_password(&req.password, DUMMY_HASH);
                let _ = self
                    .audit
                    .record(
                        Some(tenant_id),
                        None,
                        ip,
                        AuditEvent::LoginFailed {
                            email: req.email.clone(),
                            ip: ip.map(|i| i.to_string()),
                            reason: "no such user".into(),
                        },
                    )
                    .await;
                return Err(AuthError::AccessDenied("invalid credentials".into()));
            }
        };

        if !matches!(user.status, UserStatus::Active) {
            let _ = self
                .audit
                .record(
                    Some(user.tenant_id),
                    Some(user.id),
                    ip,
                    AuditEvent::LoginFailed {
                        email: req.email.clone(),
                        ip: ip.map(|i| i.to_string()),
                        reason: format!("status={}", user.status.as_str()),
                    },
                )
                .await;
            return Err(AuthError::Forbidden("account is not active".into()));
        }

        let stored_hash = match user.password_hash.as_deref() {
            Some(h) => h,
            None => {
                // Federated-only user. Tell them to use SSO without
                // confirming or denying the email.
                let _ = verify_password(&req.password, DUMMY_HASH);
                return Err(AuthError::AccessDenied("invalid credentials".into()));
            }
        };
        if !verify_password(&req.password, stored_hash) {
            let _ = self
                .audit
                .record(
                    Some(user.tenant_id),
                    Some(user.id),
                    ip,
                    AuditEvent::LoginFailed {
                        email: req.email.clone(),
                        ip: ip.map(|i| i.to_string()),
                        reason: "wrong password".into(),
                    },
                )
                .await;
            return Err(AuthError::AccessDenied("invalid credentials".into()));
        }

        let session = self
            .sessions
            .create(
                user.id,
                user.tenant_id,
                self.op_session_ttl,
                user_agent,
                ip,
                "urn:mokosh:loa:pwd",
                &["pwd".to_string()],
            )
            .await?;

        let _ = self
            .users
            .update_last_login(user.id, mokosh_auth_core::time::SystemClock.now_or_default())
            .await;
        let _ = self
            .audit
            .record(
                Some(user.tenant_id),
                Some(user.id),
                ip,
                AuditEvent::LoginSuccess {
                    user_id: user.id,
                    ip: ip.map(|i| i.to_string()),
                    user_agent: user_agent.map(str::to_string),
                },
            )
            .await;

        Ok(session)
    }
}

// Helper trait so the storage layer doesn't have to depend on `chrono`'s
// Utc::now in an ad-hoc place.
trait NowOrDefault {
    fn now_or_default(&self) -> chrono::DateTime<chrono::Utc>;
}
impl NowOrDefault for mokosh_auth_core::time::SystemClock {
    fn now_or_default(&self) -> chrono::DateTime<chrono::Utc> {
        use mokosh_auth_core::Clock;
        self.now()
    }
}
