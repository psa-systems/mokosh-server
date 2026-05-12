//! Local password authentication for the OP's own login UI.
//!
//! Distinct from `mokosh-auth-oidc`: that crate deals with the OIDC
//! protocol surface (authorize/token/userinfo). This module is what
//! happens when a user types email + password into our login form.
//! Successful login creates an OP session whose `sid` becomes the cookie
//! value the browser then carries on every subsequent request.

use chrono::Duration;
use mokosh_auth_core::{
    AuditEvent, AuthError, OpSession, OpSessionRepository, TenantId, User, UserRepository,
    UserStatus,
};
use mokosh_auth_crypto::password::verify_password;
use serde::Deserialize;
use std::sync::Arc;

#[derive(Debug, Clone, Deserialize)]
pub struct LocalLoginRequest {
    /// Optional. When omitted, the tenant is resolved by looking up the
    /// email globally (`UserRepository::find_by_email_globally`). The
    /// override is kept for service-account or admin flows that need to
    /// pin a specific tenant unambiguously.
    #[serde(default)]
    pub tenant_id: Option<uuid::Uuid>,
    pub email: String,
    pub password: String,
}

/// Result of a successful local-password login. Bundles the OP session
/// (whose `sid` becomes the cookie value) with the authenticated User
/// so HTTP-layer callers can mint OIDC tokens for first-party SPA
/// clients without an extra `users.find_by_id` round-trip.
pub struct LocalLoginOk {
    pub session: OpSession,
    pub user: User,
}

pub struct LocalAuth {
    pub users: Arc<dyn UserRepository>,
    pub sessions: Arc<dyn OpSessionRepository>,
    pub audit: Arc<dyn mokosh_auth_core::AuditLogger>,
    pub op_session_ttl: Duration,
    /// Consecutive-failure count that triggers a lock. Defaults to 5
    /// when constructed via `bootstrap.rs` (overridable via
    /// `MOKOSH_AUTH_LOCKOUT_THRESHOLD`).
    pub lockout_threshold: i32,
    /// How long the lock lasts, in seconds. Defaults to 15 minutes.
    pub lockout_seconds: i64,
}

/// Result of password-only verification. Carries the verified `User` but
/// does NOT create an op_session; used by the MFA-required branch of
/// `/v1/auth/login` to issue a challenge before the session exists.
pub struct LocalVerifyOk {
    pub user: User,
}

impl LocalAuth {
    pub async fn login(
        &self,
        req: LocalLoginRequest,
        ip: Option<std::net::IpAddr>,
        user_agent: Option<&str>,
    ) -> Result<LocalLoginOk, AuthError> {
        // Always do a password verification, even when the user does not
        // exist or the tenant is ambiguous, to avoid a username-
        // enumeration timing oracle. We use a fixed dummy hash known to
        // never match.
        const DUMMY_HASH: &str =
            "$argon2id$v=19$m=65536,t=3,p=4$ZHVtbXkxMjM0NTY3OA$\
             SGEgaGEgdGhpcyBpcyBub3QgcmVhbCBoYXNoIGxlbmd0aA";

        let user = match req.tenant_id {
            Some(tid) => self
                .users
                .find_by_email(TenantId(tid), &req.email)
                .await?,
            None => {
                // Email-only flow: resolve tenant from the user record.
                // 0 matches: invalid (do not reveal whether the email exists).
                // 1 match:   use that tenant.
                // 2+ matches: ambiguous; refuse without naming the tenants
                //             (telling the user which tenants own the email
                //             is itself an enumeration oracle).
                let mut matches = self.users.find_by_email_globally(&req.email).await?;
                if matches.len() >= 2 {
                    let _ = verify_password(&req.password, DUMMY_HASH);
                    let _ = self
                        .audit
                        .record(
                            None,
                            None,
                            ip,
                            AuditEvent::LoginFailed {
                                email: req.email.clone(),
                                ip: ip.map(|i| i.to_string()),
                                reason: "ambiguous email across tenants".into(),
                            },
                        )
                        .await;
                    return Err(AuthError::AccessDenied("invalid credentials".into()));
                }
                matches.pop()
            }
        };
        let user = match user {
            Some(u) => u,
            None => {
                let _ = verify_password(&req.password, DUMMY_HASH);
                let _ = self
                    .audit
                    .record(
                        req.tenant_id.map(TenantId),
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
        if let Some(locked_until) = self.users.lockout_status(user.id).await? {
            if locked_until > chrono::Utc::now() {
                let _ = verify_password(&req.password, DUMMY_HASH);
                let _ = self
                    .audit
                    .record(
                        Some(user.tenant_id),
                        Some(user.id),
                        ip,
                        AuditEvent::AccountLockoutHit {
                            user_id: user.id,
                            locked_until,
                            ip: ip.map(|i| i.to_string()),
                        },
                    )
                    .await;
                return Err(AuthError::AccessDenied("invalid credentials".into()));
            }
        }
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
            let outcome = self
                .users
                .record_failed_login(
                    user.id,
                    self.lockout_threshold,
                    chrono::Duration::seconds(self.lockout_seconds),
                )
                .await?;
            if let Some(locked_until) = outcome.locked_until {
                if locked_until > chrono::Utc::now() {
                    let _ = self
                        .audit
                        .record(
                            Some(user.tenant_id),
                            Some(user.id),
                            ip,
                            AuditEvent::AccountLocked {
                                user_id: user.id,
                                locked_until,
                                ip: ip.map(|i| i.to_string()),
                            },
                        )
                        .await;
                }
            }
            return Err(AuthError::AccessDenied("invalid credentials".into()));
        }
        let _ = self.users.clear_failed_logins(user.id).await;

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

        Ok(LocalLoginOk { session, user })
    }

    /// Verify-only path: same enumeration-resistant flow as `login`, but
    /// does not create an op_session. The handler is responsible for
    /// session creation downstream (the MFA-verified branch creates the
    /// session inside the same SERIALIZABLE tx that consumes the
    /// challenge). On a wrong password it still emits the same audit
    /// event so the failure trail is identical to `login`.
    pub async fn verify_only(
        &self,
        req: LocalLoginRequest,
        ip: Option<std::net::IpAddr>,
        _user_agent: Option<&str>,
    ) -> Result<LocalVerifyOk, AuthError> {
        const DUMMY_HASH: &str =
            "$argon2id$v=19$m=65536,t=3,p=4$ZHVtbXkxMjM0NTY3OA$\
             SGEgaGEgdGhpcyBpcyBub3QgcmVhbCBoYXNoIGxlbmd0aA";

        let user = match req.tenant_id {
            Some(tid) => self.users.find_by_email(TenantId(tid), &req.email).await?,
            None => {
                let mut matches = self.users.find_by_email_globally(&req.email).await?;
                if matches.len() >= 2 {
                    let _ = verify_password(&req.password, DUMMY_HASH);
                    return Err(AuthError::AccessDenied("invalid credentials".into()));
                }
                matches.pop()
            }
        };
        let user = match user {
            Some(u) => u,
            None => {
                let _ = verify_password(&req.password, DUMMY_HASH);
                return Err(AuthError::AccessDenied("invalid credentials".into()));
            }
        };
        if !matches!(user.status, mokosh_auth_core::UserStatus::Active) {
            let _ = verify_password(&req.password, DUMMY_HASH);
            return Err(AuthError::AccessDenied("invalid credentials".into()));
        }
        let stored_hash = match user.password_hash.as_deref() {
            Some(h) => h,
            None => {
                let _ = verify_password(&req.password, DUMMY_HASH);
                return Err(AuthError::AccessDenied("invalid credentials".into()));
            }
        };
        // Lockout pre-check: refuse the login if the user is still
        // inside the lockout window. We do this AFTER establishing the
        // user identity but BEFORE the password verify; the dummy-hash
        // pass on the early-exit paths keeps the timing oracle closed.
        if let Some(locked_until) = self.users.lockout_status(user.id).await? {
            if locked_until > chrono::Utc::now() {
                let _ = verify_password(&req.password, DUMMY_HASH);
                let _ = self
                    .audit
                    .record(
                        Some(user.tenant_id),
                        Some(user.id),
                        ip,
                        AuditEvent::AccountLockoutHit {
                            user_id: user.id,
                            locked_until,
                            ip: ip.map(|i| i.to_string()),
                        },
                    )
                    .await;
                return Err(AuthError::AccessDenied("invalid credentials".into()));
            }
        }
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
            let outcome = self
                .users
                .record_failed_login(
                    user.id,
                    self.lockout_threshold,
                    chrono::Duration::seconds(self.lockout_seconds),
                )
                .await?;
            if let Some(locked_until) = outcome.locked_until {
                if locked_until > chrono::Utc::now() {
                    let _ = self
                        .audit
                        .record(
                            Some(user.tenant_id),
                            Some(user.id),
                            ip,
                            AuditEvent::AccountLocked {
                                user_id: user.id,
                                locked_until,
                                ip: ip.map(|i| i.to_string()),
                            },
                        )
                        .await;
                }
            }
            return Err(AuthError::AccessDenied("invalid credentials".into()));
        }
        // Successful password: clear the counter.
        let _ = self.users.clear_failed_logins(user.id).await;
        Ok(LocalVerifyOk { user })
    }

    /// Create an op_session for an already-verified user. Mirrors the
    /// session-creation tail of `login`. `acr` and `amr` are set by the
    /// caller so the MFA branch can pass the stronger context class.
    pub async fn create_session(
        &self,
        user: &User,
        ip: Option<std::net::IpAddr>,
        user_agent: Option<&str>,
        acr: &str,
        amr: &[String],
    ) -> Result<OpSession, AuthError> {
        let session = self
            .sessions
            .create(
                user.id,
                user.tenant_id,
                self.op_session_ttl,
                user_agent,
                ip,
                acr,
                amr,
            )
            .await?;
        // `OpSessionRepository::create` is upsert-on-(user_id, user_agent):
        // an existing row (active OR revoked-by-logout) gets its sid
        // rotated and revoked_at cleared in place, preserving display_name
        // and created_at. Cleanup-other-rows is no longer needed here.
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
