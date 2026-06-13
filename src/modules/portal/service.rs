//! Portal authentication and contact-session issuance.
//!
//! Mirrors the agent-side `AuthService::login` shape but reads from the
//! `contacts` table and mints HS256 JWTs tagged with `typ =
//! "portal_access"` so the middleware can distinguish them from agent
//! tokens.

use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use uuid::Uuid;

use crate::db::Database;
use crate::utils::crypto::{hash_password, verify_password};
use crate::utils::error::{AppError, AppResult};

use super::models::*;

/// Portal-side counterpart to `AuthService`. Stateless except for the
/// JWT signing secret and the database handle.
#[derive(Clone)]
pub struct PortalAuthService {
    db: Database,
    jwt_secret: String,
    access_token_ttl: Duration,
}

impl PortalAuthService {
    pub fn new(db: Database, jwt_secret: String) -> Self {
        Self {
            db,
            jwt_secret,
            access_token_ttl: Duration::hours(8),
        }
    }

    /// Verify (tenant_slug, email, password) against the contacts table
    /// and issue a portal JWT on success. Returns 401 on any failure
    /// path so the surface stays enumeration-resistant.
    #[allow(clippy::type_complexity)]
    #[tracing::instrument(skip_all)]
    pub async fn login(&self, request: &PortalLoginRequest) -> AppResult<PortalLoginResponse> {
        let row: Option<(
            Uuid,
            Uuid,
            Uuid,
            String,
            String,
            String,
            bool,
            Option<String>,
        )> = sqlx::query_as(
            r#"
                SELECT c.id, c.tenant_id, c.company_id, c.email, c.first_name,
                       c.last_name, c.is_portal_user, c.portal_password_hash
                FROM contacts c
                INNER JOIN tenants t ON c.tenant_id = t.id
                WHERE t.slug = $1 AND c.email = $2 AND t.status = 'active'
                "#,
        )
        .bind(&request.tenant_slug)
        .bind(&request.email)
        .fetch_optional(self.db.pool())
        .await?;

        let Some((id, tenant_id, company_id, email, first_name, last_name, is_portal_user, hash)) =
            row
        else {
            return Err(AppError::Unauthorized);
        };

        if !is_portal_user {
            return Err(AppError::Unauthorized);
        }
        let Some(hash) = hash else {
            return Err(AppError::Unauthorized);
        };
        if !verify_password(&request.password, &hash)? {
            return Err(AppError::Unauthorized);
        }

        sqlx::query(
            "UPDATE contacts SET portal_last_login_at = NOW(), updated_at = NOW() WHERE id = $1",
        )
        .bind(id)
        .execute(self.db.pool())
        .await?;

        let now = Utc::now();
        let expires_at = now + self.access_token_ttl;
        let claims = PortalJwtClaims {
            sub: id,
            tid: tenant_id,
            cid: company_id,
            email: email.clone(),
            iat: now.timestamp(),
            exp: expires_at.timestamp(),
            typ: "portal_access".to_string(),
        };
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.jwt_secret.as_bytes()),
        )
        .map_err(|e| AppError::Internal(format!("portal jwt sign: {e}")))?;

        Ok(PortalLoginResponse {
            access_token: token,
            expires_at,
            contact: CurrentContact {
                id,
                tenant_id,
                company_id,
                email,
                first_name,
                last_name,
            },
        })
    }

    /// Re-read a contact's display names from the `contacts` row. The
    /// portal JWT omits names (PII minimisation), so the middleware
    /// hydrates `first_name` / `last_name` for `/me`-style handlers after
    /// decoding the token (PMS-195). Scoped by `(tenant_id, id)`.
    pub async fn contact_names(
        &self,
        tenant_id: Uuid,
        contact_id: Uuid,
    ) -> AppResult<Option<(String, String)>> {
        let row: Option<(String, String)> = sqlx::query_as(
            "SELECT first_name, last_name FROM contacts WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(contact_id)
        .fetch_optional(self.db.pool())
        .await?;
        Ok(row)
    }

    /// Decode + validate a portal JWT. Rejects anything that isn't
    /// `typ = "portal_access"` so an agent's access token cannot be
    /// replayed against the portal surface.
    pub fn decode_token(&self, token: &str) -> AppResult<PortalJwtClaims> {
        let data = decode::<PortalJwtClaims>(
            token,
            &DecodingKey::from_secret(self.jwt_secret.as_bytes()),
            &Validation::default(),
        )
        .map_err(|_| AppError::Unauthorized)?;
        if data.claims.typ != "portal_access" {
            return Err(AppError::Unauthorized);
        }
        Ok(data.claims)
    }

    /// Redeem a single-use portal setup token and set the contact's
    /// password (PMS-136). The token is `{contact_id}.{secret}`; only the
    /// Argon2 hash of the secret is stored (`portal_setup_tokens`), so the
    /// lookup is scoped by `contact_id` and each candidate row's hash is
    /// verified in turn. Status contract:
    ///
    /// - valid, unused, unexpired -> sets `portal_password_hash`, marks the
    ///   token used, returns `Ok(())` (the handler maps to 204).
    /// - already redeemed -> `AppError::Gone` (410).
    /// - expired -> `AppError::BadRequest` (400).
    /// - no matching token -> `AppError::BadRequest` (400), so a guessed or
    ///   stale token is indistinguishable from an expired one.
    #[tracing::instrument(skip_all)]
    pub async fn setup_password(&self, token: &str, new_password: &str) -> AppResult<()> {
        if new_password.len() < 8 {
            return Err(AppError::BadRequest(
                "Password must be at least 8 characters".to_string(),
            ));
        }

        let (contact_id, secret) = parse_contact_bound_token(token)
            .ok_or_else(|| AppError::BadRequest("Invalid or expired setup token".to_string()))?;

        // All tokens ever minted for this contact, newest first. We need the
        // used/expired rows too so a replay can be told apart from an expired
        // link. Tokens are salted Argon2 hashes and cannot be looked up by
        // value, so each candidate is verified against the presented secret.
        let candidates =
            sqlx::query_as::<_, (Uuid, Uuid, String, Option<DateTime<Utc>>, DateTime<Utc>)>(
                r#"
            SELECT id, tenant_id, token_hash, used_at, expires_at
            FROM portal_setup_tokens
            WHERE contact_id = $1
            ORDER BY created_at DESC
            "#,
            )
            .bind(contact_id)
            .fetch_all(self.db.pool())
            .await?;

        let mut matched: Option<(Uuid, Uuid)> = None; // (token_id, tenant_id)
        for (token_id, tenant_id, token_hash, used_at, expires_at) in &candidates {
            if verify_password(secret, token_hash)? {
                if used_at.is_some() {
                    return Err(AppError::Gone("Setup token already used".to_string()));
                }
                if *expires_at <= Utc::now() {
                    return Err(AppError::BadRequest(
                        "Invalid or expired setup token".to_string(),
                    ));
                }
                matched = Some((*token_id, *tenant_id));
                break;
            }
        }
        let Some((token_id, tenant_id)) = matched else {
            return Err(AppError::BadRequest(
                "Invalid or expired setup token".to_string(),
            ));
        };

        let hash = hash_password(new_password)?;
        // Tenant-scoped write: set the credential and burn the token in one
        // transaction so a crash cannot leave a usable token behind a set
        // password.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            "UPDATE contacts SET portal_password_hash = $1, is_portal_user = TRUE, updated_at = NOW() \
             WHERE id = $2 AND tenant_id = $3",
        )
        .bind(&hash)
        .bind(contact_id)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE portal_setup_tokens SET used_at = NOW() WHERE id = $1 AND tenant_id = $2",
        )
        .bind(token_id)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;

        Ok(())
    }

    /// Set or replace the portal password for a contact. Surfaces to a
    /// future `PUT /api/v1/portal/auth/password` endpoint that the
    /// customer hits after clicking their setup link.
    #[allow(dead_code)]
    #[tracing::instrument(skip_all)]
    pub async fn set_password(&self, contact_id: Uuid, new_password: &str) -> AppResult<()> {
        if new_password.len() < 8 {
            return Err(AppError::BadRequest(
                "Password must be at least 8 characters".to_string(),
            ));
        }
        let hash = hash_password(new_password)?;
        sqlx::query(
            "UPDATE contacts SET portal_password_hash = $1, is_portal_user = TRUE, updated_at = NOW() WHERE id = $2",
        )
        .bind(&hash)
        .bind(contact_id)
        .execute(self.db.pool())
        .await?;
        Ok(())
    }
}

/// Split a portal setup token `{contact_id}.{secret}` into its parts.
/// Mirrors the user-bound reset token shape in `auth::service` so the
/// stored hash can be scoped to a single contact. Returns `None` for any
/// malformed token (no dot, unparseable id, empty secret).
fn parse_contact_bound_token(token: &str) -> Option<(Uuid, &str)> {
    let (id, secret) = token.split_once('.')?;
    if secret.is_empty() {
        return None;
    }
    let contact_id = Uuid::parse_str(id).ok()?;
    Some((contact_id, secret))
}
