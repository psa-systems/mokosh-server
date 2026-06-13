//! Portal authentication and contact-session issuance.
//!
//! Mirrors the agent-side `AuthService::login` shape but reads from the
//! `contacts` table and mints HS256 JWTs tagged with `typ =
//! "portal_access"` so the middleware can distinguish them from agent
//! tokens.

use chrono::{Duration, Utc};
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
        // SAFETY (PMS-285): the portal runs on a separate `contacts`-row identity
        // plane (`CurrentContact`), not the `users`/`AuthState` plane, and
        // per-user RLS isolation is deliberately NOT applied to portal contacts
        // yet (see `dev-docs/rls-per-user-isolation.md`, "Portal identity"). This
        // login is pre-auth - it resolves the contact by `(tenant_slug, email)`
        // before any session exists - so there is no GUC to set and it runs on
        // the migrator pool. `contacts` is RLS-covered, so the app pool would
        // fail this lookup closed.
        .fetch_optional(self.db.migrator_pool())
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

        // SAFETY (PMS-285): companion write to the portal login above, same
        // separate `contacts`-identity plane with portal isolation deferred.
        // Targets the just-authenticated contact by primary key; migrator pool
        // because `contacts` is RLS-covered and the portal plane sets no GUC.
        sqlx::query(
            "UPDATE contacts SET portal_last_login_at = NOW(), updated_at = NOW() WHERE id = $1",
        )
        .bind(id)
        .execute(self.db.migrator_pool())
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
        // SAFETY (PMS-285): portal account setup on the separate
        // `contacts`-identity plane (portal isolation deferred; see the login
        // note above). Reached via an emailed setup link before any portal
        // session exists, so it sets no GUC and targets the one contact by id.
        // Migrator pool because `contacts` is RLS-covered.
        sqlx::query(
            "UPDATE contacts SET portal_password_hash = $1, is_portal_user = TRUE, updated_at = NOW() WHERE id = $2",
        )
        .bind(&hash)
        .bind(contact_id)
        .execute(self.db.migrator_pool())
        .await?;
        Ok(())
    }
}
