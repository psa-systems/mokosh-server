//! Infisical API client with Universal Auth authentication.

use std::sync::Arc;
use std::time::{Duration, Instant};

use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::error::CoreError;

/// Default token expiry margin (refresh 5 minutes before expiry).
const TOKEN_EXPIRY_MARGIN: Duration = Duration::from_secs(300);

/// Authentication token with expiry tracking.
#[derive(Debug, Clone)]
struct AuthToken {
    access_token: String,
    expires_at: Instant,
}

impl AuthToken {
    fn is_valid(&self) -> bool {
        Instant::now() + TOKEN_EXPIRY_MARGIN < self.expires_at
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LoginResponse {
    access_token: String,
    expires_in: u64,
    #[allow(dead_code)]
    token_type: String,
    #[allow(dead_code)]
    access_token_max_ttl: Option<u64>,
}

/// Infisical API client.
///
/// Uses Universal Auth (machine identities) to authenticate with Infisical.
/// The client automatically manages token refresh when tokens expire.
pub struct InfisicalClient {
    base_url: String,
    client_id: String,
    client_secret: String,
    http: Client,
    token: Arc<RwLock<Option<AuthToken>>>,
}

impl InfisicalClient {
    /// Create a new Infisical client.
    ///
    /// This does not authenticate immediately; authentication happens
    /// on the first API call.
    pub async fn new(
        base_url: &str,
        client_id: &str,
        client_secret: &str,
    ) -> Result<Self, CoreError> {
        let http = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| {
                CoreError::ExternalService(format!("Failed to create HTTP client: {}", e))
            })?;

        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            http,
            token: Arc::new(RwLock::new(None)),
        })
    }

    async fn authenticate(&self) -> Result<AuthToken, CoreError> {
        info!("Authenticating with Infisical");

        let url = format!("{}/api/v1/auth/universal-auth/login", self.base_url);

        let response = self
            .http
            .post(&url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(format!(
                "clientId={}&clientSecret={}",
                urlencoding::encode(&self.client_id),
                urlencoding::encode(&self.client_secret)
            ))
            .send()
            .await
            .map_err(|e| {
                CoreError::ExternalService(format!("Infisical auth request failed: {}", e))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(CoreError::ExternalService(format!(
                "Infisical authentication failed ({}): {}",
                status, body
            )));
        }

        let login: LoginResponse = response.json().await.map_err(|e| {
            CoreError::ExternalService(format!("Failed to parse auth response: {}", e))
        })?;

        let expires_at = Instant::now() + Duration::from_secs(login.expires_in);

        debug!(
            "Infisical authentication successful, token expires in {} seconds",
            login.expires_in
        );

        Ok(AuthToken {
            access_token: login.access_token,
            expires_at,
        })
    }

    /// Ensure we have a valid token, refreshing if necessary.
    pub async fn ensure_authenticated(&self) -> Result<String, CoreError> {
        {
            let token = self.token.read().await;
            if let Some(ref t) = *token {
                if t.is_valid() {
                    return Ok(t.access_token.clone());
                }
            }
        }

        let mut token = self.token.write().await;

        if let Some(ref t) = *token {
            if t.is_valid() {
                return Ok(t.access_token.clone());
            }
        }

        let new_token = self.authenticate().await?;
        let access_token = new_token.access_token.clone();
        *token = Some(new_token);

        Ok(access_token)
    }

    /// Make an authenticated GET request.
    pub async fn get(&self, path: &str) -> Result<reqwest::Response, CoreError> {
        let token = self.ensure_authenticated().await?;
        let url = format!("{}{}", self.base_url, path);

        debug!("GET {}", url);

        let response = self
            .http
            .get(&url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .map_err(|e| CoreError::ExternalService(format!("Request failed: {}", e)))?;

        self.check_response(response).await
    }

    /// Make an authenticated POST request.
    pub async fn post<T: Serialize>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<reqwest::Response, CoreError> {
        let token = self.ensure_authenticated().await?;
        let url = format!("{}{}", self.base_url, path);

        debug!("POST {}", url);

        let response = self
            .http
            .post(&url)
            .header("Authorization", format!("Bearer {}", token))
            .json(body)
            .send()
            .await
            .map_err(|e| CoreError::ExternalService(format!("Request failed: {}", e)))?;

        self.check_response(response).await
    }

    /// Make an authenticated PATCH request.
    pub async fn patch<T: Serialize>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<reqwest::Response, CoreError> {
        let token = self.ensure_authenticated().await?;
        let url = format!("{}{}", self.base_url, path);

        debug!("PATCH {}", url);

        let response = self
            .http
            .patch(&url)
            .header("Authorization", format!("Bearer {}", token))
            .json(body)
            .send()
            .await
            .map_err(|e| CoreError::ExternalService(format!("Request failed: {}", e)))?;

        self.check_response(response).await
    }

    /// Make an authenticated DELETE request.
    pub async fn delete<T: Serialize>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<reqwest::Response, CoreError> {
        let token = self.ensure_authenticated().await?;
        let url = format!("{}{}", self.base_url, path);

        debug!("DELETE {}", url);

        let response = self
            .http
            .delete(&url)
            .header("Authorization", format!("Bearer {}", token))
            .json(body)
            .send()
            .await
            .map_err(|e| CoreError::ExternalService(format!("Request failed: {}", e)))?;

        self.check_response(response).await
    }

    async fn check_response(
        &self,
        response: reqwest::Response,
    ) -> Result<reqwest::Response, CoreError> {
        let status = response.status();

        if status.is_success() {
            return Ok(response);
        }

        match status.as_u16() {
            401 => {
                // Token might be expired, clear it for next retry.
                warn!("Infisical returned 401, clearing token");
                let mut token = self.token.write().await;
                *token = None;
                Err(CoreError::AuthenticationFailed(
                    "Infisical authentication failed".to_string(),
                ))
            }
            403 => Err(CoreError::AuthorizationDenied(
                "Infisical access denied: insufficient permissions".to_string(),
            )),
            404 => {
                let body = response.text().await.unwrap_or_default();
                Err(CoreError::NotFound(format!(
                    "Infisical resource not found: {}",
                    body
                )))
            }
            _ => {
                let body = response.text().await.unwrap_or_default();
                Err(CoreError::ExternalService(format!(
                    "Infisical API error ({}): {}",
                    status, body
                )))
            }
        }
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }
}

impl std::fmt::Debug for InfisicalClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InfisicalClient")
            .field("base_url", &self.base_url)
            .field("client_id", &self.client_id)
            .field("client_secret", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn client_creation() {
        let client = InfisicalClient::new(
            "https://app.infisical.com",
            "test-client-id",
            "test-client-secret",
        )
        .await
        .unwrap();

        assert_eq!(client.base_url(), "https://app.infisical.com");
    }

    #[tokio::test]
    async fn client_strips_trailing_slash() {
        let client = InfisicalClient::new(
            "https://app.infisical.com/",
            "test-client-id",
            "test-client-secret",
        )
        .await
        .unwrap();

        assert_eq!(client.base_url(), "https://app.infisical.com");
    }

    #[test]
    fn token_validity() {
        let valid = AuthToken {
            access_token: "test".to_string(),
            expires_at: Instant::now() + Duration::from_secs(3600),
        };
        assert!(valid.is_valid());

        let expired = AuthToken {
            access_token: "test".to_string(),
            expires_at: Instant::now() - Duration::from_secs(1),
        };
        assert!(!expired.is_valid());

        // Within the 5-minute refresh margin: treated as not valid so we refresh early.
        let expiring_soon = AuthToken {
            access_token: "test".to_string(),
            expires_at: Instant::now() + Duration::from_secs(60),
        };
        assert!(!expiring_soon.is_valid());
    }

    #[test]
    fn debug_redacts_client_secret() {
        let format = format!(
            "{:?}",
            InfisicalClient {
                base_url: "https://test.com".to_string(),
                client_id: "id".to_string(),
                client_secret: "super-secret".to_string(),
                http: Client::new(),
                token: Arc::new(RwLock::new(None)),
            }
        );
        assert!(format.contains("[REDACTED]"));
        assert!(!format.contains("super-secret"));
    }
}
