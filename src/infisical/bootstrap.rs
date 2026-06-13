//! First-run bootstrap for a fresh Infisical instance.
//!
//! Drives the API calls that take Infisical from "container is healthy and
//! has never been used" to "Mokosh has the credentials it needs to read and
//! write secrets in a project". The whole flow is seven API calls:
//!
//! 1. `POST /api/v1/admin/signup` - create the first admin (no auth required).
//!    Returns a JWT plus the auto-created admin organization.
//! 2. `POST /api/v3/auth/select-organization` - exchange the user-scoped JWT
//!    for one that carries `organizationId`. All subsequent calls fail with
//!    "no organization found in request" without this step.
//! 3. `POST /api/v1/projects` - create the project that will hold Mokosh's
//!    secrets. The response includes auto-created environments
//!    (`dev`, `staging`, `prod`); we use `dev` by default.
//! 4. `POST /api/v1/projects/{id}/identities` - create a project-scoped
//!    machine identity. The endpoint creates the membership row but
//!    silently assigns the `no-access` role; the next call promotes it.
//! 5. `PATCH /api/v2/workspace/{id}/identity-memberships/{identityId}` -
//!    set the membership role to `admin` so the identity can read/write
//!    secrets and create folders inside the project.
//! 6. `POST /api/v1/auth/universal-auth/identities/{id}` - attach Universal
//!    Auth to the identity. Trusted IPs must be CIDR ranges (use `0.0.0.0/0`
//!    for "any"; a bare IP is treated as `/32` and triggers Infisical's paid
//!    plan IP-restriction feature). The response includes the new `clientId`.
//! 7. `POST /api/v1/auth/universal-auth/identities/{id}/client-secrets` -
//!    create a client secret. The full secret value is returned only here,
//!    so we capture it on the spot.
//!
//! Every request carries a `User-Agent` header (set on the underlying
//! `reqwest::Client`). At least `select-organization` rejects requests
//! without one.
//!
//! The function is idempotent only on a fresh instance. Re-running against
//! an Infisical that already has an admin will fail at step 1 with a
//! 4xx/5xx error from the server. That is intentional: re-bootstrapping is
//! a destructive operation and should be a separate code path.

use std::time::Duration;

use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

use crate::utils::error::AppError;

/// Inputs for [`bootstrap_infisical`]. All `*_name` and credential fields
/// are required; description fields default to sensible values when omitted.
#[derive(Debug, Clone)]
pub struct BootstrapInput {
    /// Email for the admin user. Used as the login identifier.
    pub admin_email: String,
    /// Password for the admin user. Must satisfy Infisical's policy
    /// (at the time of writing: at least 12 characters).
    pub admin_password: String,
    /// First name for the admin user (cosmetic).
    pub admin_first_name: String,
    /// Last name for the admin user (cosmetic).
    pub admin_last_name: String,
    /// Display name for the project Infisical will create.
    pub project_name: String,
    /// Optional project description. Empty string when `None`.
    pub project_description: Option<String>,
    /// Display name for the machine identity Mokosh will use.
    pub identity_name: String,
    /// Optional description for the client secret. Defaults to a generic
    /// "Mokosh bootstrap" tag.
    pub client_secret_description: Option<String>,
    /// Environment slug to surface in [`BootstrapOutput::environment`].
    /// Defaults to `"dev"`, which Infisical creates automatically.
    pub environment_slug: Option<String>,
}

/// Everything Mokosh needs to talk to the freshly-bootstrapped Infisical
/// instance. The caller writes `client_id` and `client_secret` (plus
/// `project_id` and `environment`) into Mokosh's runtime configuration.
#[derive(Debug, Clone)]
pub struct BootstrapOutput {
    pub user_id: String,
    pub organization_id: String,
    pub project_id: String,
    pub project_slug: String,
    pub environment: String,
    pub identity_id: String,
    pub client_id: String,
    /// Plain-text client secret. Returned only once by Infisical; the caller
    /// is responsible for storing it securely.
    pub client_secret: String,
}

// --- Wire types ---------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AdminSignupReq<'a> {
    email: &'a str,
    password: &'a str,
    first_name: &'a str,
    last_name: &'a str,
}

#[derive(Deserialize)]
struct AdminSignupResp {
    token: String,
    user: IdShape,
    organization: IdShape,
}

#[derive(Deserialize)]
struct IdShape {
    id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SelectOrgReq<'a> {
    organization_id: &'a str,
}

#[derive(Deserialize)]
struct SelectOrgResp {
    token: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateProjectReq<'a> {
    project_name: &'a str,
    project_description: &'a str,
    template: &'a str,
    #[serde(rename = "type")]
    kind: &'a str,
}

#[derive(Deserialize)]
struct CreateProjectResp {
    project: ProjectShape,
}

#[derive(Deserialize)]
struct ProjectShape {
    id: String,
    slug: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateFolderReq<'a> {
    workspace_id: &'a str,
    environment: &'a str,
    path: &'a str,
    name: &'a str,
}

/// Folders the runtime needs to write secrets into. The Universal Auth
/// identity has secret-write but not folder-create permissions, so the
/// bootstrap admin token (which has full perms) must pre-create them.
///
/// Each Mokosh module gets its own top-level folder so the admin UI in
/// Infisical groups them naturally.
const MOKOSH_FOLDERS: &[(&str, &str)] = &[
    ("/", "mokosh"),
    ("/mokosh", "tenants"),
    ("/mokosh", "integrations"),
];

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateIdentityReq<'a> {
    name: &'a str,
    has_delete_protection: bool,
    metadata: &'a [serde_json::Value],
}

#[derive(Deserialize)]
struct CreateIdentityResp {
    identity: IdShape,
}

#[derive(Serialize)]
struct RoleAssignment<'a> {
    role: &'a str,
}

#[derive(Serialize)]
struct UpdateMembershipReq<'a> {
    roles: &'a [RoleAssignment<'a>],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TrustedIp<'a> {
    ip_address: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AttachUaReq<'a> {
    client_secret_trusted_ips: &'a [TrustedIp<'a>],
    access_token_trusted_ips: &'a [TrustedIp<'a>],
    // serde(rename_all = "camelCase") would emit "accessTokenTtl"; Infisical
    // wants the all-caps acronym form on these three fields.
    #[serde(rename = "accessTokenTTL")]
    access_token_ttl: u32,
    #[serde(rename = "accessTokenMaxTTL")]
    access_token_max_ttl: u32,
    access_token_num_uses_limit: u32,
}

#[derive(Deserialize)]
struct AttachUaResp {
    #[serde(rename = "identityUniversalAuth")]
    universal_auth: UaShape,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UaShape {
    client_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateClientSecretReq<'a> {
    description: &'a str,
    ttl: u32,
    num_uses_limit: u32,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateClientSecretResp {
    client_secret: String,
}

// --- HTTP helper --------------------------------------------------------

struct BootstrapClient {
    base_url: String,
    http: Client,
    token: Option<String>,
}

/// User-Agent sent on every bootstrap request. Infisical rejects requests
/// without a User-Agent on some endpoints (for example,
/// `/api/v3/auth/select-organization` returns a 401 with
/// `"User-Agent header is required"`).
const USER_AGENT: &str = concat!("mokosh-bootstrap/", env!("CARGO_PKG_VERSION"));

impl BootstrapClient {
    fn new(base_url: &str) -> Result<Self, AppError> {
        let http = Client::builder()
            .user_agent(USER_AGENT)
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| {
                AppError::external_service(
                    "Infisical",
                    format!("Failed to create HTTP client: {}", e),
                )
            })?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            http,
            token: None,
        })
    }

    fn auth_header(&self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.token {
            Some(t) => builder.header("Authorization", format!("Bearer {}", t)),
            None => builder,
        }
    }

    async fn post<Req: Serialize, Resp: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &Req,
    ) -> Result<Resp, AppError> {
        let url = format!("{}{}", self.base_url, path);
        debug!("POST {}", url);
        let resp = self
            .auth_header(self.http.post(&url).json(body))
            .send()
            .await
            .map_err(|e| {
                AppError::external_service(
                    "Infisical",
                    format!("Request to {} failed: {}", path, e),
                )
            })?;
        Self::parse_json(path, resp).await
    }

    async fn patch<Req: Serialize, Resp: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &Req,
    ) -> Result<Resp, AppError> {
        let url = format!("{}{}", self.base_url, path);
        debug!("PATCH {}", url);
        let resp = self
            .auth_header(self.http.patch(&url).json(body))
            .send()
            .await
            .map_err(|e| {
                AppError::external_service(
                    "Infisical",
                    format!("Request to {} failed: {}", path, e),
                )
            })?;
        Self::parse_json(path, resp).await
    }

    async fn parse_json<Resp: for<'de> Deserialize<'de>>(
        path: &str,
        resp: reqwest::Response,
    ) -> Result<Resp, AppError> {
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(AppError::external_service(
                "Infisical",
                format!(
                    "Infisical bootstrap call {} returned {}: {}",
                    path, status, body
                ),
            ));
        }
        resp.json::<Resp>().await.map_err(|e| {
            AppError::external_service(
                "Infisical",
                format!("Failed to parse response from {}: {}", path, e),
            )
        })
    }

    /// Create a folder; treat "already exists" as success so re-bootstrap
    /// against a partially-set-up project is idempotent.
    async fn create_folder(
        &self,
        workspace_id: &str,
        environment: &str,
        path: &str,
        name: &str,
    ) -> Result<(), AppError> {
        debug!("Creating folder {}/{} (env {})", path, name, environment);
        let req = CreateFolderReq {
            workspace_id,
            environment,
            path,
            name,
        };
        match self
            .post::<_, serde_json::Value>("/api/v1/folders", &req)
            .await
        {
            Ok(_) => Ok(()),
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("already exists") || msg.contains("409") {
                    Ok(())
                } else {
                    Err(e)
                }
            }
        }
    }
}

// --- Public entry point -------------------------------------------------

/// Run the full first-run bootstrap. See the module-level documentation
/// for the exact API calls performed.
pub async fn bootstrap_infisical(
    base_url: &str,
    input: &BootstrapInput,
) -> Result<BootstrapOutput, AppError> {
    let mut client = BootstrapClient::new(base_url)?;

    info!("Bootstrapping Infisical at {}", base_url);

    // 1. Admin signup (no auth).
    info!("Creating admin user {}", input.admin_email);
    let signup: AdminSignupResp = client
        .post(
            "/api/v1/admin/signup",
            &AdminSignupReq {
                email: &input.admin_email,
                password: &input.admin_password,
                first_name: &input.admin_first_name,
                last_name: &input.admin_last_name,
            },
        )
        .await?;
    client.token = Some(signup.token);

    // 2. Exchange user-scoped token for an org-scoped one.
    info!("Scoping token to organization {}", signup.organization.id);
    let selected: SelectOrgResp = client
        .post(
            "/api/v3/auth/select-organization",
            &SelectOrgReq {
                organization_id: &signup.organization.id,
            },
        )
        .await?;
    client.token = Some(selected.token);

    // 3. Create the project; environments are auto-created.
    info!("Creating project {:?}", input.project_name);
    let project_resp: CreateProjectResp = client
        .post(
            "/api/v1/projects",
            &CreateProjectReq {
                project_name: &input.project_name,
                project_description: input.project_description.as_deref().unwrap_or(""),
                template: "default",
                kind: "secret-manager",
            },
        )
        .await?;
    let project = project_resp.project;
    let environment = input
        .environment_slug
        .clone()
        .unwrap_or_else(|| "dev".to_string());

    // 3a. Pre-create the folders the runtime will write secrets into.
    //     The Universal Auth identity created below has secret-write but
    //     not folder-create permissions, so this has to happen now using
    //     the org-scoped admin token.
    for (parent, name) in MOKOSH_FOLDERS {
        client
            .create_folder(&project.id, &environment, parent, name)
            .await?;
    }
    info!(
        "Created application folder hierarchy ({} folders) in project {}",
        MOKOSH_FOLDERS.len(),
        project.id
    );

    // 4. Create the machine identity. The project-scoped endpoint adds the
    //    identity as a project member but with the `no-access` role; step 5
    //    promotes it to `admin` so it can read/write secrets and folders.
    info!("Creating machine identity {:?}", input.identity_name);
    let identity_resp: CreateIdentityResp = client
        .post(
            &format!("/api/v1/projects/{}/identities", project.id),
            &CreateIdentityReq {
                name: &input.identity_name,
                has_delete_protection: false,
                metadata: &[],
            },
        )
        .await?;
    let identity_id = identity_resp.identity.id;

    // 5. Promote the project membership to admin. Without this, every
    //    secret-write call from the runtime returns a 403 "Cannot execute
    //    create on secrets" because the default no-access role grants
    //    nothing inside the project.
    info!(
        "Granting admin role to identity {} in project {}",
        identity_id, project.id
    );
    let _: serde_json::Value = client
        .patch(
            &format!(
                "/api/v2/workspace/{}/identity-memberships/{}",
                project.id, identity_id
            ),
            &UpdateMembershipReq {
                roles: &[RoleAssignment { role: "admin" }],
            },
        )
        .await?;

    // 6. Attach Universal Auth (returns the new client ID).
    //    `0.0.0.0/0` is the wildcard form that does not trip Infisical's
    //    paid-plan "IP access range" gate; a bare `0.0.0.0` is read as `/32`.
    info!("Attaching Universal Auth to identity {}", identity_id);
    let wildcard = [TrustedIp {
        ip_address: "0.0.0.0/0",
    }];
    let ua: AttachUaResp = client
        .post(
            &format!("/api/v1/auth/universal-auth/identities/{}", identity_id),
            &AttachUaReq {
                client_secret_trusted_ips: &wildcard,
                access_token_trusted_ips: &wildcard,
                access_token_ttl: 2_592_000,
                access_token_max_ttl: 2_592_000,
                access_token_num_uses_limit: 0,
            },
        )
        .await?;

    // 7. Create the client secret.
    info!("Creating client secret for identity {}", identity_id);
    let secret: CreateClientSecretResp = client
        .post(
            &format!(
                "/api/v1/auth/universal-auth/identities/{}/client-secrets",
                identity_id
            ),
            &CreateClientSecretReq {
                description: input
                    .client_secret_description
                    .as_deref()
                    .unwrap_or("Mokosh bootstrap"),
                ttl: 0,
                num_uses_limit: 0,
            },
        )
        .await?;

    Ok(BootstrapOutput {
        user_id: signup.user.id,
        organization_id: signup.organization.id,
        project_id: project.id,
        project_slug: project.slug,
        environment,
        identity_id,
        client_id: ua.universal_auth.client_id,
        client_secret: secret.client_secret,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_input() -> BootstrapInput {
        BootstrapInput {
            admin_email: "admin@example.com".to_string(),
            admin_password: "supersecret123!".to_string(),
            admin_first_name: "Ada".to_string(),
            admin_last_name: "Lovelace".to_string(),
            project_name: "mokosh".to_string(),
            project_description: None,
            identity_name: "mokosh-machine".to_string(),
            client_secret_description: None,
            environment_slug: None,
        }
    }

    #[test]
    fn signup_request_uses_camel_case() {
        let req = AdminSignupReq {
            email: "a@b.c",
            password: "p",
            first_name: "F",
            last_name: "L",
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"firstName\":\"F\""), "{}", json);
        assert!(json.contains("\"lastName\":\"L\""), "{}", json);
    }

    #[test]
    fn select_org_request_uses_camel_case() {
        let req = SelectOrgReq {
            organization_id: "org-123",
        };
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(json, r#"{"organizationId":"org-123"}"#);
    }

    #[test]
    fn create_project_request_uses_camel_case_and_keeps_type_key() {
        let req = CreateProjectReq {
            project_name: "p",
            project_description: "",
            template: "default",
            kind: "secret-manager",
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"projectName\":\"p\""), "{}", json);
        assert!(json.contains("\"projectDescription\":\"\""), "{}", json);
        assert!(json.contains("\"type\":\"secret-manager\""), "{}", json);
    }

    #[test]
    fn create_identity_request_uses_camel_case() {
        let req = CreateIdentityReq {
            name: "id",
            has_delete_protection: false,
            metadata: &[],
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"hasDeleteProtection\":false"), "{}", json);
    }

    #[test]
    fn create_client_secret_request_uses_camel_case() {
        let req = CreateClientSecretReq {
            description: "d",
            ttl: 0,
            num_uses_limit: 0,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"numUsesLimit\":0"), "{}", json);
    }

    #[test]
    fn signup_response_parses_real_payload() {
        let body = r#"{
            "message":"Successfully set up admin account",
            "user":{"id":"7650a105-9f96-45e4-a399-c5e76a3381c7"},
            "organization":{"id":"f7eec429-82ad-494f-8e4a-c2360b722e65"},
            "token":"eyJjwt"
        }"#;
        let resp: AdminSignupResp = serde_json::from_str(body).unwrap();
        assert_eq!(resp.user.id, "7650a105-9f96-45e4-a399-c5e76a3381c7");
        assert_eq!(resp.organization.id, "f7eec429-82ad-494f-8e4a-c2360b722e65");
        assert_eq!(resp.token, "eyJjwt");
    }

    #[test]
    fn create_project_response_parses_real_payload() {
        let body = r#"{
            "project":{
                "id":"e1687b4a-c6da-4d6c-b63c-8bab4c7d5769",
                "slug":"mokosh-3-p1l",
                "environments":[{"slug":"dev"},{"slug":"staging"},{"slug":"prod"}]
            }
        }"#;
        let resp: CreateProjectResp = serde_json::from_str(body).unwrap();
        assert_eq!(resp.project.id, "e1687b4a-c6da-4d6c-b63c-8bab4c7d5769");
        assert_eq!(resp.project.slug, "mokosh-3-p1l");
    }

    #[test]
    fn attach_ua_request_uses_camel_case_and_cidr() {
        let wildcard = [TrustedIp {
            ip_address: "0.0.0.0/0",
        }];
        let req = AttachUaReq {
            client_secret_trusted_ips: &wildcard,
            access_token_trusted_ips: &wildcard,
            access_token_ttl: 2_592_000,
            access_token_max_ttl: 2_592_000,
            access_token_num_uses_limit: 0,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"clientSecretTrustedIps\""), "{}", json);
        assert!(json.contains("\"accessTokenTTL\":2592000"), "{}", json);
        assert!(json.contains("\"ipAddress\":\"0.0.0.0/0\""), "{}", json);
        // A bare 0.0.0.0 (without prefix) would trip Infisical's paid plan
        // gate. Make sure that's not what we send.
        assert!(!json.contains("\"ipAddress\":\"0.0.0.0\""), "{}", json);
    }

    #[test]
    fn attach_ua_response_parses_real_payload() {
        let body = r#"{
            "identityUniversalAuth":{
                "id":"6c697187-b590-4503-a8a9-001146b6b176",
                "clientId":"10d90334-2a67-4f04-b928-e6665743cec3",
                "identityId":"6eeaaec0-1c96-4a3b-82f7-d8a7b4ff3b02"
            }
        }"#;
        let resp: AttachUaResp = serde_json::from_str(body).unwrap();
        assert_eq!(
            resp.universal_auth.client_id,
            "10d90334-2a67-4f04-b928-e6665743cec3"
        );
    }

    #[test]
    fn create_client_secret_response_parses_real_payload() {
        let body = r#"{
            "clientSecret":"e83bcdeb501b6c5d8f9f16be4c7f5ad48c3cb40ad6de730e25f9e2703dacdb44",
            "clientSecretData":{"id":"e5fda7de-7c73-49d2-a45e-bd5cf31784ce"}
        }"#;
        let resp: CreateClientSecretResp = serde_json::from_str(body).unwrap();
        assert!(resp.client_secret.starts_with("e83bcdeb"));
        assert_eq!(resp.client_secret.len(), 64);
    }

    #[test]
    fn input_defaults_environment_to_dev() {
        let input = sample_input();
        assert!(input.environment_slug.is_none());
        let default: &str = input.environment_slug.as_deref().unwrap_or("dev");
        assert_eq!(default, "dev");
    }
}
