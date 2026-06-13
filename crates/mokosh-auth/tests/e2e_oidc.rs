//! End-to-end OIDC flow against a real router on a real TCP socket.
//!
//! Each test gets its own Postgres database via `#[sqlx::test]`, which
//! reads DATABASE_URL and provisions a fresh DB per run.
//!
//! What the happy-path test covers, in order:
//!   1. Anonymous `/oauth2/authorize`            -> 302 to `/login`
//!   2. POST `/login` with email + password      -> 302 back to `/oauth2/authorize`
//!   3. Resumed `/oauth2/authorize` with cookie  -> 302 to `redirect_uri?code=...`
//!   4. POST `/oauth2/token` with code + PKCE    -> JSON access/id/refresh tokens
//!   5. GET `/oauth2/userinfo` with bearer       -> sub + email claims
//!   6. POST `/oauth2/token` refresh grant       -> rotated tokens
//!   7. POST `/oauth2/token` with the OLD refresh token (replay) -> `invalid_grant`
//!   8. POST `/oauth2/token` with the NEW token after replay -> also revoked
//!
//! The server-side schema invariants we rely on:
//!   - PKCE S256 enforced at the DB layer
//!   - SERIALIZABLE refresh rotation revokes the entire family on replay
//!
//! These tests exercise the integration boundary, not the protocol
//! semantics in isolation; the latter has unit coverage in the OIDC
//! engine and policy modules.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Duration;
use ed25519_dalek::pkcs8::{EncodePrivateKey, EncodePublicKey};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration as StdDuration;
use tempfile::TempDir;
use url::Url;

use mokosh_auth::{bootstrap, AuthConfig};

/// All the moving parts a test needs to drive the flow.
struct TestEnv {
    base: Url,
    client_id: uuid::Uuid,
    client_secret: String,
    redirect_uri: String,
    user_id: uuid::Uuid,
    user_email: String,
    user_password: String,
    /// Holding refs so they live as long as the test does.
    _temp: TempDir,
    _server: tokio::task::JoinHandle<()>,
}

async fn make_env(pool: PgPool) -> TestEnv {
    // 1. Minimal `public.tenants` so the auth-side FK is satisfiable.
    //    A real deploy gets the full PSA schema; the e2e test only needs
    //    the columns the auth migrations reference.
    // Two separate queries: sqlx prepares each statement, and Postgres
    // refuses multiple commands in one prepared statement.
    sqlx::query(r#"CREATE EXTENSION IF NOT EXISTS "uuid-ossp""#)
        .execute(&pool)
        .await
        .expect("create uuid-ossp");
    sqlx::query(
        r#"CREATE TABLE IF NOT EXISTS public.tenants (
            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            name VARCHAR(255) NOT NULL,
            slug VARCHAR(100) NOT NULL UNIQUE,
            status VARCHAR(20) NOT NULL DEFAULT 'active',
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )"#,
    )
    .execute(&pool)
    .await
    .expect("create public.tenants");

    // 2. Generate an Ed25519 PKCS#8 PEM keypair into a tempdir. The
    //    OidcKeySet at startup time scans the dir for *.pub.pem files
    //    and matches the active kid.
    let temp = TempDir::new().expect("tempdir");
    let kid = "test-key";
    // Build the signing key from raw bytes to dodge a rand_core version
    // mismatch between ed25519-dalek (0.6) and rand (0.9).
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).expect("getrandom");
    let signing = SigningKey::from_bytes(&seed);
    // Hand-format PEM from the DER bytes. Avoids pulling pkcs8 in just
    // for the LineEnding enum (ed25519_dalek's pkcs8 module doesn't
    // re-export it).
    let priv_der = signing.to_pkcs8_der().expect("encode private der");
    let pub_der = signing
        .verifying_key()
        .to_public_key_der()
        .expect("encode public der");
    let priv_pem = pem_wrap("PRIVATE KEY", priv_der.as_bytes());
    let pub_pem = pem_wrap("PUBLIC KEY", pub_der.as_bytes());
    let priv_path: PathBuf = temp.path().join(format!("{kid}.pem"));
    let pub_path: PathBuf = temp.path().join(format!("{kid}.pub.pem"));
    std::fs::write(&priv_path, priv_pem.as_bytes()).expect("write priv");
    std::fs::write(&pub_path, pub_pem.as_bytes()).expect("write pub");

    // 3. Pre-bind to discover the port. The issuer URL must include the
    //    real port because it is used in the cookie SameSite check, the
    //    JWT `iss` claim, and the login_url that `/oauth2/authorize`
    //    redirects to. Bootstrapping with a placeholder issuer and
    //    "fixing it later" would diverge from the same code path that
    //    runs in production.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind 0");
    let local_addr = listener.local_addr().expect("local_addr");
    let base = Url::parse(&format!("http://{}/", local_addr)).expect("base url");

    let cfg = AuthConfig {
        issuer: base.clone(),
        cookie_domain: None,
        jwt_private_key_path: priv_path,
        jwt_active_kid: kid.into(),
        jwt_public_keys_dir: temp.path().to_path_buf(),
        // 32 bytes of zeros, hex-encoded. Fine for tests; never use in
        // production, where the real key comes from Infisical.
        data_encryption_key: secrecy::SecretString::from("0".repeat(64)),
        data_encryption_key_prev: None,
        data_key_version: 1,
        access_token_ttl: Duration::seconds(600),
        refresh_token_ttl: Duration::seconds(3600),
        refresh_idle_ttl: Duration::seconds(1800),
        authorization_code_ttl: Duration::seconds(60),
        op_session_ttl: Duration::days(1),
    };

    let auth = bootstrap(cfg, pool.clone()).await.expect("bootstrap");

    // 4. Insert a tenant and a test user. The user's password hash
    //    uses the same Argon2id parameters production uses, so this
    //    is also a smoke test of the verifier.
    let tenant_id: uuid::Uuid =
        sqlx::query_scalar("INSERT INTO public.tenants (name, slug) VALUES ($1, $2) RETURNING id")
            .bind("Test Tenant")
            .bind(format!("t-{}", uuid::Uuid::new_v4()))
            .fetch_one(&pool)
            .await
            .expect("insert tenant");

    let user_email = "alice@example.com".to_string();
    let user_password = "Sup3rL0ngPass!".to_string();
    let pw_hash = mokosh_auth_crypto::hash_password(&user_password).expect("hash password");
    let user_id: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO mokosh_auth.users
            (tenant_id, email, password_hash, role, status, email_verified_at)
         VALUES ($1, $2, $3, 'admin', 'active', NOW())
         RETURNING id",
    )
    .bind(tenant_id)
    .bind(&user_email)
    .bind(&pw_hash)
    .fetch_one(&pool)
    .await
    .expect("insert user");

    // 5. Register a confidential OAuth client. redirect_uri is the
    //    loopback root; policy::validate_redirect_uri allows any
    //    http://127.0.0.1[:port][/path] to match it (RFC 8252).
    let client_id = uuid::Uuid::new_v4();
    let client_secret = "super-secret-test-client-secret".to_string();
    let secret_hash = mokosh_auth_crypto::hash_password(&client_secret).expect("hash secret");
    sqlx::query(
        "INSERT INTO mokosh_auth.oauth_clients
            (client_id, client_type, client_secret_hash, name,
             redirect_uris, post_logout_redirect_uris,
             allowed_scopes, allowed_grant_types,
             token_endpoint_auth_method, audience)
         VALUES ($1, 'confidential', $2, 'e2e-test-client',
                 ARRAY['http://127.0.0.1']::TEXT[],
                 ARRAY['http://127.0.0.1/']::TEXT[],
                 ARRAY['openid','email','offline_access']::TEXT[],
                 ARRAY['authorization_code','refresh_token']::TEXT[],
                 'client_secret_basic', 'http://api.test.local')",
    )
    .bind(client_id)
    .bind(&secret_hash)
    .execute(&pool)
    .await
    .expect("insert oauth_client");

    // 6. Spawn the server.
    let app = auth.router();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .expect("axum::serve");
    });

    TestEnv {
        base,
        client_id,
        client_secret,
        redirect_uri: "http://127.0.0.1/cb".to_string(),
        user_id,
        user_email,
        user_password,
        _temp: temp,
        _server: server,
    }
}

/// Wrap raw DER bytes as RFC 7468 textual encoding ("PEM"). Splits the
/// base64 body at 64 characters per line. We do not pull pkcs8's PEM
/// machinery in just for this.
fn pem_wrap(label: &str, der: &[u8]) -> String {
    use base64::engine::general_purpose::STANDARD;
    let body = STANDARD.encode(der);
    let mut out = String::with_capacity(body.len() + 64);
    out.push_str(&format!("-----BEGIN {label}-----\n"));
    for chunk in body.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ascii"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

fn pkce() -> (String, String) {
    let verifier = format!("test-verifier-{}", uuid::Uuid::new_v4());
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .cookie_store(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(StdDuration::from_secs(10))
        .build()
        .expect("reqwest client")
}

#[sqlx::test]
async fn full_oidc_flow_including_refresh_reuse(pool: PgPool) {
    let env = make_env(pool).await;
    let client = http_client();
    let (verifier, challenge) = pkce();
    let state = "state-abcdef";
    let nonce = "nonce-123456";

    // --- Step 1: anonymous /oauth2/authorize -> 302 to /login -------------
    let mut authorize = env.base.join("oauth2/authorize").unwrap();
    authorize
        .query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &env.client_id.to_string())
        .append_pair("redirect_uri", &env.redirect_uri)
        .append_pair("scope", "openid email offline_access")
        .append_pair("state", state)
        .append_pair("nonce", nonce)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256");

    let r = client.get(authorize.clone()).send().await.unwrap();
    assert_eq!(
        r.status(),
        302,
        "anonymous authorize must redirect to login"
    );
    let login_loc = r.headers()["location"].to_str().unwrap();
    assert!(
        login_loc.contains("/login?return_to="),
        "expected /login redirect, got {login_loc}"
    );

    // Pull `return_to` off the redirect so we can echo it on POST /login.
    let login_url = env.base.join(login_loc).unwrap();
    let return_to = login_url
        .query_pairs()
        .find(|(k, _)| k == "return_to")
        .map(|(_, v)| v.into_owned())
        .expect("return_to");

    // --- Step 2: POST /login with email + password -----------------------
    let r = client
        .post(env.base.join("login").unwrap())
        .form(&[
            ("email", &env.user_email),
            ("password", &env.user_password),
            ("return_to", &return_to),
            ("tenant_id", &String::new()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 302, "successful login must redirect");
    let resume_loc = r.headers()["location"].to_str().unwrap();
    assert!(
        resume_loc.starts_with("/oauth2/authorize"),
        "expected /oauth2/authorize redirect, got {resume_loc}"
    );

    // --- Step 3: resume /oauth2/authorize (cookie now set) ---------------
    let r = client
        .get(env.base.join(resume_loc).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 302, "authenticated authorize must issue code");
    let cb_loc = r.headers()["location"].to_str().unwrap();
    let cb_url = Url::parse(cb_loc).unwrap();
    let code = cb_url
        .query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.into_owned())
        .expect("code in callback");
    let returned_state = cb_url
        .query_pairs()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.into_owned())
        .expect("state in callback");
    assert_eq!(returned_state, state, "state must echo verbatim");

    // --- Step 4: POST /oauth2/token to exchange the code -----------------
    let token_resp = client
        .post(env.base.join("oauth2/token").unwrap())
        .basic_auth(env.client_id.to_string(), Some(&env.client_secret))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", &env.redirect_uri),
            ("code_verifier", &verifier),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(token_resp.status(), 200, "code exchange must succeed");
    let body: serde_json::Value = token_resp.json().await.unwrap();
    let access_token = body["access_token"]
        .as_str()
        .expect("access_token")
        .to_string();
    let refresh_token = body["refresh_token"]
        .as_str()
        .expect("refresh_token")
        .to_string();
    let id_token = body["id_token"].as_str().expect("id_token").to_string();
    assert_eq!(body["token_type"].as_str().unwrap(), "Bearer");
    assert!(body["expires_in"].as_i64().unwrap() > 0);
    assert!(!access_token.is_empty() && !refresh_token.is_empty() && !id_token.is_empty());

    // --- Step 5: GET /oauth2/userinfo with the bearer token --------------
    let userinfo = client
        .get(env.base.join("oauth2/userinfo").unwrap())
        .bearer_auth(&access_token)
        .send()
        .await
        .unwrap();
    assert_eq!(userinfo.status(), 200, "userinfo must accept the at+jwt");
    let info: serde_json::Value = userinfo.json().await.unwrap();
    assert_eq!(info["sub"].as_str().unwrap(), env.user_id.to_string());
    assert_eq!(info["email"].as_str().unwrap(), env.user_email);
    assert!(info["email_verified"].as_bool().unwrap());

    // --- Step 6: refresh -> rotated tokens -------------------------------
    let refresh_resp = client
        .post(env.base.join("oauth2/token").unwrap())
        .basic_auth(env.client_id.to_string(), Some(&env.client_secret))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", &refresh_token),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(refresh_resp.status(), 200, "first refresh must succeed");
    let body2: serde_json::Value = refresh_resp.json().await.unwrap();
    let new_refresh = body2["refresh_token"].as_str().unwrap().to_string();
    let new_access = body2["access_token"].as_str().unwrap().to_string();
    assert_ne!(refresh_token, new_refresh, "refresh token must rotate");
    assert_ne!(access_token, new_access, "access token must rotate");

    // --- Step 7: replay the OLD refresh token. Family must be revoked ----
    let reuse = client
        .post(env.base.join("oauth2/token").unwrap())
        .basic_auth(env.client_id.to_string(), Some(&env.client_secret))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", &refresh_token), // replayed
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(reuse.status(), 400, "replay must yield invalid_grant");
    let err: serde_json::Value = reuse.json().await.unwrap();
    assert_eq!(err["error"].as_str().unwrap(), "invalid_grant");

    // --- Step 8: the previously-rotated NEW token must also be revoked ---
    // The reuse-detection branch revokes the entire family, so the
    // sibling token (issued in Step 6) is now dead too. This is the
    // core of family-based reuse detection.
    let after_reuse = client
        .post(env.base.join("oauth2/token").unwrap())
        .basic_auth(env.client_id.to_string(), Some(&env.client_secret))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", &new_refresh),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(
        after_reuse.status(),
        400,
        "family revocation must extend to siblings of the replayed token"
    );
    let err2: serde_json::Value = after_reuse.json().await.unwrap();
    assert_eq!(err2["error"].as_str().unwrap(), "invalid_grant");
}

#[sqlx::test]
async fn revoke_kills_refresh_family(pool: PgPool) {
    // Drive the flow up to a valid refresh token, POST /oauth2/revoke
    // for that token, then verify the next refresh attempt is dead.
    // RFC 7009 demands /revoke always return 200, including for unknown
    // tokens; we also assert that.
    let env = make_env(pool).await;
    let client = http_client();
    let (verifier, challenge) = pkce();

    let mut authorize = env.base.join("oauth2/authorize").unwrap();
    authorize
        .query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &env.client_id.to_string())
        .append_pair("redirect_uri", &env.redirect_uri)
        .append_pair("scope", "openid email offline_access")
        .append_pair("state", "s")
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256");

    let r = client.get(authorize).send().await.unwrap();
    let return_to = Url::parse(
        env.base
            .join(r.headers()["location"].to_str().unwrap())
            .unwrap()
            .as_str(),
    )
    .unwrap()
    .query_pairs()
    .find(|(k, _)| k == "return_to")
    .map(|(_, v)| v.into_owned())
    .unwrap();
    let r = client
        .post(env.base.join("login").unwrap())
        .form(&[
            ("email", &env.user_email),
            ("password", &env.user_password),
            ("return_to", &return_to),
            ("tenant_id", &String::new()),
        ])
        .send()
        .await
        .unwrap();
    let resume = r.headers()["location"].to_str().unwrap().to_string();
    let r = client
        .get(env.base.join(&resume).unwrap())
        .send()
        .await
        .unwrap();
    let cb = Url::parse(r.headers()["location"].to_str().unwrap()).unwrap();
    let code = cb
        .query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.into_owned())
        .unwrap();

    let token_resp = client
        .post(env.base.join("oauth2/token").unwrap())
        .basic_auth(env.client_id.to_string(), Some(&env.client_secret))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", &env.redirect_uri),
            ("code_verifier", &verifier),
        ])
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = token_resp.json().await.unwrap();
    let refresh_token = body["refresh_token"].as_str().unwrap().to_string();

    // POST /oauth2/revoke. Should be 200 unconditionally.
    let revoke = client
        .post(env.base.join("oauth2/revoke").unwrap())
        .basic_auth(env.client_id.to_string(), Some(&env.client_secret))
        .form(&[
            ("token", &refresh_token),
            ("token_type_hint", &"refresh_token".to_string()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(revoke.status(), 200, "revoke must return 200");

    // The revoked token must now fail to refresh.
    let refresh_after = client
        .post(env.base.join("oauth2/token").unwrap())
        .basic_auth(env.client_id.to_string(), Some(&env.client_secret))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", &refresh_token),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(refresh_after.status(), 400, "revoked token must fail");
    let err: serde_json::Value = refresh_after.json().await.unwrap();
    assert_eq!(err["error"].as_str().unwrap(), "invalid_grant");

    // RFC 7009 5: unknown tokens still get 200.
    let revoke_unknown = client
        .post(env.base.join("oauth2/revoke").unwrap())
        .basic_auth(env.client_id.to_string(), Some(&env.client_secret))
        .form(&[("token", &"definitely-not-a-real-refresh-token".to_string())])
        .send()
        .await
        .unwrap();
    assert_eq!(revoke_unknown.status(), 200, "unknown token still 200");
}

#[sqlx::test]
async fn token_endpoint_rejects_wrong_client_secret(pool: PgPool) {
    let env = make_env(pool).await;
    let client = http_client();
    let (_verifier, _challenge) = pkce();

    // No code yet, but the client-auth check happens before the grant
    // is dispatched, so a wrong secret here yields invalid_client even
    // though the request is otherwise nonsensical.
    let r = client
        .post(env.base.join("oauth2/token").unwrap())
        .basic_auth(env.client_id.to_string(), Some("wrong-secret"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", "anything"),
            ("redirect_uri", &env.redirect_uri),
            ("code_verifier", "anything"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401, "wrong client secret must be 401");
    let err: serde_json::Value = r.json().await.unwrap();
    assert_eq!(err["error"].as_str().unwrap(), "invalid_client");
}

#[sqlx::test]
async fn pkce_mismatch_rejected(pool: PgPool) {
    let env = make_env(pool).await;
    let client = http_client();
    let (_verifier, challenge) = pkce();

    // Drive steps 1-3 with one verifier, then exchange the code with a
    // *different* verifier. The token endpoint must reject.
    let mut authorize = env.base.join("oauth2/authorize").unwrap();
    authorize
        .query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &env.client_id.to_string())
        .append_pair("redirect_uri", &env.redirect_uri)
        .append_pair("scope", "openid")
        .append_pair("state", "s")
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256");

    let r = client.get(authorize).send().await.unwrap();
    let return_to = Url::parse(
        env.base
            .join(r.headers()["location"].to_str().unwrap())
            .unwrap()
            .as_str(),
    )
    .unwrap()
    .query_pairs()
    .find(|(k, _)| k == "return_to")
    .map(|(_, v)| v.into_owned())
    .unwrap();

    let r = client
        .post(env.base.join("login").unwrap())
        .form(&[
            ("email", &env.user_email),
            ("password", &env.user_password),
            ("return_to", &return_to),
            ("tenant_id", &String::new()),
        ])
        .send()
        .await
        .unwrap();
    let resume = r.headers()["location"].to_str().unwrap().to_string();

    let r = client
        .get(env.base.join(&resume).unwrap())
        .send()
        .await
        .unwrap();
    let cb = Url::parse(r.headers()["location"].to_str().unwrap()).unwrap();
    let code = cb
        .query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.into_owned())
        .unwrap();

    // Wrong verifier (does not hash to `challenge`).
    let r = client
        .post(env.base.join("oauth2/token").unwrap())
        .basic_auth(env.client_id.to_string(), Some(&env.client_secret))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", &env.redirect_uri),
            ("code_verifier", "definitely-not-the-original-verifier"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400, "PKCE mismatch must be invalid_grant");
    let err: serde_json::Value = r.json().await.unwrap();
    assert_eq!(err["error"].as_str().unwrap(), "invalid_grant");
}
