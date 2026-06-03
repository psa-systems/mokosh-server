//! Shared integration-test harness.
//!
//! `boot(pool)` spins the real PSA router up on a per-test TCP socket and
//! returns a `TestApp` with a cookie-aware reqwest client. The SSO
//! subsystem is intentionally NOT mounted: tests cover the legacy
//! HS256-cookie auth path that 99% of PSA endpoints still go through.
//!
//! Each #[sqlx::test] gets a fresh database with the PSA migrations
//! pre-applied. The `seed_admin` helper inserts a super_admin user under
//! the default tenant (id 00000000-0000-0000-0000-000000000001) directly
//! via SQL, mirroring `modules::auth::bootstrap::maybe_bootstrap_admin`
//! without depending on process env vars.

use std::net::SocketAddr;
use std::sync::Arc;

use mokosh_server::api::create_api_router;
use mokosh_server::utils::email::{LogMailer, Mailer};
use mokosh_server::Database;
use sqlx::PgPool;
use tokio::net::TcpListener;
use uuid::Uuid;

/// Default tenant the PSA seed migration always inserts.
pub const DEFAULT_TENANT_ID: Uuid = Uuid::from_u128(1);

/// Handle a test holds while exercising the API.
pub struct TestApp {
    /// `http://127.0.0.1:<random>` - the per-test base URL.
    pub base: String,
    /// reqwest client with a cookie jar so `Set-Cookie` from `/login`
    /// carries forward into subsequent requests automatically.
    pub client: reqwest::Client,
    /// Per-test DB pool. Tests use it to seed fixtures or assert state.
    pub pool: PgPool,
}

impl TestApp {
    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }
}

/// Bring up the API against `pool` on a random localhost port.
pub async fn boot(pool: PgPool) -> TestApp {
    let db = Database::from_pool(pool.clone());

    // Stub Google OAuth client - tests never drive the Google flow.
    let google_oauth = Arc::new(
        google_oauth_flow::Client::new(google_oauth_flow::Config {
            client_id: "test-client".into(),
            client_secret: "test-secret".into(),
            redirect_uri: "http://localhost/callback".into(),
        })
        .expect("build stub google_oauth client"),
    );

    let mailer: Arc<dyn Mailer> = Arc::new(LogMailer);
    let encryption_key = [0u8; 32];

    let router = create_api_router(
        db,
        "test-jwt-secret-that-is-clearly-not-for-prod".into(),
        google_oauth,
        "http://localhost".into(),
        vec!["http://localhost".into()],
        Vec::new(),
        false, // cookie_secure: false so the test client accepts cookies over HTTP
        None,  // at_jwt verifier disabled in tests
        None,  // bunyip RS verifier disabled in tests
        mailer,
        encryption_key,
    );

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind random port");
    let addr = listener.local_addr().expect("local_addr");

    tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .expect("axum::serve failed");
    });

    let client = reqwest::Client::builder()
        .cookie_store(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("build reqwest client");

    TestApp {
        base: format!("http://{addr}"),
        client,
        pool,
    }
}

/// Seed a super_admin user under the default tenant. Returns
/// `(user_id, email, plaintext_password)` so the test can drive `/login`.
pub async fn seed_admin(pool: &PgPool) -> (Uuid, String, String) {
    let email = "test-admin@example.com".to_string();
    let password = "test-password-12345".to_string();
    let password_hash = mokosh_server::utils::crypto::hash_password(&password)
        .expect("hash test admin password");
    let user_id = Uuid::new_v4();

    sqlx::query(
        r#"
        INSERT INTO users (
            id, tenant_id, email, password_hash,
            first_name, last_name, role, status, email_verified_at
        )
        VALUES ($1, $2, $3, $4, 'Test', 'Admin', 'super_admin', 'active', NOW())
        "#,
    )
    .bind(user_id)
    .bind(DEFAULT_TENANT_ID)
    .bind(&email)
    .bind(&password_hash)
    .execute(pool)
    .await
    .expect("insert seeded admin");

    (user_id, email, password)
}

/// Drive `POST /api/v1/auth/login`. On success the cookie jar inside
/// `app.client` is populated, so subsequent calls are authenticated.
pub async fn login(app: &TestApp, email: &str, password: &str) -> reqwest::Response {
    app.client
        .post(app.url("/api/v1/auth/login"))
        .json(&serde_json::json!({ "email": email, "password": password }))
        .send()
        .await
        .expect("send /login request")
}
