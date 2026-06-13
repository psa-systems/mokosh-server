//! Shared integration-test harness.
//!
//! `boot(pool)` spins the real PSA router up on a per-test TCP socket and
//! returns a `TestApp` with a reqwest client and (after `login`) a Bearer
//! access token. The SSO subsystem is intentionally NOT mounted: tests
//! cover the legacy HS256 path that 99% of PSA endpoints still go through.
//! The legacy `AuthMiddleware` reads `Authorization: Bearer <token>`
//! (`src/modules/auth/middleware.rs:123-126`), so tests authenticate by
//! pulling `access_token` out of the login JSON response and attaching
//! it via `.bearer_auth()` on subsequent requests.
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
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use tokio::net::TcpListener;
use uuid::Uuid;

/// Default tenant the PSA seed migration always inserts.
///
/// `#[allow(dead_code)]` because each integration-test binary compiles
/// its own copy of `common::` and clippy's per-binary dead-code analysis
/// fires when a binary does not happen to reference this constant.
#[allow(dead_code)]
pub const DEFAULT_TENANT_ID: Uuid = Uuid::from_u128(1);

/// Handle a test holds while exercising the API.
pub struct TestApp {
    /// `http://127.0.0.1:<random>` - the per-test base URL.
    pub base: String,
    /// Plain reqwest client. Tests attach the bearer token themselves
    /// via `.bearer_auth(&token)` per request.
    pub client: reqwest::Client,
    /// Per-test DB pool, kept on the handle so future tests can assert
    /// post-mutation state directly. Clippy runs dead-code analysis per
    /// integration-test binary and not every test reads `app.pool`
    /// today, so silence the per-binary `dead_code` warning rather
    /// than drop the field.
    #[allow(dead_code)]
    pub pool: PgPool,
    /// PMS-285: the unprivileged (`NOBYPASSRLS`) request-serving pool when the
    /// app was booted via [`boot_rls`]; `None` for the default superuser
    /// [`boot`]. RLS-exercising suites read this to prove fail-closed behaviour
    /// through the actual application role (e.g. a no-GUC read returns zero
    /// rows). `#[allow(dead_code)]` for the same per-binary reason as `pool`.
    #[allow(dead_code)]
    pub app_pool: Option<PgPool>,
}

impl TestApp {
    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }
}

/// Bring up the API against `pool` on a random localhost port.
///
/// `#[allow(dead_code)]` because each integration-test binary compiles its
/// own copy of `common::`; binaries that exercise services directly (e.g.
/// `tests/sla.rs`, `tests/contracts.rs`) never boot the HTTP app.
#[allow(dead_code)]
pub async fn boot(pool: PgPool) -> TestApp {
    let db = Database::from_pool(pool.clone());
    boot_with_db(pool, db, None).await
}

/// PMS-285: bring up the API with the request-serving connection running as an
/// unprivileged `NOBYPASSRLS` role, so the HTTP suite exercises Row Level
/// Security rather than only the app-layer `WHERE tenant_id` filters.
///
/// `#[sqlx::test]` provisions a single superuser pool; this builds a SECOND
/// pool that connects as a freshly created `NOSUPERUSER NOBYPASSRLS` role
/// (the production `mokosh_app` posture) against the same per-test database,
/// and wires it as the app pool while the superuser pool stays the migrator
/// pool. Seed helpers (`seed_*`) keep writing through the returned superuser
/// `pool`, so test setup is unaffected; only the request path is RLS-bound.
#[allow(dead_code)]
pub async fn boot_rls(pool: PgPool) -> TestApp {
    let app_pool = build_app_role_pool(&pool).await;
    let db = Database::from_pools(app_pool.clone(), pool.clone());
    boot_with_db(pool, db, Some(app_pool)).await
}

/// Create a per-test `NOSUPERUSER NOBYPASSRLS` role, grant it the same
/// privileges `mokosh_app` gets in production, and return a pool that connects
/// as it against the same database as `superuser_pool`.
///
/// Roles are cluster-global while each `#[sqlx::test]` gets its own database,
/// so the role name is made unique to avoid cross-test clashes (mirroring
/// `tests/rls_isolation.rs`). The role owns no objects, so it stays exempt from
/// neither RLS nor the `tenants`-root carve-out: exactly the production posture.
#[allow(dead_code)]
pub async fn build_app_role_pool(superuser_pool: &PgPool) -> PgPool {
    let role = format!("mokosh_app_test_{}", Uuid::new_v4().simple());
    let password = "app-role-test-pw";

    sqlx::query(&format!(
        "CREATE ROLE {role} LOGIN PASSWORD '{password}' NOSUPERUSER NOBYPASSRLS"
    ))
    .execute(superuser_pool)
    .await
    .expect("create unprivileged app role");

    for stmt in [
        format!("GRANT USAGE ON SCHEMA public TO {role}"),
        format!("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {role}"),
        format!("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {role}"),
        format!("GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO {role}"),
    ] {
        sqlx::query(&stmt)
            .execute(superuser_pool)
            .await
            .unwrap_or_else(|e| panic!("grant `{stmt}`: {e}"));
    }

    // Derive the app-role connection from the superuser pool's options so it
    // targets the SAME per-test database, only swapping the login role.
    let opts = superuser_pool
        .connect_options()
        .as_ref()
        .clone()
        .username(&role)
        .password(password);

    PgPoolOptions::new()
        .max_connections(5)
        .connect_with(opts)
        .await
        .expect("connect app-role pool")
}

#[allow(dead_code)]
async fn boot_with_db(pool: PgPool, db: Database, app_pool: Option<PgPool>) -> TestApp {
    // Route the server's tracing events to libtest's per-thread capture so
    // a failing test surfaces the real cause in its panic output (e.g. the
    // sqlx error swallowed by `AppError::Database("Database operation
    // failed")` in `src/utils/error.rs`). `try_init` because concurrent
    // tests in the same binary share the global subscriber.
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("error,mokosh_server=info")),
        )
        .try_init();

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
        false, // cookie_secure: irrelevant for bearer-token tests
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
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("build reqwest client");

    TestApp {
        base: format!("http://{addr}"),
        client,
        pool,
        app_pool,
    }
}

/// Seed a super_admin user under the default tenant. Returns
/// `(user_id, email, plaintext_password)` so the test can drive `/login`.
///
/// `#[allow(dead_code)]` because each integration-test binary compiles
/// its own copy of `common::` and clippy's per-binary dead-code analysis
/// fires for binaries that exercise the API without authenticating
/// (e.g. `tests/dispatch_stub.rs` hits an unauthenticated stub).
#[allow(dead_code)]
pub async fn seed_admin(pool: &PgPool) -> (Uuid, String, String) {
    let email = "test-admin@example.com".to_string();
    let password = "test-password-12345".to_string();
    let password_hash =
        mokosh_server::utils::crypto::hash_password(&password).expect("hash test admin password");
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

/// Seed a non-admin user under the default tenant. Returns
/// `(user_id, email, plaintext_password)`. Caller picks the email +
/// role so a single test can stand up several distinct seeded users.
/// Password is uniform across seeds; tests run against an ephemeral DB.
#[allow(dead_code)]
pub async fn seed_user(pool: &PgPool, email: &str, role: &str) -> (Uuid, String, String) {
    let password = "test-password-12345".to_string();
    let password_hash =
        mokosh_server::utils::crypto::hash_password(&password).expect("hash seeded user password");
    let user_id = Uuid::new_v4();

    sqlx::query(
        r#"
        INSERT INTO users (
            id, tenant_id, email, password_hash,
            first_name, last_name, role, status, email_verified_at
        )
        VALUES ($1, $2, $3, $4, 'Test', 'User', $5, 'active', NOW())
        "#,
    )
    .bind(user_id)
    .bind(DEFAULT_TENANT_ID)
    .bind(email)
    .bind(&password_hash)
    .bind(role)
    .execute(pool)
    .await
    .expect("insert seeded user");

    (user_id, email.to_string(), password)
}

/// Seed a user with a caller-chosen `id` and `tenant_id`. Used by the
/// Bunyip placement tests, where the `users.id` must equal the OIDC `sub`
/// and the row must start in a specific tenant (e.g. the default tenant)
/// to exercise the PMS-245 backfill.
#[allow(dead_code)]
pub async fn seed_user_in_tenant(
    pool: &PgPool,
    id: Uuid,
    tenant_id: Uuid,
    email: &str,
    role: &str,
) {
    let password_hash =
        mokosh_server::utils::crypto::hash_password("test-password-12345").expect("hash password");

    sqlx::query(
        r#"
        INSERT INTO users (
            id, tenant_id, email, password_hash,
            first_name, last_name, role, status, email_verified_at
        )
        VALUES ($1, $2, $3, $4, 'Test', 'User', $5, 'active', NOW())
        "#,
    )
    .bind(id)
    .bind(tenant_id)
    .bind(email)
    .bind(&password_hash)
    .bind(role)
    .execute(pool)
    .await
    .expect("insert seeded user in tenant");
}

/// Seed a fresh tenant + admin so a test can prove tenant isolation.
/// Returns `(tenant_id, user_id, email, password)`. The tenant uses
/// the caller-supplied label both as its display name and as the
/// unique `slug` column.
#[allow(dead_code)]
pub async fn seed_tenant_with_admin(
    pool: &PgPool,
    tenant_label: &str,
) -> (Uuid, Uuid, String, String) {
    let tenant_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO tenants (id, name, slug, status, kind)
        VALUES ($1, $2, $3, 'active', 'org')
        "#,
    )
    .bind(tenant_id)
    .bind(tenant_label)
    .bind(tenant_label)
    .execute(pool)
    .await
    .expect("insert tenant");

    let email = format!("admin-{tenant_label}@example.com");
    let password = "test-password-12345".to_string();
    let password_hash =
        mokosh_server::utils::crypto::hash_password(&password).expect("hash tenant admin password");
    let user_id = Uuid::new_v4();

    sqlx::query(
        r#"
        INSERT INTO users (
            id, tenant_id, email, password_hash,
            first_name, last_name, role, status, email_verified_at
        )
        VALUES ($1, $2, $3, $4, 'Tenant', 'Admin', 'super_admin', 'active', NOW())
        "#,
    )
    .bind(user_id)
    .bind(tenant_id)
    .bind(&email)
    .bind(&password_hash)
    .execute(pool)
    .await
    .expect("insert tenant admin");

    (tenant_id, user_id, email, password)
}

/// Drive `POST /api/v1/auth/login` and return the `access_token` the
/// caller should attach as `Authorization: Bearer ...` on subsequent
/// requests. Panics on a non-2xx login because tests that get this far
/// already seeded a valid admin.
///
/// `#[allow(dead_code)]` for the same per-binary reason as
/// [`seed_admin`]: not every integration-test binary authenticates.
#[allow(dead_code)]
pub async fn login(app: &TestApp, email: &str, password: &str) -> String {
    let resp = app
        .client
        .post(app.url("/api/v1/auth/login"))
        .json(&serde_json::json!({ "email": email, "password": password }))
        .send()
        .await
        .expect("send /login request");
    assert!(
        resp.status().is_success(),
        "login expected 2xx, got {}",
        resp.status()
    );
    let body: serde_json::Value = resp.json().await.expect("/login JSON body");
    body["access_token"]
        .as_str()
        .expect("login response has access_token")
        .to_string()
}
