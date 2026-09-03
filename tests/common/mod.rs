//! Shared integration-test harness.
//!
//! `boot(pool)` spins the real PSA router up on a per-test TCP socket and
//! returns a `TestApp` with a reqwest client and (after `login`) a Bearer
//! access token. The SSO subsystem is intentionally NOT mounted by `boot`:
//! tests cover the legacy HS256 path that 99% of PSA endpoints still go
//! through. `boot_with_bunyip` (PMS-698) mounts the bunyip Resource-Server
//! verifier for the suites that need the bunyip branch instead.
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
use mokosh_server::utils::email::{LogMailer, SharedMailer};
use mokosh_server::Database;
use rust_decimal::Decimal;
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
    /// PMS-991: the swappable mailer the router was built with, so a suite
    /// can `swap` in a capturing one and assert on what the API sent.
    /// `#[allow(dead_code)]` for the same per-binary reason as `pool`.
    #[allow(dead_code)]
    pub mailer: Arc<SharedMailer>,
}

impl TestApp {
    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }
}

/// Seed a company named "Acme Co" under the default tenant; returns its
/// id. Consolidates the per-file copies that several billing/time/ticket
/// test binaries used to each define.
///
/// `#[allow(dead_code)]` for the same per-binary reason as the other
/// helpers: each integration-test binary compiles its own copy of
/// `common::` and not every one seeds a company.
#[allow(dead_code)]
pub async fn seed_company(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO companies (id, tenant_id, name)
        VALUES ($1, $2, 'Acme Co')
        "#,
    )
    .bind(id)
    .bind(DEFAULT_TENANT_ID)
    .execute(pool)
    .await
    .expect("seed test company");
    id
}

/// Seed a ticket plus one internal note on it under the default tenant,
/// reusing the seeded statuses / priorities / queues. Returns
/// `(ticket_id, note_id)`.
///
/// Shared by the two attachment binaries (`ticket_note_attachments.rs` and
/// `attachment_download_streaming.rs`, split apart in PMS-822) so the fixture
/// cannot drift between them. `#[allow(dead_code)]` for the same per-binary
/// reason as the other helpers.
#[allow(dead_code)]
pub async fn seed_ticket_and_note(pool: &PgPool, admin_id: Uuid, company_id: Uuid) -> (Uuid, Uuid) {
    let status_id: Uuid =
        sqlx::query_scalar("SELECT id FROM ticket_statuses WHERE tenant_id = $1 LIMIT 1")
            .bind(DEFAULT_TENANT_ID)
            .fetch_one(pool)
            .await
            .expect("status");
    let priority_id: Uuid =
        sqlx::query_scalar("SELECT id FROM ticket_priorities WHERE tenant_id = $1 LIMIT 1")
            .bind(DEFAULT_TENANT_ID)
            .fetch_one(pool)
            .await
            .expect("priority");
    let queue_id: Uuid =
        sqlx::query_scalar("SELECT id FROM ticket_queues WHERE tenant_id = $1 LIMIT 1")
            .bind(DEFAULT_TENANT_ID)
            .fetch_one(pool)
            .await
            .expect("queue");
    let ticket_id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO tickets
           (id, tenant_id, ticket_number, title, status_id, priority_id,
            queue_id, company_id, created_by_id)
           VALUES ($1, $2, $3, 'Attachment ticket', $4, $5, $6, $7, $8)"#,
    )
    .bind(ticket_id)
    .bind(DEFAULT_TENANT_ID)
    .bind(format!("T-{}", &ticket_id.to_string()[..8]))
    .bind(status_id)
    .bind(priority_id)
    .bind(queue_id)
    .bind(company_id)
    .bind(admin_id)
    .execute(pool)
    .await
    .expect("seed ticket");
    let note_id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO ticket_notes
           (id, tenant_id, ticket_id, content, note_type, created_by_id)
           VALUES ($1, $2, $3, 'parent note', 'internal', $4)"#,
    )
    .bind(note_id)
    .bind(DEFAULT_TENANT_ID)
    .bind(ticket_id)
    .bind(admin_id)
    .execute(pool)
    .await
    .expect("seed note");
    (ticket_id, note_id)
}

/// Parse a decimal string literal into a [`Decimal`] for test fixtures
/// that bind money columns. Panics on malformed input (test-only).
#[allow(dead_code)]
pub fn dec(s: &str) -> Decimal {
    s.parse().expect("parse Decimal literal")
}

/// A storage root private to this test binary's run, exported as
/// `ATTACHMENT_DIR`.
///
/// Nine suites used to name a fixed path under `/tmp` (`/tmp/mokosh-pms923-test`
/// and friends). `/tmp` is world-writable with the sticky bit, so whichever OS
/// user ran the suite FIRST on a host owned that directory, and `LocalStore`
/// created it with that process's umask. A second user on the same host then
/// could not write into it, `StorageConfig` failed with `Permission denied`,
/// and the API surfaced a 500 - which reads as a defect in the storage seam and
/// costs a triage cycle before anyone thinks to `ls -ld /tmp`. CI never saw it,
/// because each job gets a fresh container, so it only ever bit the place it
/// was most expensive to diagnose.
///
/// One root per binary rather than one per test case, because `ATTACHMENT_DIR`
/// is process-global env and `#[sqlx::test]` cases within a binary run
/// concurrently: a case that gave itself a private root would change the root
/// under its neighbours mid-run. Every case in a binary therefore shares this
/// one, which is safe for the same reason the old shared path was safe within a
/// suite - stored objects are named by uuid, so two cases cannot collide.
///
/// The `TempDir` is parked in a `OnceLock` to keep it alive for the whole run.
/// A static is never dropped, so the directory outlives the process rather than
/// being cleaned up; that is the deliberate trade. `tempfile` gives it a random
/// name, so the property that actually matters - no two runs and no two users
/// ever address the same directory - holds, and what is left behind is an empty
/// tree under `/tmp` that the OS reclaims.
#[allow(dead_code)]
pub fn storage_root() -> &'static std::path::Path {
    static ROOT: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();

    let dir = ROOT.get_or_init(|| {
        tempfile::Builder::new()
            .prefix("mokosh-test-storage-")
            .tempdir()
            .expect("create a private storage root for this test run")
    });
    // Re-exported on every call, not only on the first: a suite may set other
    // storage env beside this one, and the cost of being sure is one setenv.
    std::env::set_var("ATTACHMENT_DIR", dir.path());
    dir.path()
}

/// Bring up the API against `pool` on a random localhost port.
///
/// `#[allow(dead_code)]` because each integration-test binary compiles its
/// own copy of `common::`; binaries that exercise services directly (e.g.
/// `tests/sla.rs`, `tests/contracts.rs`) never boot the HTTP app.
#[allow(dead_code)]
pub async fn boot(pool: PgPool) -> TestApp {
    let db = Database::from_pool(pool.clone());
    boot_with_db(pool, db, None, None).await
}

/// PMS-698: bring up the API with the bunyip Resource-Server verifier mounted,
/// so a suite can exercise the bunyip auth branch end-to-end against a stub OP.
#[allow(dead_code)]
pub async fn boot_with_bunyip(
    pool: PgPool,
    verifier: mokosh_server::modules::auth::oidc_rs::Verifier,
) -> TestApp {
    let db = Database::from_pool(pool.clone());
    boot_with_db(pool, db, None, Some(verifier)).await
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
    boot_with_db(pool, db, Some(app_pool), None).await
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
async fn boot_with_db(
    pool: PgPool,
    db: Database,
    app_pool: Option<PgPool>,
    bunyip: Option<mokosh_server::modules::auth::oidc_rs::Verifier>,
) -> TestApp {
    // PMS-958: the object store is process-wide and built on first use, so
    // the root has to be chosen before anything in this binary can ask for
    // it. Every suite that stores bytes already calls this itself; doing it
    // here as well means a suite that never touches storage cannot pin the
    // compiled-in `./attachments` root for a neighbour that does.
    storage_root();
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

    // create_api_router now takes the swappable handle (PMS-638); wrap the
    // test LogMailer so the signature matches. Tests never swap it.
    let mailer = Arc::new(SharedMailer::new(Arc::new(LogMailer)));
    let mailer_handle = mailer.clone();
    let encryption_key = [0u8; 32];
    // PMS-968: the database backend under the same zero key the router is
    // given, so a suite that stores a gateway credential can read it back.
    // Deliberately not `store_from_env`: process env is shared across the cases
    // in a binary, so reading SECRET_BACKEND here would let one suite's
    // configuration decide another's.
    let secrets = std::sync::Arc::new(mokosh_server::secrets::DatabaseSecretStore::new(
        db.clone(),
        encryption_key,
    ));

    let router = create_api_router(
        db,
        "test-jwt-secret-that-is-clearly-not-for-prod".into(),
        "http://localhost".into(),
        // MAPPS-425 spa_base_url: deliberately different from client_origin so
        // a test asserting an emailed link's host cannot pass by accident.
        "http://spa.localhost".into(),
        vec!["http://localhost".into()],
        bunyip, // bunyip RS verifier: None unless the suite booted via `boot_with_bunyip`
        mailer,
        encryption_key,
        // PMS-591: no Bunyip webhook path exercised in these tests, but the
        // constructor now requires a shared secret. Any non-empty value works
        // for the constructor; specs that hit the webhook build their own
        // signature against the same secret.
        b"test-bunyip-webhook-secret".to_vec(),
        None,  // PMS-657: no geoip DB in tests; login-location alerts disabled
        None,  // BUNYIP-475: no IP2Proxy DB in tests; enrichment lookup reports nothing
        false, // PMS-658: login-approval gate off in the default test router
        // PMS-748: an abuse address IS configured here, so the request-form
        // suite can assert the notice appears; the unconfigured case is a unit
        // test on the composition itself.
        Some("abuse@test.invalid".to_string()),
        // MAPPS-429: a public API base IS configured here, so the request-form
        // suite can assert an emailed logo resolves absolutely.
        Some("http://api.localhost".to_string()),
        // MAPPS-457: default test router has no tenant cap so integration
        // suites that spin up dozens of tenants stay unblocked. Cap-behavior
        // specs override this by building their own router.
        None,
        // PMS-904: self-hosted, so the integration suite exercises the mode
        // that sends everything. The suppression is a unit test on
        // `AuthService`, which can hold both modes in one binary; flipping the
        // shared router here would silently change what every other suite is
        // testing.
        mokosh_server::utils::deployment::DeploymentMode::SelfHosted,
        secrets,
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
        mailer: mailer_handle,
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

    // MAPPS-518 (MAPPS-513 stage B): also seed a `platform_admins` row
    // for the same email + password so tests that hit endpoints gated
    // by `RequirePlatformAdmin` (post stage B: list/create/suspend/
    // activate/resend_welcome tenants, get/update tenant admin) can
    // call `common::platform_login` to get a platform bearer. Older
    // tests that just use `common::login` still work; the users row
    // is unchanged.
    sqlx::query(
        "INSERT INTO platform_admins (email, password_hash, first_name, last_name, status) \
         VALUES ($1, $2, 'Test', 'Admin', 'active') ON CONFLICT DO NOTHING",
    )
    .bind(&email)
    .bind(&password_hash)
    .execute(pool)
    .await
    .expect("insert seeded platform admin");

    (user_id, email, password)
}

/// Seed a non-admin user under `tenant_id`. Returns
/// `(user_id, email, plaintext_password)`. Caller picks the tenant,
/// email + role so a single test can stand up several distinct seeded
/// users (including the same email under two tenants, for the PMS-138
/// colliding-email scenarios). Password is uniform across seeds; tests
/// run against an ephemeral DB. Pass [`DEFAULT_TENANT_ID`] for the
/// common single-tenant case.
#[allow(dead_code)]
pub async fn seed_user(
    pool: &PgPool,
    tenant_id: Uuid,
    email: &str,
    role: &str,
) -> (Uuid, String, String) {
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
    .bind(tenant_id)
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
    // PMS-728 AC1: the local password path rejects a credential presented
    // without an explicit tenant identifier. This helper backs the whole
    // suite's default-admin login path (which uses `seed_admin`, populating
    // the default tenant, slug `default`, seeded by migration 002), so
    // threading the slug in here keeps the change localised: the callers
    // don't need to know the tenant lookup semantics.
    let resp = app
        .client
        .post(app.url("/api/v1/auth/login"))
        .json(&serde_json::json!({
            "email": email,
            "password": password,
            "tenant_slug": "default",
        }))
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

/// MAPPS-518 (MAPPS-513 stage B): drive `POST /api/v1/platform/login`
/// and return the platform bearer. `seed_admin` seeds a matching
/// `platform_admins` row so this works with the same email/password
/// pair. Use this for tests that hit endpoints gated by
/// `RequirePlatformAdmin` (list_tenants, create_tenant,
/// suspend_tenant, activate_tenant, resend_admin_welcome,
/// get_tenant_admin, update_tenant_admin).
#[allow(dead_code)]
pub async fn platform_login(app: &TestApp, email: &str, password: &str) -> String {
    let resp = app
        .client
        .post(app.url("/api/v1/platform/login"))
        .json(&serde_json::json!({ "email": email, "password": password }))
        .send()
        .await
        .expect("send /platform/login request");
    assert!(
        resp.status().is_success(),
        "platform login expected 2xx, got {}",
        resp.status()
    );
    let body: serde_json::Value = resp.json().await.expect("/platform/login JSON body");
    body["access_token"]
        .as_str()
        .expect("platform login response has access_token")
        .to_string()
}

/// PMS-791 / MAPPS-461: seed a team owned by the given tenant. Returns the
/// team id. `manager_id` is optional; when set, the caller has typically
/// just `seed_user`-ed that user in the same tenant.
#[allow(dead_code)]
pub async fn seed_team(
    pool: &PgPool,
    tenant_id: Uuid,
    name: &str,
    manager_id: Option<Uuid>,
) -> Uuid {
    let team_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO teams (id, tenant_id, name, manager_id, color, is_active)
        VALUES ($1, $2, $3, $4, '#6366F1', TRUE)
        "#,
    )
    .bind(team_id)
    .bind(tenant_id)
    .bind(name)
    .bind(manager_id)
    .execute(pool)
    .await
    .expect("seed_team");
    team_id
}

/// PMS-791 / MAPPS-461: add a user to a team with the given role
/// (`"leader"` or `"member"`). Bypass the production service so tests
/// can set up invalid states on purpose (e.g. wrong-tenant user_id).
#[allow(dead_code)]
pub async fn seed_team_member(
    pool: &PgPool,
    tenant_id: Uuid,
    team_id: Uuid,
    user_id: Uuid,
    role: &str,
) {
    sqlx::query(
        r#"
        INSERT INTO team_members (tenant_id, team_id, user_id, role, joined_at)
        VALUES ($1, $2, $3, $4, NOW())
        "#,
    )
    .bind(tenant_id)
    .bind(team_id)
    .bind(user_id)
    .bind(role)
    .execute(pool)
    .await
    .expect("seed_team_member");
}

/// PMS-791 / MAPPS-461: shorthand for the common test setup — an admin
/// (via `seed_admin`) + a team + the admin as leader. Returns
/// `(admin_id, admin_email, admin_password, team_id)`.
#[allow(dead_code)]
pub async fn seed_admin_and_team(pool: &PgPool, team_name: &str) -> (Uuid, String, String, Uuid) {
    let (admin_id, email, password) = seed_admin(pool).await;
    let team_id = seed_team(pool, DEFAULT_TENANT_ID, team_name, Some(admin_id)).await;
    seed_team_member(pool, DEFAULT_TENANT_ID, team_id, admin_id, "leader").await;
    (admin_id, email, password, team_id)
}
