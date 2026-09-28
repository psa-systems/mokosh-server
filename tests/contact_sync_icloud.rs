//! PMS-1409: connecting an iCloud account, and a tenant holding two providers.
//!
//! The CardDAV wire format is pinned in `contact_sync::carddav`'s own tests
//! against its fixtures. What is pinned HERE is the connect: that the
//! app-specific password is verified BEFORE anything is stored, that it lands in
//! the secret provider rather than in a column, that reconnecting the same Apple
//! ID keeps the connection the imported contacts hang off, and that a Google
//! connection and an iCloud one can be live in one tenant at the same time with
//! their own selections.
//!
//! The CardDAV server is a local stub, reached through
//! `ContactSyncService::with_carddav_base_url`, for the reason
//! `GoogleContactsProvider::with_base_url` exists: verifying a credential is a
//! real request, so a suite that drives the connect has to answer it.

mod common;

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::StatusCode as AxumStatus;
use axum::response::{IntoResponse, Response};
use mokosh_server::db::Database;
use mokosh_server::modules::auth::TenantId;
use mokosh_server::modules::contact_sync::service::{ConnectOutcome, ContactSyncService};
use mokosh_server::secrets::{DatabaseSecretProvider, SecretKey, SecretProvider};
use mokosh_test::mokosh_test;
use sqlx::PgPool;
use uuid::Uuid;

const PRINCIPAL: &str = include_str!("fixtures/carddav/principal.xml");
const HOME_SET: &str = include_str!("fixtures/carddav/home_set.xml");
const ADDRESSBOOKS: &str = include_str!("fixtures/carddav/addressbooks.xml");

const APPLE_ID: &str = "ops@icloud.example";
const APP_PASSWORD: &str = "abcd-efgh-ijkl-mnop";

/// A scripted CardDAV server: answers in order, and records what it was asked so
/// a test can say "nothing was requested" as well as "this was".
#[derive(Clone, Default)]
struct Stub {
    script: Arc<Mutex<VecDeque<(u16, String)>>>,
    seen: Arc<Mutex<Vec<String>>>,
}

async fn answer(
    State(stub): State<Stub>,
    method: axum::http::Method,
    uri: axum::http::Uri,
) -> Response {
    stub.seen
        .lock()
        .unwrap()
        .push(format!("{method} {}", uri.path()));
    match stub.script.lock().unwrap().pop_front() {
        Some((status, body)) => (
            AxumStatus::from_u16(status).expect("a status"),
            [("content-type", "application/xml; charset=utf-8")],
            body,
        )
            .into_response(),
        None => (AxumStatus::INTERNAL_SERVER_ERROR, "script exhausted").into_response(),
    }
}

/// The three PROPFINDs `address_book` makes when the credential works.
fn discovery() -> Vec<(u16, &'static str)> {
    vec![(207, PRINCIPAL), (207, HOME_SET), (207, ADDRESSBOOKS)]
}

struct Fixture {
    pool: PgPool,
    service: ContactSyncService,
    secrets: Arc<dyn SecretProvider>,
    stub: Stub,
    tenant: TenantId,
    admin: Uuid,
}

impl Fixture {
    async fn new(pool: PgPool, script: Vec<(u16, &'static str)>) -> Self {
        let (admin, _email, _password) = common::seed_admin(&pool).await;
        let stub = Stub::default();
        stub.script
            .lock()
            .unwrap()
            .extend(script.into_iter().map(|(s, b)| (s, b.to_string())));
        let app = axum::Router::new()
            .fallback(answer)
            .with_state(stub.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        // The unprivileged app role, so a query that forgot its tenant scope
        // reads nothing and fails loudly rather than passing by accident.
        let app_pool = common::build_app_role_pool(&pool).await;
        let db = Database::from_pools(app_pool, pool.clone());
        let secrets: Arc<dyn SecretProvider> =
            Arc::new(DatabaseSecretProvider::new(db.clone(), [0u8; 32]));
        let service = ContactSyncService::new(
            db,
            secrets.clone(),
            None,
            "https://app.msp.example".to_string(),
        )
        .with_carddav_base_url(base);
        Self {
            pool,
            service,
            secrets,
            stub,
            tenant: TenantId::from_trusted(common::DEFAULT_TENANT_ID),
            admin,
        }
    }

    async fn connect(&self) -> Result<ConnectOutcome, String> {
        self.service
            .connect_icloud(self.tenant, self.admin, APPLE_ID, APP_PASSWORD)
            .await
            .map_err(|e| e.to_string())
    }

    async fn password(&self, connection_id: Uuid) -> Option<String> {
        self.secrets
            .get(&SecretKey::contact_sync(
                common::DEFAULT_TENANT_ID,
                "icloud",
                connection_id,
            ))
            .await
            .unwrap()
    }

    async fn count(&self, sql: &str) -> i64 {
        sqlx::query_scalar(sql)
            .fetch_one(&self.pool)
            .await
            .unwrap_or_else(|e| panic!("{sql}: {e}"))
    }
}

/// The credential is checked against Apple before anything is written, and a
/// refusal says what to do about it in Apple's own terms.
///
/// The reason this is checked at connect rather than left to the first run: a
/// stored password that does not work is a connection that reads healthy for
/// hours and then fails as a sync error, which is the wrong place for a typo to
/// surface.
#[mokosh_test]
async fn a_password_apple_refuses_is_refused_before_anything_is_stored(pool: PgPool) {
    let f = Fixture::new(pool, vec![(401, "")]).await;

    let refused = f.connect().await.expect_err("Apple said no");
    assert!(
        refused.contains("app-specific password") && refused.contains("appleid.apple.com"),
        "{refused}"
    );
    assert!(
        !refused.contains("Google"),
        "an iCloud refusal must not name Google: {refused}"
    );
    assert_eq!(
        f.count("SELECT count(*) FROM contact_sync_connections")
            .await,
        0,
        "nothing is stored for a credential that does not work"
    );
    assert_eq!(f.count("SELECT count(*) FROM secrets").await, 0);
}

/// A working credential connects: the Apple ID is on the row, the password is in
/// the secret provider, and the row is the shape the run's source factory reads.
#[mokosh_test]
async fn connecting_stores_the_apple_id_and_keeps_the_password_in_the_secret_provider(
    pool: PgPool,
) {
    let f = Fixture::new(pool, discovery()).await;

    let ConnectOutcome::Connected(id) = f.connect().await.expect("connected") else {
        panic!("a first connect is a new connection");
    };
    assert_eq!(
        f.stub.seen.lock().unwrap().len(),
        3,
        "the discovery ladder verified the credential"
    );

    let (provider, account, status): (String, String, String) = sqlx::query_as(
        "SELECT provider, account_email, sync_status FROM contact_sync_connections WHERE id = $1",
    )
    .bind(id)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!(
        (provider.as_str(), account.as_str(), status.as_str()),
        ("icloud", APPLE_ID, "never")
    );
    assert_eq!(
        f.password(id).await.as_deref(),
        Some(APP_PASSWORD),
        "the password is in the secret provider, which is where the run reads it"
    );
}

/// Reconnecting the same Apple ID keeps the connection, because every link, run,
/// selection and queued review hangs off its id: a disconnect-then-connect would
/// turn every imported contact into a local record first. A DIFFERENT Apple ID is
/// refused, because every link names the account it came from.
#[mokosh_test]
async fn reconnecting_the_same_apple_id_keeps_the_connection(pool: PgPool) {
    let mut script = discovery();
    script.extend(discovery());
    let f = Fixture::new(pool, script).await;

    let ConnectOutcome::Connected(id) = f.connect().await.expect("connected") else {
        panic!("a first connect is a new connection");
    };
    sqlx::query(
        "UPDATE contact_sync_connections SET sync_status = 'reconnect_required', \
         last_error = 'Apple no longer accepts this app-specific password.', \
         consecutive_failures = 4 WHERE id = $1",
    )
    .bind(id)
    .execute(&f.pool)
    .await
    .unwrap();

    assert_eq!(
        f.connect().await.expect("reconnected"),
        ConnectOutcome::Reconnected(id),
        "the same connection, so nothing imported through it is orphaned"
    );
    let (status, error, failures): (String, Option<String>, i32) = sqlx::query_as(
        "SELECT sync_status, last_error, consecutive_failures \
         FROM contact_sync_connections WHERE id = $1",
    )
    .bind(id)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!(
        (status.as_str(), error, failures),
        ("never", None, 0),
        "reconnecting is the way out of reconnect_required"
    );
}

#[mokosh_test]
async fn a_different_apple_id_is_refused_and_names_the_connected_one(pool: PgPool) {
    let mut script = discovery();
    script.extend(discovery());
    let f = Fixture::new(pool, script).await;
    f.connect().await.expect("connected");

    let refused = f
        .service
        .connect_icloud(f.tenant, f.admin, "someone@else.example", APP_PASSWORD)
        .await
        .expect_err("a different Apple ID is refused");
    let refused = refused.to_string();
    assert!(refused.contains(APPLE_ID), "{refused}");
    assert!(
        refused.contains("Apple ID") && !refused.contains("Google account"),
        "the refusal names what kind of account this is: {refused}"
    );
}

/// The point of PMS-1409: two providers, one tenant, one response, and a
/// selection each. The prefix check that refused every iCloud group id is the
/// thing that made this impossible, so both halves are asserted here.
#[mokosh_test]
async fn a_tenant_holds_a_google_and_an_icloud_connection_at_once(pool: PgPool) {
    let f = Fixture::new(pool, discovery()).await;
    let ctx = mokosh_server::modules::audit::AuditCtx::system(common::DEFAULT_TENANT_ID);

    let google = f
        .service
        .record_connection(f.tenant, f.admin, "google", "ops@msp.example", "grant")
        .await
        .expect("a Google connection");
    let ConnectOutcome::Connected(icloud_id) = f.connect().await.expect("an iCloud connection")
    else {
        panic!("a first connect is a new connection");
    };
    let google_id = match google {
        ConnectOutcome::Connected(id) | ConnectOutcome::Reconnected(id) => id,
    };
    assert_ne!(google_id, icloud_id);

    // Each provider's own group-id shape, which is the validation PMS-1409 fixed.
    const APPLE_GROUP: &str = "GGGG1111-2222-3333-4444-555566667777";
    let refused = f
        .service
        .set_selection(f.tenant, "google", &[APPLE_GROUP.to_string()], &ctx)
        .await
        .expect_err("an Apple UID is not a Google label id");
    // The field message, not the Display: `validation_field` puts the words an
    // admin reads in the body's `errors` and keeps "one or more fields are
    // invalid" as the summary (PMS-298).
    let mokosh_server::utils::error::AppError::Validation { errors, .. } = &refused else {
        panic!("a shape refusal is a validation error: {refused}");
    };
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].field, "group_ids");
    assert!(
        errors[0].message.contains("Google label"),
        "{}",
        errors[0].message
    );
    f.service
        .set_selection(f.tenant, "icloud", &[APPLE_GROUP.to_string()], &ctx)
        .await
        .expect("an Apple group id is a valid iCloud selection");
    f.service
        .set_selection(
            f.tenant,
            "google",
            &["contactGroups/clients".to_string()],
            &ctx,
        )
        .await
        .expect("a Google label id is a valid Google selection");

    // One read carries both, each with its own selection.
    let overview = f.service.overview(f.tenant).await.expect("the overview");
    let google_card = overview.connection.expect("the Google card");
    let icloud_card = overview.icloud_connection.expect("the iCloud card");
    assert_eq!(google_card.selected_groups, vec!["contactGroups/clients"]);
    assert_eq!(icloud_card.selected_groups, vec![APPLE_GROUP]);
    assert_eq!(icloud_card.account_email, APPLE_ID);
    assert_eq!(
        f.count("SELECT count(*) FROM contact_sync_connections WHERE disconnected_at IS NULL")
            .await,
        2,
        "the live-connection index is per provider, so both stay live"
    );

    // Disconnecting one leaves the other alone.
    f.service
        .disconnect(f.tenant, "icloud", &ctx)
        .await
        .expect("disconnect iCloud");
    let overview = f.service.overview(f.tenant).await.expect("the overview");
    assert!(overview.icloud_connection.is_none());
    assert!(
        overview.connection.is_some(),
        "the Google connection is untouched"
    );
}

/// The off switch is per integration (PMS-1341), so iCloud's stops an iCloud
/// connect and Google's does not.
#[mokosh_test]
async fn the_icloud_switch_is_the_one_that_stops_an_icloud_connect(pool: PgPool) {
    let f = Fixture::new(pool, discovery()).await;
    let set = |category: &'static str, key: &'static str, value: bool| {
        let pool = f.pool.clone();
        async move {
            sqlx::query(
                "INSERT INTO tenant_settings (tenant_id, category, key, value) \
                 VALUES ($1, $2, $3, $4)",
            )
            .bind(common::DEFAULT_TENANT_ID)
            .bind(category)
            .bind(key)
            .bind(serde_json::json!(value))
            .execute(&pool)
            .await
            .unwrap();
        }
    };

    set("integrations", "google_contacts_enabled", false).await;
    f.connect()
        .await
        .expect("Google's switch says nothing about iCloud");

    set("integrations", "icloud_contacts_enabled", false).await;
    let refused = f
        .service
        .connect_icloud(f.tenant, f.admin, APPLE_ID, APP_PASSWORD)
        .await
        .expect_err("iCloud is turned off")
        .to_string();
    assert!(refused.contains("iCloud Contacts"), "{refused}");
}
