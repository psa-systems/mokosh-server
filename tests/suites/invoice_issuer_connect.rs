//! MAPPS-1142: connecting a Xero organisation or a QuickBooks company.
//!
//! The round trip the rest of MAPPS-1099 was waiting on. What is asserted
//! here is mostly what a connection flow must REFUSE: a replayed state, an
//! expired one, a secret that does not verify, and a Xero grant covering
//! more than one organisation. The happy path is one case because it is the
//! easy half; every one of those refusals is a way a connection flow goes
//! wrong quietly.
//!
//! The providers are stubs on `127.0.0.1:0`, the shape every other suite
//! here uses, with the identity and API bases pointed at them.

use crate::common;

use std::sync::{Arc, Mutex};

use axum::{extract::State, response::IntoResponse, Json};
use chrono::Utc;
use mokosh_server::db::Database;
use mokosh_server::modules::auth::TenantId;
use mokosh_server::modules::billing::invoice_issuer::InvoiceProviderKind;
use mokosh_server::modules::billing::invoice_issuer_app::{IssuerApp, IssuerApps};
use mokosh_server::modules::billing::invoice_issuer_connect::InvoiceIssuerConnectService;
use mokosh_server::modules::billing::invoice_issuer_credentials::{
    parse_blob, IntegrationCredentialBlob,
};
use mokosh_server::modules::billing::provider_invoice::{QuickBooksClient, XeroClient};
use mokosh_server::modules::billing::service::BillingService;
use mokosh_server::secrets::{DatabaseSecretProvider, SecretKey, SecretProvider};
use mokosh_test::mokosh_test;
use serde_json::{json, Value};
use sqlx::PgPool;

/// How many organisations the stub's `GET /connections` reports.
#[derive(Clone, Default)]
struct Script {
    organisations: Arc<Mutex<Vec<String>>>,
    exchanges: Arc<Mutex<Vec<String>>>,
}

async fn token(State(script): State<Script>, body: String) -> impl IntoResponse {
    script.exchanges.lock().unwrap().push(body);
    Json(json!({
        "access_token": "fresh-access",
        "refresh_token": "fresh-refresh",
        "expires_in": 1800,
        "x_refresh_token_expires_in": 8_640_000,
        "token_type": "Bearer",
    }))
}

async fn connections(State(script): State<Script>) -> impl IntoResponse {
    let orgs = script.organisations.lock().unwrap().clone();
    Json(Value::Array(
        orgs.into_iter()
            .map(|id| json!({ "tenantId": id, "tenantName": "Acme Books" }))
            .collect(),
    ))
}

async fn start_stub() -> (Script, String) {
    let script = Script::default();
    script
        .organisations
        .lock()
        .unwrap()
        .push("xero-org-1".to_string());
    let app = axum::Router::new()
        .route("/connect/token", axum::routing::post(token))
        .route("/oauth2/v1/tokens/bearer", axum::routing::post(token))
        .route("/connections", axum::routing::get(connections))
        .with_state(script.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (script, base)
}

fn apps() -> IssuerApps {
    let app = || {
        Some(IssuerApp {
            client_id: "host-client".to_string(),
            client_secret: "fixture-only-not-a-credential".to_string(),
            webhook_key: None,
        })
    };
    IssuerApps {
        xero: app(),
        quickbooks: app(),
    }
}

async fn service(
    pool: &PgPool,
    base: &str,
    apps: IssuerApps,
) -> (
    InvoiceIssuerConnectService,
    Arc<dyn SecretProvider>,
    Database,
) {
    // The deployment toggle on, which is what a deployment that has decided
    // to use this looks like. `service_without_the_toggle` is the other one.
    service_with_toggle(pool, base, apps, true).await
}

async fn service_without_the_toggle(
    pool: &PgPool,
    base: &str,
    apps: IssuerApps,
) -> (
    InvoiceIssuerConnectService,
    Arc<dyn SecretProvider>,
    Database,
) {
    service_with_toggle(pool, base, apps, false).await
}

async fn service_with_toggle(
    pool: &PgPool,
    base: &str,
    apps: IssuerApps,
    delegation_enabled: bool,
) -> (
    InvoiceIssuerConnectService,
    Arc<dyn SecretProvider>,
    Database,
) {
    let app_pool = common::build_app_role_pool(pool).await;
    let db = Database::from_pools(app_pool, pool.clone());
    let secrets: Arc<dyn SecretProvider> =
        Arc::new(DatabaseSecretProvider::new(db.clone(), [0u8; 32]));
    let toggles = if delegation_enabled {
        mokosh_server::modules::features::FeatureToggles::from_rows([(
            mokosh_server::modules::features::Feature::DelegatedInvoiceIssuer.key(),
            true,
        )])
    } else {
        mokosh_server::modules::features::FeatureToggles::default()
    };
    let service = InvoiceIssuerConnectService::new(
        db.clone(),
        secrets.clone(),
        Arc::new(apps),
        mokosh_server::modules::features::FeatureSnapshot::new(toggles),
        Arc::new(
            XeroClient::new()
                .with_api_base(base)
                .with_identity_base(base),
        ),
        Arc::new(
            QuickBooksClient::new()
                .with_api_base(base)
                .with_identity_base(base),
        ),
        Some("https://api.msp.example".to_string()),
        "https://app.msp.example".to_string(),
    );
    (service, secrets, db)
}

/// The state parameter a consent URL carries, pulled back out of it.
fn state_from(url: &str) -> String {
    let raw = url
        .split('&')
        .find_map(|p| p.strip_prefix("state="))
        .expect("the consent URL carries a state");
    urlencoding::decode(raw).expect("decodable").into_owned()
}

async fn integration_row(
    pool: &PgPool,
    provider: &str,
) -> Option<(String, Vec<String>, Option<String>)> {
    sqlx::query_as(
        "SELECT status, enabled_capabilities, external_organisation_id \
         FROM integrations WHERE tenant_id = $1 AND provider = $2",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(provider)
    .fetch_optional(pool)
    .await
    .expect("read the integrations row")
}

/// Connecting Xero: the token pair is stored, the organisation is recorded,
/// and the row reads as connected with invoicing delegated.
#[mokosh_test]
async fn connecting_xero_writes_the_credential_and_names_the_organisation(pool: PgPool) {
    let (script, base) = start_stub().await;
    let (admin, _email, _password) = common::seed_admin(&pool).await;
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);
    let (svc, secrets, db) = service(&pool, &base, apps()).await;

    let url = svc
        .begin(tenant, admin, InvoiceProviderKind::Xero)
        .await
        .expect("begin");
    assert!(url.contains("login.xero.com"), "{url}");
    assert!(
        url.contains(
            &urlencoding::encode(&svc.redirect_uri(InvoiceProviderKind::Xero).unwrap())
                .into_owned()
        ),
        "the consent URL carries the exact redirect the exchange will repeat: {url}"
    );

    let destination = svc
        .complete(
            InvoiceProviderKind::Xero,
            &state_from(&url),
            "auth-code",
            None,
        )
        .await
        .expect("complete");
    assert!(
        destination.contains("/settings/integrations"),
        "{destination}"
    );

    let exchange = script.exchanges.lock().unwrap()[0].clone();
    assert!(
        exchange.contains("grant_type=authorization_code") && exchange.contains("code_verifier="),
        "the exchange sends the code and the verifier that was never in the browser: {exchange}"
    );

    let stored = secrets
        .get(&SecretKey::integration(common::DEFAULT_TENANT_ID, "xero"))
        .await
        .expect("read")
        .expect("a blob was written");
    let blob = parse_blob(Some(&stored), InvoiceProviderKind::Xero).expect("it parses as Xero's");
    let IntegrationCredentialBlob::Xero(xero) = blob else {
        panic!("wrong variant")
    };
    assert_eq!(xero.refresh_token, "fresh-refresh");
    assert_eq!(
        xero.tenant_id, "xero-org-1",
        "the organisation comes from GET /connections, since the token response does not say"
    );
    assert!(xero.access_token_expires_at > Utc::now());

    let row = integration_row(&pool, "xero").await.expect("a row");
    assert_eq!(row.0, "connected");
    assert_eq!(
        row.1,
        vec!["invoicing".to_string()],
        "connecting through this flow IS the delegation"
    );
    assert_eq!(row.2.as_deref(), Some("xero-org-1"));

    // And the receivers can find their way back from the organisation.
    let billing = BillingService::new(db);
    assert_eq!(
        billing
            .tenant_for_external_organisation("xero", "xero-org-1")
            .await
            .expect("lookup"),
        Some(common::DEFAULT_TENANT_ID),
        "which is what the webhook route resolves on"
    );
}

/// QuickBooks names its company on the callback, and that is what is
/// recorded.
#[mokosh_test]
async fn connecting_quickbooks_records_the_realm_from_the_callback(pool: PgPool) {
    let (_script, base) = start_stub().await;
    let (admin, _email, _password) = common::seed_admin(&pool).await;
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);
    let (svc, secrets, _db) = service(&pool, &base, apps()).await;

    let url = svc
        .begin(tenant, admin, InvoiceProviderKind::Quickbooks)
        .await
        .expect("begin");
    assert!(url.contains("appcenter.intuit.com"), "{url}");

    svc.complete(
        InvoiceProviderKind::Quickbooks,
        &state_from(&url),
        "auth-code",
        Some("4620816365"),
    )
    .await
    .expect("complete");

    let stored = secrets
        .get(&SecretKey::integration(
            common::DEFAULT_TENANT_ID,
            "quickbooks",
        ))
        .await
        .expect("read")
        .expect("a blob");
    let blob = parse_blob(Some(&stored), InvoiceProviderKind::Quickbooks).expect("parses");
    let IntegrationCredentialBlob::Quickbooks(qbo) = blob else {
        panic!("wrong variant")
    };
    assert_eq!(qbo.realm_id, "4620816365");
    assert!(
        qbo.refresh_token_expires_at.is_some(),
        "Intuit's refresh token has its own lifetime and the blob keeps it"
    );
    assert_eq!(
        integration_row(&pool, "quickbooks")
            .await
            .and_then(|r| r.2)
            .as_deref(),
        Some("4620816365")
    );
}

/// A callback with no realm is refused rather than connected blind.
#[mokosh_test]
async fn quickbooks_without_a_realm_is_refused(pool: PgPool) {
    let (_script, base) = start_stub().await;
    let (admin, _email, _password) = common::seed_admin(&pool).await;
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);
    let (svc, _secrets, _db) = service(&pool, &base, apps()).await;

    let url = svc
        .begin(tenant, admin, InvoiceProviderKind::Quickbooks)
        .await
        .expect("begin");
    let err = svc
        .complete(
            InvoiceProviderKind::Quickbooks,
            &state_from(&url),
            "auth-code",
            None,
        )
        .await
        .expect_err("no company was named");
    assert!(err.to_string().contains("named no company"), "{err}");
    assert!(integration_row(&pool, "quickbooks").await.is_none());
}

/// A state is spent once.
///
/// Consumed BEFORE the exchange, so a replay cannot ride a slow or failing
/// first attempt, and the second caller is told to start again rather than
/// being handed a second connection.
#[mokosh_test]
async fn a_state_is_single_use(pool: PgPool) {
    let (_script, base) = start_stub().await;
    let (admin, _email, _password) = common::seed_admin(&pool).await;
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);
    let (svc, _secrets, _db) = service(&pool, &base, apps()).await;

    let url = svc
        .begin(tenant, admin, InvoiceProviderKind::Xero)
        .await
        .expect("begin");
    let state = state_from(&url);
    svc.complete(InvoiceProviderKind::Xero, &state, "auth-code", None)
        .await
        .expect("the first one works");
    let err = svc
        .complete(InvoiceProviderKind::Xero, &state, "auth-code", None)
        .await
        .expect_err("the second must not");
    assert!(err.to_string().contains("no longer valid"), "{err}");
}

/// An expired state, and a state whose secret does not verify, are both
/// refused with the copy that sends an admin back to Settings.
#[mokosh_test]
async fn an_expired_or_forged_state_is_refused(pool: PgPool) {
    let (_script, base) = start_stub().await;
    let (admin, _email, _password) = common::seed_admin(&pool).await;
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);
    let (svc, _secrets, _db) = service(&pool, &base, apps()).await;

    let url = svc
        .begin(tenant, admin, InvoiceProviderKind::Xero)
        .await
        .expect("begin");
    let state = state_from(&url);
    let (state_id, _secret) = state.split_once('.').expect("id.secret");

    // The right row, the wrong secret.
    let forged = format!("{state_id}.not-the-secret-that-was-minted");
    let err = svc
        .complete(InvoiceProviderKind::Xero, &forged, "code", None)
        .await
        .expect_err("a forged secret");
    assert!(err.to_string().contains("no longer valid"), "{err}");

    // The right secret, too late.
    sqlx::query("UPDATE invoice_issuer_oauth_states SET expires_at = NOW() - INTERVAL '1 minute'")
        .execute(&pool)
        .await
        .expect("age the state");
    let err = svc
        .complete(InvoiceProviderKind::Xero, &state, "code", None)
        .await
        .expect_err("an expired state");
    assert!(err.to_string().contains("no longer valid"), "{err}");
    assert!(integration_row(&pool, "xero").await.is_none());
}

/// A Xero grant covering several organisations is refused, not guessed at.
///
/// Picking one would delegate this tenant's invoicing to an organisation
/// nobody chose, and `integrations` holds one row per provider so the
/// others have nowhere to go. The refusal says what to do instead.
#[mokosh_test]
async fn a_grant_over_several_organisations_is_refused(pool: PgPool) {
    let (script, base) = start_stub().await;
    let (admin, _email, _password) = common::seed_admin(&pool).await;
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);
    let (svc, secrets, _db) = service(&pool, &base, apps()).await;
    *script.organisations.lock().unwrap() =
        vec!["xero-org-1".to_string(), "xero-org-2".to_string()];

    let url = svc
        .begin(tenant, admin, InvoiceProviderKind::Xero)
        .await
        .expect("begin");
    let err = svc
        .complete(InvoiceProviderKind::Xero, &state_from(&url), "code", None)
        .await
        .expect_err("two organisations");
    assert!(
        err.to_string().contains("2 organisations")
            && err.to_string().contains("authorise the one"),
        "the refusal says what to do instead: {err}"
    );
    assert!(
        secrets
            .get(&SecretKey::integration(common::DEFAULT_TENANT_ID, "xero"))
            .await
            .expect("read")
            .is_none(),
        "and nothing is stored for a connection that was not made"
    );
    assert!(integration_row(&pool, "xero").await.is_none());
}

/// What the settings page reads, through the four states it has to
/// render.
///
/// `configured` is the deployment's answer and the one the catalog cannot
/// give: a built provider on a deployment holding no client id still
/// cannot be connected, and a page that offered Connect for it would be
/// MAPPS-1121 again.
#[mokosh_test]
async fn the_overview_answers_for_the_deployment_and_for_the_tenant(pool: PgPool) {
    let (_script, base) = start_stub().await;
    let (admin, _email, _password) = common::seed_admin(&pool).await;
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);

    // A deployment with no application: configured false, and never
    // connected reads as an offer rather than an error.
    let (bare, _secrets, _db) = service(&pool, &base, IssuerApps::default()).await;
    let view = bare
        .overview(tenant, InvoiceProviderKind::Xero)
        .await
        .expect("overview");
    assert!(!view.configured, "no application on this deployment");
    assert_eq!(view.status.as_str(), "not_connected");
    assert!(view.organisation_id.is_none());
    assert!(!view.delegated);

    // Configured, still not connected.
    let (svc, _secrets, _db) = service(&pool, &base, apps()).await;
    let view = svc
        .overview(tenant, InvoiceProviderKind::Xero)
        .await
        .expect("overview");
    assert!(view.configured);
    assert_eq!(view.status.as_str(), "not_connected");

    // Connected, through the flow that is the only thing that sets it.
    let url = svc
        .begin(tenant, admin, InvoiceProviderKind::Xero)
        .await
        .expect("begin");
    svc.complete(InvoiceProviderKind::Xero, &state_from(&url), "code", None)
        .await
        .expect("complete");
    let view = svc
        .overview(tenant, InvoiceProviderKind::Xero)
        .await
        .expect("overview");
    assert_eq!(view.status.as_str(), "connected");
    assert_eq!(
        view.organisation_id.as_deref(),
        Some("xero-org-1"),
        "an admin with two Xero organisations needs to know which one this is"
    );
    assert!(
        view.delegated,
        "connecting through this flow IS the delegation"
    );

    // And the other provider is untouched by any of it.
    let other = svc
        .overview(tenant, InvoiceProviderKind::Quickbooks)
        .await
        .expect("overview");
    assert_eq!(other.status.as_str(), "not_connected");
    assert!(other.configured, "the deployment holds both applications");
}

/// Disconnecting forgets the credential, keeps what was delegated, and
/// leaves the next invoice on the local path.
///
/// The last clause is the one worth the case. `plan` used to decide by
/// reading the capability alone, and the capability survives a disconnect
/// on purpose, so this exact state would have sent every new invoice down
/// a delegated path whose credential had just been deleted - every invoice
/// create for the tenant refusing, with a row that says `disconnected` as
/// the explanation.
#[mokosh_test]
async fn disconnecting_forgets_the_credential_and_stops_delegating(pool: PgPool) {
    let (_script, base) = start_stub().await;
    let (admin, _email, _password) = common::seed_admin(&pool).await;
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);
    let (svc, secrets, db) = service(&pool, &base, apps()).await;

    let url = svc
        .begin(tenant, admin, InvoiceProviderKind::Xero)
        .await
        .expect("begin");
    svc.complete(InvoiceProviderKind::Xero, &state_from(&url), "code", None)
        .await
        .expect("complete");

    svc.disconnect(tenant, InvoiceProviderKind::Xero)
        .await
        .expect("disconnect");

    assert!(
        secrets
            .get(&SecretKey::integration(common::DEFAULT_TENANT_ID, "xero"))
            .await
            .expect("read")
            .is_none(),
        "a disconnect that left the credential behind would leave a working connection \
         the page says is off"
    );
    let view = svc
        .overview(tenant, InvoiceProviderKind::Xero)
        .await
        .expect("overview");
    assert_eq!(view.status.as_str(), "disconnected");
    assert!(
        view.delegated,
        "what was delegated is the tenant's answer and survives, so reconnecting does \
         not start from an empty page"
    );

    // And the invoice path reads the pair, not the capability alone.
    let integrations =
        mokosh_server::modules::integrations::IntegrationsService::new(db.clone(), secrets.clone());
    let row = integrations
        .get(
            tenant,
            mokosh_types::integrations::IntegrationProvider::Xero,
        )
        .await
        .expect("read the row");
    assert!(
        row.enabled_capabilities.iter().any(|c| c == "invoicing"),
        "the capability is still there, which is exactly why the status has to be read too"
    );

    // Reconnecting restores a usable connection without the admin choosing
    // anything again.
    let url = svc
        .begin(tenant, admin, InvoiceProviderKind::Xero)
        .await
        .expect("begin again");
    svc.complete(InvoiceProviderKind::Xero, &state_from(&url), "code", None)
        .await
        .expect("complete again");
    let view = svc
        .overview(tenant, InvoiceProviderKind::Xero)
        .await
        .expect("overview");
    assert_eq!(view.status.as_str(), "connected");
    assert!(view.delegated);
}

/// MAPPS-1154: the overview says whether the DEPLOYMENT has delegated
/// issuing switched on, which is the gate that is off everywhere by
/// default.
///
/// Without it a tenant can be configured, connected and delegated and
/// still have every invoice issued locally, because `IssuerDispatcher::plan`
/// answers `Local` while the toggle is off - and the card would be saying
/// the opposite. The connect itself is deliberately NOT gated: preparing a
/// tenant before the flip is a reasonable order to work in.
#[mokosh_test]
async fn the_overview_says_whether_the_deployment_has_switched_it_on(pool: PgPool) {
    let (_script, base) = start_stub().await;
    let (admin, _email, _password) = common::seed_admin(&pool).await;
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);

    let (off, _secrets, _db) = service_without_the_toggle(&pool, &base, apps()).await;
    let view = off
        .overview(tenant, InvoiceProviderKind::Xero)
        .await
        .expect("overview");
    assert!(view.configured, "the deployment holds an application");
    assert!(
        !view.delegation_enabled,
        "and has not switched delegated issuing on, which is the default everywhere"
    );

    // Connecting still works with the toggle off, and the two facts stay
    // apart: the tenant has delegated, the deployment has not switched it on.
    let url = off
        .begin(tenant, admin, InvoiceProviderKind::Xero)
        .await
        .expect("begin");
    off.complete(InvoiceProviderKind::Xero, &state_from(&url), "code", None)
        .await
        .expect("complete");
    let view = off
        .overview(tenant, InvoiceProviderKind::Xero)
        .await
        .expect("overview");
    assert_eq!(view.status.as_str(), "connected");
    assert!(view.delegated, "the tenant delegated invoicing");
    assert!(
        !view.delegation_enabled,
        "and no invoice will go to Xero until the deployment switches it on"
    );

    // The same tenant read through a service whose deployment HAS switched
    // it on. Same row, different deployment answer.
    let (on, _secrets, _db) = service(&pool, &base, apps()).await;
    let view = on
        .overview(tenant, InvoiceProviderKind::Xero)
        .await
        .expect("overview");
    assert!(view.delegated && view.delegation_enabled);
}

/// One tenant's connection is invisible to another.
#[mokosh_test]
async fn an_overview_does_not_leak_another_tenants_connection(pool: PgPool) {
    let (_script, base) = start_stub().await;
    let (admin, _email, _password) = common::seed_admin(&pool).await;
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);
    let (svc, _secrets, _db) = service(&pool, &base, apps()).await;

    let url = svc
        .begin(tenant, admin, InvoiceProviderKind::Xero)
        .await
        .expect("begin");
    svc.complete(InvoiceProviderKind::Xero, &state_from(&url), "code", None)
        .await
        .expect("complete");

    let other_tenant = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO tenants (id, name, slug, kind) VALUES ($1, 'Other MSP', $2, 'org')")
        .bind(other_tenant)
        .bind(format!("other-{}", &other_tenant.to_string()[..8]))
        .execute(&pool)
        .await
        .expect("seed the other tenant");

    let view = svc
        .overview(
            TenantId::from_trusted(other_tenant),
            InvoiceProviderKind::Xero,
        )
        .await
        .expect("overview");
    assert_eq!(view.status.as_str(), "not_connected");
    assert!(view.organisation_id.is_none());
}

/// A deployment with no application for the provider cannot start a
/// connection, and says so in the deployment's terms.
#[mokosh_test]
async fn a_deployment_without_an_application_cannot_connect(pool: PgPool) {
    let (_script, base) = start_stub().await;
    let (admin, _email, _password) = common::seed_admin(&pool).await;
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);
    let (svc, _secrets, _db) = service(&pool, &base, IssuerApps::default()).await;

    let err = svc
        .begin(tenant, admin, InvoiceProviderKind::Xero)
        .await
        .expect_err("nothing to authorise against");
    assert!(
        err.to_string().contains("not available on this deployment"),
        "{err}"
    );
    let states: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM invoice_issuer_oauth_states")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(
        states, 0,
        "and no state is minted for a flow that cannot run"
    );
}
