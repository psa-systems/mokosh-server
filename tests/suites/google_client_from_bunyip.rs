//! PMS-1537: the host's Google client, read from bunyip's host-secrets route.
//!
//! The sibling of `google_client_from_infisical.rs`, with one difference that
//! decides its shape: bunyip's route is a contract between two of our own
//! services, so it can be stubbed faithfully, and this suite therefore runs in
//! the default profile instead of needing a service stood up.
//!
//! What it pins is the contract, in both directions. Mokosh sends an HTTP Basic
//! credential (bunyip's `/oauth2/token` mints nothing for a machine, so there
//! is no bearer to present) and reads `data.value` as a STRING holding the
//! client pair. And every refusal names the place it is fixed, because the
//! three of them are fixed in three different places: a 403 is bunyip's
//! allow-list, a 404 is bunyip's admin page, and an unreachable host is this
//! deployment's URL.

use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use mokosh_server::app_secrets::{
    AppSecretProviderKind, AppSecrets, BunyipProvider, BunyipSecretsConfig, GovernedSecret,
};
use mokosh_server::modules::contact_sync::OauthClient;
use serde_json::{json, Value};

const CLIENT_ID: &str = "123456789012-abc123def456.apps.googleusercontent.com";
const CLIENT_SECRET: &str = "fixture-google-client-secret";
const MACHINE_ID: &str = "7b1f3c9e-0000-4000-8000-00000000c0de";
const MACHINE_SECRET: &str = "fixture-machine-credential";

/// What the stub was asked, and what it answers.
#[derive(Default)]
struct Calls {
    /// The `Authorization` header of each request, so the suite can prove the
    /// credential was presented as Basic rather than as a bearer.
    authorizations: Vec<String>,
    /// The paths asked for, so the suite can prove the key is namespaced.
    paths: Vec<String>,
    /// When set, the route answers this status with bunyip's error shape.
    refuse_with: Option<StatusCode>,
    /// When set, the 200 carries this instead of the pair.
    value_override: Option<String>,
}

type Stub = Arc<Mutex<Calls>>;

async fn host_secret(
    State(stub): State<Stub>,
    headers: HeaderMap,
    uri: axum::http::Uri,
) -> axum::response::Response {
    let mut calls = stub.lock().unwrap();
    calls.authorizations.push(
        headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string(),
    );
    calls.paths.push(uri.path().to_string());
    if let Some(status) = calls.refuse_with {
        return (status, Json(json!({ "error": "refused" }))).into_response();
    }
    let value = calls.value_override.clone().unwrap_or_else(|| {
        serde_json::to_string(&json!({
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        }))
        .expect("serialise the pair")
    });
    Json(json!({
        "data": { "key": "mokosh/google_oauth_client", "value": value }
    }))
    .into_response()
}

async fn start_stub() -> (Stub, String) {
    let stub: Stub = Arc::new(Mutex::new(Calls::default()));
    // The key carries a `/`, so the route has to capture a tail, exactly as
    // bunyip's own does.
    let app = axum::Router::new()
        .route("/v1/host/secrets/{*key}", axum::routing::get(host_secret))
        .with_state(stub.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (stub, base)
}

fn config(base: &str) -> BunyipSecretsConfig {
    BunyipSecretsConfig::resolve(base, MACHINE_ID, MACHINE_SECRET)
        .expect("a complete triad resolves")
        .expect("and is Some")
}

/// The pair bunyip holds becomes the host's Google client, through the same
/// seam the Infisical and database providers answer.
#[tokio::test]
async fn the_pair_comes_from_bunyip_and_feeds_the_host_client() {
    let (stub, base) = start_stub().await;

    let provider = BunyipProvider::load(&config(&base))
        .await
        .expect("bunyip serves the pair");
    let secrets = AppSecrets::with_provider(AppSecretProviderKind::Bunyip, Arc::new(provider));

    let client = OauthClient::from_app_secrets(&secrets)
        .expect("the pair resolves")
        .expect("and both halves are present");
    assert_eq!(client.client_id, CLIENT_ID);
    assert_eq!(client.client_secret, CLIENT_SECRET);

    let (authorizations, paths) = {
        let calls = stub.lock().unwrap();
        (calls.authorizations.clone(), calls.paths.clone())
    };
    assert_eq!(paths, vec!["/v1/host/secrets/mokosh/google_oauth_client"]);
    assert_eq!(
        authorizations.len(),
        1,
        "one call for the one key, cached afterwards"
    );
    let expected = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(format!("{MACHINE_ID}:{MACHINE_SECRET}"))
    };
    assert_eq!(
        authorizations[0],
        format!("Basic {expected}"),
        "Basic, because bunyip mints no machine bearer to present"
    );
}

/// A credential bunyip does not recognise names the credential, not the key:
/// the fix is a rotation, and the deployment cannot tell a revoked
/// registration from a mistyped secret.
#[tokio::test]
async fn a_401_names_the_credential_and_how_to_rotate_it() {
    let (stub, base) = start_stub().await;
    stub.lock().unwrap().refuse_with = Some(StatusCode::UNAUTHORIZED);

    let error = BunyipProvider::load(&config(&base))
        .await
        .expect_err("an unknown credential refuses");
    let message = error.to_string();
    assert!(message.contains("BUNYIP_SECRETS_CLIENT_ID"), "{message}");
    assert!(message.contains("machine-client rotate"), "{message}");
}

/// A 403 is bunyip's allow-list, so the message names the key and the command
/// that adds it.
#[tokio::test]
async fn a_403_names_the_allow_list() {
    let (stub, base) = start_stub().await;
    stub.lock().unwrap().refuse_with = Some(StatusCode::FORBIDDEN);

    let error = BunyipProvider::load(&config(&base))
        .await
        .expect_err("an unentitled credential refuses");
    let message = error.to_string();
    assert!(message.contains("mokosh/google_oauth_client"), "{message}");
    assert!(message.contains("--secret-key"), "{message}");
    assert!(
        message.contains("allowed_secret_keys") || message.contains("allow-list"),
        "and says what it is: {message}"
    );
}

/// A 404 is bunyip's admin page: nobody has set the pair yet, which is a
/// different person doing a different thing from the 403.
#[tokio::test]
async fn a_404_names_the_admin_page() {
    let (stub, base) = start_stub().await;
    stub.lock().unwrap().refuse_with = Some(StatusCode::NOT_FOUND);

    let error = BunyipProvider::load(&config(&base))
        .await
        .expect_err("an unset key refuses");
    let message = error.to_string();
    assert!(message.contains("Admin > Mokosh"), "{message}");
    assert!(
        message.contains("no Mokosh tenant"),
        "and what stops working: {message}"
    );
}

/// A bunyip nobody can reach names the URL and the variable that holds it,
/// because that is the one thing this deployment controls.
#[tokio::test]
async fn an_unreachable_bunyip_names_the_url() {
    // A port nothing listens on: bound, read for its address, then dropped.
    let closed = {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        format!("http://{addr}")
    };

    let error = BunyipProvider::load(&config(&closed))
        .await
        .expect_err("an unreachable bunyip refuses");
    let message = error.to_string();
    assert!(message.contains(&closed), "{message}");
    assert!(message.contains("BUNYIP_SECRETS_URL"), "{message}");
}

/// A value that is not the pair is a configuration error naming the key, not a
/// panic and not a half-resolved client.
#[tokio::test]
async fn a_value_that_is_not_the_pair_is_refused_by_name() {
    let (stub, base) = start_stub().await;
    stub.lock().unwrap().value_override = Some("not json at all".to_string());

    let error = BunyipProvider::load(&config(&base))
        .await
        .expect_err("a malformed value refuses");
    assert!(
        error.to_string().contains("client_id / client_secret pair"),
        "{error}"
    );
}

/// The provider refuses writes, so `provider-set` cannot put a copy in bunyip
/// that bunyip's own admin page would then disagree with.
#[tokio::test]
async fn bunyip_takes_no_writes_from_mokosh() {
    let (_stub, base) = start_stub().await;
    let provider = BunyipProvider::load(&config(&base))
        .await
        .expect("bunyip serves the pair");

    use mokosh_server::app_secrets::AppSecretProvider;
    assert!(!provider.is_writable());
    let error = provider
        .set(GovernedSecret::GoogleContactsClientId, "x")
        .await
        .expect_err("the write is refused");
    assert!(error.to_string().contains("bunyip"), "{error}");
}

/// The declaration is per secret: bunyip answers for the Google pair and the
/// process provider still answers for everything else, with no read falling
/// back from one to the other.
#[tokio::test]
async fn bunyip_serves_the_pair_and_nothing_else_moves() {
    let (_stub, base) = start_stub().await;
    let bunyip = BunyipProvider::load(&config(&base))
        .await
        .expect("bunyip serves the pair");

    let secrets = AppSecrets::with_provider(AppSecretProviderKind::Database, Arc::new(Local))
        .with_additional_provider(AppSecretProviderKind::Bunyip, Arc::new(bunyip))
        .declaring(
            GovernedSecret::GoogleContactsClientId,
            AppSecretProviderKind::Bunyip,
        )
        .declaring(
            GovernedSecret::GoogleContactsClientSecret,
            AppSecretProviderKind::Bunyip,
        );

    let client = OauthClient::from_app_secrets(&secrets)
        .expect("the pair resolves")
        .expect("and both halves are present");
    assert_eq!(
        client.client_id, CLIENT_ID,
        "the pair comes from bunyip even though the process provider holds one too"
    );
    assert_eq!(
        secrets.get(GovernedSecret::SmtpPassword).as_deref(),
        Some(LOCAL_VALUE),
        "and the process provider still serves its own secrets"
    );
    assert_eq!(
        secrets.get(GovernedSecret::XeroClientId).as_deref(),
        Some(LOCAL_VALUE),
        "including the invoicing clients, which are this deployment's own"
    );
}

const LOCAL_VALUE: &str = "held-by-the-process-provider";

/// A stand-in for whatever `APP_SECRET_BACKEND` names: it holds every governed
/// secret, so a reader that ignored the declaration would still find a value
/// and the assertion above would be the only thing that noticed.
struct Local;

#[async_trait::async_trait]
impl mokosh_server::app_secrets::AppSecretProvider for Local {
    fn name(&self) -> &'static str {
        "database"
    }

    fn get(&self, _secret: GovernedSecret) -> Option<String> {
        Some(LOCAL_VALUE.to_string())
    }
}

/// The pair is fetched once, at construction, and served from the cache after
/// that: a `has` per classification round would otherwise be a live call per
/// secret per boot.
#[tokio::test]
async fn the_key_is_fetched_once_and_cached() {
    let (stub, base) = start_stub().await;
    let provider = BunyipProvider::load(&config(&base))
        .await
        .expect("bunyip serves the pair");

    use mokosh_server::app_secrets::AppSecretProvider;
    for _ in 0..5 {
        assert!(provider.has(GovernedSecret::GoogleContactsClientId));
        assert!(provider
            .get(GovernedSecret::GoogleContactsClientSecret)
            .is_some());
    }
    assert_eq!(
        stub.lock().unwrap().authorizations.len(),
        1,
        "one fetch, however many reads"
    );
}

/// The envelope is bunyip's, not the pair: a reader that expected
/// `{"client_id": ...}` at the top level would fail on every real answer.
#[tokio::test]
async fn the_value_is_read_out_of_bunyips_envelope() {
    let (stub, base) = start_stub().await;
    // The pair at the top level, which is what a reader would see if bunyip
    // served the value raw.
    stub.lock().unwrap().value_override = None;
    let provider = BunyipProvider::load(&config(&base))
        .await
        .expect("the envelope parses");
    use mokosh_server::app_secrets::AppSecretProvider;
    assert_eq!(
        provider
            .get(GovernedSecret::GoogleContactsClientId)
            .as_deref(),
        Some(CLIENT_ID)
    );

    let raw: Value = serde_json::from_str(
        &serde_json::to_string(&json!({ "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET }))
            .unwrap(),
    )
    .unwrap();
    assert!(
        raw.get("data").is_none(),
        "the fixture value is the pair itself; the envelope is what wraps it"
    );
}
