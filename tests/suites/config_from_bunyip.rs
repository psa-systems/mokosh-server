//! PMS-1553: the Bunyip configuration provider, against the route bunyip
//! actually serves.
//!
//! PMS-987 shipped this provider against `POST /v1/oauth2/token` and
//! `GET /v1/config/{KEY}`, neither of which exists in bunyip, so it could not
//! have resolved a key against a real one. Nothing noticed because no boot
//! path can select it: `CONFIG_BACKEND` takes `environment` alone and
//! `CONFIG_PROVIDERS` is read by the provider CLI. BUNYIP-1011 shipped
//! `GET /v1/host/config/{KEY}` and this suite is the proof that the client
//! speaks it.
//!
//! The one case worth reading twice is `only_the_keys_bunyip_owns_are_asked_for`.
//! The old implementation looped the whole declared registry, which is over a
//! hundred requests per build and more than bunyip's own per-app cap allows in
//! a minute, so the provider would have throttled itself even once the route
//! existed.

use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use mokosh_server::config::{BunyipConfig, BunyipProvider, ConfigProvider};
use serde_json::json;

const SUPPORT_INBOX: &str = "abuse@suite.example";
const MACHINE_ID: &str = "b2f4c6a8-0000-4000-8000-00000000f00d";
const MACHINE_SECRET: &str = "fixture-config-credential";

#[derive(Default)]
struct Calls {
    /// Every path asked for, so the suite can prove which keys were requested
    /// and that the key is namespaced.
    paths: Vec<String>,
    /// Every `Authorization` header, to prove the credential went as Basic
    /// rather than as a bearer from a token exchange that does not exist.
    authorizations: Vec<String>,
    /// When set, the route answers this status instead of a value.
    refuse_with: Option<StatusCode>,
}

type Stub = Arc<Mutex<Calls>>;

async fn host_config(
    State(stub): State<Stub>,
    headers: HeaderMap,
    uri: axum::http::Uri,
) -> axum::response::Response {
    let mut calls = stub.lock().unwrap();
    calls.paths.push(uri.path().to_string());
    calls.authorizations.push(
        headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string(),
    );
    if let Some(status) = calls.refuse_with {
        return (status, Json(json!({ "error": "refused" }))).into_response();
    }
    Json(json!({
        "data": { "key": "mokosh/abuse_contact_email", "value": SUPPORT_INBOX }
    }))
    .into_response()
}

async fn start_stub() -> (Stub, String) {
    let stub: Stub = Arc::new(Mutex::new(Calls::default()));
    let app = axum::Router::new()
        .route("/v1/host/config/{*key}", axum::routing::get(host_config))
        .with_state(stub.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (stub, base)
}

fn config(base: &str) -> BunyipConfig {
    BunyipConfig {
        base_url: base.trim_end_matches('/').to_string(),
        client_id: MACHINE_ID.to_string(),
        client_secret: MACHINE_SECRET.to_string(),
    }
}

/// The value bunyip holds becomes a declared key here, read through the
/// provider trait every other configuration provider answers through.
#[tokio::test]
async fn the_support_mailbox_comes_from_bunyip() {
    let (stub, base) = start_stub().await;

    let provider = BunyipProvider::load(&config(&base))
        .await
        .expect("bunyip serves the key");

    assert_eq!(
        provider.get("ABUSE_CONTACT_EMAIL").as_deref(),
        Some(SUPPORT_INBOX)
    );
    assert!(provider.has("ABUSE_CONTACT_EMAIL"));
    assert_eq!(provider.name(), "bunyip");

    let (paths, authorizations) = {
        let calls = stub.lock().unwrap();
        (calls.paths.clone(), calls.authorizations.clone())
    };
    assert_eq!(paths, vec!["/v1/host/config/mokosh/abuse_contact_email"]);
    let expected = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(format!("{MACHINE_ID}:{MACHINE_SECRET}"))
    };
    assert_eq!(
        authorizations,
        vec![format!("Basic {expected}")],
        "Basic, because bunyip mints no bearer for a machine caller"
    );
}

/// Only the keys bunyip owns are asked for.
///
/// The old implementation walked every declared key, which is over a hundred
/// requests and an instant 429 against bunyip's per-app cap. This is the
/// assertion that keeps the mapping honest as keys are added.
#[tokio::test]
async fn only_the_keys_bunyip_owns_are_asked_for() {
    let (stub, base) = start_stub().await;

    let _provider = BunyipProvider::load(&config(&base))
        .await
        .expect("bunyip serves the key");

    let paths = stub.lock().unwrap().paths.clone();
    assert_eq!(
        paths.len(),
        1,
        "one request per key bunyip serves, not one per declared key: {paths:?}"
    );
    for path in &paths {
        assert!(
            path.starts_with("/v1/host/config/mokosh/"),
            "every key is namespaced to the product that reads it: {path}"
        );
    }
}

/// A key bunyip serves but holds no value for leaves it unheld, and the
/// provider still builds: that is a fact about bunyip's own configuration,
/// not a failure of this provider.
#[tokio::test]
async fn a_key_bunyip_holds_no_value_for_is_unheld() {
    let (stub, base) = start_stub().await;
    stub.lock().unwrap().refuse_with = Some(StatusCode::NOT_FOUND);

    let provider = BunyipProvider::load(&config(&base))
        .await
        .expect("the provider still builds");

    assert!(!provider.has("ABUSE_CONTACT_EMAIL"));
    assert_eq!(provider.get("ABUSE_CONTACT_EMAIL"), None);
}

/// A refused credential is the provider failing, so it is an error naming the
/// rotation rather than a key reported as unheld.
#[tokio::test]
async fn a_401_names_the_credential_and_how_to_rotate_it() {
    let (stub, base) = start_stub().await;
    stub.lock().unwrap().refuse_with = Some(StatusCode::UNAUTHORIZED);

    let error = BunyipProvider::load(&config(&base))
        .await
        .expect_err("an unknown credential refuses");
    let message = error.to_string();
    assert!(message.contains("BUNYIP_CONFIG_CLIENT_ID"), "{message}");
    assert!(message.contains("machine-client rotate"), "{message}");
}

/// A 403 names the allow-list AND the trap: a host-secrets credential does not
/// carry configuration keys, which is the entitlement split BUNYIP-855 D9
/// asked for and the mistake an operator is most likely to make here.
#[tokio::test]
async fn a_403_names_the_config_allow_list_and_the_two_registrations() {
    let (stub, base) = start_stub().await;
    stub.lock().unwrap().refuse_with = Some(StatusCode::FORBIDDEN);

    let error = BunyipProvider::load(&config(&base))
        .await
        .expect_err("an unentitled credential refuses");
    let message = error.to_string();
    assert!(message.contains("--config-key"), "{message}");
    assert!(
        message.contains("host-SECRETS credential") || message.contains("BUNYIP-855"),
        "and says the two registrations are separate: {message}"
    );
}

/// A bunyip nobody can reach names the URL and the variable that holds it.
#[tokio::test]
async fn an_unreachable_bunyip_names_the_url() {
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
    assert!(message.contains("BUNYIP_CONFIG_URL"), "{message}");
    assert!(message.contains(&closed), "{message}");
}

/// The provider takes no writes: bunyip owns these values, and an operator
/// migrating TO it gets a named refusal rather than a silent success.
#[tokio::test]
async fn bunyip_takes_no_configuration_writes() {
    let (_stub, base) = start_stub().await;
    let provider = BunyipProvider::load(&config(&base))
        .await
        .expect("bunyip serves the key");

    let error = provider
        .set("ABUSE_CONTACT_EMAIL", "someone@else.example")
        .await
        .expect_err("the write is refused");
    assert!(error.to_string().contains("bunyip"), "{error}");
}
