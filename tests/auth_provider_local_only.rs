//! PMS-1309: a deployment with no Bunyip authenticates, end to end.
//!
//! PMS-981 made the authentication provider selectable (`AUTH_PROVIDERS`) and
//! pinned the decision as a pure function in
//! `modules::auth::providers`'s own unit tests. What it did not have is a test
//! that a deployment which EXCLUDES Bunyip still signs a person in and serves
//! them, which is the acceptance criterion PMS-1309 cares about: standalone and
//! development deployments must run with no Bunyip reachable, and "runs" means a
//! password reaches a protected route rather than a selection struct holding the
//! right enum.
//!
//! # One test, one process
//!
//! `install_selection` writes a process-wide `OnceLock` shared by every test in
//! a binary, so a second test here that installed a different selection would
//! race this one under plain `cargo test` (threads in one process) even though
//! nextest gives each test its own. Hence one test in its own file: the
//! opposite direction (an explicit selection that excludes a provider gates it
//! off) is already pinned as a pure function in
//! `auth::providers::tests::an_explicit_selection_that_excludes_a_provider_gates_it_off`,
//! where it needs no install at all.

mod common;

use mokosh_server::modules::auth::providers::{
    install_selection, AuthProviderKind, AuthProviderSelection,
};
use mokosh_server::utils::deployment::EnablementSource;
use mokosh_test::mokosh_test;
use reqwest::StatusCode;
use sqlx::PgPool;

/// A standalone deployment: `AUTH_PROVIDERS=local`, no Bunyip verifier mounted,
/// nothing on the network to reach.
///
/// Three things are asserted in the order an operator would meet them: the
/// password gets a token, the token serves a protected route, and a bearer of
/// the shape Bunyip issues is refused without the response saying why. The last
/// one is the disclosure rule PMS-981 states: a refusal under a disabled
/// provider must read exactly like a refusal under an invalid credential, or the
/// 401 body becomes a way to ask which providers a deployment has enabled.
#[mokosh_test]
async fn a_local_only_deployment_signs_a_person_in_with_no_bunyip(pool: PgPool) {
    // Explicit, not the profile default: PMS-981 gates only on an operator's own
    // list, because a profile default that omits a provider must not change
    // behaviour for a deployment that configured nothing.
    install_selection(AuthProviderSelection {
        providers: vec![AuthProviderKind::Local],
        source: EnablementSource::Explicit,
    });

    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    // `common::boot` mounts no `oidc_rs::Verifier` (that is `boot_with_bunyip`),
    // so this is the standalone shape: no issuer, no JWKS, nothing to reach.
    let app = common::boot(pool).await;

    let token = common::login(&app, &email, &password).await;
    assert!(!token.is_empty(), "the local path issued no token");

    let me = app
        .client
        .get(app.url("/api/v1/auth/me"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send /auth/me");
    assert_eq!(
        me.status(),
        StatusCode::OK,
        "a token from the local path must serve a protected route"
    );

    // A bearer shaped like Bunyip's (`typ=at+jwt`, an issuer this deployment was
    // never told about) is refused, and the refusal names nothing: no provider,
    // no "disabled", no issuer. Under a deployment that HAD Bunyip enabled this
    // same request is also a 401, which is the point.
    let refused = app
        .client
        .get(app.url("/api/v1/auth/me"))
        .bearer_auth("eyJ0eXAiOiJhdCtqd3QiLCJhbGciOiJFZERTQSJ9.e30.not-a-real-signature")
        .send()
        .await
        .expect("send /auth/me with a bunyip-shaped bearer");
    assert_eq!(
        refused.status(),
        StatusCode::UNAUTHORIZED,
        "a bearer this deployment cannot verify is a plain 401"
    );
    let body = refused.text().await.unwrap_or_default().to_lowercase();
    for leak in ["bunyip", "provider", "disabled", "auth_providers"] {
        assert!(
            !body.contains(leak),
            "the refusal must not disclose the configured set, found {leak:?} in {body}"
        );
    }
}
