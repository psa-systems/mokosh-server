//! PMS-1430: the host's Google client, served from Infisical, with no copy in
//! the database.
//!
//! Runs when `INFISICAL_ADDRESS` is set and skips, saying so, when it is not.
//! That is the `tests/s3_storage.rs` shape and it is in the `unsupported`
//! nextest profile for the same reason (PMS-1394): standing Infisical up costs
//! the pull-request job a second service and its own Postgres, for a provider
//! the code is deliberately agnostic about. `just dev-infisical` plus
//! `just infisical-bootstrap` is what fills those variables locally.
//!
//! ## What is Infisical-only, and what is not
//!
//! The reader is not. `OauthClient::from_app_secrets` takes an `AppSecrets` and
//! asks it for two governed secrets; which provider answers is `SECRET_BACKEND`'s
//! business, and the four shapes of the pair are pinned as pure functions in
//! `contact_sync::oauth::pms1430_host_client`. What needs a real Infisical is the
//! deployment claim: that the hosted shape actually works end to end, that the
//! value comes out of the `/app` folder, and that nothing on the way put a copy
//! in Postgres.
//!
//! That last assertion is the one worth the setup. "The credential is in
//! Infisical, not in the database" is a sentence about two systems, and a test
//! that stubs one of them cannot make it.

mod common;

use mokosh_server::app_secrets::{AppSecretProvider, GovernedSecret};
use mokosh_server::modules::contact_sync::OauthClient;
use mokosh_test::mokosh_test;
use sqlx::PgPool;

const ID: GovernedSecret = GovernedSecret::GoogleContactsClientId;
const SECRET: GovernedSecret = GovernedSecret::GoogleContactsClientSecret;

/// A value this suite can recognise again, so a leftover from another run or
/// another developer's project cannot make the assertions pass.
fn marker() -> String {
    format!("pms1430-{}", uuid::Uuid::new_v4().simple())
}

/// The provider under test, or `None` with a skip line when Infisical is not
/// configured for this process.
async fn provider() -> Option<mokosh_server::app_secrets::InfisicalProvider> {
    if std::env::var("INFISICAL_ADDRESS")
        .unwrap_or_default()
        .trim()
        .is_empty()
    {
        eprintln!("google_client_from_infisical: skipped, INFISICAL_ADDRESS is not set");
        return None;
    }
    match mokosh_server::app_secrets::InfisicalProvider::load().await {
        Ok(provider) => Some(provider),
        Err(e) => panic!(
            "INFISICAL_ADDRESS is set, so this suite must be able to build the provider: {e}"
        ),
    }
}

/// The pair written to Infisical's `/app` folder comes back as the host client,
/// and Postgres holds neither half.
///
/// The database check is deliberately broad: every text-ish column of the two
/// tables that ever held this credential under PMS-1264 and PMS-1340, plus the
/// application-tier `app_secrets` table, because the claim being made is "not in
/// the database" rather than "not in the row I happen to remember".
#[mokosh_test]
async fn the_pair_is_served_from_infisical_and_postgres_holds_no_copy(pool: PgPool) {
    let Some(provider) = provider().await else {
        return;
    };
    let client_id = format!("{}.apps.googleusercontent.com", marker());
    let client_secret = marker();

    provider
        .set(ID, &client_id)
        .await
        .expect("write the client id to Infisical /app");
    provider
        .set(SECRET, &client_secret)
        .await
        .expect("write the client secret to Infisical /app");

    // Re-load rather than reading the handle just written: the provider caches
    // at construction, so a fresh load is what proves the values are in
    // Infisical rather than in this process.
    let reloaded = mokosh_server::app_secrets::InfisicalProvider::load()
        .await
        .expect("reload the provider");
    let secrets = mokosh_server::app_secrets::AppSecrets::with_provider(
        mokosh_server::app_secrets::AppSecretProviderKind::Infisical,
        std::sync::Arc::new(reloaded),
    );

    let resolved = OauthClient::from_app_secrets(&secrets)
        .expect("a complete pair resolves")
        .expect("and is configured");
    assert_eq!(resolved.client_id, client_id);
    assert_eq!(resolved.client_secret, client_secret);

    for (table, column) in [
        ("tenant_settings", "value::text"),
        ("app_secrets", "name"),
        ("contact_sync_connections", "account_email"),
    ] {
        let hits: i64 = sqlx::query_scalar(&format!(
            "SELECT count(*) FROM {table} WHERE {column} LIKE $1 OR {column} LIKE $2"
        ))
        .bind(format!("%{client_id}%"))
        .bind(format!("%{client_secret}%"))
        .fetch_one(&pool)
        .await
        .unwrap_or(0);
        assert_eq!(
            hits, 0,
            "{table}.{column} holds a copy of the host's Google client"
        );
    }

    // Leave the folder as it was found, so a re-run and a developer's own
    // project are not affected by this suite's markers.
    provider.delete(ID).await.expect("clean up the id");
    provider.delete(SECRET).await.expect("clean up the secret");
}
