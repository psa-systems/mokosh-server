//! PMS-1430: the Google OAuth client is the host's, and no tenant holds one.
//!
//! PMS-1264 stored one client on the system tenant; PMS-1340 gave every tenant
//! its own and made the two a ladder. Both put a Google Cloud console
//! walkthrough in front of a customer, and the per-tenant version put it in front
//! of every customer. Which Google application this installation authenticates as
//! is a property of the deployment, so it is one pair of governed
//! application-tier secrets and there is nothing tenant-facing left.
//!
//! This suite replaces `tests/contact_sync_client_per_tenant.rs`, which pinned
//! the ladder. What is worth pinning now is the absence: no route to read or
//! write a client, no row holding one, and a refusal that does not send a tenant
//! admin somewhere they cannot act.
//!
//! The pair itself is read through `AppSecrets` by the startup wiring
//! (`OauthClient::from_app_secrets`), which is unit-tested in
//! `contact_sync::oauth` against each of the four shapes. What needs a database
//! and a booted app is everything below.

mod common;

use mokosh_server::modules::contact_sync::OauthClient;
use mokosh_test::mokosh_test;
use reqwest::{Method, StatusCode};
use sqlx::PgPool;

const CLIENT_PATH: &str = "/api/v1/integrations/contact-sync/google/client";
const OVERVIEW_PATH: &str = "/api/v1/integrations/contact-sync";
/// A path under the same prefix that has never been mounted, so the retired one
/// has something to be compared against.
const NEVER_EXISTED: &str = "/api/v1/integrations/contact-sync/google/nonsense";

fn host_client() -> OauthClient {
    OauthClient {
        client_id: "host-client.apps.googleusercontent.com".to_string(),
        client_secret: "host-secret".to_string(),
    }
}

/// The routes that let a tenant read or write a client are gone, both of them,
/// for an admin who would have been allowed to use them.
///
/// Asserted as "indistinguishable from a path that never existed" rather than
/// against a status code, because the code is not the point and is not even
/// constant: this router's fallback serves GET, so an unmatched path answers 404
/// to a GET and 405 to anything else. What MAPPS-977 needs to know is that the
/// surface is gone, not forbidden, so the retired path is compared against a
/// nonsense one under the same method.
#[mokosh_test]
async fn the_client_routes_are_gone(pool: PgPool) {
    let (_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot_with_google_client(pool, host_client()).await;
    let token = common::login(&app, &email, &password).await;

    let status = |method: Method, path: &'static str| {
        let app = &app;
        let token = &token;
        async move {
            app.client
                .request(method, app.url(path))
                .bearer_auth(token)
                .json(&serde_json::json!({ "client_id": "x.apps.googleusercontent.com" }))
                .send()
                .await
                .expect("call the retired client route")
                .status()
        }
    };

    for method in [Method::GET, Method::PUT] {
        let retired = status(method.clone(), CLIENT_PATH).await;
        let never_existed = status(method.clone(), NEVER_EXISTED).await;
        assert!(
            !retired.is_success(),
            "{method} {CLIENT_PATH} still serves ({retired})"
        );
        assert_eq!(
            retired, never_existed,
            "{method} {CLIENT_PATH} answers differently from a path that never existed, \
             so something still matches it"
        );
    }
}

/// The card reports whether the HOST can connect, and says nothing about the
/// caller being allowed to change it, because nobody is.
#[mokosh_test]
async fn the_overview_reports_the_host_client_and_offers_no_form(pool: PgPool) {
    let (_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot_with_google_client(pool, host_client()).await;
    let token = common::login(&app, &email, &password).await;

    let body: serde_json::Value = app
        .client
        .get(app.url(OVERVIEW_PATH))
        .bearer_auth(&token)
        .send()
        .await
        .expect("overview")
        .json()
        .await
        .expect("overview json");

    assert_eq!(body["configured"], true, "{body}");
    assert!(
        body.get("client_editable").is_none(),
        "a tenant cannot configure the host's client, so the flag is gone: {body}"
    );
    let rendered = body.to_string();
    assert!(
        !rendered.contains("host-secret") && !rendered.contains("host-client"),
        "neither half of the host client belongs in a tenant-facing read: {rendered}"
    );
}

/// A deployment whose host has no client says so, to every tenant, and the
/// answer does not change with who is asking.
#[mokosh_test]
async fn an_unconfigured_host_reports_unavailable(pool: PgPool) {
    let (_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let body: serde_json::Value = app
        .client
        .get(app.url(OVERVIEW_PATH))
        .bearer_auth(&token)
        .send()
        .await
        .expect("overview")
        .json()
        .await
        .expect("overview json");
    assert_eq!(body["configured"], false, "{body}");
}

/// Nothing writes a client id to `tenant_settings` any more.
///
/// The row is what migration 258 deletes, so a write path that put one back
/// would leave a deployment half migrated with nothing to notice it. Asserted
/// against the table rather than against the API, because the point is that no
/// code path reaches it, not that one particular route does not.
#[mokosh_test]
async fn no_tenant_row_holds_a_google_client_id(pool: PgPool) {
    let (_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot_with_google_client(pool.clone(), host_client()).await;
    let token = common::login(&app, &email, &password).await;

    // Drive the read that would have populated it under the old model.
    let _ = app
        .client
        .get(app.url(OVERVIEW_PATH))
        .bearer_auth(&token)
        .send()
        .await
        .expect("overview");

    let rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM tenant_settings \
         WHERE category = 'integrations' AND key = 'google_contacts_client_id'",
    )
    .fetch_one(&pool)
    .await
    .expect("count the retired setting");
    assert_eq!(rows, 0, "a Google client id is stored against a tenant");
}

/// Migration 258 removes the ids a deployment already had, whatever tenant they
/// were stored against, and leaves the connection rows alone.
///
/// Seeded after the migration has run, which is the only way to have "old" rows
/// in a template-cloned database; what it proves is the statement's reach, which
/// is what a deployment upgrading depends on.
#[mokosh_test]
async fn the_migration_statement_clears_every_stored_id(pool: PgPool) {
    let tenant = common::DEFAULT_TENANT_ID;
    sqlx::query(
        "INSERT INTO tenant_settings (tenant_id, category, key, value) \
         VALUES ($1, 'integrations', 'google_contacts_client_id', $2) \
         ON CONFLICT (tenant_id, category, key) DO UPDATE SET value = EXCLUDED.value",
    )
    .bind(tenant)
    .bind(serde_json::json!("legacy.apps.googleusercontent.com"))
    .execute(&pool)
    .await
    .expect("seed a pre-migration client id");
    // A setting that must survive, so the DELETE is shown to be narrow.
    sqlx::query(
        "INSERT INTO tenant_settings (tenant_id, category, key, value) \
         VALUES ($1, 'integrations', 'google_contacts_enabled', 'true'::jsonb) \
         ON CONFLICT (tenant_id, category, key) DO UPDATE SET value = EXCLUDED.value",
    )
    .bind(tenant)
    .execute(&pool)
    .await
    .expect("seed the enable flag");

    let migration = include_str!("../migrations/258_google_client_is_the_hosts.sql");
    sqlx::raw_sql(migration)
        .execute(&pool)
        .await
        .expect("run the cleanup");

    let ids: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM tenant_settings \
         WHERE category = 'integrations' AND key = 'google_contacts_client_id'",
    )
    .fetch_one(&pool)
    .await
    .expect("count ids");
    assert_eq!(ids, 0, "a stored client id survived the migration");

    let kept: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM tenant_settings \
         WHERE category = 'integrations' AND key = 'google_contacts_enabled'",
    )
    .fetch_one(&pool)
    .await
    .expect("count the enable flag");
    assert_eq!(kept, 1, "the DELETE took a setting it was not aimed at");
}
