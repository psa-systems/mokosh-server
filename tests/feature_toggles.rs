//! PMS-1414: the feature-toggle registry, end to end.
//!
//! The resolution rule is unit-tested in `features::registry` against rows
//! without a database. What needs one is everything an operator and a client
//! actually touch: the list, the flip, the audit row, the 404 on a key no variant
//! matches, the gate, and the public probe a client reads before it has a session.
//!
//! The negative cases carry the weight here. A registry whose missing row read as
//! ON would turn every unfinished feature on at the moment of upgrade, and an
//! unknown key accepted on `PUT` would let the table grow rows for features that
//! do not exist, which is how a toggle list stops being trustworthy.

mod common;

use mokosh_server::modules::features::Feature;
use mokosh_test::mokosh_test;
use reqwest::StatusCode;
use sqlx::PgPool;

const LIST: &str = "/api/v1/settings/feature-toggles";
const PUBLIC: &str = "/api/v1/public/config";

fn flip(key: &str) -> String {
    format!("{LIST}/{key}")
}

/// The first registry entry, named once so a later entry does not silently move
/// what these cases are about.
const FIRST: Feature = Feature::IntegrationsOverview;

/// A deployment that has never flipped anything lists every registered feature,
/// off, with no row metadata.
///
/// Built from the registry rather than the table, which is the property a client
/// depends on: a feature with no row is `false`, not absent, so nobody has to
/// tell those apart.
#[mokosh_test]
async fn a_fresh_deployment_lists_every_feature_off(pool: PgPool) {
    let (_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let operator = common::login(&app, &email, &password).await;

    let body: serde_json::Value = app
        .client
        .get(app.url(LIST))
        .bearer_auth(&operator)
        .send()
        .await
        .expect("list")
        .json()
        .await
        .expect("json");

    let rows = body.as_array().expect("an array of features");
    assert_eq!(
        rows.len(),
        Feature::ALL.len(),
        "the list is the registry, not the table: {body}"
    );
    for row in rows {
        assert_eq!(row["enabled"], false, "nothing is on by default: {row}");
        assert!(
            row.get("updated_at").is_none() && row.get("updated_by").is_none(),
            "a feature nobody flipped has no row and therefore no metadata: {row}"
        );
        for named in ["key", "label", "help", "issue"] {
            assert!(
                row[named].as_str().is_some_and(|s| !s.is_empty()),
                "{named} has to be present for the admin page to render a row: {row}"
            );
        }
    }

    // And no row was created by reading.
    let stored: i64 = sqlx::query_scalar("SELECT count(*) FROM feature_toggles")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(stored, 0, "listing must not write");
}

/// A flip is stored, audited, reflected in the list, and visible on the public
/// probe without a restart or a scheduler tick.
///
/// The probe assertion is the one that proves the snapshot swap in the write
/// path: the harness runs no scheduler, so if the handler did not swap, the probe
/// would still read the boot-time state and this would fail.
#[mokosh_test]
async fn a_flip_is_stored_audited_and_live_at_once(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let operator = common::login(&app, &email, &password).await;

    let before: serde_json::Value = app
        .client
        .get(app.url(PUBLIC))
        .send()
        .await
        .expect("probe")
        .json()
        .await
        .expect("json");
    assert_eq!(
        before["features"][FIRST.key()],
        false,
        "the probe starts off: {before}"
    );

    let response = app
        .client
        .put(app.url(&flip(FIRST.key())))
        .bearer_auth(&operator)
        .json(&serde_json::json!({ "enabled": true }))
        .send()
        .await
        .expect("flip");
    assert_eq!(response.status(), StatusCode::OK);
    let view: serde_json::Value = response.json().await.expect("json");
    assert_eq!(view["enabled"], true, "{view}");
    assert_eq!(view["key"], FIRST.key(), "{view}");
    assert!(
        view["updated_at"].as_str().is_some(),
        "a flipped feature has a row, so it has metadata: {view}"
    );

    let row: (bool, Option<uuid::Uuid>) =
        sqlx::query_as("SELECT enabled, updated_by FROM feature_toggles WHERE key = $1")
            .bind(FIRST.key())
            .fetch_one(&pool)
            .await
            .expect("the row exists");
    assert!(row.0, "the stored row is on");
    assert_eq!(
        row.1,
        Some(admin_id),
        "the row names who flipped it, for the admin page's provenance"
    );

    // Audited in the same transaction as the upsert, with the previous state, so
    // the log says what changed rather than only that something did.
    let entries: Vec<serde_json::Value> = sqlx::query_scalar(
        "SELECT new_values FROM audit_log WHERE entity_type = 'feature_toggles' ORDER BY timestamp",
    )
    .fetch_all(&pool)
    .await
    .expect("audit rows");
    assert_eq!(entries.len(), 1, "one flip, one audit row");
    assert_eq!(entries[0]["key"], FIRST.key(), "{}", entries[0]);
    assert_eq!(entries[0]["enabled"], true, "{}", entries[0]);
    assert_eq!(
        entries[0]["issue"],
        FIRST.issue(),
        "the audit row carries the owning issue, so a flip is traceable to its work: {}",
        entries[0]
    );
    let old: Vec<serde_json::Value> = sqlx::query_scalar(
        "SELECT old_values FROM audit_log WHERE entity_type = 'feature_toggles'",
    )
    .fetch_all(&pool)
    .await
    .expect("audit rows");
    assert_eq!(
        old[0]["enabled"], false,
        "the previous state is recorded, or the log cannot say what changed: {}",
        old[0]
    );

    let after: serde_json::Value = app
        .client
        .get(app.url(PUBLIC))
        .send()
        .await
        .expect("probe")
        .json()
        .await
        .expect("json");
    assert_eq!(
        after["features"][FIRST.key()],
        true,
        "the write path has to swap this process's snapshot, or a flip is invisible until the \
         next refresh tick and the admin who made it thinks it failed: {after}"
    );

    // Flipping back leaves one row and two audit entries, so the switch is a
    // toggle rather than a one-way door.
    let status = app
        .client
        .put(app.url(&flip(FIRST.key())))
        .bearer_auth(&operator)
        .json(&serde_json::json!({ "enabled": false }))
        .send()
        .await
        .expect("flip back")
        .status();
    assert_eq!(status, StatusCode::OK);
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM feature_toggles")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(rows, 1, "the upsert replaces rather than accumulating");
}

/// A key no variant matches is a 404, and nothing is written.
///
/// 404 rather than 400 because the client named a resource that is not there. The
/// store assertion is the point: if an unknown key reached the upsert, the table
/// would grow rows for features that do not exist, and the next reader could not
/// tell those from a feature this build removed.
#[mokosh_test]
async fn an_unknown_key_is_a_404_and_writes_nothing(pool: PgPool) {
    let (_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let operator = common::login(&app, &email, &password).await;

    let response = app
        .client
        .put(app.url(&flip("a_feature_nobody_registered")))
        .bearer_auth(&operator)
        .json(&serde_json::json!({ "enabled": true }))
        .send()
        .await
        .expect("flip an unknown key");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = response.text().await.unwrap_or_default();
    assert!(
        body.contains(FIRST.key()),
        "the refusal lists what this build does register, so the caller can fix the typo: {body}"
    );

    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM feature_toggles")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(rows, 0, "a refused flip stored something");
}

/// A row naming a feature this build does not register reads as absent, and does
/// not stop the known ones resolving.
///
/// This is the rollback case. A deployment that ran a newer build, had a feature
/// on, and rolled back leaves a row nothing matches. Deleting it would lose the
/// operator's intent; failing on it would make the rollback unbootable. It is
/// read as off, and the known features still resolve around it.
#[mokosh_test]
async fn a_row_for_an_unregistered_feature_is_ignored(pool: PgPool) {
    sqlx::query("INSERT INTO feature_toggles (key, enabled) VALUES ($1, TRUE), ($2, TRUE)")
        .bind("a_feature_from_a_newer_build")
        .bind(FIRST.key())
        .execute(&pool)
        .await
        .expect("seed a stale row beside a real one");

    let (_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let operator = common::login(&app, &email, &password).await;

    let body: serde_json::Value = app
        .client
        .get(app.url(LIST))
        .bearer_auth(&operator)
        .send()
        .await
        .expect("list")
        .json()
        .await
        .expect("json");
    let rows = body.as_array().expect("an array");
    assert_eq!(
        rows.len(),
        Feature::ALL.len(),
        "the stale row must not appear as a feature: {body}"
    );
    assert_eq!(
        rows[0]["enabled"], true,
        "and the real row beside it still resolves: {body}"
    );

    // The stale row is still there: kept, not cleaned up.
    let kept: i64 = sqlx::query_scalar("SELECT count(*) FROM feature_toggles WHERE key = $1")
        .bind("a_feature_from_a_newer_build")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(kept, 1, "a row for an unknown key is kept for a rollback");
}

/// Only the deployment's operator, on both routes.
///
/// An admin of a customer organisation is refused on the read as well as the
/// write, and the two have to agree: a readable list of unfinished features on a
/// deployment where only the operator can flip them is a map of what to try next.
#[mokosh_test]
async fn only_the_deployment_operator_sees_or_flips_toggles(pool: PgPool) {
    let (_id, email, password) = common::seed_admin(&pool).await;
    let (_tenant, _user, other_email, other_password) =
        common::seed_tenant_with_admin(&pool, "customer-msp").await;
    let app = common::boot(pool.clone()).await;
    let operator = common::login(&app, &email, &password).await;

    let login: serde_json::Value = app
        .client
        .post(app.url("/api/v1/auth/login"))
        .json(&serde_json::json!({
            "email": other_email,
            "password": other_password,
            "tenant_slug": "customer-msp",
        }))
        .send()
        .await
        .expect("login")
        .json()
        .await
        .expect("json");
    let customer = login["access_token"]
        .as_str()
        .expect("the customer organisation's admin signs in")
        .to_string();

    let listed = app
        .client
        .get(app.url(LIST))
        .bearer_auth(&customer)
        .send()
        .await
        .expect("list")
        .status();
    assert_eq!(listed, StatusCode::FORBIDDEN, "the list is operator-only");

    let flipped = app
        .client
        .put(app.url(&flip(FIRST.key())))
        .bearer_auth(&customer)
        .json(&serde_json::json!({ "enabled": true }))
        .send()
        .await
        .expect("flip")
        .status();
    assert_eq!(flipped, StatusCode::FORBIDDEN);

    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM feature_toggles")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(rows, 0, "the refused flip stored something");

    // The operator keeps the read.
    let status = app
        .client
        .get(app.url(LIST))
        .bearer_auth(&operator)
        .send()
        .await
        .expect("list")
        .status();
    assert_eq!(status, StatusCode::OK);
}

/// The public probe needs no session and publishes keys and booleans only.
///
/// No session is the requirement: a feature gating part of the sign-in path could
/// never be gated by a map that required signing in first. Keys and booleans only
/// is the limit that makes that acceptable, so this asserts the absence of the
/// row metadata the operator list carries.
#[mokosh_test]
async fn the_public_probe_needs_no_session_and_leaks_no_metadata(pool: PgPool) {
    let (_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let operator = common::login(&app, &email, &password).await;
    let _ = app
        .client
        .put(app.url(&flip(FIRST.key())))
        .bearer_auth(&operator)
        .json(&serde_json::json!({ "enabled": true }))
        .send()
        .await
        .expect("flip");

    // No bearer at all.
    let response = app.client.get(app.url(PUBLIC)).send().await.expect("probe");
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = response.json().await.expect("json");

    let features = body["features"]
        .as_object()
        .expect("a features map keyed by the registry");
    assert_eq!(features.len(), Feature::ALL.len());
    for feature in Feature::ALL {
        assert!(
            features[feature.key()].is_boolean(),
            "every value is a bare boolean: {body}"
        );
    }

    let rendered = body.to_string();
    for leaked in ["updated_by", "updated_at", FIRST.label(), FIRST.help()] {
        assert!(
            !rendered.contains(leaked),
            "the public probe carries keys and booleans only, not {leaked:?}: {rendered}"
        );
    }
}
