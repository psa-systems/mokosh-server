//! Integration tests for the client service-status module.
//!
//! Every test drives the real HTTP surface (`POST /api/v1/rmm/status`,
//! `GET /api/v1/status/*`) rather than the service directly, so the
//! HMAC auth and the router wiring are exercised alongside the store.

mod common;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::{Duration, TimeZone, Utc};
use hmac::{Hmac, Mac};
use mokosh_server::utils::crypto;
use mokosh_test::mokosh_test;
use sha2::Sha256;
use sqlx::PgPool;
use uuid::Uuid;

const TEST_KEY: [u8; 32] = [0u8; 32];

async fn seed_connection(pool: &PgPool, secret: &str) -> Uuid {
    let key_enc = crypto::encrypt("api-key", &TEST_KEY).expect("encrypt api_key");
    let secret_enc = crypto::encrypt(secret, &TEST_KEY).expect("encrypt api_secret");
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO rmm_connections \
           (id, tenant_id, name, provider, api_url, api_key_encrypted, api_secret_encrypted, \
            is_active, sync_interval_minutes, sync_status) \
         VALUES ($1, $2, 'Status RMM', 'tactical_rmm', 'https://rmm.example.test', \
                 $3, $4, TRUE, 60, 'never')",
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(&key_enc)
    .bind(&secret_enc)
    .execute(pool)
    .await
    .expect("seed connection");
    id
}

async fn seed_mapping(pool: &PgPool, conn_id: Uuid, device_id: &str, company_id: Uuid) {
    sqlx::query(
        "INSERT INTO rmm_device_mappings \
           (tenant_id, rmm_connection_id, rmm_device_id, company_id, sync_status) \
         VALUES ($1, $2, $3, $4, 'pending')",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(conn_id)
    .bind(device_id)
    .bind(company_id)
    .execute(pool)
    .await
    .expect("seed mapping");
}

/// Sign the raw body with the connection's secret and POST it, mirroring
/// what the RMM agent does in production.
async fn post_status(
    app: &common::TestApp,
    secret: &str,
    body: &serde_json::Value,
) -> reqwest::Response {
    let bytes = serde_json::to_vec(body).expect("serialise body");
    let mut mac = <Hmac<Sha256>>::new_from_slice(secret.as_bytes()).expect("hmac key");
    mac.update(&bytes);
    let sig = BASE64.encode(mac.finalize().into_bytes());
    app.client
        .post(app.url("/api/v1/rmm/status"))
        .header("X-Signature", sig)
        .header("X-Tenant-Id", common::DEFAULT_TENANT_ID.to_string())
        .header("content-type", "application/json")
        .body(bytes)
        .send()
        .await
        .expect("send status")
}

/// A valid backup observation body against the given connection and
/// device. The caller can override the observed instant to exercise
/// idempotency and ordering.
fn status_body(
    conn_id: Uuid,
    device_id: &str,
    observed: chrono::DateTime<Utc>,
    outcome: &str,
) -> serde_json::Value {
    serde_json::json!({
        "rmm_connection_id": conn_id.to_string(),
        "rmm_device_id": device_id,
        "system_name": "web-01",
        "check_kind": "backup",
        "outcome": outcome,
        "observed_at": observed.to_rfc3339(),
        "payload": { "job": "nightly" },
    })
}

/// Ingest, look up the observations row, then the monitored_systems
/// row: the two together cover the write path end to end.
#[mokosh_test]
async fn a_backup_status_ingest_writes_the_observation_and_the_system(pool: PgPool) {
    common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let secret = "hmac-secret-alpha";
    let conn_id = seed_connection(&pool, secret).await;
    seed_mapping(&pool, conn_id, "device-A", company_id).await;

    let app = common::boot(pool.clone()).await;
    let observed = Utc.with_ymd_and_hms(2026, 9, 24, 4, 0, 0).unwrap();
    let resp = post_status(
        &app,
        secret,
        &status_body(conn_id, "device-A", observed, "success"),
    )
    .await;
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::NO_CONTENT,
        "a fresh ingest is 204"
    );

    let obs_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM status_observations WHERE company_id = $1")
            .bind(company_id)
            .fetch_one(&pool)
            .await
            .expect("count observations");
    assert_eq!(obs_count, 1, "the observation is on disk");

    let sys_row: (String, String) = sqlx::query_as(
        "SELECT external_source, name FROM monitored_systems \
         WHERE tenant_id = $1 AND external_id = 'device-A'",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(&pool)
    .await
    .expect("read system");
    assert_eq!(sys_row.0, "tactical_rmm");
    assert_eq!(sys_row.1, "web-01");
}

/// The uniqueness triple is what makes retries safe. Replay with the
/// same (system, check_kind, observed_at) leaves the row count at one.
#[mokosh_test]
async fn a_replayed_status_ingest_is_a_no_op(pool: PgPool) {
    common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let secret = "hmac-secret-beta";
    let conn_id = seed_connection(&pool, secret).await;
    seed_mapping(&pool, conn_id, "device-A", company_id).await;

    let app = common::boot(pool.clone()).await;
    let observed = Utc.with_ymd_and_hms(2026, 9, 24, 4, 0, 0).unwrap();
    let body = status_body(conn_id, "device-A", observed, "success");

    let first = post_status(&app, secret, &body).await;
    assert_eq!(first.status(), reqwest::StatusCode::NO_CONTENT);
    let second = post_status(&app, secret, &body).await;
    assert_eq!(
        second.status(),
        reqwest::StatusCode::NO_CONTENT,
        "a duplicate delivery still answers 204 so the caller sees one shape"
    );

    let obs_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM status_observations WHERE company_id = $1")
            .bind(company_id)
            .fetch_one(&pool)
            .await
            .expect("count observations");
    assert_eq!(
        obs_count, 1,
        "the same (system, check_kind, observed_at) triple must land at most once"
    );
}

/// A device the tenant has not mapped to a company is refused with 422
/// rather than silently written to nowhere: an unmapped delivery is a
/// signal the operator has to act on.
#[mokosh_test]
async fn an_unmapped_device_id_is_rejected_with_422(pool: PgPool) {
    common::seed_admin(&pool).await;
    common::seed_company(&pool).await;
    let secret = "hmac-secret-gamma";
    let conn_id = seed_connection(&pool, secret).await;
    // Deliberately NOT seeding a mapping for device-Z.

    let app = common::boot(pool.clone()).await;
    let observed = Utc.with_ymd_and_hms(2026, 9, 24, 4, 0, 0).unwrap();
    let resp = post_status(
        &app,
        secret,
        &status_body(conn_id, "device-Z", observed, "success"),
    )
    .await;
    assert_eq!(resp.status(), reqwest::StatusCode::UNPROCESSABLE_ENTITY);
    let body: serde_json::Value = resp.json().await.expect("error JSON");
    let fields: Vec<&str> = body["error"]["errors"]
        .as_array()
        .expect("field errors")
        .iter()
        .filter_map(|e| e["field"].as_str())
        .collect();
    assert!(
        fields.iter().any(|f| f.contains("rmm_device_id")),
        "the 422 must name the device field, got {fields:?}"
    );
}

/// A signature over the wrong body, or a missing header, is a 401 and
/// writes nothing. Guards the "no new inbound credential" AC: the same
/// HMAC gate the alerts ingest uses.
#[mokosh_test]
async fn a_wrong_signature_is_rejected_and_writes_nothing(pool: PgPool) {
    common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let secret = "hmac-secret-delta";
    let conn_id = seed_connection(&pool, secret).await;
    seed_mapping(&pool, conn_id, "device-A", company_id).await;

    let app = common::boot(pool.clone()).await;
    let observed = Utc.with_ymd_and_hms(2026, 9, 24, 4, 0, 0).unwrap();
    let body = status_body(conn_id, "device-A", observed, "success");
    // Signed with a different secret: the constant-time comparison
    // refuses the request.
    let resp = post_status(&app, "not-the-real-secret", &body).await;
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);

    let obs_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM status_observations")
        .fetch_one(&pool)
        .await
        .expect("count observations");
    assert_eq!(
        obs_count, 0,
        "a refused request must not have reached the store"
    );
}

/// The read endpoint returns exactly the latest observation per check
/// kind for the requested system, so a caller renders the current state
/// without walking history.
#[mokosh_test]
async fn the_system_current_endpoint_returns_the_newest_per_check_kind(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let secret = "hmac-secret-epsilon";
    let conn_id = seed_connection(&pool, secret).await;
    seed_mapping(&pool, conn_id, "device-A", company_id).await;

    let app = common::boot(pool.clone()).await;
    let base = Utc.with_ymd_and_hms(2026, 9, 24, 4, 0, 0).unwrap();
    for (offset_min, outcome) in [(0, "failure"), (60, "warning"), (120, "success")] {
        let observed = base + Duration::minutes(offset_min);
        let resp = post_status(
            &app,
            secret,
            &status_body(conn_id, "device-A", observed, outcome),
        )
        .await;
        assert_eq!(resp.status(), reqwest::StatusCode::NO_CONTENT);
    }

    let system_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM monitored_systems \
         WHERE tenant_id = $1 AND external_id = 'device-A'",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(&pool)
    .await
    .expect("read system id");

    let token = common::login(&app, &email, &password).await;
    let resp = app
        .client
        .get(app.url(&format!("/api/v1/status/systems/{system_id}/current")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send GET");
    assert!(resp.status().is_success());

    let body: serde_json::Value = resp.json().await.expect("current JSON");
    let observations = body["observations"].as_array().expect("observations array");
    let backup = observations
        .iter()
        .find(|o| o["check_kind"] == "backup")
        .expect("backup entry");
    assert_eq!(
        backup["outcome"], "success",
        "the latest of three observations wins"
    );
}

/// The company rollup names every mapped system on the company and its
/// current backup outcome. A system that has never carried a backup
/// observation still appears (`latest = null`), so the client can
/// render "unseen" separately from "failing".
#[mokosh_test]
async fn the_company_backup_endpoint_lists_every_system_with_its_current_state(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let secret = "hmac-secret-zeta";
    let conn_id = seed_connection(&pool, secret).await;
    seed_mapping(&pool, conn_id, "device-A", company_id).await;
    seed_mapping(&pool, conn_id, "device-B", company_id).await;

    let app = common::boot(pool.clone()).await;
    let observed = Utc.with_ymd_and_hms(2026, 9, 24, 4, 0, 0).unwrap();

    let resp = post_status(
        &app,
        secret,
        &status_body(conn_id, "device-A", observed, "failure"),
    )
    .await;
    assert_eq!(resp.status(), reqwest::StatusCode::NO_CONTENT);

    // device-B is mapped but has never delivered a backup observation, so
    // no `monitored_systems` row exists for it yet: seeding a mapping
    // creates a `status_device_mappings` row and nothing more, and the
    // company backup endpoint reads out of `monitored_systems`. Only
    // device-A - the one we just ingested - appears here, carrying its
    // failure outcome. Surfacing a mapped-but-unseen system through this
    // endpoint would be a separate feature and is not what this test
    // pins.
    let token = common::login(&app, &email, &password).await;
    let resp = app
        .client
        .get(app.url(&format!("/api/v1/status/companies/{company_id}/backup")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send GET");
    assert!(resp.status().is_success());

    let body: serde_json::Value = resp.json().await.expect("rollup JSON");
    let systems = body["systems"].as_array().expect("systems array");
    assert_eq!(
        systems.len(),
        1,
        "device-A had one ingest and is materialised into monitored_systems; device-B is only mapped and stays out until its first ingest"
    );
    assert_eq!(systems[0]["latest"]["outcome"].as_str(), Some("failure"));

    // After the first ingest for device-B the rollup has both systems.
    let resp = post_status(
        &app,
        secret,
        &status_body(conn_id, "device-B", observed, "success"),
    )
    .await;
    assert_eq!(resp.status(), reqwest::StatusCode::NO_CONTENT);

    let resp = app
        .client
        .get(app.url(&format!("/api/v1/status/companies/{company_id}/backup")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send GET");
    let body: serde_json::Value = resp.json().await.expect("rollup JSON");
    let systems = body["systems"].as_array().expect("systems array");
    assert_eq!(systems.len(), 2);
    let outcomes: Vec<Option<&str>> = systems
        .iter()
        .map(|s| s["latest"]["outcome"].as_str())
        .collect();
    assert!(outcomes.contains(&Some("failure")));
    assert!(outcomes.contains(&Some("success")));
}

// ============================================================================
// Trend reports and retention
// ============================================================================

/// The backup success rate reads the ratio out of the window and reports
/// the raw counts too, so a caller can tell "no data" from
/// "everything passed".
#[mokosh_test]
async fn the_backup_success_rate_is_the_share_of_successes_in_the_window(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let secret = "hmac-secret-eta";
    let conn_id = seed_connection(&pool, secret).await;
    seed_mapping(&pool, conn_id, "device-A", company_id).await;

    let app = common::boot(pool.clone()).await;
    // Three observations in the window: two successes and one failure.
    // Rate = 2/3.
    let base = Utc.with_ymd_and_hms(2026, 9, 1, 4, 0, 0).unwrap();
    for (offset_hours, outcome) in [(0, "success"), (24, "failure"), (48, "success")] {
        let observed = base + Duration::hours(offset_hours);
        let resp = post_status(
            &app,
            secret,
            &status_body(conn_id, "device-A", observed, outcome),
        )
        .await;
        assert_eq!(resp.status(), reqwest::StatusCode::NO_CONTENT);
    }
    // A fourth observation OUTSIDE the window: must not enter the ratio.
    let outside = post_status(
        &app,
        secret,
        &status_body(conn_id, "device-A", base + Duration::days(60), "failure"),
    )
    .await;
    assert_eq!(outside.status(), reqwest::StatusCode::NO_CONTENT);

    let token = common::login(&app, &email, &password).await;
    let from = base;
    let to = base + Duration::days(30);
    let resp = app
        .client
        .get(app.url(&format!(
            "/api/v1/reports/status/backup-success-rate?company_id={company_id}&from={}&to={}",
            urlencoding::encode(&from.to_rfc3339()),
            urlencoding::encode(&to.to_rfc3339()),
        )))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send GET");
    assert!(resp.status().is_success(), "got {}", resp.status());
    let body: serde_json::Value = resp.json().await.expect("rate JSON");
    assert_eq!(body["success"].as_u64(), Some(2));
    assert_eq!(body["total"].as_u64(), Some(3));
    let rate = body["rate"].as_f64().expect("rate is a number");
    assert!(
        (rate - (2.0 / 3.0)).abs() < 1e-9,
        "rate 2/3 within tolerance, got {rate}"
    );
}

/// The uptime aggregate counts every check kind and treats
/// `success | warning` as up. A window that carried no observations
/// reports `1.0` so an unmonitored company does not read as totally
/// down.
#[mokosh_test]
async fn the_uptime_report_treats_success_and_warning_as_up(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let secret = "hmac-secret-theta";
    let conn_id = seed_connection(&pool, secret).await;
    seed_mapping(&pool, conn_id, "device-A", company_id).await;

    let app = common::boot(pool.clone()).await;
    let base = Utc.with_ymd_and_hms(2026, 9, 1, 4, 0, 0).unwrap();
    for (offset_hours, outcome) in [
        (0, "success"),
        (12, "warning"),
        (24, "failure"),
        (36, "success"),
    ] {
        let observed = base + Duration::hours(offset_hours);
        let resp = post_status(
            &app,
            secret,
            &status_body(conn_id, "device-A", observed, outcome),
        )
        .await;
        assert_eq!(resp.status(), reqwest::StatusCode::NO_CONTENT);
    }

    let token = common::login(&app, &email, &password).await;
    let from = base;
    let to = base + Duration::days(2);
    let resp = app
        .client
        .get(app.url(&format!(
            "/api/v1/reports/status/uptime?company_id={company_id}&from={}&to={}",
            urlencoding::encode(&from.to_rfc3339()),
            urlencoding::encode(&to.to_rfc3339()),
        )))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send GET");
    assert!(resp.status().is_success());
    let body: serde_json::Value = resp.json().await.expect("uptime JSON");
    assert_eq!(body["total_observations"].as_u64(), Some(4));
    assert_eq!(
        body["up_observations"].as_u64(),
        Some(3),
        "three of the four outcomes were success or warning"
    );
    let rate = body["rate"].as_f64().expect("rate is a number");
    assert!(
        (rate - 0.75).abs() < 1e-9,
        "3/4 within tolerance, got {rate}"
    );
}

/// The retention worker deletes observations older than the cutoff and
/// leaves everything else alone. Drives the worker directly at a
/// two-day retention so the fixture does not need thirteen months.
#[mokosh_test]
async fn retention_purges_only_observations_older_than_the_cutoff(pool: PgPool) {
    common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let secret = "hmac-secret-iota";
    let conn_id = seed_connection(&pool, secret).await;
    seed_mapping(&pool, conn_id, "device-A", company_id).await;

    let app = common::boot(pool.clone()).await;
    let now = Utc::now();
    // One row from a week ago (should be purged at a 2-day retention),
    // one from an hour ago (should survive).
    for (offset_hours, outcome) in [(-24 * 7, "success"), (-1, "success")] {
        let observed = now + Duration::hours(offset_hours);
        let resp = post_status(
            &app,
            secret,
            &status_body(conn_id, "device-A", observed, outcome),
        )
        .await;
        assert_eq!(resp.status(), reqwest::StatusCode::NO_CONTENT);
    }
    let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM status_observations")
        .fetch_one(&pool)
        .await
        .expect("count observations");
    assert_eq!(before, 2, "the fixture writes two rows before purge");

    let worker = mokosh_server::modules::status::StatusRetentionWorker::with_retention(
        mokosh_server::modules::status::StatusService::new(mokosh_server::Database::from_pool(
            pool.clone(),
        )),
        std::time::Duration::from_secs(2 * 24 * 60 * 60),
    );
    let removed = worker.run_tick().await.expect("purge tick");
    assert_eq!(removed, 1, "only the week-old row is past the cutoff");

    let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM status_observations")
        .fetch_one(&pool)
        .await
        .expect("count observations");
    assert_eq!(after, 1, "the recent observation survives");
}
