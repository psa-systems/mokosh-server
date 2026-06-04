//! Integration test for the RMM module (PMS-103).
//!
//! Covers the gaps the PMS-100 story-verification pass surfaced:
//!   * `RmmSyncWorker::sync_one` against a mocked `RmmProvider`
//!     drives the full sync loop: UPSERT mapping, create/link asset,
//!     write `asset_audit_log` with `action='synced'`, and flip the
//!     connection's `sync_status` to `success`.
//!   * Alert ingest at `POST /api/v1/rmm/alerts` (HMAC-signed) goes
//!     through `TicketService::create_ticket` so the resulting ticket
//!     gets the canonical creation path (sequenced ticket number,
//!     status / priority / queue defaults).
//!   * Alerts below the rule's `suppression_rules.min_severity` are
//!     dropped before any ticket is created.
//!   * A second alert inside the `dedupe_window_minutes` window does
//!     NOT open a new ticket.
//!   * `rmm_connections.api_key_encrypted` ciphertext does not
//!     contain a plaintext canary (zero-key regression guard mirrored
//!     from PMS-92).

mod common;

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use mokosh_server::modules::rmm::{
    IngestAlertRequest, ProviderAlert, ProviderDevice, RmmProvider, RmmSyncWorker,
};
use mokosh_server::utils::crypto;
use mokosh_server::Database;
use sha2::Sha256;
use sqlx::PgPool;
use uuid::Uuid;

/// Test encryption key. Mirrors `tests/common/mod.rs` so the harness +
/// the worker decrypt the same bytes we encrypt here.
const TEST_KEY: [u8; 32] = [0u8; 32];

/// Mock provider that returns a fixed device + alert list. Injected
/// straight into `RmmSyncWorker::sync_one` so the test does not need
/// the `build_provider` factory.
struct StaticProvider {
    devices: Vec<ProviderDevice>,
}

#[async_trait]
impl RmmProvider for StaticProvider {
    async fn list_devices(
        &self,
    ) -> mokosh_server::utils::error::AppResult<Vec<ProviderDevice>> {
        Ok(self.devices.clone())
    }
    async fn list_alerts(
        &self,
        _since: DateTime<Utc>,
    ) -> mokosh_server::utils::error::AppResult<Vec<ProviderAlert>> {
        Ok(vec![])
    }
    async fn ping(&self) -> mokosh_server::utils::error::AppResult<()> {
        Ok(())
    }
}

#[sqlx::test]
async fn sync_writes_mapping_asset_audit_and_status(pool: PgPool) {
    common::seed_admin(&pool).await;
    let tenant_id = common::DEFAULT_TENANT_ID;

    let company_id = seed_company(&pool).await;
    let conn_id = seed_connection(&pool, "canary-key-not-in-cipher", Some("hmac-secret")).await;
    // Pre-bind the mapping to the company so the worker promotes it
    // into an asset (per PMS-103 spec: company_id on mapping is the
    // gate for autonomous asset creation).
    seed_unlinked_mapping(&pool, conn_id, "device-A", company_id).await;

    let worker = RmmSyncWorker::new(Database::from_pool(pool.clone()), TEST_KEY);
    let provider = StaticProvider {
        devices: vec![ProviderDevice {
            rmm_device_id: "device-A".into(),
            hostname: Some("web-01".into()),
            serial_number: Some("SN0001".into()),
            last_seen: Some(Utc::now()),
            raw: serde_json::json!({"agent_id": "device-A"}),
        }],
    };
    let stats = worker
        .sync_one(tenant_id, conn_id, &provider)
        .await
        .expect("sync_one");
    assert_eq!(stats.devices_seen, 1);
    assert_eq!(stats.mappings_upserted, 1);
    assert_eq!(stats.assets_created, 1, "asset should be auto-created when mapping has company_id");

    // Mapping promoted to synced + linked to the new asset.
    let (asset_id, sync_status): (Option<Uuid>, Option<String>) = sqlx::query_as(
        r#"SELECT asset_id, sync_status FROM rmm_device_mappings
           WHERE tenant_id = $1 AND rmm_connection_id = $2 AND rmm_device_id = $3"#,
    )
    .bind(tenant_id)
    .bind(conn_id)
    .bind("device-A")
    .fetch_one(&pool)
    .await
    .expect("read mapping");
    assert_eq!(sync_status.as_deref(), Some("synced"));
    let asset_id = asset_id.expect("mapping should be linked to a new asset");

    // Asset stamped with last_sync_at + rmm_device_id.
    let (rmm_id, last_sync_at, serial): (Option<String>, Option<DateTime<Utc>>, Option<String>) =
        sqlx::query_as(
            "SELECT rmm_device_id, last_sync_at, serial_number FROM assets WHERE id = $1",
        )
        .bind(asset_id)
        .fetch_one(&pool)
        .await
        .expect("read asset");
    assert_eq!(rmm_id.as_deref(), Some("device-A"));
    assert!(last_sync_at.is_some());
    assert_eq!(serial.as_deref(), Some("SN0001"));

    // Audit row with action='created' (first sync) or 'synced' (after).
    let audit_actions: Vec<(String,)> = sqlx::query_as(
        "SELECT action FROM asset_audit_log WHERE asset_id = $1 ORDER BY performed_at",
    )
    .bind(asset_id)
    .fetch_all(&pool)
    .await
    .expect("read audit");
    assert!(
        audit_actions.iter().any(|(a,)| a == "created" || a == "synced"),
        "audit log should have a created/synced row, got {audit_actions:?}",
    );

    // Connection flipped to success + last_sync_at + cleared error.
    let (status, last_sync_at, last_error): (
        Option<String>,
        Option<DateTime<Utc>>,
        Option<String>,
    ) = sqlx::query_as(
        "SELECT sync_status, last_sync_at, last_error FROM rmm_connections WHERE id = $1",
    )
    .bind(conn_id)
    .fetch_one(&pool)
    .await
    .expect("read conn");
    assert_eq!(status.as_deref(), Some("success"));
    assert!(last_sync_at.is_some());
    assert!(last_error.is_none());
}

#[sqlx::test]
async fn alert_ingest_routes_through_tickets_service_and_honors_suppression_and_dedupe(
    pool: PgPool,
) {
    common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let tenant_id = common::DEFAULT_TENANT_ID;

    let secret = "rmm-shared-secret-xyz";
    let company_id = seed_company(&pool).await;
    let conn_id = seed_connection(&pool, "api-key", Some(secret)).await;
    seed_unlinked_mapping(&pool, conn_id, "device-A", company_id).await;
    seed_alert_rule(
        &pool,
        conn_id,
        "cpu_high",
        Some(serde_json::json!({"min_severity": "high", "dedupe_window_minutes": 15})),
        Some(serde_json::json!({
            "title": "CPU pressure on {{rmm_device_id}}",
            "description": "Alert: {{title}} ({{severity}})",
        })),
    )
    .await;

    // 1. critical alert -> ticket should land via TicketService.
    let critical = build_alert(conn_id, "device-A", "cpu_high", "High CPU", Some("critical"));
    let resp = post_alert(&app, secret, &critical).await;
    assert!(resp.status().is_success(), "first alert should ingest, got {}", resp.status());

    let ticket_count_after_first: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM tickets WHERE tenant_id = $1 AND source = 'rmm'")
            .bind(tenant_id)
            .fetch_one(&pool)
            .await
            .expect("count tickets");
    assert_eq!(ticket_count_after_first, 1, "critical alert should create exactly one ticket");

    let (title, description, ticket_number): (String, Option<String>, String) = sqlx::query_as(
        "SELECT title, description, ticket_number FROM tickets WHERE tenant_id = $1 AND source = 'rmm'",
    )
    .bind(tenant_id)
    .fetch_one(&pool)
    .await
    .expect("read ticket");
    assert_eq!(title, "CPU pressure on device-A", "ticket title should be rendered from template");
    assert_eq!(
        description.as_deref(),
        Some("Alert: High CPU (critical)"),
        "ticket description should be rendered from template",
    );
    assert!(
        ticket_number.starts_with('T'),
        "ticket_number should come from TicketService sequence (T<n>), got {ticket_number}",
    );

    // 2. low alert -> dropped by suppression.
    let low = build_alert(conn_id, "device-A", "cpu_high", "Mild CPU", Some("low"));
    let resp = post_alert(&app, secret, &low).await;
    assert!(resp.status().is_success(), "low alert should ingest cleanly, got {}", resp.status());
    let count_after_low: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM tickets WHERE tenant_id = $1 AND source = 'rmm'")
            .bind(tenant_id)
            .fetch_one(&pool)
            .await
            .expect("count tickets");
    assert_eq!(count_after_low, 1, "low alert should be suppressed below min_severity");

    // 3. second critical alert inside dedupe window -> no new ticket.
    let again = build_alert(
        conn_id,
        "device-A",
        "cpu_high",
        "High CPU again",
        Some("critical"),
    );
    let resp = post_alert(&app, secret, &again).await;
    assert!(resp.status().is_success(), "duplicate alert should ingest cleanly");
    let count_after_dup: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM tickets WHERE tenant_id = $1 AND source = 'rmm'")
            .bind(tenant_id)
            .fetch_one(&pool)
            .await
            .expect("count tickets");
    assert_eq!(
        count_after_dup, 1,
        "second alert inside dedupe_window_minutes should not open a new ticket",
    );
}

#[sqlx::test]
async fn channel_credentials_are_encrypted_at_rest(pool: PgPool) {
    common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let tenant_id = common::DEFAULT_TENANT_ID;
    let token = common::login(&app, "test-admin@example.com", "test-password-12345").await;

    let canary = "PMS103-not-encrypted-canary-token";
    let create_resp = app
        .client
        .post(app.url("/api/v1/rmm/connections"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "name": "Smoke",
            "provider": "tactical_rmm",
            "api_url": "https://rmm.example.test",
            "api_key": canary,
            "is_active": false,
            "sync_interval_minutes": 60,
        }))
        .send()
        .await
        .expect("send create connection");
    assert!(
        create_resp.status().is_success(),
        "create connection should 2xx, got {}",
        create_resp.status(),
    );

    let stored: String =
        sqlx::query_scalar("SELECT api_key_encrypted FROM rmm_connections WHERE tenant_id = $1")
            .bind(tenant_id)
            .fetch_one(&pool)
            .await
            .expect("fetch ciphertext");

    assert!(
        !stored.contains(canary),
        "api_key_encrypted should be ciphertext, but contained the plaintext canary: {stored}",
    );
}

// --- helpers ---------------------------------------------------------------

async fn seed_company(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, 'Acme Co')",
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .execute(pool)
    .await
    .expect("seed test company");
    id
}

async fn seed_connection(pool: &PgPool, api_key: &str, api_secret: Option<&str>) -> Uuid {
    let key_enc = crypto::encrypt(api_key, &TEST_KEY).expect("encrypt api_key");
    let secret_enc = api_secret
        .map(|s| crypto::encrypt(s, &TEST_KEY).expect("encrypt api_secret"));
    let id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO rmm_connections
           (id, tenant_id, name, provider, api_url, api_key_encrypted, api_secret_encrypted,
            is_active, sync_interval_minutes, sync_status)
           VALUES ($1, $2, 'Test RMM', 'tactical_rmm', 'https://rmm.example.test',
                   $3, $4, TRUE, 60, 'never')"#,
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

async fn seed_unlinked_mapping(
    pool: &PgPool,
    conn_id: Uuid,
    rmm_device_id: &str,
    company_id: Uuid,
) {
    sqlx::query(
        r#"INSERT INTO rmm_device_mappings
           (tenant_id, rmm_connection_id, rmm_device_id, company_id, sync_status)
           VALUES ($1, $2, $3, $4, 'pending')"#,
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(conn_id)
    .bind(rmm_device_id)
    .bind(company_id)
    .execute(pool)
    .await
    .expect("seed mapping");
}

async fn seed_alert_rule(
    pool: &PgPool,
    conn_id: Uuid,
    alert_type: &str,
    suppression: Option<serde_json::Value>,
    ticket_template: Option<serde_json::Value>,
) {
    sqlx::query(
        r#"INSERT INTO rmm_alert_rules
           (tenant_id, rmm_connection_id, name, alert_type, auto_create_ticket,
            ticket_template, suppression_rules, is_active)
           VALUES ($1, $2, 'Test Rule', $3, TRUE, $4, $5, TRUE)"#,
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(conn_id)
    .bind(alert_type)
    .bind(ticket_template.unwrap_or_else(|| serde_json::json!({})))
    .bind(suppression.unwrap_or_else(|| serde_json::json!({})))
    .execute(pool)
    .await
    .expect("seed alert rule");
}

fn build_alert(
    conn_id: Uuid,
    rmm_device_id: &str,
    alert_type: &str,
    title: &str,
    severity: Option<&str>,
) -> IngestAlertRequest {
    IngestAlertRequest {
        rmm_connection_id: conn_id,
        rmm_device_id: rmm_device_id.to_string(),
        alert_type: alert_type.to_string(),
        title: title.to_string(),
        message: Some(title.to_string()),
        severity: severity.map(str::to_string),
    }
}

/// POST `/api/v1/rmm/alerts` with the matching HMAC. Mirrors what the
/// RMM agent does in production: serialise the body, HMAC-SHA256 it
/// with the connection's `api_secret`, base64-encode, attach as
/// `X-Signature`. The route reconstructs the body via
/// `serde_json::to_vec(&IngestAlertRequest)`, so we use the same
/// struct here to get byte-identical input on both sides.
async fn post_alert(
    app: &common::TestApp,
    secret: &str,
    body: &IngestAlertRequest,
) -> reqwest::Response {
    let bytes = serde_json::to_vec(body).expect("serialise alert body");
    let mut mac = <Hmac<Sha256>>::new_from_slice(secret.as_bytes()).expect("hmac key");
    mac.update(&bytes);
    let sig = BASE64.encode(mac.finalize().into_bytes());

    app.client
        .post(app.url("/api/v1/rmm/alerts"))
        .header("X-Signature", sig)
        .header("X-Tenant-Id", common::DEFAULT_TENANT_ID.to_string())
        .header("content-type", "application/json")
        .body(bytes)
        .send()
        .await
        .expect("send alert")
}
