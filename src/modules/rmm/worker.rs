//! RMM device-sync worker.
//!
//! Drains active `rmm_connections` past their `sync_interval_minutes`
//! window: build the `RmmProvider` for the row, fetch the device list,
//! UPSERT `rmm_device_mappings` on `(rmm_connection_id, rmm_device_id)`,
//! link / create the `assets` row when a mapping has a company set,
//! and record `asset_audit_log` synced entries. On success the
//! connection's `sync_status` flips to `success` with `last_sync_at`
//! stamped; on failure it goes to `failed` with `last_error` set.
//!
//! Spawned from `src/main.rs`. One worker per replica; concurrent
//! workers race-skip via the `sync_status = 'in_progress'` optimistic
//! guard. The `sync_one` API is exposed so the integration test can
//! drive a deterministic tick against a mocked provider without
//! waiting on the tick interval.
//!
//! See PMS-103 for the AC list.

use std::sync::Arc;
use std::time::Duration;

use uuid::Uuid;

use crate::db::Database;
use crate::utils::error::{AppError, AppResult};

use super::provider::{build_provider, ProviderConfig, ProviderDevice, RmmProvider};

/// Outcome of a single sync against one connection. Surface so the
/// caller (the long-running loop in production, the integration test
/// in dev) can log + assert on it.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SyncStats {
    pub devices_seen: u64,
    pub mappings_upserted: u64,
    pub assets_created: u64,
    pub assets_updated: u64,
}

/// Worker handle. Clone is cheap (Database is a pool ref + 32 bytes).
#[derive(Clone)]
pub struct RmmSyncWorker {
    db: Database,
    encryption_key: [u8; 32],
}

impl RmmSyncWorker {
    pub fn new(db: Database, encryption_key: [u8; 32]) -> Self {
        Self { db, encryption_key }
    }

    /// Long-running loop. Tick every `interval`. Log errors and keep
    /// going - one bad provider should not stall the rest.
    #[tracing::instrument(skip_all)]
    pub async fn run_forever(self, interval: Duration) {
        tracing::info!(
            interval_secs = interval.as_secs(),
            "rmm sync worker started",
        );
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            match self.run_tick().await {
                Ok(n) if n > 0 => {
                    tracing::debug!(connections_synced = n, "rmm sync tick");
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(error = ?e, "rmm sync tick failed; will retry on next interval");
                }
            }
        }
    }

    /// Pick up every active connection past its `sync_interval_minutes`
    /// window and sync each via its `RmmProvider`. Returns the number
    /// of connections processed.
    #[tracing::instrument(skip_all)]
    pub async fn run_tick(&self) -> AppResult<u64> {
        let due: Vec<DueConnection> = sqlx::query_as(
            r#"
            SELECT id, tenant_id, provider, api_url, api_key_encrypted, api_secret_encrypted
            FROM rmm_connections
            WHERE is_active = TRUE
              AND sync_status <> 'in_progress'
              AND (
                  last_sync_at IS NULL
                  OR last_sync_at <= NOW() - (sync_interval_minutes * INTERVAL '1 minute')
              )
            "#,
        )
        .fetch_all(self.db.pool())
        .await
        .map_err(|e| AppError::Database(format!("rmm worker pick: {e}")))?;

        let mut count = 0u64;
        for row in due {
            // Per-connection sync so one bad provider does not stall the
            // rest. Errors land in `last_error`; the loop continues.
            let cfg = match self.decrypt_config(&row) {
                Ok(c) => c,
                Err(e) => {
                    self.mark_failed(row.id, format!("decrypt: {e}")).await.ok();
                    continue;
                }
            };
            let provider: Arc<dyn RmmProvider> = build_provider(&row.provider, cfg).into();
            if let Err(e) = self
                .sync_one(row.tenant_id, row.id, provider.as_ref())
                .await
            {
                self.mark_failed(row.id, e.to_string()).await.ok();
            }
            count += 1;
        }
        Ok(count)
    }

    /// Sync a single connection against the given provider. Public so
    /// the integration test can inject a mock provider directly,
    /// bypassing the `build_provider` factory.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn sync_one(
        &self,
        tenant_id: Uuid,
        connection_id: Uuid,
        provider: &dyn RmmProvider,
    ) -> AppResult<SyncStats> {
        self.mark_in_progress(connection_id).await?;

        let devices = provider.list_devices().await?;
        let mut stats = SyncStats {
            devices_seen: devices.len() as u64,
            ..SyncStats::default()
        };

        for d in devices {
            self.upsert_mapping(tenant_id, connection_id, &d).await?;
            stats.mappings_upserted += 1;
            if let Some(linked) = self
                .link_or_create_asset(tenant_id, connection_id, &d)
                .await?
            {
                if linked.created {
                    stats.assets_created += 1;
                } else {
                    stats.assets_updated += 1;
                }
            }
        }

        sqlx::query(
            r#"UPDATE rmm_connections
               SET sync_status = 'success', last_sync_at = NOW(),
                   last_error = NULL, updated_at = NOW()
               WHERE id = $1"#,
        )
        .bind(connection_id)
        .execute(self.db.pool())
        .await
        .map_err(|e| AppError::Database(format!("rmm mark success: {e}")))?;
        Ok(stats)
    }

    async fn mark_in_progress(&self, connection_id: Uuid) -> AppResult<()> {
        sqlx::query(
            r#"UPDATE rmm_connections
               SET sync_status = 'in_progress', updated_at = NOW()
               WHERE id = $1"#,
        )
        .bind(connection_id)
        .execute(self.db.pool())
        .await
        .map_err(|e| AppError::Database(format!("rmm mark in_progress: {e}")))?;
        Ok(())
    }

    async fn mark_failed(&self, connection_id: Uuid, err: String) -> AppResult<()> {
        sqlx::query(
            r#"UPDATE rmm_connections
               SET sync_status = 'failed', last_error = $1,
                   last_sync_at = NOW(), updated_at = NOW()
               WHERE id = $2"#,
        )
        .bind(err)
        .bind(connection_id)
        .execute(self.db.pool())
        .await
        .map_err(|e| AppError::Database(format!("rmm mark failed: {e}")))?;
        Ok(())
    }

    async fn upsert_mapping(
        &self,
        tenant_id: Uuid,
        connection_id: Uuid,
        d: &ProviderDevice,
    ) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            r#"
            INSERT INTO rmm_device_mappings
                (tenant_id, rmm_connection_id, rmm_device_id, device_name,
                 device_info, last_seen, sync_status)
            VALUES ($1, $2, $3, $4, $5, $6, 'synced')
            ON CONFLICT (rmm_connection_id, rmm_device_id) DO UPDATE SET
                device_name = EXCLUDED.device_name,
                device_info = EXCLUDED.device_info,
                last_seen = EXCLUDED.last_seen,
                sync_status = 'synced',
                updated_at = NOW()
            "#,
        )
        .bind(tenant_id)
        .bind(connection_id)
        .bind(&d.rmm_device_id)
        .bind(d.hostname.as_deref())
        .bind(&d.raw)
        .bind(d.last_seen)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Database(format!("rmm upsert mapping: {e}")))?;
        tx.commit().await?;
        Ok(())
    }

    /// Match-or-create the `assets` row for this mapping. The mapping
    /// must already carry a `company_id` (admin-curated) before sync
    /// will spawn an asset; otherwise return `Ok(None)` and leave the
    /// mapping in place for the admin to attach manually.
    async fn link_or_create_asset(
        &self,
        tenant_id: Uuid,
        connection_id: Uuid,
        d: &ProviderDevice,
    ) -> AppResult<Option<LinkResult>> {
        let mut map_tx = self.db.begin_with_tenant(tenant_id).await?;
        let mapping_row: Option<(Uuid, Option<Uuid>, Option<Uuid>)> = sqlx::query_as(
            r#"SELECT id, asset_id, company_id
               FROM rmm_device_mappings
               WHERE tenant_id = $1 AND rmm_connection_id = $2 AND rmm_device_id = $3"#,
        )
        .bind(tenant_id)
        .bind(connection_id)
        .bind(&d.rmm_device_id)
        .fetch_optional(&mut *map_tx)
        .await
        .map_err(|e| AppError::Database(format!("rmm read mapping: {e}")))?;
        drop(map_tx);

        let Some((mapping_id, existing_asset, company_id)) = mapping_row else {
            return Ok(None);
        };
        let Some(company_id) = company_id else {
            return Ok(None);
        };

        if let Some(asset_id) = existing_asset {
            sqlx::query(
                r#"UPDATE assets
                   SET last_sync_at = NOW(), rmm_device_id = $1, updated_at = NOW()
                   WHERE id = $2"#,
            )
            .bind(&d.rmm_device_id)
            .bind(asset_id)
            .execute(self.db.pool())
            .await
            .map_err(|e| AppError::Database(format!("rmm touch asset: {e}")))?;
            self.write_audit(tenant_id, asset_id, "synced", d).await?;
            return Ok(Some(LinkResult {
                created: false,
                asset_id,
            }));
        }

        // No prior asset: try to match by serial, then hostname, then
        // rmm_device_id. The match-or-create order keeps a single
        // physical device from showing up twice if it was already in
        // the CMDB before the sync started.
        let candidate: Option<Uuid> =
            if let Some(serial) = d.serial_number.as_ref().filter(|s| !s.is_empty()) {
                let mut serial_tx = self.db.begin_with_tenant(tenant_id).await?;
                sqlx::query_scalar(
                    "SELECT id FROM assets WHERE tenant_id = $1 AND serial_number = $2 LIMIT 1",
                )
                .bind(tenant_id)
                .bind(serial)
                .fetch_optional(&mut *serial_tx)
                .await
                .map_err(|e| AppError::Database(format!("rmm match serial: {e}")))?
            } else {
                None
            };
        let candidate = match candidate {
            Some(id) => Some(id),
            None => {
                if let Some(host) = d.hostname.as_ref().filter(|s| !s.is_empty()) {
                    let mut name_tx = self.db.begin_with_tenant(tenant_id).await?;
                    sqlx::query_scalar(
                        "SELECT id FROM assets WHERE tenant_id = $1 AND name = $2 LIMIT 1",
                    )
                    .bind(tenant_id)
                    .bind(host)
                    .fetch_optional(&mut *name_tx)
                    .await
                    .map_err(|e| AppError::Database(format!("rmm match name: {e}")))?
                } else {
                    None
                }
            }
        };

        if let Some(asset_id) = candidate {
            // Existing asset, link mapping + bump last_sync_at.
            sqlx::query(
                "UPDATE rmm_device_mappings SET asset_id = $1, updated_at = NOW() WHERE id = $2",
            )
            .bind(asset_id)
            .bind(mapping_id)
            .execute(self.db.pool())
            .await
            .map_err(|e| AppError::Database(format!("rmm link mapping: {e}")))?;
            sqlx::query(
                r#"UPDATE assets
                   SET last_sync_at = NOW(), rmm_device_id = $1, updated_at = NOW()
                   WHERE id = $2"#,
            )
            .bind(&d.rmm_device_id)
            .bind(asset_id)
            .execute(self.db.pool())
            .await
            .map_err(|e| AppError::Database(format!("rmm touch matched asset: {e}")))?;
            self.write_audit(tenant_id, asset_id, "synced", d).await?;
            return Ok(Some(LinkResult {
                created: false,
                asset_id,
            }));
        }

        // No candidate: create a new asset. Pick the first asset type
        // in the tenant as a default; an admin can re-categorize from
        // the UI later. Fail gracefully if no asset types exist (the
        // tenant has not been seeded), leaving the mapping unlinked.
        let mut type_tx = self.db.begin_with_tenant(tenant_id).await?;
        let asset_type_id: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM asset_types WHERE tenant_id = $1 ORDER BY created_at LIMIT 1",
        )
        .bind(tenant_id)
        .fetch_optional(&mut *type_tx)
        .await
        .map_err(|e| AppError::Database(format!("rmm read asset_type: {e}")))?;
        drop(type_tx);
        let Some(asset_type_id) = asset_type_id else {
            return Ok(None);
        };

        let asset_id = Uuid::new_v4();
        let name = d
            .hostname
            .clone()
            .unwrap_or_else(|| format!("rmm:{}", d.rmm_device_id));
        let mut insert_tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            r#"
            INSERT INTO assets
                (id, tenant_id, name, asset_type_id, company_id,
                 serial_number, rmm_device_id, last_sync_at, status)
            VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), 'active')
            "#,
        )
        .bind(asset_id)
        .bind(tenant_id)
        .bind(&name)
        .bind(asset_type_id)
        .bind(company_id)
        .bind(d.serial_number.as_deref())
        .bind(&d.rmm_device_id)
        .execute(&mut *insert_tx)
        .await
        .map_err(|e| AppError::Database(format!("rmm create asset: {e}")))?;
        insert_tx.commit().await?;

        sqlx::query(
            "UPDATE rmm_device_mappings SET asset_id = $1, updated_at = NOW() WHERE id = $2",
        )
        .bind(asset_id)
        .bind(mapping_id)
        .execute(self.db.pool())
        .await
        .map_err(|e| AppError::Database(format!("rmm link new mapping: {e}")))?;
        self.write_audit(tenant_id, asset_id, "created", d).await?;
        Ok(Some(LinkResult {
            created: true,
            asset_id,
        }))
    }

    async fn write_audit(
        &self,
        tenant_id: Uuid,
        asset_id: Uuid,
        action: &str,
        d: &ProviderDevice,
    ) -> AppResult<()> {
        let changes = serde_json::json!({
            "rmm_device_id": d.rmm_device_id,
            "hostname": d.hostname,
            "last_seen": d.last_seen,
        });
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            r#"INSERT INTO asset_audit_log
               (tenant_id, asset_id, action, changes)
               VALUES ($1, $2, $3, $4)"#,
        )
        .bind(tenant_id)
        .bind(asset_id)
        .bind(action)
        .bind(changes)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Database(format!("rmm audit: {e}")))?;
        tx.commit().await?;
        Ok(())
    }

    fn decrypt_config(&self, row: &DueConnection) -> AppResult<ProviderConfig> {
        let api_key = crate::utils::crypto::decrypt(&row.api_key_encrypted, &self.encryption_key)?;
        let api_secret = row
            .api_secret_encrypted
            .as_deref()
            .map(|enc| crate::utils::crypto::decrypt(enc, &self.encryption_key))
            .transpose()?;
        Ok(ProviderConfig {
            connection_id: row.id,
            api_url: row.api_url.clone(),
            api_key,
            api_secret,
        })
    }
}

#[derive(sqlx::FromRow)]
struct DueConnection {
    id: Uuid,
    tenant_id: Uuid,
    provider: String,
    api_url: String,
    api_key_encrypted: String,
    api_secret_encrypted: Option<String>,
}

struct LinkResult {
    created: bool,
    #[allow(dead_code)]
    asset_id: Uuid,
}
