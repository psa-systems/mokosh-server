//! The default provider: the `secrets` table, AES-256-GCM at rest.
//!
//! This is today's behaviour with the location factored out. The crypto is the
//! same `crate::utils::crypto` pair every per-feature column already used, and
//! the key is the same host `ENCRYPTION_KEY`, so a deployment that configures
//! nothing keeps exactly the storage properties it had (PMS-967).

use async_trait::async_trait;

use super::{SecretKey, SecretProvider};
use crate::db::Database;
use crate::utils::error::AppResult;

#[derive(Clone)]
pub struct DatabaseSecretProvider {
    db: Database,
    /// The host `ENCRYPTION_KEY`, as parsed by
    /// [`crate::utils::crypto::parse_encryption_key`].
    encryption_key: [u8; 32],
}

impl DatabaseSecretProvider {
    pub fn new(db: Database, encryption_key: [u8; 32]) -> Self {
        Self { db, encryption_key }
    }
}

#[async_trait]
impl SecretProvider for DatabaseSecretProvider {
    async fn get(&self, key: &SecretKey) -> AppResult<Option<String>> {
        let name = key.name()?;
        // `begin_with_tenant` and not the migrator pool, even though the row is
        // also filtered by `tenant_id` below. RLS is then the second of two
        // independent reasons this read cannot cross a tenant, and it is the
        // one that still holds if a later caller builds the query wrong.
        //
        // It works on the pre-auth webhook path too, which is what made the
        // existing gateway lookup reach for the migrator pool: the tenant there
        // comes from the URL rather than a session, but it is still a tenant to
        // set as the GUC, and confining the read to it before the signature is
        // checked is strictly safer than not confining it at all.
        let mut tx = self.db.begin_with_tenant(key.tenant_id()).await?;
        let stored: Option<String> = sqlx::query_scalar(
            "SELECT value_encrypted FROM secrets WHERE tenant_id = $1 AND name = $2",
        )
        .bind(key.tenant_id())
        .bind(&name)
        .fetch_optional(&mut *tx)
        .await?;

        match stored {
            Some(ciphertext) => Ok(Some(crate::utils::crypto::decrypt(
                &ciphertext,
                &self.encryption_key,
            )?)),
            None => Ok(None),
        }
    }

    async fn put(&self, key: &SecretKey, value: &str) -> AppResult<()> {
        let name = key.name()?;
        let ciphertext = crate::utils::crypto::encrypt(value, &self.encryption_key)?;
        let mut tx = self.db.begin_with_tenant(key.tenant_id()).await?;
        sqlx::query(
            "INSERT INTO secrets (tenant_id, name, value_encrypted) VALUES ($1, $2, $3) \
             ON CONFLICT (tenant_id, name) DO UPDATE \
             SET value_encrypted = EXCLUDED.value_encrypted, updated_at = NOW()",
        )
        .bind(key.tenant_id())
        .bind(&name)
        .bind(&ciphertext)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn delete(&self, key: &SecretKey) -> AppResult<()> {
        let name = key.name()?;
        let mut tx = self.db.begin_with_tenant(key.tenant_id()).await?;
        // No row affected is success: see `SecretProvider::delete`.
        sqlx::query("DELETE FROM secrets WHERE tenant_id = $1 AND name = $2")
            .bind(key.tenant_id())
            .bind(&name)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }
}
