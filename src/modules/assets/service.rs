//! Assets service.

use rust_decimal::Decimal;
use uuid::Uuid;

use crate::db::Database;
use crate::modules::audit::{audit_write, AuditAction, AuditCtx};
use crate::modules::auth::TenantId;
use crate::utils::error::{AppError, AppResult};
use crate::utils::pagination::PaginationParams;

use super::models::*;

#[derive(Clone)]
pub struct AssetsService {
    db: Database,
    encryption_key: [u8; 32],
}

impl AssetsService {
    pub fn new(db: Database) -> Self {
        Self {
            db,
            encryption_key: [0u8; 32],
        }
    }

    pub fn with_encryption_key(db: Database, encryption_key: [u8; 32]) -> Self {
        Self { db, encryption_key }
    }

    // PMS-73 asset types ------------------------------------------------------
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_asset_types(
        &self,
        tenant_id: TenantId,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<AssetTypeResponse>, u64)> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let total: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM asset_types WHERE tenant_id = $1")
                .bind(tenant_id)
                .fetch_one(&mut *tx)
                .await?;

        let rows = sqlx::query_as::<_, AssetTypeRow>(
            r#"SELECT id, name, icon, parent_type_id, is_active
               FROM asset_types WHERE tenant_id = $1 ORDER BY name
               LIMIT $2 OFFSET $3"#,
        )
        .bind(tenant_id)
        .bind(pagination.limit() as i64)
        .bind(pagination.offset() as i64)
        .fetch_all(&mut *tx)
        .await?;
        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create_asset_type(
        &self,
        tenant_id: TenantId,
        request: &UpsertAssetTypeRequest,
    ) -> AppResult<AssetTypeResponse> {
        let id = Uuid::new_v4();
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            r#"INSERT INTO asset_types (id, tenant_id, name, icon, parent_type_id, is_active)
               VALUES ($1, $2, $3, $4, $5, $6)"#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(&request.name)
        .bind(&request.icon)
        .bind(request.parent_type_id)
        .bind(request.is_active)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(AssetTypeResponse {
            id,
            name: request.name.clone(),
            icon: request.icon.clone(),
            parent_type_id: request.parent_type_id,
            is_active: request.is_active,
        })
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn update_asset_type(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        request: &UpsertAssetTypeRequest,
    ) -> AppResult<AssetTypeResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let n = sqlx::query(
            r#"UPDATE asset_types SET name = $3, icon = $4, parent_type_id = $5,
                   is_active = $6, updated_at = NOW()
               WHERE tenant_id = $1 AND id = $2"#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(&request.name)
        .bind(&request.icon)
        .bind(request.parent_type_id)
        .bind(request.is_active)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("AssetType".to_string()));
        }
        tx.commit().await?;
        Ok(AssetTypeResponse {
            id,
            name: request.name.clone(),
            icon: request.icon.clone(),
            parent_type_id: request.parent_type_id,
            is_active: request.is_active,
        })
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn delete_asset_type(&self, tenant_id: TenantId, id: Uuid) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let n = sqlx::query("DELETE FROM asset_types WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("AssetType".to_string()));
        }
        tx.commit().await?;
        Ok(())
    }

    // PMS-74 assets CRUD ------------------------------------------------------
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_assets(
        &self,
        tenant_id: TenantId,
        filter: &AssetFilter,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<AssetResponse>, u64)> {
        let mut conditions = vec!["tenant_id = $1".to_string()];
        let mut idx = 2;
        if filter.company_id.is_some() {
            conditions.push(format!("company_id = ${idx}"));
            idx += 1;
        }
        if filter.asset_type_id.is_some() {
            conditions.push(format!("asset_type_id = ${idx}"));
            idx += 1;
        }
        if filter.status.is_some() {
            conditions.push(format!("status = ${idx}"));
            idx += 1;
        }
        let where_clause = conditions.join(" AND ");

        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let count_query = format!("SELECT COUNT(*) FROM assets WHERE {where_clause}");
        let mut cq = sqlx::query_scalar::<_, i64>(&count_query).bind(tenant_id);
        if let Some(v) = filter.company_id {
            cq = cq.bind(v);
        }
        if let Some(v) = filter.asset_type_id {
            cq = cq.bind(v);
        }
        if let Some(v) = &filter.status {
            cq = cq.bind(v);
        }
        let total: i64 = cq.fetch_one(&mut *tx).await?;

        let query = format!(
            r#"SELECT id, asset_tag, name, asset_type_id, company_id, site_id, contact_id,
                      status, manufacturer, model, serial_number, purchase_date,
                      purchase_price, warranty_expiry, end_of_life, created_at, updated_at
               FROM assets WHERE {where_clause} ORDER BY name
               LIMIT ${limit_idx} OFFSET ${offset_idx}"#,
            limit_idx = idx,
            offset_idx = idx + 1,
        );
        let mut q = sqlx::query_as::<_, AssetRow>(&query).bind(tenant_id);
        if let Some(v) = filter.company_id {
            q = q.bind(v);
        }
        if let Some(v) = filter.asset_type_id {
            q = q.bind(v);
        }
        if let Some(v) = &filter.status {
            q = q.bind(v);
        }
        q = q
            .bind(pagination.limit() as i64)
            .bind(pagination.offset() as i64);
        let rows = q.fetch_all(&mut *tx).await?;
        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create_asset(
        &self,
        tenant_id: TenantId,
        performer: Uuid,
        request: &CreateAssetRequest,
    ) -> AppResult<AssetResponse> {
        let id = Uuid::new_v4();
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            r#"INSERT INTO assets (id, tenant_id, asset_tag, name, asset_type_id, company_id,
                                    site_id, contact_id, status, manufacturer, model, serial_number,
                                    purchase_date, purchase_price, warranty_expiry, end_of_life)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)"#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(&request.asset_tag)
        .bind(&request.name)
        .bind(request.asset_type_id)
        .bind(request.company_id)
        .bind(request.site_id)
        .bind(request.contact_id)
        .bind(&request.status)
        .bind(&request.manufacturer)
        .bind(&request.model)
        .bind(&request.serial_number)
        .bind(request.purchase_date)
        .bind(request.purchase_price)
        .bind(request.warranty_expiry)
        .bind(request.end_of_life)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            r#"INSERT INTO asset_audit_log (tenant_id, asset_id, action, performed_by_id)
               VALUES ($1, $2, 'created', $3)"#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(performer)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        self.get_asset(tenant_id, id).await
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn get_asset(&self, tenant_id: TenantId, id: Uuid) -> AppResult<AssetResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row = sqlx::query_as::<_, AssetRow>(
            r#"SELECT id, asset_tag, name, asset_type_id, company_id, site_id, contact_id,
                      status, manufacturer, model, serial_number, purchase_date,
                      purchase_price, warranty_expiry, end_of_life, created_at, updated_at
               FROM assets WHERE tenant_id = $1 AND id = $2"#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| AppError::NotFound("Asset".to_string()))?;
        Ok(row.into())
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn update_asset(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        performer: Uuid,
        request: &UpdateAssetRequest,
    ) -> AppResult<AssetResponse> {
        let prior = self.get_asset(tenant_id, id).await?;
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        // Snapshot before/after so the audit row records the field-level
        // before -> after diff, not just the action (PMS-204).
        let before: Option<serde_json::Value> =
            sqlx::query_scalar("SELECT to_jsonb(a) FROM assets a WHERE tenant_id = $1 AND id = $2")
                .bind(tenant_id)
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?;
        let n = sqlx::query(
            r#"UPDATE assets SET
                asset_tag = COALESCE($3, asset_tag),
                name = COALESCE($4, name),
                asset_type_id = COALESCE($5, asset_type_id),
                site_id = COALESCE($6, site_id),
                contact_id = COALESCE($7, contact_id),
                status = COALESCE($8, status),
                manufacturer = COALESCE($9, manufacturer),
                model = COALESCE($10, model),
                serial_number = COALESCE($11, serial_number),
                purchase_date = COALESCE($12, purchase_date),
                purchase_price = COALESCE($13, purchase_price),
                warranty_expiry = COALESCE($14, warranty_expiry),
                end_of_life = COALESCE($15, end_of_life),
                updated_at = NOW()
               WHERE tenant_id = $1 AND id = $2"#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(&request.asset_tag)
        .bind(&request.name)
        .bind(request.asset_type_id)
        .bind(request.site_id)
        .bind(request.contact_id)
        .bind(&request.status)
        .bind(&request.manufacturer)
        .bind(&request.model)
        .bind(&request.serial_number)
        .bind(request.purchase_date)
        .bind(request.purchase_price)
        .bind(request.warranty_expiry)
        .bind(request.end_of_life)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("Asset".to_string()));
        }
        let after: Option<serde_json::Value> =
            sqlx::query_scalar("SELECT to_jsonb(a) FROM assets a WHERE tenant_id = $1 AND id = $2")
                .bind(tenant_id)
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?;
        let action = if request.status.is_some() && request.status.as_ref() != Some(&prior.status) {
            "status_changed"
        } else {
            "updated"
        };
        // Persist the before -> after diff as a JSON array of {field, old, new}
        // so the asset detail page can show the actual content of the edit.
        let changes = serde_json::to_value(crate::modules::audit::field_changes(&before, &after))
            .unwrap_or(serde_json::Value::Null);
        sqlx::query(
            r#"INSERT INTO asset_audit_log (tenant_id, asset_id, action, performed_by_id, changes)
               VALUES ($1, $2, $3, $4, $5)"#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(action)
        .bind(performer)
        .bind(changes)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        self.get_asset(tenant_id, id).await
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn delete_asset(&self, tenant_id: TenantId, id: Uuid) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let n = sqlx::query("DELETE FROM assets WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("Asset".to_string()));
        }
        tx.commit().await?;
        Ok(())
    }

    // PMS-75 relationships ----------------------------------------------------
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_asset_relationships(
        &self,
        tenant_id: TenantId,
        asset_id: Uuid,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<AssetRelationshipResponse>, u64)> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let total: i64 = sqlx::query_scalar(
            r#"SELECT COUNT(*) FROM asset_relationships
               WHERE tenant_id = $1 AND (parent_asset_id = $2 OR child_asset_id = $2)"#,
        )
        .bind(tenant_id)
        .bind(asset_id)
        .fetch_one(&mut *tx)
        .await?;

        let rows = sqlx::query_as::<_, RelRow>(
            r#"SELECT id, parent_asset_id, child_asset_id, relationship_type
               FROM asset_relationships
               WHERE tenant_id = $1 AND (parent_asset_id = $2 OR child_asset_id = $2)
               LIMIT $3 OFFSET $4"#,
        )
        .bind(tenant_id)
        .bind(asset_id)
        .bind(pagination.limit() as i64)
        .bind(pagination.offset() as i64)
        .fetch_all(&mut *tx)
        .await?;
        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create_asset_relationship(
        &self,
        tenant_id: TenantId,
        parent_id: Uuid,
        request: &CreateAssetRelationshipRequest,
    ) -> AppResult<AssetRelationshipResponse> {
        let id = Uuid::new_v4();
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            r#"INSERT INTO asset_relationships
               (id, tenant_id, parent_asset_id, child_asset_id, relationship_type)
               VALUES ($1, $2, $3, $4, $5)"#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(parent_id)
        .bind(request.child_asset_id)
        .bind(&request.relationship_type)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(AssetRelationshipResponse {
            id,
            parent_asset_id: parent_id,
            child_asset_id: request.child_asset_id,
            relationship_type: request.relationship_type.clone(),
        })
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn delete_asset_relationship(&self, tenant_id: TenantId, id: Uuid) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let n = sqlx::query("DELETE FROM asset_relationships WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("AssetRelationship".to_string()));
        }
        tx.commit().await?;
        Ok(())
    }

    // PMS-76 configuration items ---------------------------------------------
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    /// List configuration items WITHOUT decrypting their values. The
    /// encrypted secret never appears in a list; callers reveal a single
    /// item via `reveal_configuration_item` (audited).
    pub async fn list_configuration_items(
        &self,
        tenant_id: TenantId,
        asset_id: Uuid,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<ConfigurationItemSummary>, u64)> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM configuration_items WHERE tenant_id = $1 AND asset_id = $2",
        )
        .bind(tenant_id)
        .bind(asset_id)
        .fetch_one(&mut *tx)
        .await?;

        let rows = sqlx::query_as::<_, ConfigItemRow>(
            r#"SELECT id, asset_id, name, category, value_encrypted, notes, created_at
               FROM configuration_items WHERE tenant_id = $1 AND asset_id = $2
               ORDER BY name
               LIMIT $3 OFFSET $4"#,
        )
        .bind(tenant_id)
        .bind(asset_id)
        .bind(pagination.limit() as i64)
        .bind(pagination.offset() as i64)
        .fetch_all(&mut *tx)
        .await?;
        let items: Vec<ConfigurationItemSummary> = rows
            .into_iter()
            .map(|r| ConfigurationItemSummary {
                id: r.id,
                asset_id: r.asset_id,
                name: r.name,
                category: r.category,
                notes: r.notes,
                created_at: r.created_at,
            })
            .collect();
        Ok((items, total as u64))
    }

    /// Reveal a single configuration item's decrypted value. Authz is
    /// enforced at the route (`RequireAssets`); the reveal is recorded in
    /// `asset_audit_log` so every decryption is traceable.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn reveal_configuration_item(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        performer: Uuid,
    ) -> AppResult<ConfigurationItemResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let r = sqlx::query_as::<_, ConfigItemRow>(
            r#"SELECT id, asset_id, name, category, value_encrypted, notes, created_at
               FROM configuration_items WHERE tenant_id = $1 AND id = $2"#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| AppError::NotFound("ConfigurationItem".to_string()))?;
        let value = crate::utils::crypto::decrypt(&r.value_encrypted, &self.encryption_key)?;
        sqlx::query(
            r#"INSERT INTO asset_audit_log (tenant_id, asset_id, action, performed_by_id, changes)
               VALUES ($1, $2, 'synced', $3, '{"event":"config_item_revealed"}'::jsonb)"#,
        )
        .bind(tenant_id)
        .bind(r.asset_id)
        .bind(performer)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(ConfigurationItemResponse {
            id: r.id,
            asset_id: r.asset_id,
            name: r.name,
            category: r.category,
            value,
            notes: r.notes,
            created_at: r.created_at,
        })
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn upsert_configuration_item(
        &self,
        tenant_id: TenantId,
        asset_id: Uuid,
        request: &UpsertConfigurationItemRequest,
    ) -> AppResult<ConfigurationItemResponse> {
        let encrypted = crate::utils::crypto::encrypt(&request.value, &self.encryption_key)?;
        let id = Uuid::new_v4();
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            r#"INSERT INTO configuration_items
               (id, tenant_id, asset_id, name, category, value_encrypted, notes)
               VALUES ($1, $2, $3, $4, $5, $6, $7)"#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(asset_id)
        .bind(&request.name)
        .bind(&request.category)
        .bind(&encrypted)
        .bind(&request.notes)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(ConfigurationItemResponse {
            id,
            asset_id,
            name: request.name.clone(),
            category: request.category.clone(),
            value: request.value.clone(),
            notes: request.notes.clone(),
            created_at: chrono::Utc::now(),
        })
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn delete_configuration_item(&self, tenant_id: TenantId, id: Uuid) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let n = sqlx::query("DELETE FROM configuration_items WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("ConfigurationItem".to_string()));
        }
        tx.commit().await?;
        Ok(())
    }

    // PMS-77 credential vault ------------------------------------------------
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    /// List vault credentials WITHOUT decrypting secrets. Username,
    /// password, and notes never appear in a list; callers reveal a single
    /// credential via `reveal_credential` (audited).
    pub async fn list_credentials(
        &self,
        tenant_id: TenantId,
        asset_id: Uuid,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<CredentialSummary>, u64)> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM credential_vault WHERE tenant_id = $1 AND asset_id = $2",
        )
        .bind(tenant_id)
        .bind(asset_id)
        .fetch_one(&mut *tx)
        .await?;

        let rows = sqlx::query_as::<_, CredRow>(
            r#"SELECT id, name, company_id, asset_id, credential_type,
                      username_encrypted, password_encrypted, url, notes_encrypted,
                      last_rotated, created_at
               FROM credential_vault WHERE tenant_id = $1 AND asset_id = $2
               ORDER BY name
               LIMIT $3 OFFSET $4"#,
        )
        .bind(tenant_id)
        .bind(asset_id)
        .bind(pagination.limit() as i64)
        .bind(pagination.offset() as i64)
        .fetch_all(&mut *tx)
        .await?;

        let items: Vec<CredentialSummary> = rows
            .into_iter()
            .map(|r| CredentialSummary {
                id: r.id,
                name: r.name,
                company_id: r.company_id,
                asset_id: r.asset_id,
                credential_type: r.credential_type,
                url: r.url,
                last_rotated: r.last_rotated,
                created_at: r.created_at,
            })
            .collect();
        Ok((items, total as u64))
    }

    /// Reveal a single credential's decrypted secrets. Authz is enforced
    /// at the route (`RequireAssets`); the reveal is recorded in
    /// `asset_audit_log` so every decryption is traceable.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn reveal_credential(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        performer: Uuid,
    ) -> AppResult<CredentialResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let r = sqlx::query_as::<_, CredRow>(
            r#"SELECT id, name, company_id, asset_id, credential_type,
                      username_encrypted, password_encrypted, url, notes_encrypted,
                      last_rotated, created_at
               FROM credential_vault WHERE tenant_id = $1 AND id = $2"#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| AppError::NotFound("Credential".to_string()))?;

        let username = crate::utils::crypto::decrypt(&r.username_encrypted, &self.encryption_key)?;
        let password = crate::utils::crypto::decrypt(&r.password_encrypted, &self.encryption_key)?;
        let notes = match r.notes_encrypted {
            Some(enc) => Some(crate::utils::crypto::decrypt(&enc, &self.encryption_key)?),
            None => None,
        };
        sqlx::query(
            r#"INSERT INTO asset_audit_log (tenant_id, asset_id, action, performed_by_id, changes)
               VALUES ($1, $2, 'synced', $3, '{"event":"credential_read"}'::jsonb)"#,
        )
        .bind(tenant_id)
        .bind(r.asset_id)
        .bind(performer)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;

        Ok(CredentialResponse {
            id: r.id,
            name: r.name,
            company_id: r.company_id,
            asset_id: r.asset_id,
            credential_type: r.credential_type,
            username,
            password,
            url: r.url,
            notes,
            last_rotated: r.last_rotated,
            created_at: r.created_at,
        })
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create_credential(
        &self,
        tenant_id: TenantId,
        asset_id: Uuid,
        performer: Uuid,
        request: &CreateCredentialRequest,
        ctx: &AuditCtx,
    ) -> AppResult<CredentialResponse> {
        let username_enc = crate::utils::crypto::encrypt(&request.username, &self.encryption_key)?;
        let password_enc = crate::utils::crypto::encrypt(&request.password, &self.encryption_key)?;
        let notes_enc = match &request.notes {
            Some(n) => Some(crate::utils::crypto::encrypt(n, &self.encryption_key)?),
            None => None,
        };
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        // Fetch company_id from the asset for the credential row.
        let company_id: Option<Uuid> =
            sqlx::query_scalar("SELECT company_id FROM assets WHERE id = $1 AND tenant_id = $2")
                .bind(asset_id)
                .bind(tenant_id)
                .fetch_optional(&mut *tx)
                .await?;
        let id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO credential_vault
               (id, tenant_id, name, company_id, asset_id, credential_type,
                username_encrypted, password_encrypted, url, notes_encrypted)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)"#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(&request.name)
        .bind(company_id)
        .bind(asset_id)
        .bind(&request.credential_type)
        .bind(&username_enc)
        .bind(&password_enc)
        .bind(&request.url)
        .bind(&notes_enc)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            r#"INSERT INTO asset_audit_log (tenant_id, asset_id, action, performed_by_id,
                                            changes)
               VALUES ($1, $2, 'updated', $3, '{"event":"credential_created"}'::jsonb)"#,
        )
        .bind(tenant_id)
        .bind(asset_id)
        .bind(performer)
        .execute(&mut *tx)
        .await?;

        // PMS-117 audit: snapshot the new row WITHOUT the encrypted secret
        // columns, so the audit trail records who created which credential
        // but never the secret material itself.
        let after: Option<serde_json::Value> = sqlx::query_scalar(
            r#"SELECT to_jsonb(t) - 'username_encrypted' - 'password_encrypted'
                      - 'notes_encrypted'
               FROM credential_vault t WHERE tenant_id = $1 AND id = $2"#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        // PMS-139: audit_write is a cross-module hub still on Uuid (swept last);
        // unwrap the TenantId at the boundary.
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Create,
            "credential_vault",
            Some(id),
            None,
            after,
        )
        .await?;
        tx.commit().await?;

        Ok(CredentialResponse {
            id,
            name: request.name.clone(),
            company_id,
            asset_id: Some(asset_id),
            credential_type: request.credential_type.clone(),
            username: request.username.clone(),
            password: request.password.clone(),
            url: request.url.clone(),
            notes: request.notes.clone(),
            last_rotated: None,
            created_at: chrono::Utc::now(),
        })
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn delete_credential(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        ctx: &AuditCtx,
    ) -> AppResult<()> {
        // PMS-117 audit: snapshot before deleting, omitting the encrypted
        // secret columns. Mutation + audit row share one transaction so a
        // rollback drops both.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let before: Option<serde_json::Value> = sqlx::query_scalar(
            r#"SELECT to_jsonb(t) - 'username_encrypted' - 'password_encrypted'
                      - 'notes_encrypted'
               FROM credential_vault t WHERE tenant_id = $1 AND id = $2"#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        let n = sqlx::query("DELETE FROM credential_vault WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("Credential".to_string()));
        }
        // PMS-139: audit_write is a cross-module hub still on Uuid (swept last);
        // unwrap the TenantId at the boundary.
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Delete,
            "credential_vault",
            Some(id),
            before,
            None,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    // PMS-78 audit log read --------------------------------------------------
    //
    // Previously hard-capped at `LIMIT 500` in a single SELECT. PMS-127
    // replaced the hard cap with the standard pagination clamp
    // (`PaginationParams::MAX_PER_PAGE = 100`), so a single response is
    // bounded *more strictly* than before. A caller can still enumerate
    // the full history page by page; that is the explicit point of an
    // audit log read endpoint, so the enumeration cost is intentional
    // (and rate-limited via the per-page clamp).
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_asset_audit_log(
        &self,
        tenant_id: TenantId,
        asset_id: Uuid,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<AssetAuditLogResponse>, u64)> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM asset_audit_log WHERE tenant_id = $1 AND asset_id = $2",
        )
        .bind(tenant_id)
        .bind(asset_id)
        .fetch_one(&mut *tx)
        .await?;

        let rows = sqlx::query_as::<_, AuditRow>(
            r#"SELECT id, asset_id, action, changes, performed_by_id, performed_at
               FROM asset_audit_log WHERE tenant_id = $1 AND asset_id = $2
               ORDER BY performed_at DESC
               LIMIT $3 OFFSET $4"#,
        )
        .bind(tenant_id)
        .bind(asset_id)
        .bind(pagination.limit() as i64)
        .bind(pagination.offset() as i64)
        .fetch_all(&mut *tx)
        .await?;
        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }
}

#[derive(sqlx::FromRow)]
struct AssetTypeRow {
    id: Uuid,
    name: String,
    icon: Option<String>,
    parent_type_id: Option<Uuid>,
    is_active: Option<bool>,
}

impl From<AssetTypeRow> for AssetTypeResponse {
    fn from(r: AssetTypeRow) -> Self {
        Self {
            id: r.id,
            name: r.name,
            icon: r.icon,
            parent_type_id: r.parent_type_id,
            is_active: r.is_active.unwrap_or(true),
        }
    }
}

#[derive(sqlx::FromRow)]
struct AssetRow {
    id: Uuid,
    asset_tag: Option<String>,
    name: String,
    asset_type_id: Uuid,
    company_id: Uuid,
    site_id: Option<Uuid>,
    contact_id: Option<Uuid>,
    status: Option<String>,
    manufacturer: Option<String>,
    model: Option<String>,
    serial_number: Option<String>,
    purchase_date: Option<chrono::NaiveDate>,
    purchase_price: Option<Decimal>,
    warranty_expiry: Option<chrono::NaiveDate>,
    end_of_life: Option<chrono::NaiveDate>,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<AssetRow> for AssetResponse {
    fn from(r: AssetRow) -> Self {
        Self {
            id: r.id,
            asset_tag: r.asset_tag,
            name: r.name,
            asset_type_id: r.asset_type_id,
            company_id: r.company_id,
            site_id: r.site_id,
            contact_id: r.contact_id,
            status: r.status.unwrap_or_else(|| "active".into()),
            manufacturer: r.manufacturer,
            model: r.model,
            serial_number: r.serial_number,
            purchase_date: r.purchase_date,
            purchase_price: r.purchase_price,
            warranty_expiry: r.warranty_expiry,
            end_of_life: r.end_of_life,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct RelRow {
    id: Uuid,
    parent_asset_id: Uuid,
    child_asset_id: Uuid,
    relationship_type: String,
}

impl From<RelRow> for AssetRelationshipResponse {
    fn from(r: RelRow) -> Self {
        Self {
            id: r.id,
            parent_asset_id: r.parent_asset_id,
            child_asset_id: r.child_asset_id,
            relationship_type: r.relationship_type,
        }
    }
}

#[derive(sqlx::FromRow)]
struct ConfigItemRow {
    id: Uuid,
    asset_id: Uuid,
    name: String,
    category: Option<String>,
    value_encrypted: String,
    notes: Option<String>,
    created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(sqlx::FromRow)]
struct CredRow {
    id: Uuid,
    name: String,
    company_id: Option<Uuid>,
    asset_id: Option<Uuid>,
    credential_type: String,
    username_encrypted: String,
    password_encrypted: String,
    url: Option<String>,
    notes_encrypted: Option<String>,
    last_rotated: Option<chrono::DateTime<chrono::Utc>>,
    created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(sqlx::FromRow)]
struct AuditRow {
    id: Uuid,
    asset_id: Uuid,
    action: String,
    changes: Option<serde_json::Value>,
    performed_by_id: Option<Uuid>,
    performed_at: chrono::DateTime<chrono::Utc>,
}

impl From<AuditRow> for AssetAuditLogResponse {
    fn from(r: AuditRow) -> Self {
        Self {
            id: r.id,
            asset_id: r.asset_id,
            action: r.action,
            changes: r.changes,
            performed_by_id: r.performed_by_id,
            performed_at: r.performed_at,
        }
    }
}
