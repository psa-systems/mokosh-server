//! Store + business logic for the asset catalog.

use uuid::Uuid;

use super::models::{AssetModelResponse, AssetModelsQuery, CreateAssetModelRequest};
use crate::db::Database;
use crate::modules::auth::TenantId;
use crate::utils::error::{AppError, AppResult};

#[derive(Clone)]
pub struct AssetCatalogService {
    db: Database,
}

impl AssetCatalogService {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Typeahead for the SPA's model picker. Trimmed `q` ILIKE-matched
    /// against `lower(manufacturer || ' ' || model)` so the trigram GIN
    /// (migration 271) serves the predicate. Empty / whitespace `q`
    /// returns the tenant's N most-used models so the picker is useful
    /// even before the operator types.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn search_models(
        &self,
        tenant_id: TenantId,
        query: &AssetModelsQuery,
    ) -> AppResult<Vec<AssetModelResponse>> {
        let limit = query.limit.unwrap_or(10).clamp(1, 50);
        let needle = query
            .q
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.to_lowercase());
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows: Vec<AssetModelResponse> = if let Some(needle) = needle {
            sqlx::query_as::<_, AssetModelResponse>(
                "SELECT id, manufacturer, model, asset_type_id, \
                        warranty_months, end_of_life_months, default_department, \
                        default_license_vendor, default_tags, specs, image_url, \
                        source, uses_count, created_at, updated_at \
                 FROM asset_models \
                 WHERE tenant_id = $1 \
                   AND lower(manufacturer || ' ' || model) LIKE $2 \
                 ORDER BY uses_count DESC, lower(manufacturer), lower(model) \
                 LIMIT $3",
            )
            .bind(*tenant_id)
            .bind(format!("%{needle}%"))
            .bind(limit)
            .fetch_all(&mut *tx)
            .await?
        } else {
            sqlx::query_as::<_, AssetModelResponse>(
                "SELECT id, manufacturer, model, asset_type_id, \
                        warranty_months, end_of_life_months, default_department, \
                        default_license_vendor, default_tags, specs, image_url, \
                        source, uses_count, created_at, updated_at \
                 FROM asset_models \
                 WHERE tenant_id = $1 \
                 ORDER BY uses_count DESC, lower(manufacturer), lower(model) \
                 LIMIT $2",
            )
            .bind(*tenant_id)
            .bind(limit)
            .fetch_all(&mut *tx)
            .await?
        };
        Ok(rows)
    }

    /// Create a tenant-authored catalog row. The handler stamps
    /// `source = 'tenant_authored'`; this method cannot be reached with
    /// another value from the HTTP surface. The uniqueness constraint on
    /// `(tenant_id, lower(manufacturer), lower(model), asset_type_id)`
    /// produces a 409-shaped error up at the mapper when a row of the
    /// same shape already exists.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create_model(
        &self,
        tenant_id: TenantId,
        request: &CreateAssetModelRequest,
    ) -> AppResult<AssetModelResponse> {
        self.assert_asset_type_in_tenant(tenant_id, request.asset_type_id)
            .await?;
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row = sqlx::query_as::<_, AssetModelResponse>(
            "INSERT INTO asset_models (tenant_id, manufacturer, model, asset_type_id, \
                warranty_months, end_of_life_months, default_department, \
                default_license_vendor, default_tags, specs, image_url, source) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'tenant_authored') \
             RETURNING id, manufacturer, model, asset_type_id, \
                       warranty_months, end_of_life_months, default_department, \
                       default_license_vendor, default_tags, specs, image_url, \
                       source, uses_count, created_at, updated_at",
        )
        .bind(*tenant_id)
        .bind(&request.manufacturer)
        .bind(&request.model)
        .bind(request.asset_type_id)
        .bind(request.warranty_months)
        .bind(request.end_of_life_months)
        .bind(&request.default_department)
        .bind(&request.default_license_vendor)
        .bind(&request.default_tags)
        .bind(&request.specs)
        .bind(&request.image_url)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| {
            if let Some(dbe) = e.as_database_error() {
                if let Some(code) = dbe.code() {
                    if code == "23505" {
                        return AppError::Conflict(
                            "A catalog row for this manufacturer / model / type already exists."
                                .to_string(),
                        );
                    }
                }
            }
            e.into()
        })?;
        tx.commit().await?;
        Ok(row)
    }

    /// Read one, scoped to tenant.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn get_model(&self, tenant_id: TenantId, id: Uuid) -> AppResult<AssetModelResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row = sqlx::query_as::<_, AssetModelResponse>(
            "SELECT id, manufacturer, model, asset_type_id, \
                    warranty_months, end_of_life_months, default_department, \
                    default_license_vendor, default_tags, specs, image_url, \
                    source, uses_count, created_at, updated_at \
             FROM asset_models WHERE tenant_id = $1 AND id = $2",
        )
        .bind(*tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| AppError::NotFound("Asset model".to_string()))?;
        Ok(row)
    }

    async fn assert_asset_type_in_tenant(
        &self,
        tenant_id: TenantId,
        asset_type_id: Uuid,
    ) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let found: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM asset_types WHERE tenant_id = $1 AND id = $2")
                .bind(*tenant_id)
                .bind(asset_type_id)
                .fetch_optional(&mut *tx)
                .await?;
        if found.is_none() {
            return Err(AppError::validation_field(
                "asset_type_id",
                "asset type does not exist in this tenant",
            ));
        }
        Ok(())
    }
}
