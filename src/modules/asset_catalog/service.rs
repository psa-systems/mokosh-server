//! Store + business logic for the asset catalog.

use uuid::Uuid;

use super::models::{
    AssetModelResponse, AssetModelsQuery, AssetTemplateResponse, CreateAssetModelRequest,
    CreateAssetTemplateRequest, SignatureCandidate, SignatureDetectorResponse, TemplateSuggestion,
    UpdateAssetModelRequest, UpdateAssetTemplateRequest,
};
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

    /// MR2: partial update. Each field is Option; absent fields leave
    /// the column untouched via `COALESCE($N, col)`. The unique index on
    /// `(tenant_id, lower(manufacturer), lower(model), asset_type_id)`
    /// may raise 23505 when a rename moves two models into the same
    /// shape; mapped to 409 at the HTTP layer the same way `create_model`
    /// does.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn update_model(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        request: &UpdateAssetModelRequest,
    ) -> AppResult<AssetModelResponse> {
        if let Some(type_id) = request.asset_type_id {
            self.assert_asset_type_in_tenant(tenant_id, type_id).await?;
        }
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let n = sqlx::query(
            "UPDATE asset_models SET \
                manufacturer = COALESCE($3, manufacturer), \
                model = COALESCE($4, model), \
                asset_type_id = COALESCE($5, asset_type_id), \
                warranty_months = COALESCE($6, warranty_months), \
                end_of_life_months = COALESCE($7, end_of_life_months), \
                default_department = COALESCE($8, default_department), \
                default_license_vendor = COALESCE($9, default_license_vendor), \
                default_tags = COALESCE($10, default_tags), \
                specs = COALESCE($11, specs), \
                image_url = COALESCE($12, image_url), \
                updated_at = NOW() \
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(*tenant_id)
        .bind(id)
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
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            if let Some(dbe) = e.as_database_error() {
                if let Some(code) = dbe.code() {
                    if code == "23505" {
                        return AppError::Conflict(
                            "Another catalog row already has this manufacturer / model / type."
                                .to_string(),
                        );
                    }
                }
            }
            e.into()
        })?
        .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("Asset model".to_string()));
        }
        tx.commit().await?;
        self.get_model(tenant_id, id).await
    }

    /// MR2: delete. Assets referencing the row keep their rows (the FK on
    /// `assets.asset_model_id` is ON DELETE SET NULL per migration 271);
    /// templates referencing the row are cascade-deleted by their own
    /// FK (so the operator's intent "I don't want this model anymore"
    /// implies the dependent templates go too).
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn delete_model(&self, tenant_id: TenantId, id: Uuid) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let n = sqlx::query("DELETE FROM asset_models WHERE tenant_id = $1 AND id = $2")
            .bind(*tenant_id)
            .bind(id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("Asset model".to_string()));
        }
        tx.commit().await?;
        Ok(())
    }

    // -- Templates ------------------------------------------------

    /// `GET /api/v1/asset-templates`: all templates for the tenant, each
    /// eagerly joined to its asset_model so the typeahead can render
    /// "<name> - <manufacturer> <model>" inline without a second round
    /// trip. Ordered by `updated_at DESC` so recent edits float.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_templates(
        &self,
        tenant_id: TenantId,
    ) -> AppResult<Vec<AssetTemplateResponse>> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows: Vec<AssetTemplateResponse> = sqlx::query_as::<_, AssetTemplateResponse>(
            "SELECT t.id, t.name, t.asset_model_id, m.manufacturer, m.model, m.asset_type_id, \
                    t.company_id, t.site_id, t.default_assigned_user_id, \
                    t.department, t.tags, t.notes, t.license_seat_count, \
                    t.created_by, t.uses_count, t.created_at, t.updated_at \
             FROM asset_templates t \
             INNER JOIN asset_models m ON m.id = t.asset_model_id AND m.tenant_id = t.tenant_id \
             WHERE t.tenant_id = $1 \
             ORDER BY t.updated_at DESC",
        )
        .bind(*tenant_id)
        .fetch_all(&mut *tx)
        .await?;
        Ok(rows)
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn get_template(
        &self,
        tenant_id: TenantId,
        id: Uuid,
    ) -> AppResult<AssetTemplateResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row = sqlx::query_as::<_, AssetTemplateResponse>(
            "SELECT t.id, t.name, t.asset_model_id, m.manufacturer, m.model, m.asset_type_id, \
                    t.company_id, t.site_id, t.default_assigned_user_id, \
                    t.department, t.tags, t.notes, t.license_seat_count, \
                    t.created_by, t.uses_count, t.created_at, t.updated_at \
             FROM asset_templates t \
             INNER JOIN asset_models m ON m.id = t.asset_model_id AND m.tenant_id = t.tenant_id \
             WHERE t.tenant_id = $1 AND t.id = $2",
        )
        .bind(*tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| AppError::NotFound("Asset template".to_string()))?;
        Ok(row)
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create_template(
        &self,
        tenant_id: TenantId,
        performer: Uuid,
        request: &CreateAssetTemplateRequest,
    ) -> AppResult<AssetTemplateResponse> {
        // Model must be in-tenant. The INSERT's FK would catch it too but
        // the message would read as a generic DB error.
        self.get_model(tenant_id, request.asset_model_id).await?;
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row: (Uuid,) = sqlx::query_as(
            "INSERT INTO asset_templates (tenant_id, name, asset_model_id, company_id, site_id, \
                default_assigned_user_id, department, tags, notes, license_seat_count, created_by) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) \
             RETURNING id",
        )
        .bind(*tenant_id)
        .bind(&request.name)
        .bind(request.asset_model_id)
        .bind(request.company_id)
        .bind(request.site_id)
        .bind(request.default_assigned_user_id)
        .bind(&request.department)
        .bind(&request.tags)
        .bind(&request.notes)
        .bind(request.license_seat_count)
        .bind(performer)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| {
            if let Some(dbe) = e.as_database_error() {
                if let Some(code) = dbe.code() {
                    if code == "23505" {
                        return AppError::Conflict(
                            "A template with this name already exists.".to_string(),
                        );
                    }
                }
            }
            e.into()
        })?;
        tx.commit().await?;
        self.get_template(tenant_id, row.0).await
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn update_template(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        request: &UpdateAssetTemplateRequest,
    ) -> AppResult<AssetTemplateResponse> {
        if let Some(model_id) = request.asset_model_id {
            self.get_model(tenant_id, model_id).await?;
        }
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let n = sqlx::query(
            "UPDATE asset_templates SET \
                name = COALESCE($3, name), \
                asset_model_id = COALESCE($4, asset_model_id), \
                company_id = COALESCE($5, company_id), \
                site_id = COALESCE($6, site_id), \
                default_assigned_user_id = COALESCE($7, default_assigned_user_id), \
                department = COALESCE($8, department), \
                tags = COALESCE($9, tags), \
                notes = COALESCE($10, notes), \
                license_seat_count = COALESCE($11, license_seat_count), \
                updated_at = NOW() \
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(*tenant_id)
        .bind(id)
        .bind(&request.name)
        .bind(request.asset_model_id)
        .bind(request.company_id)
        .bind(request.site_id)
        .bind(request.default_assigned_user_id)
        .bind(&request.department)
        .bind(&request.tags)
        .bind(&request.notes)
        .bind(request.license_seat_count)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            if let Some(dbe) = e.as_database_error() {
                if let Some(code) = dbe.code() {
                    if code == "23505" {
                        return AppError::Conflict(
                            "Another template already uses this name.".to_string(),
                        );
                    }
                }
            }
            e.into()
        })?
        .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("Asset template".to_string()));
        }
        tx.commit().await?;
        self.get_template(tenant_id, id).await
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn delete_template(&self, tenant_id: TenantId, id: Uuid) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let n = sqlx::query("DELETE FROM asset_templates WHERE tenant_id = $1 AND id = $2")
            .bind(*tenant_id)
            .bind(id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("Asset template".to_string()));
        }
        tx.commit().await?;
        Ok(())
    }

    /// Internal helper for `bulk_create_assets` to resolve a template id
    /// into the model + per-order context it carries. Returns the row
    /// shape as a tuple of (asset_model_id, context overlay).
    #[allow(clippy::type_complexity)]
    pub async fn resolve_template_for_bulk(
        &self,
        tenant_id: TenantId,
        template_id: Uuid,
    ) -> AppResult<AssetTemplateResponse> {
        self.get_template(tenant_id, template_id).await
    }

    /// MR3: signature detector read. Returns zero or one row: the top
    /// `(tenant, manufacturer, model, asset_type)` group from the last
    /// 7 days of asset creates, filtered to groups the operator has not
    /// yet "owned" by writing a `tenant_authored` catalog row. An
    /// `auto_derived` row still returns (the detector is the write path
    /// for those, so the banner can still prompt).
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn signature_detector(
        &self,
        tenant_id: TenantId,
    ) -> AppResult<SignatureDetectorResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        // LEFT JOIN against asset_models filtered by `source =
        // 'tenant_authored'` so the WHERE condition can suppress the
        // candidate when a catalog row the operator wrote already
        // covers the pattern. `auto_derived` rows do not suppress -
        // the detector is where they come from in the first place.
        let row: Option<(String, String, uuid::Uuid, i64, Option<uuid::Uuid>)> = sqlx::query_as(
            "SELECT mv.manufacturer, mv.model, mv.asset_type_id, mv.group_count, am.id \
             FROM asset_signature_candidates_mv mv \
             LEFT JOIN asset_models am \
               ON am.tenant_id = mv.tenant_id \
              AND lower(am.manufacturer) = mv.manufacturer_lower \
              AND lower(am.model) = mv.model_lower \
              AND am.asset_type_id = mv.asset_type_id \
             WHERE mv.tenant_id = $1 \
               AND (am.id IS NULL OR am.source = 'auto_derived') \
             ORDER BY mv.group_count DESC \
             LIMIT 1",
        )
        .bind(*tenant_id)
        .fetch_optional(&mut *tx)
        .await?;
        Ok(SignatureDetectorResponse {
            signature: row.map(
                |(manufacturer, model, asset_type_id, recent_count, existing_model_id)| {
                    let name_hint = format!("{manufacturer} {model}");
                    SignatureCandidate {
                        manufacturer,
                        model,
                        asset_type_id,
                        recent_count,
                        window_days: 7,
                        existing_model_id,
                        template_suggestion: TemplateSuggestion { name_hint },
                    }
                },
            ),
        })
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
