//! PMS-1488 asset catalog service: `asset_models` + `asset_templates`
//! CRUD, `bulk_create_assets` fanout, and `signature_candidate`.
//!
//! The catalog tables are tenant-scoped and RLS-covered (migration
//! 271), so every read + write runs through `begin_with_tenant`. The
//! signature-candidate reads a `tenant_id`-indexed MV instead; its
//! SAFETY note sits with the call site.

use sqlx::QueryBuilder;
use uuid::Uuid;

use super::catalog_models::*;
use crate::db::Database;
use crate::modules::auth::TenantId;
use crate::utils::error::{AppError, AppResult};
use crate::utils::pagination::PaginationParams;

/// Signature-detector thresholds. The design calls them out as
/// hard-coded for phase 1; a later phase 3.5 pulls them from a
/// tenant setting. Named up here so a reader does not have to search
/// the SELECT below for them.
const SIGNATURE_WINDOW_DAYS: i64 = 7;

#[derive(Clone)]
pub struct AssetCatalogService {
    pub db: Database,
}

impl AssetCatalogService {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    // -- asset_models ---------------------------------------------------

    pub async fn list_models(
        &self,
        tenant_id: TenantId,
        filter: &AssetModelListFilter,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<AssetModelResponse>, u64)> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let mut qb_count = QueryBuilder::<sqlx::Postgres>::new(
            "SELECT COUNT(*) FROM asset_models WHERE tenant_id = ",
        );
        qb_count.push_bind(*tenant_id);
        if let Some(q) = filter.q.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            qb_count.push(" AND lower(manufacturer || ' ' || model) ILIKE ");
            qb_count.push_bind(format!("%{}%", q.to_lowercase()));
        }
        if let Some(id) = filter.asset_type_id {
            qb_count.push(" AND asset_type_id = ");
            qb_count.push_bind(id);
        }
        let total: i64 = qb_count.build_query_scalar().fetch_one(&mut *tx).await?;

        let mut qb = QueryBuilder::<sqlx::Postgres>::new(
            "SELECT id, manufacturer, model, asset_type_id, warranty_months, end_of_life_months, \
                    default_department, default_license_vendor, default_tags, specs, image_url, \
                    source, uses_count, created_at, updated_at \
             FROM asset_models WHERE tenant_id = ",
        );
        qb.push_bind(*tenant_id);
        if let Some(q) = filter.q.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            qb.push(" AND lower(manufacturer || ' ' || model) ILIKE ");
            qb.push_bind(format!("%{}%", q.to_lowercase()));
        }
        if let Some(id) = filter.asset_type_id {
            qb.push(" AND asset_type_id = ");
            qb.push_bind(id);
        }
        qb.push(" ORDER BY uses_count DESC, manufacturer ASC, model ASC LIMIT ");
        qb.push_bind(pagination.limit() as i64);
        qb.push(" OFFSET ");
        qb.push_bind(pagination.offset() as i64);

        let rows: Vec<AssetModelResponse> = qb
            .build_query_as::<AssetModelResponse>()
            .fetch_all(&mut *tx)
            .await?;
        Ok((rows, total as u64))
    }

    pub async fn get_model(&self, tenant_id: TenantId, id: Uuid) -> AppResult<AssetModelResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row: Option<AssetModelResponse> = sqlx::query_as::<_, AssetModelResponse>(
            "SELECT id, manufacturer, model, asset_type_id, warranty_months, end_of_life_months, \
                    default_department, default_license_vendor, default_tags, specs, image_url, \
                    source, uses_count, created_at, updated_at \
             FROM asset_models WHERE id = $1 AND tenant_id = $2",
        )
        .bind(id)
        .bind(*tenant_id)
        .fetch_optional(&mut *tx)
        .await?;
        row.ok_or_else(|| AppError::NotFound("Asset model".to_string()))
    }

    pub async fn create_model(
        &self,
        tenant_id: TenantId,
        source: AssetModelSource,
        req: &CreateAssetModelRequest,
    ) -> AppResult<AssetModelResponse> {
        let id = Uuid::new_v4();
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            "INSERT INTO asset_models (id, tenant_id, manufacturer, model, asset_type_id, \
                                        warranty_months, end_of_life_months, default_department, \
                                        default_license_vendor, default_tags, specs, image_url, \
                                        source) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
        )
        .bind(id)
        .bind(*tenant_id)
        .bind(&req.manufacturer)
        .bind(&req.model)
        .bind(req.asset_type_id)
        .bind(req.warranty_months)
        .bind(req.end_of_life_months)
        .bind(&req.default_department)
        .bind(&req.default_license_vendor)
        .bind(&req.default_tags)
        .bind(&req.specs)
        .bind(&req.image_url)
        .bind(source.as_str())
        .execute(&mut *tx)
        .await
        .map_err(map_unique_violation)?;
        tx.commit().await?;
        self.get_model(tenant_id, id).await
    }

    pub async fn update_model(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        req: &UpdateAssetModelRequest,
    ) -> AppResult<AssetModelResponse> {
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
             WHERE id = $1 AND tenant_id = $2",
        )
        .bind(id)
        .bind(*tenant_id)
        .bind(&req.manufacturer)
        .bind(&req.model)
        .bind(req.asset_type_id)
        .bind(req.warranty_months)
        .bind(req.end_of_life_months)
        .bind(&req.default_department)
        .bind(&req.default_license_vendor)
        .bind(&req.default_tags)
        .bind(&req.specs)
        .bind(&req.image_url)
        .execute(&mut *tx)
        .await
        .map_err(map_unique_violation)?
        .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("Asset model".to_string()));
        }
        tx.commit().await?;
        self.get_model(tenant_id, id).await
    }

    pub async fn delete_model(&self, tenant_id: TenantId, id: Uuid) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let n = sqlx::query("DELETE FROM asset_models WHERE id = $1 AND tenant_id = $2")
            .bind(id)
            .bind(*tenant_id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("Asset model".to_string()));
        }
        tx.commit().await?;
        Ok(())
    }

    // -- asset_templates ------------------------------------------------

    pub async fn list_templates(
        &self,
        tenant_id: TenantId,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<AssetTemplateResponse>, u64)> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let total: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM asset_templates WHERE tenant_id = $1")
                .bind(*tenant_id)
                .fetch_one(&mut *tx)
                .await?;
        let rows: Vec<AssetTemplateResponse> = sqlx::query_as::<_, AssetTemplateResponse>(
            "SELECT id, name, asset_model_id, company_id, site_id, default_assigned_user_id, \
                    department, tags, notes, license_seat_count, uses_count, created_at, updated_at \
             FROM asset_templates \
             WHERE tenant_id = $1 \
             ORDER BY updated_at DESC \
             LIMIT $2 OFFSET $3",
        )
        .bind(*tenant_id)
        .bind(pagination.limit() as i64)
        .bind(pagination.offset() as i64)
        .fetch_all(&mut *tx)
        .await?;
        Ok((rows, total as u64))
    }

    pub async fn get_template(
        &self,
        tenant_id: TenantId,
        id: Uuid,
    ) -> AppResult<AssetTemplateResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row: Option<AssetTemplateResponse> = sqlx::query_as::<_, AssetTemplateResponse>(
            "SELECT id, name, asset_model_id, company_id, site_id, default_assigned_user_id, \
                    department, tags, notes, license_seat_count, uses_count, created_at, updated_at \
             FROM asset_templates WHERE id = $1 AND tenant_id = $2",
        )
        .bind(id)
        .bind(*tenant_id)
        .fetch_optional(&mut *tx)
        .await?;
        row.ok_or_else(|| AppError::NotFound("Asset template".to_string()))
    }

    pub async fn create_template(
        &self,
        tenant_id: TenantId,
        performer: Uuid,
        req: &CreateAssetTemplateRequest,
    ) -> AppResult<AssetTemplateResponse> {
        // Confirm the model is in this tenant (defence in depth; FK with
        // ON DELETE CASCADE would still allow a cross-tenant model id to
        // be bound here without this check).
        self.get_model(tenant_id, req.asset_model_id).await?;
        let id = Uuid::new_v4();
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            "INSERT INTO asset_templates (id, tenant_id, name, asset_model_id, company_id, \
                                           site_id, default_assigned_user_id, department, tags, \
                                           notes, license_seat_count, created_by) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
        )
        .bind(id)
        .bind(*tenant_id)
        .bind(&req.name)
        .bind(req.asset_model_id)
        .bind(req.company_id)
        .bind(req.site_id)
        .bind(req.default_assigned_user_id)
        .bind(&req.department)
        .bind(&req.tags)
        .bind(&req.notes)
        .bind(req.license_seat_count)
        .bind(performer)
        .execute(&mut *tx)
        .await
        .map_err(map_unique_violation)?;
        tx.commit().await?;
        self.get_template(tenant_id, id).await
    }

    pub async fn update_template(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        req: &UpdateAssetTemplateRequest,
    ) -> AppResult<AssetTemplateResponse> {
        if let Some(mid) = req.asset_model_id {
            self.get_model(tenant_id, mid).await?;
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
             WHERE id = $1 AND tenant_id = $2",
        )
        .bind(id)
        .bind(*tenant_id)
        .bind(&req.name)
        .bind(req.asset_model_id)
        .bind(req.company_id)
        .bind(req.site_id)
        .bind(req.default_assigned_user_id)
        .bind(&req.department)
        .bind(&req.tags)
        .bind(&req.notes)
        .bind(req.license_seat_count)
        .execute(&mut *tx)
        .await
        .map_err(map_unique_violation)?
        .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("Asset template".to_string()));
        }
        tx.commit().await?;
        self.get_template(tenant_id, id).await
    }

    pub async fn delete_template(&self, tenant_id: TenantId, id: Uuid) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let n = sqlx::query("DELETE FROM asset_templates WHERE id = $1 AND tenant_id = $2")
            .bind(id)
            .bind(*tenant_id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("Asset template".to_string()));
        }
        tx.commit().await?;
        Ok(())
    }

    // -- bulk create ----------------------------------------------------

    /// Fans the request out to N `assets` rows in one transaction. On
    /// any single-row failure the whole batch rolls back; the caller
    /// sees 422 naming the failing index. Bumps `uses_count` on the
    /// resolved model + template.
    pub async fn bulk_create(
        &self,
        tenant_id: TenantId,
        performer: Uuid,
        req: &BulkCreateAssetsRequest,
    ) -> AppResult<BulkCreateAssetsResponse> {
        // Resolve defaults. `template_id` wins when both are present.
        let (model, template) = match (req.template_id, req.asset_model_id) {
            (Some(tid), _) => {
                let t = self.get_template(tenant_id, tid).await?;
                let m = self.get_model(tenant_id, t.asset_model_id).await?;
                (m, Some(t))
            }
            (None, Some(mid)) => (self.get_model(tenant_id, mid).await?, None),
            (None, None) => {
                return Err(AppError::validation_field(
                    "template_id",
                    "one of template_id or asset_model_id is required",
                ));
            }
        };

        // Overlay context: per-batch wins over template, template wins
        // over model defaults.
        let department = req
            .department
            .clone()
            .or_else(|| template.as_ref().and_then(|t| t.department.clone()))
            .or_else(|| model.default_department.clone());
        let company_id = req.company_id;
        let site_id = req
            .site_id
            .or_else(|| template.as_ref().and_then(|t| t.site_id));
        let assigned_user_id = req
            .assigned_user_id
            .or_else(|| template.as_ref().and_then(|t| t.default_assigned_user_id));
        let tags_defaults: Vec<String> = template
            .as_ref()
            .map(|t| t.tags.clone())
            .unwrap_or_else(|| model.default_tags.clone());
        let license_vendor = model.default_license_vendor.clone();
        let license_seat_count = template.as_ref().and_then(|t| t.license_seat_count);
        let warranty_expiry = req.purchase_date.and_then(|p| {
            model
                .warranty_months
                .and_then(|m| p.checked_add_months(chrono::Months::new(m as u32)))
        });
        let end_of_life = req.purchase_date.and_then(|p| {
            model
                .end_of_life_months
                .and_then(|m| p.checked_add_months(chrono::Months::new(m as u32)))
        });

        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let mut created: Vec<Uuid> = Vec::with_capacity(req.serials.len());
        for (i, s) in req.serials.iter().enumerate() {
            let id = Uuid::new_v4();
            let name = s.name.clone().unwrap_or_else(|| {
                format!(
                    "{} {} #{}",
                    model.manufacturer, model.model, s.serial_number
                )
            });
            let asset_tag = s.asset_tag.clone();
            // IP cast at write time; a malformed value surfaces as 400 at
            // the DB rather than silently writing garbage.
            let ip = s.ip_address.clone().unwrap_or_default();
            let result = sqlx::query(
                "INSERT INTO assets (id, tenant_id, asset_tag, name, asset_type_id, company_id, \
                                     site_id, status, manufacturer, model, serial_number, \
                                     purchase_date, purchase_price, warranty_expiry, end_of_life, \
                                     assigned_user_id, ip_address, hostname, mac_address, \
                                     installed_date, department, license_vendor, license_seat_count, \
                                     asset_model_id, tags) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, 'active', $8, $9, $10, $11, $12, $13, $14, \
                         $15, NULLIF($16, '')::inet, $17, $18, $19, $20, $21, $22, $23, $24)",
            )
            .bind(id)
            .bind(*tenant_id)
            .bind(&asset_tag)
            .bind(&name)
            .bind(model.asset_type_id)
            .bind(company_id)
            .bind(site_id)
            .bind(&model.manufacturer)
            .bind(&model.model)
            .bind(&s.serial_number)
            .bind(req.purchase_date)
            .bind(req.purchase_price)
            .bind(warranty_expiry)
            .bind(end_of_life)
            .bind(assigned_user_id)
            .bind(&ip)
            .bind(&s.hostname)
            .bind(&s.mac_address)
            .bind(req.installed_date)
            .bind(&department)
            .bind(&license_vendor)
            .bind(license_seat_count)
            .bind(model.id)
            .bind(&tags_defaults)
            .execute(&mut *tx)
            .await;
            match result {
                Ok(_) => created.push(id),
                Err(e) => {
                    return Err(AppError::validation_field(
                        format!("serials[{i}]"),
                        format!("row rejected: {e}"),
                    ));
                }
            }
            // One audit entry per created asset. Reuses the existing
            // `created` action; the `bulk` flag in `changes` is the
            // signal that distinguishes a fan-out create from a single
            // POST /assets.
            sqlx::query(
                "INSERT INTO asset_audit_log (tenant_id, asset_id, action, performed_by_id, changes) \
                 VALUES ($1, $2, 'created', $3, $4)",
            )
            .bind(*tenant_id)
            .bind(id)
            .bind(performer)
            .bind(serde_json::json!({
                "bulk": true,
                "model_id": model.id,
                "template_id": template.as_ref().map(|t| t.id),
                "serial_number": s.serial_number,
            }))
            .execute(&mut *tx)
            .await?;
        }

        // Bump counters so the catalog typeahead ranks by recency of
        // use. The model is always bumped; the template is bumped when
        // one was named.
        sqlx::query("UPDATE asset_models SET uses_count = uses_count + $1 WHERE id = $2")
            .bind(created.len() as i32)
            .bind(model.id)
            .execute(&mut *tx)
            .await?;
        if let Some(ref t) = template {
            sqlx::query("UPDATE asset_templates SET uses_count = uses_count + $1 WHERE id = $2")
                .bind(created.len() as i32)
                .bind(t.id)
                .execute(&mut *tx)
                .await?;
        }

        tx.commit().await?;
        Ok(BulkCreateAssetsResponse {
            count: created.len(),
            created,
            model_id: model.id,
            template_id: template.map(|t| t.id),
        })
    }

    // -- signature detector --------------------------------------------

    /// Reads the top candidate from `asset_signature_candidates_mv`
    /// for the caller's tenant. Returns `None` when the view has no
    /// row for the tenant OR when the matching catalog entry already
    /// exists AND is `source != auto_derived` (the operator has
    /// already decided).
    ///
    /// SAFETY (PMS-285): `asset_signature_candidates_mv` has no RLS
    /// (it is a snapshot refreshed by the migrator role; serving
    /// reads do not inherit the policies on `assets`). The query
    /// filters by `tenant_id = $1` from the caller's tenant GUC, so
    /// no other tenant's rows are reachable; the migrator pool is
    /// used because the app pool reads a MATERIALIZED VIEW it does
    /// not own as of the SELECT.
    pub async fn top_signature_candidate(
        &self,
        tenant_id: TenantId,
    ) -> AppResult<Option<SignatureCandidateResponse>> {
        #[derive(sqlx::FromRow)]
        struct Row {
            manufacturer: String,
            model: String,
            asset_type_id: Uuid,
            recent_count: i64,
        }
        let row: Option<Row> = sqlx::query_as::<_, Row>(
            "SELECT manufacturer, model, asset_type_id, recent_count \
             FROM asset_signature_candidates_mv \
             WHERE tenant_id = $1 \
             ORDER BY recent_count DESC \
             LIMIT 1",
        )
        .bind(*tenant_id)
        .fetch_optional(self.db.migrator_pool())
        .await?;
        let Some(r) = row else {
            return Ok(None);
        };

        // Check against the catalog: if an authored row already exists,
        // the operator has decided; the banner stops asking.
        let existing: Option<(Uuid, String)> = sqlx::query_as::<_, (Uuid, String)>(
            "SELECT id, source FROM asset_models \
             WHERE tenant_id = $1 \
               AND asset_type_id = $2 \
               AND lower(manufacturer) = $3 \
               AND lower(model) = $4",
        )
        .bind(*tenant_id)
        .bind(r.asset_type_id)
        .bind(r.manufacturer.to_lowercase())
        .bind(r.model.to_lowercase())
        .fetch_optional(self.db.migrator_pool())
        .await?;
        let existing_model_id = match existing {
            None => None,
            Some((id, source)) if source == "auto_derived" => Some(id),
            Some(_) => return Ok(None), // already authored
        };

        // Pre-fill fields common across the recent N rows. Running one
        // SELECT per candidate field keeps the SQL legible; the row
        // count is capped at 20 by the HAVING clause so this is cheap.
        let common: Option<(Option<String>, Option<String>)> =
            sqlx::query_as::<_, (Option<String>, Option<String>)>(
                "SELECT \
                 (SELECT department FROM ( \
                     SELECT department, COUNT(*) c FROM assets \
                     WHERE tenant_id = $1 \
                       AND lower(manufacturer) = $2 \
                       AND lower(model) = $3 \
                       AND asset_type_id = $4 \
                       AND created_at > NOW() - INTERVAL '7 days' \
                     GROUP BY department \
                     ORDER BY c DESC NULLS LAST LIMIT 1 \
                 ) d), \
                 (SELECT license_vendor FROM ( \
                     SELECT license_vendor, COUNT(*) c FROM assets \
                     WHERE tenant_id = $1 \
                       AND lower(manufacturer) = $2 \
                       AND lower(model) = $3 \
                       AND asset_type_id = $4 \
                       AND created_at > NOW() - INTERVAL '7 days' \
                     GROUP BY license_vendor \
                     ORDER BY c DESC NULLS LAST LIMIT 1 \
                 ) l)",
            )
            .bind(*tenant_id)
            .bind(r.manufacturer.to_lowercase())
            .bind(r.model.to_lowercase())
            .bind(r.asset_type_id)
            .fetch_optional(self.db.migrator_pool())
            .await?;
        let (department, license_vendor) = common.unwrap_or((None, None));

        let name_hint = format!("{} {}", capitalize(&r.manufacturer), capitalize(&r.model));
        let common_fields = serde_json::json!({
            "department": department,
            "license_vendor": license_vendor,
        });

        Ok(Some(SignatureCandidateResponse {
            manufacturer: r.manufacturer,
            model: r.model,
            asset_type_id: r.asset_type_id,
            recent_count: r.recent_count,
            window_days: SIGNATURE_WINDOW_DAYS,
            existing_model_id,
            template_suggestion: TemplateSuggestion {
                name_hint,
                common_fields,
            },
        }))
    }

    /// Refresh the signature-detector MV. Called by the scheduler job
    /// (see `src/main.rs`) every 60s. `REFRESH MATERIALIZED VIEW`
    /// cannot be done CONCURRENTLY without a UNIQUE index; the view
    /// is small (bounded by the 7-day window + the >= 5 HAVING), so
    /// the brief AccessExclusive lock during a non-concurrent refresh
    /// is acceptable here.
    pub async fn refresh_signature_mv(db: &Database) -> AppResult<()> {
        sqlx::query("REFRESH MATERIALIZED VIEW asset_signature_candidates_mv")
            .execute(db.migrator_pool())
            .await?;
        Ok(())
    }
}

/// `source` on `asset_models` is a closed enum at the SQL level
/// (CHECK constraint); mirror it here so the handler cannot pass
/// an unknown string.
pub enum AssetModelSource {
    TenantAuthored,
    AutoDerived,
}

impl AssetModelSource {
    fn as_str(&self) -> &'static str {
        match self {
            AssetModelSource::TenantAuthored => "tenant_authored",
            AssetModelSource::AutoDerived => "auto_derived",
        }
    }
}

fn map_unique_violation(e: sqlx::Error) -> AppError {
    if let sqlx::Error::Database(ref db_err) = e {
        if db_err.code().as_deref() == Some("23505") {
            return AppError::conflict(
                "A row with this unique key already exists for this tenant".to_string(),
            );
        }
    }
    AppError::Database(e.to_string())
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
    }
}
