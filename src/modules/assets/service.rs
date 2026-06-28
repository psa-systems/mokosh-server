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
    // PMS-188: the zero-key `new()` constructor was removed. Every asset
    // secret (credential_vault, configuration_item) must be encrypted under
    // the configured key, so the only constructor takes that key explicitly.
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
            r#"SELECT id, name, icon, parent_type_id, is_active, itil_category
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
        ctx: &AuditCtx,
    ) -> AppResult<AssetTypeResponse> {
        let id = Uuid::new_v4();
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            r#"INSERT INTO asset_types
                   (id, tenant_id, name, icon, parent_type_id, is_active, itil_category)
               VALUES ($1, $2, $3, $4, $5, $6, $7)"#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(&request.name)
        .bind(&request.icon)
        .bind(request.parent_type_id)
        .bind(request.is_active)
        .bind(&request.itil_category)
        .execute(&mut *tx)
        .await?;
        let after: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM asset_types t WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Create,
            "asset_types",
            Some(id),
            None,
            after,
        )
        .await?;
        tx.commit().await?;
        Ok(AssetTypeResponse {
            id,
            name: request.name.clone(),
            icon: request.icon.clone(),
            parent_type_id: request.parent_type_id,
            is_active: request.is_active,
            itil_category: request.itil_category.clone(),
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
                   is_active = $6, itil_category = $7, updated_at = NOW()
               WHERE tenant_id = $1 AND id = $2"#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(&request.name)
        .bind(&request.icon)
        .bind(request.parent_type_id)
        .bind(request.is_active)
        .bind(&request.itil_category)
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
            itil_category: request.itil_category.clone(),
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
        // PMS-336: the assets table is aliased `a` so the SELECT can LEFT
        // JOIN companies for company_name; qualify every condition with
        // `a.` so columns (tenant_id, status, ...) are unambiguous across
        // the join. The COUNT query reuses the same aliased clause.
        let mut conditions = vec!["a.tenant_id = $1".to_string()];
        let mut idx = 2;
        if filter.company_id.is_some() {
            conditions.push(format!("a.company_id = ${idx}"));
            idx += 1;
        }
        if filter.asset_type_id.is_some() {
            conditions.push(format!("a.asset_type_id = ${idx}"));
            idx += 1;
        }
        if filter.status.is_some() {
            conditions.push(format!("a.status = ${idx}"));
            idx += 1;
        }
        // PMS-344 follow-up: free-text name match for the AssetPicker.
        // ILIKE on name, mirroring CompanyFilter / TicketFilter free-text
        // search; without this the picker's `?q=...` was silently
        // dropped, so the dropdown listed every asset regardless of
        // typed text.
        if filter.q.is_some() {
            conditions.push(format!("a.name ILIKE ${idx}"));
            idx += 1;
        }
        let where_clause = conditions.join(" AND ");

        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let count_query = format!("SELECT COUNT(*) FROM assets a WHERE {where_clause}");
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
        let q_pattern = filter.q.as_ref().map(|s| format!("%{s}%"));
        if let Some(p) = &q_pattern {
            cq = cq.bind(p);
        }
        let total: i64 = cq.fetch_one(&mut *tx).await?;

        let query = format!(
            r#"SELECT a.id, a.asset_tag, a.name, a.asset_type_id, a.company_id, co.name AS company_name,
                      a.site_id, a.contact_id, a.status, a.manufacturer, a.model, a.serial_number,
                      a.purchase_date, a.purchase_price, a.warranty_expiry, a.end_of_life,
                      -- PMS-454: CMDB expansion columns. INET cast to text so the
                      -- sqlx FromRow target stays String. Assigned-user name is
                      -- resolved via the same join pattern company_name uses.
                      a.assigned_user_id, NULLIF(TRIM(CONCAT(au.first_name, ' ', au.last_name)), '') AS assigned_user_name,
                      a.ip_address::text AS ip_address, a.hostname, a.mac_address,
                      a.installed_date, a.department, a.in_transit_ticket_id,
                      -- PMS-456: per-CI lifecycle stage. Free-text VARCHAR(50).
                      a.itil_lifecycle_stage,
                      a.license_vendor, a.license_seat_count, a.license_expiry,
                      a.created_at, a.updated_at
               FROM assets a
               LEFT JOIN companies co ON co.id = a.company_id AND co.tenant_id = a.tenant_id
               LEFT JOIN users au ON au.id = a.assigned_user_id AND au.tenant_id = a.tenant_id
               WHERE {where_clause} ORDER BY a.name
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
        if let Some(p) = &q_pattern {
            q = q.bind(p);
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
        ctx: &AuditCtx,
    ) -> AppResult<AssetResponse> {
        let id = Uuid::new_v4();
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        // PMS-454: INSERT now carries the eight CMDB-expansion columns.
        // `ip_address` is text on the wire; Postgres ::inet cast at write
        // time validates the format and rejects garbage. NULL on any
        // omitted field keeps the column at the schema default.
        sqlx::query(
            r#"INSERT INTO assets (id, tenant_id, asset_tag, name, asset_type_id, company_id,
                                    site_id, contact_id, status, manufacturer, model, serial_number,
                                    purchase_date, purchase_price, warranty_expiry, end_of_life,
                                    assigned_user_id, ip_address, hostname, mac_address,
                                    installed_date, department, in_transit_ticket_id,
                                    itil_lifecycle_stage,
                                    license_vendor, license_seat_count, license_expiry)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,
                       $17, NULLIF($18,'')::inet, $19, $20, $21, $22, $23, $24,
                       $25, $26, $27)"#,
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
        .bind(request.assigned_user_id)
        .bind(request.ip_address.as_deref().unwrap_or(""))
        .bind(&request.hostname)
        .bind(&request.mac_address)
        .bind(request.installed_date)
        .bind(&request.department)
        .bind(request.in_transit_ticket_id)
        .bind(&request.itil_lifecycle_stage)
        .bind(&request.license_vendor)
        .bind(request.license_seat_count)
        .bind(request.license_expiry)
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
        let after: Option<serde_json::Value> =
            sqlx::query_scalar("SELECT to_jsonb(t) FROM assets t WHERE tenant_id = $1 AND id = $2")
                .bind(tenant_id)
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?;
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Create,
            "assets",
            Some(id),
            None,
            after,
        )
        .await?;
        tx.commit().await?;
        self.get_asset(tenant_id, id).await
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn get_asset(&self, tenant_id: TenantId, id: Uuid) -> AppResult<AssetResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row = sqlx::query_as::<_, AssetRow>(
            r#"SELECT a.id, a.asset_tag, a.name, a.asset_type_id, a.company_id, co.name AS company_name,
                      a.site_id, a.contact_id, a.status, a.manufacturer, a.model, a.serial_number,
                      a.purchase_date, a.purchase_price, a.warranty_expiry, a.end_of_life,
                      a.assigned_user_id, NULLIF(TRIM(CONCAT(au.first_name, ' ', au.last_name)), '') AS assigned_user_name,
                      a.ip_address::text AS ip_address, a.hostname, a.mac_address,
                      a.installed_date, a.department, a.in_transit_ticket_id,
                      a.itil_lifecycle_stage,
                      a.license_vendor, a.license_seat_count, a.license_expiry,
                      a.created_at, a.updated_at
               FROM assets a
               LEFT JOIN companies co ON co.id = a.company_id AND co.tenant_id = a.tenant_id
               LEFT JOIN users au ON au.id = a.assigned_user_id AND au.tenant_id = a.tenant_id
               WHERE a.tenant_id = $1 AND a.id = $2"#,
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
        // PMS-454: UPDATE covers the eight CMDB-expansion columns. Each
        // `COALESCE($n, ...)` leaves the existing value alone when the
        // SPA omits the field in a partial PUT. The IP arrives as text
        // and is `::inet` cast at write time so a bad value raises a
        // 400 rather than silently corrupting the column.
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
                assigned_user_id = COALESCE($16, assigned_user_id),
                ip_address = COALESCE(NULLIF($17, '')::inet, ip_address),
                hostname = COALESCE($18, hostname),
                mac_address = COALESCE($19, mac_address),
                installed_date = COALESCE($20, installed_date),
                department = COALESCE($21, department),
                in_transit_ticket_id = COALESCE($22, in_transit_ticket_id),
                itil_lifecycle_stage = COALESCE($23, itil_lifecycle_stage),
                license_vendor = COALESCE($24, license_vendor),
                license_seat_count = COALESCE($25, license_seat_count),
                license_expiry = COALESCE($26, license_expiry),
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
        .bind(request.assigned_user_id)
        .bind(request.ip_address.as_deref().unwrap_or(""))
        .bind(&request.hostname)
        .bind(&request.mac_address)
        .bind(request.installed_date)
        .bind(&request.department)
        .bind(request.in_transit_ticket_id)
        .bind(&request.itil_lifecycle_stage)
        .bind(&request.license_vendor)
        .bind(request.license_seat_count)
        .bind(request.license_expiry)
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
    pub async fn delete_asset(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        performer: Uuid,
    ) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        // PMS-188: record the deletion in asset_audit_log before the row is
        // gone, in the same tx as the delete so a rollback drops both and a
        // vault deletion is never untraceable. The asset_id FK column is not
        // declared with ON DELETE, so insert the audit row first.
        sqlx::query(
            r#"INSERT INTO asset_audit_log (tenant_id, asset_id, action, performed_by_id)
               VALUES ($1, $2, 'deleted', $3)"#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(performer)
        .execute(&mut *tx)
        .await?;
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
        ctx: &AuditCtx,
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
        let after: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM asset_relationships t WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Create,
            "asset_relationships",
            Some(id),
            None,
            after,
        )
        .await?;
        tx.commit().await?;
        Ok(AssetRelationshipResponse {
            id,
            parent_asset_id: parent_id,
            child_asset_id: request.child_asset_id,
            relationship_type: request.relationship_type.clone(),
        })
    }

    /// PMS-475: walk `asset_relationships` recursively from
    /// `asset_id` to build the CI impact-graph the SPA's CI Map tab
    /// renders. `direction` selects upstream (callers / dependents),
    /// downstream (dependencies / hosted), or both. `requested_depth`
    /// is clamped against the per-tenant
    /// `ci/impact_max_depth` setting and the server hard ceiling
    /// (10), so the caller cannot ask for a deeper traversal than
    /// the tenant configured. Cycles are bounded by the depth cap;
    /// the CTE visits each (asset_id, edge) pair up to `depth` times,
    /// which is acceptable for the modest CMDB sizes this surface
    /// targets.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id, asset_id = %asset_id))]
    pub async fn compute_impact_graph(
        &self,
        tenant_id: TenantId,
        asset_id: Uuid,
        direction: ImpactDirection,
        requested_depth: u32,
    ) -> AppResult<(u32, Vec<ImpactNodeRow>)> {
        // Confirm the asset exists in this tenant before we walk -
        // a 404 on the root keeps the SPA's "asset not found" copy
        // consistent with the GET /assets/{id} response and avoids
        // returning an empty-but-200 graph when the user typed a
        // wrong id.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let exists: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM assets WHERE tenant_id = $1 AND id = $2")
                .bind(tenant_id)
                .bind(asset_id)
                .fetch_optional(&mut *tx)
                .await?;
        if exists.is_none() {
            return Err(AppError::NotFound("Asset".into()));
        }
        let tenant_cap =
            crate::modules::settings::read_ci_impact_max_depth(&mut tx, tenant_id.get()).await?;
        let depth = requested_depth.clamp(1, 10).min(tenant_cap);

        let mut nodes: Vec<ImpactNodeRow> = Vec::new();
        if matches!(
            direction,
            ImpactDirection::Downstream | ImpactDirection::Both
        ) {
            let rows = sqlx::query_as::<_, ImpactNodeRow>(DOWNSTREAM_CTE)
                .bind(tenant_id)
                .bind(asset_id)
                .bind(depth as i32)
                .fetch_all(&mut *tx)
                .await?;
            nodes.extend(rows.into_iter().map(|n| ImpactNodeRow {
                direction: "downstream".into(),
                ..n
            }));
        }
        if matches!(direction, ImpactDirection::Upstream | ImpactDirection::Both) {
            let rows = sqlx::query_as::<_, ImpactNodeRow>(UPSTREAM_CTE)
                .bind(tenant_id)
                .bind(asset_id)
                .bind(depth as i32)
                .fetch_all(&mut *tx)
                .await?;
            nodes.extend(rows.into_iter().map(|n| ImpactNodeRow {
                direction: "upstream".into(),
                ..n
            }));
        }
        Ok((depth, nodes))
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
        ctx: &AuditCtx,
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
        let after: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) - 'value_encrypted' \
             FROM configuration_items t WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Create,
            "configuration_items",
            Some(id),
            None,
            after,
        )
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
    itil_category: Option<String>,
}

impl From<AssetTypeRow> for AssetTypeResponse {
    fn from(r: AssetTypeRow) -> Self {
        Self {
            id: r.id,
            name: r.name,
            icon: r.icon,
            parent_type_id: r.parent_type_id,
            is_active: r.is_active.unwrap_or(true),
            itil_category: r.itil_category,
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
    // PMS-336: resolved from the LEFT JOIN on companies. NULL only if the
    // company row is missing; populated for every real asset.
    company_name: Option<String>,
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
    // PMS-454: CMDB expansion columns. The IP comes back as String
    // because the SELECT casts INET to text - sqlx's INET type pulls in
    // the `ipnetwork` feature and the SPA reads it as a string anyway.
    assigned_user_id: Option<Uuid>,
    assigned_user_name: Option<String>,
    ip_address: Option<String>,
    hostname: Option<String>,
    mac_address: Option<String>,
    installed_date: Option<chrono::NaiveDate>,
    department: Option<String>,
    in_transit_ticket_id: Option<Uuid>,
    // PMS-456: ITIL CI lifecycle stage.
    itil_lifecycle_stage: Option<String>,
    // PMS-454: licence section (QA-expanded scope).
    license_vendor: Option<String>,
    license_seat_count: Option<i32>,
    license_expiry: Option<chrono::NaiveDate>,
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
            company_name: r.company_name,
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
            assigned_user_id: r.assigned_user_id,
            assigned_user_name: r.assigned_user_name,
            ip_address: r.ip_address,
            hostname: r.hostname,
            mac_address: r.mac_address,
            installed_date: r.installed_date,
            department: r.department,
            in_transit_ticket_id: r.in_transit_ticket_id,
            itil_lifecycle_stage: r.itil_lifecycle_stage,
            license_vendor: r.license_vendor,
            license_seat_count: r.license_seat_count,
            license_expiry: r.license_expiry,
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

/// PMS-475: traversal direction for [`AssetsService::compute_impact_graph`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImpactDirection {
    /// Walk parent_asset_id => child_asset_id (what this asset is
    /// hosted by / depends on / is connected to).
    Downstream,
    /// Walk child_asset_id => parent_asset_id (what depends on this
    /// asset).
    Upstream,
    /// Union of both halves.
    Both,
}

/// One walked edge of the impact graph. Maps 1:1 onto
/// `AssetImpactNode` in the route layer.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ImpactNodeRow {
    pub asset_id: Uuid,
    pub name: String,
    pub parent_asset_id: Uuid,
    pub child_asset_id: Uuid,
    pub relationship_type: String,
    pub depth: i32,
    /// Stamped by the service after the SELECT lands; the CTE itself
    /// does not know whether it ran for the upstream or downstream
    /// half of `Both`. Defaults to empty in the FromRow.
    #[sqlx(default)]
    pub direction: String,
}

/// Downstream traversal: seed with every relationship whose parent is
/// the root, then recurse by joining each step's child as the next
/// step's parent. `depth = 1` for the seed; cap is enforced by the
/// `depth < $3` predicate.
const DOWNSTREAM_CTE: &str = "
    WITH RECURSIVE downstream AS (
        SELECT r.child_asset_id AS asset_id,
               r.parent_asset_id,
               r.child_asset_id,
               r.relationship_type,
               1 AS depth
        FROM asset_relationships r
        WHERE r.tenant_id = $1 AND r.parent_asset_id = $2
        UNION ALL
        SELECT r.child_asset_id,
               r.parent_asset_id,
               r.child_asset_id,
               r.relationship_type,
               d.depth + 1
        FROM asset_relationships r
        JOIN downstream d ON r.parent_asset_id = d.asset_id
        WHERE r.tenant_id = $1 AND d.depth < $3
    )
    SELECT d.asset_id, a.name, d.parent_asset_id, d.child_asset_id,
           d.relationship_type, d.depth
    FROM downstream d
    JOIN assets a ON a.id = d.asset_id AND a.tenant_id = $1
    ORDER BY d.depth ASC, a.name ASC
";

/// Upstream traversal: seed with every relationship whose child is
/// the root, then recurse by joining each step's parent as the next
/// step's child. Mirror image of the downstream CTE.
const UPSTREAM_CTE: &str = "
    WITH RECURSIVE upstream AS (
        SELECT r.parent_asset_id AS asset_id,
               r.parent_asset_id,
               r.child_asset_id,
               r.relationship_type,
               1 AS depth
        FROM asset_relationships r
        WHERE r.tenant_id = $1 AND r.child_asset_id = $2
        UNION ALL
        SELECT r.parent_asset_id,
               r.parent_asset_id,
               r.child_asset_id,
               r.relationship_type,
               u.depth + 1
        FROM asset_relationships r
        JOIN upstream u ON r.child_asset_id = u.asset_id
        WHERE r.tenant_id = $1 AND u.depth < $3
    )
    SELECT u.asset_id, a.name, u.parent_asset_id, u.child_asset_id,
           u.relationship_type, u.depth
    FROM upstream u
    JOIN assets a ON a.id = u.asset_id AND a.tenant_id = $1
    ORDER BY u.depth ASC, a.name ASC
";

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
