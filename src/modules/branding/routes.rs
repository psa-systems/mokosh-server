//! MAPPS-618 phase B (mokosh-branding prompt 002): HTTP wiring for
//! the Company-scoped branding uploads. Three sibling router
//! builders, one per plane, each returning routes over the shared
//! [`CompanyAssetStore`] that live under the caller's respective
//! nested prefix.
//!
//! - Staff plane: `PUT/DELETE /companies/{company_id}/{asset}` and
//!   `.route("/", ...)` mounts under `/api/v1`.
//! - Contact plane: `PUT/DELETE /companies/self/{asset}` gated on
//!   `settings:manage_company_branding`; nested under
//!   `/api/v1/contact`.
//! - Public plane: `GET /companies/{company_id}/{asset}` (no auth,
//!   same rationale as the tenant logo route).

use axum::body::Body;
use axum::extract::{Multipart, Path, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, put};
use axum::{Json, Router};
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

use crate::db::Database;
use crate::modules::auth::{RequireAuth, TenantScoped};
use crate::modules::branding::assets::{asset_path, CompanyAssetKind, CompanyAssetStore};
use crate::utils::error::{AppError, AppResult};

// ============================================================================
// STAFF PLANE
// ============================================================================

#[derive(Clone)]
pub struct StaffBrandingState {
    pub db: Database,
    pub store: Arc<CompanyAssetStore>,
}

/// Mount at `/api/v1` (via `.merge(...)`). Gates on `role.is_admin()`
/// (same posture as the existing tenant-logo upload).
pub fn staff_routes(db: Database) -> Router {
    let state = StaffBrandingState {
        db,
        store: Arc::new(CompanyAssetStore::from_env()),
    };
    Router::new()
        .route(
            "/companies/{company_id}/{asset}",
            put(staff_upload_asset).delete(staff_delete_asset),
        )
        .with_state(state)
}

async fn staff_upload_asset(
    State(state): State<StaffBrandingState>,
    RequireAuth(user): RequireAuth,
    Path((company_id, asset)): Path<(Uuid, String)>,
    multipart: Multipart,
) -> AppResult<Response> {
    if !user.role.is_admin() {
        return Err(AppError::Forbidden("Access denied".to_string()));
    }
    let kind =
        CompanyAssetKind::from_segment(&asset).ok_or_else(|| AppError::not_found("asset kind"))?;
    // Cross-tenant scope check: the target Company must belong to the
    // caller's tenant. Missing row → 404 (enum-resistant), foreign
    // tenant → 404 as if missing.
    verify_company_in_tenant(&state.db, user.tenant().get(), company_id).await?;
    let (mime, bytes) = read_multipart_file(multipart).await?;
    let stored_mime = state.store.store(kind, company_id, &mime, &bytes).await?;
    write_company_branding_asset(
        &state.db,
        user.tenant().get(),
        company_id,
        kind,
        Some(&asset_path(kind, company_id)),
        Some(stored_mime),
    )
    .await?;
    Ok(Json(json!({
        "ok": true,
        "asset": asset,
        "url": asset_path(kind, company_id),
        "mime": stored_mime,
    }))
    .into_response())
}

async fn staff_delete_asset(
    State(state): State<StaffBrandingState>,
    RequireAuth(user): RequireAuth,
    Path((company_id, asset)): Path<(Uuid, String)>,
) -> AppResult<Response> {
    if !user.role.is_admin() {
        return Err(AppError::Forbidden("Access denied".to_string()));
    }
    let kind =
        CompanyAssetKind::from_segment(&asset).ok_or_else(|| AppError::not_found("asset kind"))?;
    verify_company_in_tenant(&state.db, user.tenant().get(), company_id).await?;
    // Row cleared first so a client fetch after this call never lands
    // on a URL whose file was just removed.
    write_company_branding_asset(&state.db, user.tenant().get(), company_id, kind, None, None)
        .await?;
    state.store.remove(kind, company_id).await;
    Ok(Json(json!({"ok": true})).into_response())
}

// ============================================================================
// CONTACT PLANE
// ============================================================================

#[derive(Clone)]
pub struct ContactBrandingState {
    pub db: Database,
    pub store: Arc<CompanyAssetStore>,
    pub contact_service: Arc<crate::modules::contact_portal::ContactAuthService>,
}

/// Mount at `/api/v1/contact` (via `.merge(...)`). Gates on
/// `settings:manage_company_branding`; server derives the target
/// Company from the session (`/companies/self/...`).
pub fn contact_routes(
    db: Database,
    contact_service: Arc<crate::modules::contact_portal::ContactAuthService>,
) -> Router {
    let state = ContactBrandingState {
        db,
        store: Arc::new(CompanyAssetStore::from_env()),
        contact_service,
    };
    Router::new()
        .route(
            "/companies/self/{asset}",
            put(contact_upload_asset).delete(contact_delete_asset),
        )
        .with_state(state)
}

async fn contact_upload_asset(
    State(state): State<ContactBrandingState>,
    crate::modules::contact_portal::RequireContactAuth(session): crate::modules::contact_portal::RequireContactAuth,
    Path(asset): Path<String>,
    multipart: Multipart,
) -> AppResult<Response> {
    let kind =
        CompanyAssetKind::from_segment(&asset).ok_or_else(|| AppError::not_found("asset kind"))?;
    require_branding_cap(&state.contact_service, session.tenant_id, session.id).await?;
    let (mime, bytes) = read_multipart_file(multipart).await?;
    let stored_mime = state
        .store
        .store(kind, session.company_id, &mime, &bytes)
        .await?;
    write_company_branding_asset(
        &state.db,
        session.tenant_id,
        session.company_id,
        kind,
        Some(&asset_path(kind, session.company_id)),
        Some(stored_mime),
    )
    .await?;
    Ok(Json(json!({
        "ok": true,
        "asset": asset,
        "url": asset_path(kind, session.company_id),
        "mime": stored_mime,
    }))
    .into_response())
}

async fn contact_delete_asset(
    State(state): State<ContactBrandingState>,
    crate::modules::contact_portal::RequireContactAuth(session): crate::modules::contact_portal::RequireContactAuth,
    Path(asset): Path<String>,
) -> AppResult<Response> {
    let kind =
        CompanyAssetKind::from_segment(&asset).ok_or_else(|| AppError::not_found("asset kind"))?;
    require_branding_cap(&state.contact_service, session.tenant_id, session.id).await?;
    write_company_branding_asset(
        &state.db,
        session.tenant_id,
        session.company_id,
        kind,
        None,
        None,
    )
    .await?;
    state.store.remove(kind, session.company_id).await;
    Ok(Json(json!({"ok": true})).into_response())
}

// ============================================================================
// PUBLIC PLANE
// ============================================================================

#[derive(Clone)]
pub struct PublicBrandingState {
    pub db: Database,
    pub store: Arc<CompanyAssetStore>,
}

/// Mount at `/api/v1/public` (via `.merge(...)`). No auth.
pub fn public_routes(db: Database) -> Router {
    let state = PublicBrandingState {
        db,
        store: Arc::new(CompanyAssetStore::from_env()),
    };
    Router::new()
        .route("/companies/{company_id}/{asset}", get(serve_company_asset))
        .with_state(state)
}

async fn serve_company_asset(
    State(state): State<PublicBrandingState>,
    Path((company_id, asset)): Path<(Uuid, String)>,
) -> AppResult<Response> {
    let kind =
        CompanyAssetKind::from_segment(&asset).ok_or_else(|| AppError::not_found("asset kind"))?;
    let mime: Option<String> = sqlx::query_scalar(&format!(
        "SELECT branding->>'{}' FROM companies WHERE id = $1",
        kind.mime_field()
    ))
    .bind(company_id)
    .fetch_optional(state.db.migrator_pool())
    .await?
    .flatten();
    let mime = mime.ok_or_else(|| AppError::NotFound("Asset".to_string()))?;
    let bytes = state.store.read(kind, company_id, &mime).await?;
    let mut resp = Response::new(Body::from(bytes));
    resp.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_str(&mime).unwrap());
    resp.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=3600"),
    );
    *resp.status_mut() = StatusCode::OK;
    Ok(resp)
}

// ============================================================================
// SHARED HELPERS
// ============================================================================

/// Pull the first multipart field named `"file"`; error otherwise.
/// Matches the tenant-logo upload's shape.
async fn read_multipart_file(mut multipart: Multipart) -> AppResult<(String, Vec<u8>)> {
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::BadRequest(format!("multipart parse: {e}")))?
    {
        if field.name().unwrap_or_default() != "file" {
            continue;
        }
        let mime = field
            .content_type()
            .map(str::to_string)
            .unwrap_or_else(|| "application/octet-stream".to_string());
        let bytes = field
            .bytes()
            .await
            .map_err(|e| AppError::BadRequest(format!("multipart read: {e}")))?;
        return Ok((mime, bytes.to_vec()));
    }
    Err(AppError::BadRequest(
        "missing 'file' part in multipart body".into(),
    ))
}

/// JSONB-merge two keys (`{kind}_url`, `{kind}_mime`) into the
/// Company's `branding` block. `None` on either value emits an
/// explicit JSON `null` so the merge resolver falls back to the
/// tenant default on the next fetch.
async fn write_company_branding_asset(
    db: &Database,
    tenant_id: Uuid,
    company_id: Uuid,
    kind: CompanyAssetKind,
    url: Option<&str>,
    mime: Option<&str>,
) -> AppResult<()> {
    let patch = json!({
        kind.url_field(): url,
        kind.mime_field(): mime,
    });
    let affected = sqlx::query(
        "UPDATE companies \
         SET branding = branding || $3::jsonb, updated_at = NOW() \
         WHERE tenant_id = $1 AND id = $2",
    )
    .bind(tenant_id)
    .bind(company_id)
    .bind(&patch)
    .execute(db.migrator_pool())
    .await?
    .rows_affected();
    if affected == 0 {
        return Err(AppError::NotFound("Company".to_string()));
    }
    Ok(())
}

/// Confirm the target Company exists under the caller's tenant.
/// Missing row → 404 (enum-resistant); foreign tenant → 404, same
/// shape.
async fn verify_company_in_tenant(
    db: &Database,
    tenant_id: Uuid,
    company_id: Uuid,
) -> AppResult<()> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM companies WHERE tenant_id = $1 AND id = $2)",
    )
    .bind(tenant_id)
    .bind(company_id)
    .fetch_one(db.migrator_pool())
    .await?;
    if !exists {
        return Err(AppError::NotFound("Company".to_string()));
    }
    Ok(())
}

/// Refresh the caller's live capability set from the DB (matches the
/// pattern in `update_me` from contact_portal/routes.rs) and fail
/// with 403 when `settings:manage_company_branding` is missing.
async fn require_branding_cap(
    service: &crate::modules::contact_portal::ContactAuthService,
    tenant_id: Uuid,
    contact_id: Uuid,
) -> AppResult<()> {
    use crate::modules::contact_portal::capabilities::SETTINGS_MANAGE_COMPANY_BRANDING;
    let caps = service.load_capabilities(tenant_id, contact_id).await?;
    if !caps.iter().any(|c| c == SETTINGS_MANAGE_COMPANY_BRANDING) {
        return Err(AppError::Forbidden(format!(
            "Missing required capability: {SETTINGS_MANAGE_COMPANY_BRANDING}"
        )));
    }
    Ok(())
}
