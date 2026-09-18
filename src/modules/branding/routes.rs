//! MAPPS-618/622 (mokosh-branding prompt 002): HTTP wiring for the
//! branding asset uploads. Four router builders (staff-tenant,
//! staff-company, contact-company, public) sharing the parameterized
//! [`BrandingAssetStore`], each mounted under the appropriate nested
//! prefix.
//!
//! - Staff tenant: `PUT/DELETE /tenants/current/branding/{asset}` for
//!   the MSP defaults (mount under `/api/v1`). The MAPPS-429
//!   `/tenants/current/logo` route stays live for backwards-compat;
//!   the new `.../branding/logo` route writes the SAME file so both
//!   entry points converge on one location.
//! - Staff company: `PUT/DELETE /companies/{company_id}/{asset}` for
//!   the per-Company overrides.
//! - Contact company: `PUT/DELETE /companies/self/{asset}` for the
//!   contact-plane self-Company writes, gated on
//!   `settings:manage_company_branding`.
//! - Public: `GET /companies/{id}/{asset}` + `GET /tenants/{id}/{asset}`
//!   (the tenant `/logo` variant duplicates the MAPPS-429 route to
//!   land on the same file; favicon/background are new).

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Multipart, Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use axum::{Json, Router};
use serde_json::json;
use std::sync::Arc;
use tokio_stream::StreamExt;
use tokio_util::io::ReaderStream;
use uuid::Uuid;

use crate::db::Database;
use crate::modules::auth::{RequireAuth, TenantScoped};
use crate::modules::branding::assets::{
    asset_path, AssetMeta, AssetScope, BrandAssetKind, BrandingAssetStore,
};
use crate::utils::error::{AppError, AppResult};
use crate::utils::upload_limits::body_limit_bytes;

// ============================================================================
// STAFF - COMPANY SCOPE
// ============================================================================

#[derive(Clone)]
pub struct StaffBrandingState {
    pub db: Database,
    pub store: Arc<BrandingAssetStore>,
}

/// Mount at `/api/v1` (via `.merge(...)`). Two route sets:
/// - Per-Company (`role.is_admin()` gate + cross-tenant scope check).
/// - Per-tenant defaults (`role.is_admin()` gate).
pub fn staff_routes(db: Database) -> Router {
    let store = BrandingAssetStore::from_env();
    // PMS-1233: each route accepts all three `BrandAssetKind`s through the
    // `{asset}` segment, and `store` only picks the per-kind cap once the
    // body is already buffered, so the route's `DefaultBodyLimit` has to
    // cover the largest of the three for its scope.
    let company_max_bytes = store.max_bytes_for_scope(AssetScope::Company(Uuid::nil()));
    let tenant_max_bytes = store.max_bytes_for_scope(AssetScope::Tenant(Uuid::nil()));
    let state = StaffBrandingState {
        // PMS-1234: gives the tenant-logo write path (only) a ledger, the
        // same way `TenantLogoStore::with_ledger` does.
        store: Arc::new(store.with_ledger(db.clone())),
        db,
    };
    Router::new()
        .route(
            "/companies/{company_id}/{asset}",
            put(staff_upload_company_asset)
                .delete(staff_delete_company_asset)
                .layer(DefaultBodyLimit::max(body_limit_bytes(company_max_bytes))),
        )
        .route(
            "/tenants/current/branding/{asset}",
            put(staff_upload_tenant_asset)
                .delete(staff_delete_tenant_asset)
                .layer(DefaultBodyLimit::max(body_limit_bytes(tenant_max_bytes))),
        )
        .with_state(state)
}

async fn staff_upload_company_asset(
    State(state): State<StaffBrandingState>,
    RequireAuth(user): RequireAuth,
    Path((company_id, asset)): Path<(Uuid, String)>,
    multipart: Multipart,
) -> AppResult<Response> {
    if !user.role.is_admin() {
        return Err(AppError::Forbidden(
            "You do not have permission to perform this action.".to_string(),
        ));
    }
    let kind =
        BrandAssetKind::from_segment(&asset).ok_or_else(|| AppError::not_found("asset kind"))?;
    verify_company_in_tenant(&state.db, user.tenant().get(), company_id).await?;
    upload_asset(
        &state.store,
        &state.db,
        AssetScope::Company(company_id),
        kind,
        user.tenant().get(),
        multipart,
    )
    .await
}

async fn staff_delete_company_asset(
    State(state): State<StaffBrandingState>,
    RequireAuth(user): RequireAuth,
    Path((company_id, asset)): Path<(Uuid, String)>,
) -> AppResult<Response> {
    if !user.role.is_admin() {
        return Err(AppError::Forbidden(
            "You do not have permission to perform this action.".to_string(),
        ));
    }
    let kind =
        BrandAssetKind::from_segment(&asset).ok_or_else(|| AppError::not_found("asset kind"))?;
    verify_company_in_tenant(&state.db, user.tenant().get(), company_id).await?;
    delete_asset(
        &state.store,
        &state.db,
        AssetScope::Company(company_id),
        kind,
        user.tenant().get(),
    )
    .await
}

// ============================================================================
// STAFF - TENANT SCOPE (MSP defaults)
// ============================================================================

async fn staff_upload_tenant_asset(
    State(state): State<StaffBrandingState>,
    RequireAuth(user): RequireAuth,
    Path(asset): Path<String>,
    multipart: Multipart,
) -> AppResult<Response> {
    if !user.role.is_admin() {
        return Err(AppError::Forbidden(
            "You do not have permission to perform this action.".to_string(),
        ));
    }
    let kind =
        BrandAssetKind::from_segment(&asset).ok_or_else(|| AppError::not_found("asset kind"))?;
    let tenant_id = user.tenant().get();
    upload_asset(
        &state.store,
        &state.db,
        AssetScope::Tenant(tenant_id),
        kind,
        tenant_id,
        multipart,
    )
    .await
}

async fn staff_delete_tenant_asset(
    State(state): State<StaffBrandingState>,
    RequireAuth(user): RequireAuth,
    Path(asset): Path<String>,
) -> AppResult<Response> {
    if !user.role.is_admin() {
        return Err(AppError::Forbidden(
            "You do not have permission to perform this action.".to_string(),
        ));
    }
    let kind =
        BrandAssetKind::from_segment(&asset).ok_or_else(|| AppError::not_found("asset kind"))?;
    let tenant_id = user.tenant().get();
    delete_asset(
        &state.store,
        &state.db,
        AssetScope::Tenant(tenant_id),
        kind,
        tenant_id,
    )
    .await
}

// ============================================================================
// CONTACT - SELF COMPANY SCOPE
// ============================================================================

#[derive(Clone)]
pub struct ContactBrandingState {
    pub db: Database,
    pub store: Arc<BrandingAssetStore>,
    pub contact_service: Arc<crate::modules::contact_portal::ContactAuthService>,
}

/// Mount at `/api/v1/contact` (via `.merge(...)`). Gates on
/// `settings:manage_company_branding`; server derives the target
/// Company from the session (`/companies/self/...`).
pub fn contact_routes(
    db: Database,
    contact_service: Arc<crate::modules::contact_portal::ContactAuthService>,
) -> Router {
    let store = BrandingAssetStore::from_env();
    // PMS-1233: see the matching comment in `staff_routes`.
    let company_max_bytes = store.max_bytes_for_scope(AssetScope::Company(Uuid::nil()));
    let state = ContactBrandingState {
        store: Arc::new(store.with_ledger(db.clone())),
        db,
        contact_service,
    };
    Router::new()
        .route(
            "/companies/self/{asset}",
            put(contact_upload_asset)
                .delete(contact_delete_asset)
                .layer(DefaultBodyLimit::max(body_limit_bytes(company_max_bytes))),
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
        BrandAssetKind::from_segment(&asset).ok_or_else(|| AppError::not_found("asset kind"))?;
    require_branding_cap(&state.contact_service, &session).await?;
    upload_asset(
        &state.store,
        &state.db,
        AssetScope::Company(session.company_id),
        kind,
        session.tenant_id,
        multipart,
    )
    .await
}

async fn contact_delete_asset(
    State(state): State<ContactBrandingState>,
    crate::modules::contact_portal::RequireContactAuth(session): crate::modules::contact_portal::RequireContactAuth,
    Path(asset): Path<String>,
) -> AppResult<Response> {
    let kind =
        BrandAssetKind::from_segment(&asset).ok_or_else(|| AppError::not_found("asset kind"))?;
    require_branding_cap(&state.contact_service, &session).await?;
    delete_asset(
        &state.store,
        &state.db,
        AssetScope::Company(session.company_id),
        kind,
        session.tenant_id,
    )
    .await
}

// ============================================================================
// PUBLIC
// ============================================================================

#[derive(Clone)]
pub struct PublicBrandingState {
    pub db: Database,
    pub store: Arc<BrandingAssetStore>,
}

/// Mount at `/api/v1/public` (via `.merge(...)`). No auth.
pub fn public_routes(db: Database) -> Router {
    let state = PublicBrandingState {
        db: db.clone(),
        // PMS-1246: the tenant-logo branch of `BrandingAssetStore::stat`
        // reads the `files` ledger for its size, so this reader needs the
        // same ledger the writers do, not the ledger-less store the doc
        // comment on `ledger` describes for "the public read router" from
        // before that method existed.
        store: Arc::new(BrandingAssetStore::from_env().with_ledger(db)),
    };
    Router::new()
        .route("/companies/{company_id}/{asset}", get(serve_company_asset))
        // MAPPS-622: tenant favicon + background public serving. The
        // `/tenants/{id}/logo` route already exists via MAPPS-429; the
        // new route registration here routes it as well, but since
        // both handlers read from the same file location + same
        // branding JSONB keys the two entry points converge on
        // identical content. Axum picks the earlier-registered
        // handler when a request matches both.
        .route("/tenants/{tenant_id}/{asset}", get(serve_tenant_asset))
        .with_state(state)
}

async fn serve_company_asset(
    State(state): State<PublicBrandingState>,
    headers: HeaderMap,
    Path((company_id, asset)): Path<(Uuid, String)>,
) -> AppResult<Response> {
    let kind =
        BrandAssetKind::from_segment(&asset).ok_or_else(|| AppError::not_found("asset kind"))?;
    let mime: Option<String> = sqlx::query_scalar(&format!(
        "SELECT branding->>'{}' FROM companies WHERE id = $1",
        kind.mime_field()
    ))
    .bind(company_id)
    .fetch_optional(state.db.migrator_pool())
    .await?
    .flatten();
    let mime = mime.ok_or_else(|| AppError::NotFound("Asset".to_string()))?;
    let scope = AssetScope::Company(company_id);
    serve_asset(&state.store, scope, kind, &mime, &headers).await
}

async fn serve_tenant_asset(
    State(state): State<PublicBrandingState>,
    headers: HeaderMap,
    Path((tenant_id, asset)): Path<(Uuid, String)>,
) -> AppResult<Response> {
    let kind =
        BrandAssetKind::from_segment(&asset).ok_or_else(|| AppError::not_found("asset kind"))?;
    let mime: Option<String> = sqlx::query_scalar(&format!(
        "SELECT branding->>'{}' FROM tenants WHERE id = $1",
        kind.mime_field()
    ))
    .bind(tenant_id)
    .fetch_optional(state.db.migrator_pool())
    .await?
    .flatten();
    let mime = mime.ok_or_else(|| AppError::NotFound("Asset".to_string()))?;
    let scope = AssetScope::Tenant(tenant_id);
    serve_asset(&state.store, scope, kind, &mime, &headers).await
}

/// PMS-1246: streamed rather than buffered whole into memory, mirroring
/// `knowledge_base::attachments::get_public_attachment`. A matching
/// `If-None-Match` gets a 304 with no blob read at all; see
/// `BrandingAssetStore::stat` for what the ETag is built from and its
/// tradeoff.
async fn serve_asset(
    store: &BrandingAssetStore,
    scope: AssetScope,
    kind: BrandAssetKind,
    mime: &str,
    headers: &HeaderMap,
) -> AppResult<Response> {
    let AssetMeta { size, etag } = store.stat(scope, kind, mime).await?;
    if if_none_match_matches(headers, &etag) {
        return Ok((
            StatusCode::NOT_MODIFIED,
            [
                (header::CACHE_CONTROL, "public, max-age=3600".to_string()),
                (header::ETAG, etag),
            ],
        )
            .into_response());
    }

    let reader = store.open(scope, kind, mime).await?;
    let stream = ReaderStream::new(reader).map(move |chunk| {
        chunk.inspect_err(|e| {
            tracing::error!("branding asset stream read failed: {e}");
        })
    });

    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, mime.to_string()),
            (header::CONTENT_LENGTH, size.to_string()),
            (header::CACHE_CONTROL, "public, max-age=3600".to_string()),
            (header::ETAG, etag),
        ],
        Body::from_stream(stream),
    )
        .into_response())
}

/// RFC 9110 compares `If-None-Match` with the WEAK function, so `W/"x"`
/// matches `"x"`, `*` matches any existing representation, and the value may
/// be a list. Mirrors `tickets::attachments::if_none_match_matches`;
/// duplicated for the same reason the KB module's copy is.
fn if_none_match_matches(headers: &HeaderMap, etag: &str) -> bool {
    let Some(raw) = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    raw.split(',').map(str::trim).any(|candidate| {
        candidate == "*" || candidate.strip_prefix("W/").unwrap_or(candidate) == etag
    })
}

// ============================================================================
// SHARED HELPERS
// ============================================================================

/// Do the upload dance for a scope (tenant or Company): parse the
/// multipart body, store the bytes on disk, JSONB-merge the URL +
/// MIME into the row.
async fn upload_asset(
    store: &BrandingAssetStore,
    db: &Database,
    scope: AssetScope,
    kind: BrandAssetKind,
    tenant_id: Uuid,
    multipart: Multipart,
) -> AppResult<Response> {
    let (mime, bytes) = read_multipart_file(multipart).await?;
    let stored_mime = store.store(scope, kind, &mime, &bytes).await?;
    write_branding_asset(
        db,
        scope,
        tenant_id,
        kind,
        Some(&asset_path(scope, kind)),
        Some(stored_mime),
    )
    .await?;
    Ok(Json(json!({
        "ok": true,
        "asset": segment_for(kind),
        "url": asset_path(scope, kind),
        "mime": stored_mime,
    }))
    .into_response())
}

async fn delete_asset(
    store: &BrandingAssetStore,
    db: &Database,
    scope: AssetScope,
    kind: BrandAssetKind,
    tenant_id: Uuid,
) -> AppResult<Response> {
    // Row cleared first so a client fetch after this call never lands
    // on a URL whose file was just removed.
    write_branding_asset(db, scope, tenant_id, kind, None, None).await?;
    store.remove(scope, kind).await;
    Ok(Json(json!({"ok": true})).into_response())
}

fn segment_for(kind: BrandAssetKind) -> &'static str {
    match kind {
        BrandAssetKind::Logo => "logo",
        BrandAssetKind::Favicon => "favicon",
        BrandAssetKind::Background => "background",
    }
}

/// Pull the first multipart field named `"file"`; error otherwise.
/// Matches the tenant-logo upload's shape.
async fn read_multipart_file(mut multipart: Multipart) -> AppResult<(String, Vec<u8>)> {
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::BadRequest(format!("Could not parse the multipart body: {e}.")))?
    {
        if field.name().unwrap_or_default() != "file" {
            continue;
        }
        let mime = field
            .content_type()
            .map(str::to_string)
            .unwrap_or_else(|| "application/octet-stream".to_string());
        let bytes = field.bytes().await.map_err(|e| {
            AppError::BadRequest(format!("Could not read the multipart body: {e}."))
        })?;
        return Ok((mime, bytes.to_vec()));
    }
    Err(AppError::BadRequest(
        "Missing 'file' part in the multipart body.".into(),
    ))
}

/// JSONB-merge two keys (`{kind}_url`, `{kind}_mime`) into either the
/// Company's or the Tenant's `branding` block. `None` on either value
/// emits an explicit JSON `null` so the merge resolver falls back to
/// the parent default on the next fetch.
async fn write_branding_asset(
    db: &Database,
    scope: AssetScope,
    tenant_id: Uuid,
    kind: BrandAssetKind,
    url: Option<&str>,
    mime: Option<&str>,
) -> AppResult<()> {
    let patch = json!({
        kind.url_field(): url,
        kind.mime_field(): mime,
    });
    let affected = match scope {
        AssetScope::Company(company_id) => sqlx::query(
            "UPDATE companies \
             SET branding = branding || $3::jsonb, updated_at = NOW() \
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(company_id)
        .bind(&patch)
        .execute(db.migrator_pool())
        .await?
        .rows_affected(),
        AssetScope::Tenant(id) => sqlx::query(
            "UPDATE tenants \
             SET branding = branding || $2::jsonb, updated_at = NOW() \
             WHERE id = $1",
        )
        .bind(id)
        .bind(&patch)
        .execute(db.migrator_pool())
        .await?
        .rows_affected(),
    };
    if affected == 0 {
        return Err(AppError::NotFound(match scope {
            AssetScope::Company(_) => "Company".to_string(),
            AssetScope::Tenant(_) => "Tenant".to_string(),
        }));
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

/// PMS-1199: gate on `settings:manage_company_branding` through the one
/// shared `CallerContext::require_capability` check, rather than a fifth
/// hand-rolled load-and-check shape. `RequireContactAuth` does not go
/// through `CallerContext`, so this wraps the session the same way
/// `contact_portal::routes` does for its own `settings:*`-gated routes.
async fn require_branding_cap(
    service: &crate::modules::contact_portal::ContactAuthService,
    session: &crate::modules::contact_portal::models::ContactSession,
) -> AppResult<()> {
    use crate::modules::contact_portal::capabilities::SETTINGS_MANAGE_COMPANY_BRANDING;
    crate::modules::auth::CallerContext::Contact(session.clone())
        .require_capability(SETTINGS_MANAGE_COMPANY_BRANDING, service.db())
        .await
}
