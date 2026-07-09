//! Tenant data export (PMS-647, first slice of PMS-646).
//!
//! Admin-only, UI-downloadable snapshot of a tenant's business data as one
//! versioned JSON document. The dump is schema-driven, not per-table code: it
//! reads every table that carries a `tenant_id` from the catalog, minus an
//! explicit [`EXCLUDE_TABLES`] set (secrets, auth identity/tokens, audit logs),
//! and drops any secret-looking column ([`SECRET_COLUMN_SUBSTRINGS`]) from every
//! row as defense-in-depth. New business tables are picked up automatically as
//! migrations add them; a new secrets-only table must be added to the exclude
//! set. The sibling import issue consumes this envelope.

use axum::{extract::State, response::Response, routing::get, Router};
use serde_json::{json, Map, Value};

use crate::db::Database;
use crate::modules::audit::{audit_write, AuditAction, AuditCtx};
use crate::modules::auth::{RequireAdmin, RequireAuth, TenantScoped};
use crate::utils::error::{AppError, AppResult};

const SCHEMA_VERSION: i32 = 1;

/// Tables excluded from the export entirely. Their rows never leave the
/// deployment: `*_configs`/`credential_vault`/`api_keys`/`rmm_connections` hold
/// encrypted integration secrets; the auth identity/session/one-shot-token
/// tables are Bunyip/OIDC-owned or transient; the audit/log tables are the
/// system's own records, not portable tenant data.
const EXCLUDE_TABLES: &[&str] = &[
    // integration secrets
    "payment_gateway_configs",
    "credential_vault",
    "api_keys",
    "rmm_connections",
    // auth identity + sessions + one-shot tokens
    "users",
    "user_sessions",
    "password_reset_tokens",
    "portal_setup_tokens",
    "tenant_intake_tokens",
    "tenant_invitations",
    // audit / logs
    "audit_log",
    "asset_audit_log",
    "email_intake_log",
];

/// Substrings that mark a secret COLUMN; any column whose name contains one is
/// dropped from every exported row. Catches secrets that live inside otherwise
/// business tables, e.g. `contacts.portal_password_hash` and
/// `email_mailboxes.smtp_password_encrypted`.
const SECRET_COLUMN_SUBSTRINGS: &[&str] = &[
    "encrypted",
    "password_hash",
    "_secret",
    "mfa_secret",
    "api_key",
    "api_secret",
    "private_key",
];

#[derive(Clone)]
pub struct DataTransferState {
    pub db: Database,
}

pub fn data_transfer_routes(db: Database) -> Router {
    Router::new()
        .route("/data/export", get(export_tenant_data))
        .with_state(DataTransferState { db })
}

fn is_secret_column(name: &str) -> bool {
    SECRET_COLUMN_SUBSTRINGS.iter().any(|s| name.contains(s))
}

/// Drop secret keys from a single `row_to_json` object; pass non-objects through.
fn redact_row(mut row: Value) -> Value {
    if let Value::Object(map) = &mut row {
        map.retain(|k, _| !is_secret_column(k));
    }
    row
}

/// A catalog table name is a trusted identifier, but it is interpolated into
/// SQL below, so accept only plain lowercase identifiers as defense-in-depth.
fn is_safe_identifier(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// `GET /api/v1/data/export` - admin-only tenant data snapshot download.
async fn export_tenant_data(
    State(s): State<DataTransferState>,
    RequireAuth(u): RequireAuth,
    _admin: RequireAdmin,
    ctx: AuditCtx,
) -> AppResult<Response> {
    let tenant = u.tenant();
    let mut tx = s.db.begin_with_tenant(tenant).await?;

    // Every table carrying a tenant_id, minus the excludes. Ordered for a
    // deterministic file. Reading the catalog is unaffected by RLS.
    let table_names: Vec<String> = sqlx::query_scalar(
        "SELECT table_name::text FROM information_schema.columns
         WHERE table_schema = 'public' AND column_name = 'tenant_id'
         ORDER BY table_name",
    )
    .fetch_all(&mut *tx)
    .await?;

    let mut entities = Map::new();
    let mut included: Vec<String> = Vec::new();
    for table in table_names {
        if EXCLUDE_TABLES.contains(&table.as_str()) || !is_safe_identifier(&table) {
            continue;
        }
        // `row_to_json` under the tenant transaction (RLS) + explicit
        // `WHERE tenant_id` keeps the dump scoped to this tenant on both belts.
        let sql = format!("SELECT row_to_json(t) FROM {table} t WHERE tenant_id = $1");
        let rows: Vec<Value> = sqlx::query_scalar(&sql)
            .bind(tenant)
            .fetch_all(&mut *tx)
            .await?;
        let redacted: Vec<Value> = rows.into_iter().map(redact_row).collect();
        entities.insert(table.clone(), Value::Array(redacted));
        included.push(table);
    }

    audit_write(
        &mut *tx,
        tenant,
        &ctx,
        AuditAction::Export,
        "tenant_data",
        Some(tenant.get()),
        None,
        None,
    )
    .await?;
    tx.commit().await?;

    let envelope = json!({
        "schema_version": SCHEMA_VERSION,
        "tenant_id": tenant.get(),
        "included_tables": included,
        "excluded_tables": EXCLUDE_TABLES,
        "redacted_column_patterns": SECRET_COLUMN_SUBSTRINGS,
        "notes": "Attachment/file blob payloads are metadata-only; binary bytes are not included (PMS-646).",
        "entities": entities,
    });
    let body = serde_json::to_vec_pretty(&envelope)
        .map_err(|e| AppError::Internal(format!("failed to serialise export: {e}")))?;

    let filename = format!("mokosh-export-{}.json", tenant.get());
    Response::builder()
        .header(
            axum::http::header::CONTENT_TYPE,
            "application/json; charset=utf-8",
        )
        .header(
            axum::http::header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{filename}\""),
        )
        .body(axum::body::Body::from(body))
        .map_err(|e| AppError::Internal(format!("failed to build export response: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_row_drops_secret_columns_keeps_the_rest() {
        let row = json!({
            "id": "abc",
            "name": "Acme",
            "portal_password_hash": "$argon2...",
            "smtp_password_encrypted": "base64...",
            "api_key_encrypted": "base64...",
            "mfa_secret": "JBSWY3DP",
            "email": "a@b.c",
        });
        let out = redact_row(row);
        let obj = out.as_object().unwrap();
        // kept
        assert!(obj.contains_key("id"));
        assert!(obj.contains_key("name"));
        assert!(obj.contains_key("email"));
        // dropped
        for secret in [
            "portal_password_hash",
            "smtp_password_encrypted",
            "api_key_encrypted",
            "mfa_secret",
        ] {
            assert!(!obj.contains_key(secret), "{secret} must be redacted");
        }
    }

    #[test]
    fn every_known_secret_column_is_caught() {
        for col in [
            "config_encrypted",
            "username_encrypted",
            "password_encrypted",
            "notes_encrypted",
            "value_encrypted",
            "imap_password_encrypted",
            "smtp_password_encrypted",
            "api_key_encrypted",
            "api_secret_encrypted",
            "password_hash",
            "portal_password_hash",
            "mfa_secret",
        ] {
            assert!(is_secret_column(col), "{col} should be treated as secret");
        }
        // benign columns pass through
        for col in ["id", "name", "email", "created_at", "tenant_id", "status"] {
            assert!(!is_secret_column(col), "{col} should NOT be secret");
        }
    }

    #[test]
    fn safe_identifier_rejects_non_identifiers() {
        assert!(is_safe_identifier("companies"));
        assert!(is_safe_identifier("ticket_notes"));
        assert!(!is_safe_identifier("companies; drop table x"));
        assert!(!is_safe_identifier("Companies"));
        assert!(!is_safe_identifier(""));
    }
}
