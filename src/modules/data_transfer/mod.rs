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

use std::collections::HashMap;

use axum::{
    extract::{DefaultBodyLimit, State},
    response::Response,
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use uuid::Uuid;

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
        .route(
            "/data/import",
            post(import_tenant_data).layer(DefaultBodyLimit::max(IMPORT_MAX_BYTES)),
        )
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

    // The tenant name is echoed into the envelope so a downstream orchestrator
    // (e.g. Bunyip account restore) can supply it as the import `confirm` guard
    // without a second round-trip. Read under the same tenant transaction.
    let tenant_name: String = sqlx::query_scalar("SELECT name FROM tenants WHERE id = $1")
        .bind(tenant)
        .fetch_one(&mut *tx)
        .await?;

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
        "tenant_name": tenant_name,
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

/// 25 MB cap on the uploaded import envelope. Sync import for now; a larger
/// tenant is a background-job follow-up (PMS-646). Enforced as an axum body
/// limit, so an over-size upload gets a 413 before the handler runs.
const IMPORT_MAX_BYTES: usize = 25 * 1024 * 1024;

/// `POST /api/v1/data/import` request: the export envelope plus a destructive-
/// action confirmation that must equal the target tenant's name.
#[derive(Deserialize)]
struct ImportRequest {
    confirm: String,
    export: ImportEnvelope,
}

/// The subset of the export envelope import needs: the schema version and the
/// per-table row arrays. Other envelope fields (excluded_tables, notes, ...)
/// are informational and ignored on import.
#[derive(Deserialize)]
struct ImportEnvelope {
    schema_version: i32,
    entities: Map<String, Value>,
}

/// Assign a fresh id for every row across all entity tables, keyed by its old
/// id, so primary keys and FK references can be remapped consistently. Rows
/// without a parseable string `id` are skipped (nothing can reference them by
/// id). Pure - unit-tested without a database.
fn build_id_map(entities: &Map<String, Value>) -> HashMap<Uuid, Uuid> {
    let mut map = HashMap::new();
    for rows in entities.values() {
        let Some(arr) = rows.as_array() else { continue };
        for row in arr {
            if let Some(old) = row
                .get("id")
                .and_then(Value::as_str)
                .and_then(|s| Uuid::parse_str(s).ok())
            {
                map.entry(old).or_insert_with(Uuid::new_v4);
            }
        }
    }
    map
}

/// Rewrite one row for load into `target_tenant`: force `tenant_id`, and replace
/// any UUID-valued field whose value is a known old id with its new id (remaps
/// the primary key AND any FK reference into the imported set in one pass).
/// Values not in the map are left unchanged here; dangling-FK / user-reference
/// resolution needs catalog metadata and is applied during the load
/// (PMS-648 commit 2). Pure - unit-tested without a database.
fn remap_row(mut row: Value, id_map: &HashMap<Uuid, Uuid>, target_tenant: Uuid) -> Value {
    if let Value::Object(obj) = &mut row {
        for (key, val) in obj.iter_mut() {
            if key == "tenant_id" {
                *val = Value::String(target_tenant.to_string());
                continue;
            }
            if let Some(new) = val
                .as_str()
                .and_then(|s| Uuid::parse_str(s).ok())
                .and_then(|u| id_map.get(&u))
            {
                *val = Value::String(new.to_string());
            }
        }
    }
    row
}

/// `POST /api/v1/data/import` - admin-only, wipe-and-replace. Validates the
/// envelope + tenant-name confirmation, then in ONE transaction (FK checks
/// deferred to commit, migration 088) wipes the tenant's data and reloads the
/// file with remapped ids in ANY order. A failure anywhere rolls the whole
/// thing back - the tenant is either fully replaced or untouched. Emits the
/// `import` audit action.
async fn import_tenant_data(
    State(s): State<DataTransferState>,
    RequireAuth(u): RequireAuth,
    _admin: RequireAdmin,
    ctx: AuditCtx,
    Json(req): Json<ImportRequest>,
) -> AppResult<Json<Value>> {
    if req.export.schema_version != SCHEMA_VERSION {
        return Err(AppError::BadRequest(format!(
            "unsupported schema_version {} (expected {SCHEMA_VERSION})",
            req.export.schema_version
        )));
    }
    for table in req.export.entities.keys() {
        if !is_safe_identifier(table) || EXCLUDE_TABLES.contains(&table.as_str()) {
            return Err(AppError::BadRequest(format!(
                "envelope contains an unexpected table: {table}"
            )));
        }
    }

    let tenant = u.tenant();
    let id_map = build_id_map(&req.export.entities);
    let mut tx = s.db.begin_with_tenant(tenant).await?;

    // Defer every (deferrable, migration 088) FK check to COMMIT so the wipe +
    // load run in ANY order - the schema has FK cycles, self-referential FKs, and
    // excluded tables that reference load tables, none orderable per statement.
    sqlx::query("SET CONSTRAINTS ALL DEFERRED")
        .execute(&mut *tx)
        .await?;

    // Destructive-action guard: the confirmation must equal the tenant name.
    let tenant_name: String = sqlx::query_scalar("SELECT name FROM tenants WHERE id = $1")
        .bind(tenant)
        .fetch_one(&mut *tx)
        .await?;
    if req.confirm.trim() != tenant_name.trim() {
        return Err(AppError::BadRequest(
            "confirmation does not match the tenant name".to_string(),
        ));
    }

    // Every tenant-scoped table. A file table not among them is schema drift.
    let tenant_tables: Vec<String> = sqlx::query_scalar::<_, String>(
        "SELECT table_name::text FROM information_schema.columns
         WHERE table_schema = 'public' AND column_name = 'tenant_id'",
    )
    .fetch_all(&mut *tx)
    .await?;
    let tenant_table_set: std::collections::HashSet<&str> =
        tenant_tables.iter().map(String::as_str).collect();
    for table in req.export.entities.keys() {
        if !tenant_table_set.contains(table.as_str()) {
            return Err(AppError::BadRequest(format!(
                "envelope table {table} is not a current tenant table (schema drift)"
            )));
        }
    }

    // Read tenants -> load-table references (e.g. tenants.own_company_id ->
    // companies) so they can be remapped to the new ids after the load. `tenants`
    // is not tenant-scoped, so it is neither wiped nor reloaded; its reference to
    // a wiped+reloaded row would otherwise dangle. No NULL needed: the deferred
    // check tolerates the stale value until it is remapped below.
    let tenant_fk_cols: Vec<(String, String)> = sqlx::query_as(
        "SELECT att.attname::text, ref.relname::text
         FROM pg_constraint c
         JOIN pg_class t ON t.oid = c.conrelid AND t.relname = 'tenants'
         JOIN pg_class ref ON ref.oid = c.confrelid
         JOIN pg_attribute att ON att.attrelid = c.conrelid AND att.attnum = ANY(c.conkey)
         WHERE c.contype = 'f' AND t.relnamespace = 'public'::regnamespace",
    )
    .fetch_all(&mut *tx)
    .await?;
    let mut tenant_fk_restore: Vec<(String, Uuid)> = Vec::new();
    for (col, ref_table) in &tenant_fk_cols {
        // Only remap references into a table the import actually reloads.
        if !is_safe_identifier(col) || !req.export.entities.contains_key(ref_table) {
            continue;
        }
        let old: Option<Uuid> =
            sqlx::query_scalar(&format!("SELECT {col} FROM tenants WHERE id = $1"))
                .bind(tenant)
                .fetch_one(&mut *tx)
                .await?;
        if let Some(old) = old {
            tenant_fk_restore.push((col.clone(), old));
        }
    }

    // Wipe every tenant-scoped table EXCEPT the identity tables (users,
    // user_sessions - Bunyip/OIDC-owned, referenced BY business rows rather than
    // referencing them). This clears the load tables AND the excluded
    // secret/audit/token tables that FK-reference load rows (credential_vault,
    // rmm_connections, portal_setup_tokens, ...), so nothing non-reloaded dangles
    // at commit. Order is irrelevant - constraints are deferred.
    for table in &tenant_tables {
        if table == "users" || table == "user_sessions" || !is_safe_identifier(table) {
            continue;
        }
        sqlx::query(&format!("DELETE FROM {table} WHERE tenant_id = $1"))
            .bind(tenant)
            .execute(&mut *tx)
            .await?;
    }

    // Load every table from the envelope (any order). jsonb_populate_recordset
    // coerces each remapped row to the table's rowtype; redacted-away columns
    // become NULL/default. Every FK check fires at commit.
    let mut summary = Map::new();
    for (table, rows) in &req.export.entities {
        let Some(rows) = rows.as_array() else {
            continue;
        };
        let remapped: Vec<Value> = rows
            .iter()
            .map(|r| remap_row(r.clone(), &id_map, tenant.get()))
            .collect();
        let count = remapped.len();
        if count > 0 {
            sqlx::query(&format!(
                "INSERT INTO {table} SELECT * FROM jsonb_populate_recordset(NULL::{table}, $1)"
            ))
            .bind(Value::Array(remapped))
            .execute(&mut *tx)
            .await?;
        }
        summary.insert(table.clone(), Value::from(count as u64));
    }

    // Remap tenants -> load-table references to the new ids.
    for (col, old) in &tenant_fk_restore {
        if let Some(new) = id_map.get(old) {
            sqlx::query(&format!("UPDATE tenants SET {col} = $1 WHERE id = $2"))
                .bind(new)
                .bind(tenant)
                .execute(&mut *tx)
                .await?;
        }
    }

    audit_write(
        &mut *tx,
        tenant,
        &ctx,
        AuditAction::Import,
        "tenant_data",
        Some(tenant.get()),
        None,
        None,
    )
    .await?;
    tx.commit().await?;

    Ok(Json(json!({
        "status": "imported",
        "tenant_id": tenant.get(),
        "imported": summary,
    })))
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

    #[test]
    fn build_id_map_assigns_one_fresh_id_per_row_with_an_id() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let entities = json!({
            "companies": [{ "id": a, "name": "Acme" }],
            "contacts": [{ "id": b, "company_id": a }],
            "no_id_rows": [{ "foo": "bar" }],
        });
        let map = build_id_map(entities.as_object().unwrap());
        assert_eq!(map.len(), 2, "one entry per row that carries an id");
        assert_ne!(map[&a], a, "id must be remapped to a fresh value");
        assert_ne!(map[&a], map[&b]);
    }

    #[test]
    fn remap_row_rewrites_pk_fk_and_tenant_but_not_unrelated_uuids() {
        let old_company = Uuid::new_v4();
        let old_contact = Uuid::new_v4();
        let target_tenant = Uuid::new_v4();
        let unrelated = Uuid::new_v4(); // a uuid NOT in the map
        let new_company = Uuid::new_v4();
        let new_contact = Uuid::new_v4();
        let mut map = HashMap::new();
        map.insert(old_company, new_company);
        map.insert(old_contact, new_contact);

        let row = json!({
            "id": old_contact,          // pk -> remapped
            "company_id": old_company,  // FK into the imported set -> remapped
            "tenant_id": Uuid::new_v4(), // -> forced to target
            "external_ref": unrelated,  // not in map -> unchanged
            "name": "Jane",             // non-uuid -> unchanged
        });
        let out = remap_row(row, &map, target_tenant);
        let o = out.as_object().unwrap();
        assert_eq!(o["id"], json!(new_contact.to_string()));
        assert_eq!(o["company_id"], json!(new_company.to_string()));
        assert_eq!(o["tenant_id"], json!(target_tenant.to_string()));
        assert_eq!(o["external_ref"], json!(unrelated.to_string()));
        assert_eq!(o["name"], json!("Jane"));
    }
}
