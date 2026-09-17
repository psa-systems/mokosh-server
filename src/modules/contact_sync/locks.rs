//! PMS-1214 (PSA-70 H): a field a person edits on a synced contact stops
//! following the source.
//!
//! The lock is written by the edit, not by the sync: `ContactService::
//! update_contact` and the portal's own profile edit capture the lockable
//! fields before their write and hand the capture back here after it, in the
//! same transaction. A field that changed gets a `contact_field_locks` row and
//! the sync ([`super::sync`]) never writes it again until someone releases it.
//!
//! Only a contact with a LIVE link is locked. A local contact has nothing to
//! protect a field from, and locking every edit in the CRM would leave a
//! contact that is linked later with fields nobody meant to freeze.
//!
//! Which fields are lockable is [`super::sync::fields::ALL`]: the fields a sync
//! writes. A lock on anything else would protect nothing.

use std::collections::BTreeMap;

use serde_json::json;
use uuid::Uuid;

use super::sync::fields;
use crate::modules::audit::{audit_write, AuditAction, AuditCtx};
use crate::modules::auth::TenantId;
use crate::utils::error::AppResult;

/// The lockable fields of one contact at one moment, as comparable strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditSnapshot {
    values: BTreeMap<&'static str, String>,
}

/// The scalar columns a sync writes, by lock name. `phones` and `tags` are
/// compared as whole collections.
const SCALAR_COLUMNS: &[&str] = &[
    fields::FIRST_NAME,
    fields::LAST_NAME,
    fields::EMAIL,
    fields::TITLE,
    fields::DEPARTMENT,
    fields::COMPANY_NAME,
];

impl EditSnapshot {
    /// Capture the lockable fields, or `None` when the contact has no live
    /// link and so nothing to lock.
    pub async fn capture_if_linked(
        conn: &mut sqlx::PgConnection,
        tenant_id: TenantId,
        contact_id: Uuid,
    ) -> AppResult<Option<Self>> {
        let linked: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM contact_sync_links \
             WHERE tenant_id = $1 AND contact_id = $2 AND unlinked_at IS NULL)",
        )
        .bind(tenant_id)
        .bind(contact_id)
        .fetch_one(&mut *conn)
        .await?;
        if !linked {
            return Ok(None);
        }
        Self::capture(conn, tenant_id, contact_id).await.map(Some)
    }

    async fn capture(
        conn: &mut sqlx::PgConnection,
        tenant_id: TenantId,
        contact_id: Uuid,
    ) -> AppResult<Self> {
        // One row of text, so a NULL and an empty string compare the same way
        // everywhere: a field cleared from "" to NULL is not an edit.
        let row: Option<(serde_json::Value, String, String)> = sqlx::query_as(
            "SELECT jsonb_build_object( \
                 'first_name', COALESCE(c.first_name, ''), 'last_name', COALESCE(c.last_name, ''), \
                 'email', COALESCE(c.email, ''), 'title', COALESCE(c.title, ''), \
                 'department', COALESCE(c.department, ''), 'company_name', COALESCE(c.company_name, '')), \
                 COALESCE((SELECT string_agg(t, ',' ORDER BY t) FROM unnest(c.tags) t), ''), \
                 COALESCE((SELECT string_agg(p.phone_type || ':' || p.number || ':' || COALESCE(p.extension, ''), ',' \
                                             ORDER BY p.phone_type, p.number) \
                           FROM contact_phones p WHERE p.contact_id = c.id), '') \
             FROM contacts c WHERE c.tenant_id = $1 AND c.id = $2",
        )
        .bind(tenant_id)
        .bind(contact_id)
        .fetch_optional(&mut *conn)
        .await?;
        let mut values = BTreeMap::new();
        if let Some((scalars, tags, phones)) = row {
            for column in SCALAR_COLUMNS {
                let value = scalars
                    .get(*column)
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                values.insert(*column, value);
            }
            values.insert(fields::TAGS, tags);
            values.insert(fields::PHONES, phones);
        }
        Ok(Self { values })
    }

    /// The fields that differ from `after`, in lock-name order.
    pub fn changed_fields(&self, after: &Self) -> Vec<&'static str> {
        fields::ALL
            .iter()
            .copied()
            .filter(|f| self.values.get(f) != after.values.get(f))
            .collect()
    }
}

/// Lock every field the edit changed. Call on the edit's own transaction,
/// after its write, with the capture taken before it. Returns the fields newly
/// locked; a field already locked stays as it was, with its original who and
/// when.
pub async fn lock_edited_fields(
    conn: &mut sqlx::PgConnection,
    tenant_id: TenantId,
    contact_id: Uuid,
    before: &EditSnapshot,
    ctx: &AuditCtx,
) -> AppResult<Vec<&'static str>> {
    let after = EditSnapshot::capture(conn, tenant_id, contact_id).await?;
    let mut locked = Vec::new();
    for field in before.changed_fields(&after) {
        let inserted = sqlx::query(
            "INSERT INTO contact_field_locks (tenant_id, contact_id, field, locked_by_user_id) \
             VALUES ($1, $2, $3, $4) ON CONFLICT (contact_id, field) DO NOTHING",
        )
        .bind(tenant_id)
        .bind(contact_id)
        .bind(field)
        .bind(ctx.user_id)
        .execute(&mut *conn)
        .await?
        .rows_affected();
        if inserted > 0 {
            locked.push(field);
        }
    }
    if !locked.is_empty() {
        audit_write(
            &mut *conn,
            tenant_id,
            ctx,
            AuditAction::Create,
            "contact_field_locks",
            Some(contact_id),
            None,
            Some(json!({
                "event": "contact_sync.fields_locked",
                "contact_id": contact_id,
                "fields": locked,
            })),
        )
        .await?;
    }
    Ok(locked)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(pairs: &[(&'static str, &str)]) -> EditSnapshot {
        let mut values: BTreeMap<&'static str, String> =
            fields::ALL.iter().map(|f| (*f, String::new())).collect();
        for (k, v) in pairs {
            values.insert(k, v.to_string());
        }
        EditSnapshot { values }
    }

    #[test]
    fn only_the_fields_that_changed_are_reported() {
        let before = snapshot(&[(fields::TITLE, "Analyst"), (fields::PHONES, "work:+1415")]);
        let after = snapshot(&[(fields::TITLE, "CTO"), (fields::PHONES, "work:+1415")]);
        assert_eq!(before.changed_fields(&after), vec![fields::TITLE]);
        assert!(before.changed_fields(&before).is_empty());
    }

    /// Every lockable field is captured, so none can change unnoticed.
    #[test]
    fn every_lockable_field_is_captured() {
        let captured: Vec<&str> = SCALAR_COLUMNS
            .iter()
            .copied()
            .chain([fields::TAGS, fields::PHONES])
            .collect();
        for field in fields::ALL {
            assert!(
                captured.contains(field),
                "{field} is lockable but never captured"
            );
        }
    }
}
