//! PMS-1213 (PSA-70 phase 3): one sync of one connection.
//!
//! Reads the source through [`ContactSyncProvider`] and decides, per record,
//! whether it updates a linked contact, links to one, asks a human, or becomes
//! a new contact. Scheduling, run rows and progress are PMS-1215; this is the
//! part that has to be right about the data.
//!
//! # What a sync may change on a Mokosh contact
//!
//! Mokosh is the CRM of record and the source is an address book somebody
//! also uses for their personal life, so the rules lean towards keeping what
//! Mokosh holds:
//!
//! * A field locked in `contact_field_locks` is never written (PSA-70 H).
//! * On the FIRST link to an existing contact, a field is only filled when it
//!   is empty. The contact existed before the import and whatever it holds was
//!   put there on purpose.
//! * On a later sync of a contact the import owns, the source's value wins for
//!   names, title, department and a freeform company name - but a value the
//!   source no longer has is never cleared. An import adds and corrects; it
//!   does not erase, for the same reason a deletion in the source is only
//!   flagged (PSA-70 I).
//! * `email` is only ever filled, never replaced: it is how the contact is
//!   matched and how a portal contact signs in, and a changed address in
//!   somebody's phone must not change who can sign in to the portal.
//! * Phones are only ever added, compared by [`normalize::phone_key`].
//! * A company is never linked. A record whose organisation matches exactly
//!   one existing company carries a SUGGESTION on its link row for a human to
//!   confirm (PSA-70 G).
//! * The names of the selected labels a record carries are added to the
//!   contact's `tags`, so "imported because it is labelled Client" is visible
//!   and filterable in the CRM. An unselected label never becomes a tag: the
//!   selection is what the admin agreed to bring in.
//!
//! # Idempotency (PSA-70 I)
//!
//! A record whose etag matches its link is not read further. Every write is
//! computed as a difference, so an unchanged record writes nothing - no
//! `updated_at`, no audit row. A queued question is keyed on its pair and
//! found again rather than asked twice, and a pair a human already answered is
//! never asked again. `tests/contact_sync_engine.rs` runs the same sync twice
//! and compares.
//!
//! # Failure
//!
//! Each record is its own transaction, so one bad record does not undo the
//! rest. The sync token is only advanced when EVERY record landed: a token
//! moved past a record that failed would drop that change until the record
//! next changes in the source, while replaying a delta is harmless because
//! the whole pass is idempotent.

use std::collections::{BTreeSet, HashMap, HashSet};

use chrono::{DateTime, Utc};
use mokosh_types::contacts::{
    ContactPhoneInput, ContactType, CreateContactRequest, PhoneType, PreferredContactMethod,
};
use serde_json::json;
use uuid::Uuid;

use super::mapping::{map_contact, MappedContact};
use super::matching::{decide, IncomingKeys, LocalContact, MatchDecision};
use super::normalize::{name_key, phone_key};
use super::provider::{ContactSyncProvider, SourceContact, SourceError};
use crate::db::Database;
use crate::modules::audit::{audit_write, AuditAction, AuditCtx};
use crate::modules::auth::TenantId;
use crate::modules::contacts::ContactService;
use crate::utils::error::{AppError, AppResult};

/// The Mokosh field names a lock can name, as `contact_field_locks.field`
/// stores them. The contact update path that writes locks is PMS-1214.
pub mod fields {
    pub const FIRST_NAME: &str = "first_name";
    pub const LAST_NAME: &str = "last_name";
    pub const EMAIL: &str = "email";
    pub const TITLE: &str = "title";
    pub const DEPARTMENT: &str = "department";
    pub const COMPANY_NAME: &str = "company_name";
    pub const PHONES: &str = "phones";
    pub const TAGS: &str = "tags";

    pub const ALL: &[&str] = &[
        FIRST_NAME,
        LAST_NAME,
        EMAIL,
        TITLE,
        DEPARTMENT,
        COMPANY_NAME,
        PHONES,
        TAGS,
    ];
}

/// What one sync did. Counts of records, not of writes.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct SyncReport {
    /// This pass read the whole address book rather than a delta.
    pub full_read: bool,
    pub created: u32,
    pub linked: u32,
    pub updated: u32,
    pub unchanged: u32,
    /// Records with at least one newly opened review question.
    pub queued: u32,
    /// Records whose questions were already open from an earlier sync.
    pub awaiting_review: u32,
    /// Records a human already answered every question about.
    pub already_reviewed: u32,
    /// Records carrying none of the selected labels.
    pub not_selected: u32,
    /// Links newly flagged as deleted in the source.
    pub deleted_in_source: u32,
    pub failed: u32,
}

impl SyncReport {
    /// Whether the pass wrote anything at all. The idempotency test's
    /// question.
    pub fn changed_anything(&self) -> bool {
        self.created + self.linked + self.updated + self.queued + self.deleted_in_source > 0
    }
}

#[derive(sqlx::FromRow)]
struct ConnectionRow {
    provider: String,
    account_email: String,
    is_active: bool,
    sync_token: Option<String>,
    selected_groups: serde_json::Value,
    disconnected_at: Option<DateTime<Utc>>,
}

#[derive(sqlx::FromRow)]
struct LocalRow {
    id: Uuid,
    email: Option<String>,
    first_name: String,
    last_name: String,
    company_name: Option<String>,
    phones: Vec<String>,
    company_names: Vec<String>,
    linked: bool,
}

#[derive(sqlx::FromRow, Clone)]
struct LinkRow {
    id: Uuid,
    external_id: String,
    contact_id: Uuid,
    etag: Option<String>,
    deleted_in_source_at: Option<DateTime<Utc>>,
}

#[derive(sqlx::FromRow)]
struct ContactRow {
    first_name: String,
    last_name: String,
    email: Option<String>,
    title: Option<String>,
    department: Option<String>,
    company_id: Option<Uuid>,
    company_name: Option<String>,
    tags: Option<Vec<String>>,
}

#[derive(sqlx::FromRow)]
struct PhoneRow {
    phone_type: String,
    number: String,
    extension: Option<String>,
    is_primary: bool,
}

/// Everything read once per pass, so matching N records is not N scans.
struct Snapshot {
    locals: Vec<LocalContact>,
    links: HashMap<String, LinkRow>,
    /// `(external_id, contact_id)` pairs a human already resolved.
    answered: HashSet<(String, Uuid)>,
    /// Company name key to the ids carrying it.
    companies: HashMap<String, Vec<Uuid>>,
}

#[derive(Clone)]
pub struct ContactSyncEngine {
    db: Database,
    contacts: ContactService,
}

/// Whether a first link or a later sync is being applied.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Pass {
    FirstLink,
    Owned,
}

enum Outcome {
    Created { contact_id: Uuid, link: LinkRow },
    Linked { contact_id: Uuid, link: LinkRow },
    Updated,
    Unchanged,
    Queued,
    AwaitingReview,
    AlreadyReviewed,
    NotSelected,
    DeletedInSource,
}

impl ContactSyncEngine {
    pub fn new(db: Database) -> Self {
        Self {
            contacts: ContactService::new(db.clone()),
            db,
        }
    }

    /// Run one sync of `connection_id` against `source`, recording the
    /// outcome on the connection.
    pub async fn run(
        &self,
        tenant_id: TenantId,
        connection_id: Uuid,
        source: &dyn ContactSyncProvider,
    ) -> AppResult<SyncReport> {
        let connection = self.load_connection(tenant_id, connection_id).await?;
        if connection.provider != source.id() {
            return Err(AppError::Internal(format!(
                "a {} provider was handed a {} connection",
                source.id(),
                connection.provider
            )));
        }
        if connection.disconnected_at.is_some() || !connection.is_active {
            return Err(AppError::Conflict(
                "This contact sync connection is not active.".to_string(),
            ));
        }
        let selected: BTreeSet<String> =
            serde_json::from_value::<Vec<String>>(connection.selected_groups.clone())
                .unwrap_or_default()
                .into_iter()
                .collect();
        // An empty selection is "not chosen yet", never "everything" (PSA-70 E).
        if selected.is_empty() {
            return Err(AppError::Conflict(
                "Choose at least one Google label to import before syncing.".to_string(),
            ));
        }

        self.set_status(tenant_id, connection_id, "in_progress", None)
            .await?;

        let read = async {
            let labels = source.list_groups().await?;
            let changes = source
                .changes_since(connection.sync_token.as_deref())
                .await?;
            Ok::<_, SourceError>((labels, changes))
        }
        .await;
        let (labels, changes) = match read {
            Ok(read) => read,
            Err(error) => {
                let status = match error {
                    SourceError::Throttled => "throttled",
                    SourceError::Unauthorized => "reconnect_required",
                    SourceError::Failed(_) => "failed",
                };
                self.set_status(tenant_id, connection_id, status, Some(error.to_string()))
                    .await?;
                return Err(error.into());
            }
        };
        let label_names: HashMap<String, String> =
            labels.into_iter().map(|l| (l.id, l.name)).collect();

        let mut report = SyncReport {
            full_read: connection.sync_token.is_none() || changes.was_full_resync,
            ..SyncReport::default()
        };
        let mut snapshot = self.snapshot(tenant_id, connection_id).await?;
        let ctx = AuditCtx::system(tenant_id.get());
        let mut seen: HashSet<&str> = HashSet::new();

        for record in &changes.contacts {
            seen.insert(record.external_id.as_str());
            let outcome = self
                .apply_record(
                    tenant_id,
                    connection_id,
                    &connection,
                    record,
                    &selected,
                    &label_names,
                    &snapshot,
                    &ctx,
                )
                .await;
            match outcome {
                Ok(Outcome::Created { contact_id, link }) => {
                    report.created += 1;
                    snapshot.remember(contact_id, record, link);
                }
                Ok(Outcome::Linked { contact_id, link }) => {
                    report.linked += 1;
                    snapshot.mark_linked(contact_id, link);
                }
                Ok(Outcome::Updated) => report.updated += 1,
                Ok(Outcome::Unchanged) => report.unchanged += 1,
                Ok(Outcome::Queued) => report.queued += 1,
                Ok(Outcome::AwaitingReview) => report.awaiting_review += 1,
                Ok(Outcome::AlreadyReviewed) => report.already_reviewed += 1,
                Ok(Outcome::NotSelected) => report.not_selected += 1,
                Ok(Outcome::DeletedInSource) => report.deleted_in_source += 1,
                Err(e) => {
                    report.failed += 1;
                    tracing::warn!(
                        connection_id = %connection_id,
                        external_id = %record.external_id,
                        "contact sync could not apply a record: {e}"
                    );
                }
            }
        }

        // Absent from a complete read means gone from the source. Only on a
        // full read: a delta names what changed, not what exists.
        if report.full_read && report.failed == 0 {
            let absent: Vec<LinkRow> = snapshot
                .links
                .values()
                .filter(|l| {
                    l.deleted_in_source_at.is_none() && !seen.contains(l.external_id.as_str())
                })
                .cloned()
                .collect();
            for link in absent {
                self.flag_deleted(tenant_id, &link, &ctx).await?;
                report.deleted_in_source += 1;
            }
        }

        if report.failed == 0 {
            self.finish(tenant_id, connection_id, changes.next_sync_token.as_deref())
                .await?;
        } else {
            self.set_status(
                tenant_id,
                connection_id,
                "failed",
                Some(format!(
                    "{} of {} contacts could not be imported. The next sync retries them.",
                    report.failed,
                    changes.contacts.len()
                )),
            )
            .await?;
        }
        Ok(report)
    }

    async fn load_connection(
        &self,
        tenant_id: TenantId,
        connection_id: Uuid,
    ) -> AppResult<ConnectionRow> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query_as(
            "SELECT provider, account_email, is_active, sync_token, selected_groups, disconnected_at \
             FROM contact_sync_connections WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(connection_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| AppError::NotFound("contact sync connection".to_string()))
    }

    async fn set_status(
        &self,
        tenant_id: TenantId,
        connection_id: Uuid,
        status: &str,
        error: Option<String>,
    ) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            "UPDATE contact_sync_connections \
             SET sync_status = $3, last_error = $4, updated_at = NOW(), \
                 last_sync_at = CASE WHEN $3 = 'in_progress' THEN last_sync_at ELSE NOW() END \
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(connection_id)
        .bind(status)
        .bind(error)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn finish(
        &self,
        tenant_id: TenantId,
        connection_id: Uuid,
        next_sync_token: Option<&str>,
    ) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            "UPDATE contact_sync_connections \
             SET sync_status = 'success', last_error = NULL, sync_token = $3, \
                 last_sync_at = NOW(), updated_at = NOW() \
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(connection_id)
        .bind(next_sync_token)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn snapshot(&self, tenant_id: TenantId, connection_id: Uuid) -> AppResult<Snapshot> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let locals: Vec<LocalRow> = sqlx::query_as(
            "SELECT c.id, c.email, c.first_name, c.last_name, c.company_name, \
                    ARRAY(SELECT p.number FROM contact_phones p WHERE p.contact_id = c.id) \
                        || ARRAY_REMOVE(ARRAY[c.phone, c.mobile], NULL) AS phones, \
                    ARRAY(SELECT co.name FROM contact_companies cc \
                          JOIN companies co ON co.id = cc.company_id \
                          WHERE cc.contact_id = c.id) AS company_names, \
                    EXISTS (SELECT 1 FROM contact_sync_links l \
                            WHERE l.contact_id = c.id AND l.connection_id = $2 \
                              AND l.unlinked_at IS NULL) AS linked \
             FROM contacts c WHERE c.tenant_id = $1",
        )
        .bind(tenant_id)
        .bind(connection_id)
        .fetch_all(&mut *tx)
        .await?;
        let links: Vec<LinkRow> = sqlx::query_as(
            "SELECT id, external_id, contact_id, etag, deleted_in_source_at \
             FROM contact_sync_links \
             WHERE tenant_id = $1 AND connection_id = $2 AND unlinked_at IS NULL",
        )
        .bind(tenant_id)
        .bind(connection_id)
        .fetch_all(&mut *tx)
        .await?;
        let answered: Vec<(String, Uuid)> = sqlx::query_as(
            "SELECT external_id, candidate_contact_id FROM contact_sync_candidates \
             WHERE tenant_id = $1 AND connection_id = $2 AND status <> 'open'",
        )
        .bind(tenant_id)
        .bind(connection_id)
        .fetch_all(&mut *tx)
        .await?;
        let companies: Vec<(Uuid, String)> =
            sqlx::query_as("SELECT id, name FROM companies WHERE tenant_id = $1")
                .bind(tenant_id)
                .fetch_all(&mut *tx)
                .await?;

        let mut by_name: HashMap<String, Vec<Uuid>> = HashMap::new();
        for (id, name) in companies {
            if let Some(key) = name_key(&name) {
                by_name.entry(key).or_default().push(id);
            }
        }
        Ok(Snapshot {
            locals: locals
                .into_iter()
                .map(|row| {
                    let full_name = format!("{} {}", row.first_name, row.last_name);
                    LocalContact::from_values(
                        row.id,
                        row.email.as_deref(),
                        row.phones.iter().map(String::as_str),
                        &full_name,
                        row.company_names
                            .iter()
                            .map(String::as_str)
                            .chain(row.company_name.as_deref()),
                        row.linked,
                    )
                })
                .collect(),
            links: links
                .into_iter()
                .map(|l| (l.external_id.clone(), l))
                .collect(),
            answered: answered.into_iter().collect(),
            companies: by_name,
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn apply_record(
        &self,
        tenant_id: TenantId,
        connection_id: Uuid,
        connection: &ConnectionRow,
        record: &SourceContact,
        selected: &BTreeSet<String>,
        label_names: &HashMap<String, String>,
        snapshot: &Snapshot,
        ctx: &AuditCtx,
    ) -> AppResult<Outcome> {
        let link = snapshot.links.get(&record.external_id);

        // A deletion is honoured whatever the selection: the link exists
        // because the record was once selected.
        if record.deleted {
            return match link {
                Some(link) if link.deleted_in_source_at.is_none() => {
                    self.flag_deleted(tenant_id, link, ctx).await?;
                    Ok(Outcome::DeletedInSource)
                }
                _ => Ok(Outcome::Unchanged),
            };
        }
        if !record.group_ids.iter().any(|g| selected.contains(g)) {
            return Ok(Outcome::NotSelected);
        }
        let labels: Vec<String> = record
            .group_ids
            .iter()
            .filter(|g| selected.contains(*g))
            .filter_map(|g| label_names.get(g).cloned())
            .collect();
        let mapped = map_contact(record);

        if let Some(link) = link {
            if link.etag.is_some()
                && link.etag == record.etag
                && link.deleted_in_source_at.is_none()
            {
                return Ok(Outcome::Unchanged);
            }
            let mut tx = self.db.begin_with_tenant(tenant_id).await?;
            let changed = self
                .apply_fields(
                    &mut tx,
                    tenant_id,
                    link.contact_id,
                    record,
                    &mapped,
                    &labels,
                    Pass::Owned,
                    ctx,
                )
                .await?;
            sqlx::query(
                "UPDATE contact_sync_links \
                 SET etag = $3, last_synced_at = NOW(), deleted_in_source_at = NULL, updated_at = NOW() \
                 WHERE tenant_id = $1 AND id = $2",
            )
            .bind(tenant_id)
            .bind(link.id)
            .bind(&record.etag)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            return Ok(if changed {
                Outcome::Updated
            } else {
                Outcome::Unchanged
            });
        }

        let incoming = IncomingKeys::from_values(
            record.emails.iter().map(String::as_str),
            record.phones.iter().flat_map(|p| {
                p.canonical
                    .as_deref()
                    .into_iter()
                    .chain([p.number.as_str()])
            }),
            &format!("{} {}", mapped.first_name, mapped.last_name),
            mapped.company_name.as_deref(),
        );
        match decide(&incoming, &snapshot.locals) {
            MatchDecision::Link(contact_id) => {
                let mut tx = self.db.begin_with_tenant(tenant_id).await?;
                self.apply_fields(
                    &mut tx,
                    tenant_id,
                    contact_id,
                    record,
                    &mapped,
                    &labels,
                    Pass::FirstLink,
                    ctx,
                )
                .await?;
                let link = self
                    .insert_link(
                        &mut tx,
                        tenant_id,
                        connection_id,
                        connection,
                        record,
                        contact_id,
                        None,
                        ctx,
                    )
                    .await?;
                tx.commit().await?;
                Ok(Outcome::Linked { contact_id, link })
            }
            MatchDecision::Review(pairs) => {
                let open: Vec<_> = pairs
                    .into_iter()
                    .filter(|(id, _)| {
                        !snapshot
                            .answered
                            .contains(&(record.external_id.clone(), *id))
                    })
                    .collect();
                if open.is_empty() {
                    return Ok(Outcome::AlreadyReviewed);
                }
                let snapshot_json = source_snapshot(record, &mapped, &labels);
                let mut tx = self.db.begin_with_tenant(tenant_id).await?;
                let mut inserted = 0;
                for (candidate, reason) in open {
                    // A refreshed etag refreshes the snapshot the reviewer
                    // compares against; an unchanged one writes nothing.
                    let written: Option<bool> = sqlx::query_scalar(
                        "INSERT INTO contact_sync_candidates \
                         (tenant_id, connection_id, external_id, etag, candidate_contact_id, match_reason, source_snapshot) \
                         VALUES ($1, $2, $3, $4, $5, $6, $7) \
                         ON CONFLICT (connection_id, external_id, candidate_contact_id) WHERE status = 'open' \
                         DO UPDATE SET etag = EXCLUDED.etag, source_snapshot = EXCLUDED.source_snapshot, \
                                       match_reason = EXCLUDED.match_reason \
                         WHERE contact_sync_candidates.etag IS DISTINCT FROM EXCLUDED.etag \
                         RETURNING (xmax = 0)",
                    )
                    .bind(tenant_id)
                    .bind(connection_id)
                    .bind(&record.external_id)
                    .bind(&record.etag)
                    .bind(candidate)
                    .bind(reason.as_str())
                    .bind(&snapshot_json)
                    .fetch_optional(&mut *tx)
                    .await?;
                    if written == Some(true) {
                        inserted += 1;
                    }
                }
                tx.commit().await?;
                Ok(if inserted > 0 {
                    Outcome::Queued
                } else {
                    Outcome::AwaitingReview
                })
            }
            MatchDecision::Create => {
                let suggestion = mapped
                    .company_name
                    .as_deref()
                    .and_then(name_key)
                    .and_then(|key| snapshot.companies.get(&key))
                    .and_then(|ids| match ids.as_slice() {
                        [only] => Some(*only),
                        _ => None,
                    });
                let request = create_request(&mapped, &labels);
                let mut tx = self.db.begin_with_tenant(tenant_id).await?;
                let contact_id = self
                    .contacts
                    .import_contact_in(&mut tx, tenant_id, &request, ctx)
                    .await?;
                let link = self
                    .insert_link(
                        &mut tx,
                        tenant_id,
                        connection_id,
                        connection,
                        record,
                        contact_id,
                        suggestion,
                        ctx,
                    )
                    .await?;
                tx.commit().await?;
                Ok(Outcome::Created { contact_id, link })
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn insert_link(
        &self,
        conn: &mut sqlx::PgConnection,
        tenant_id: TenantId,
        connection_id: Uuid,
        connection: &ConnectionRow,
        record: &SourceContact,
        contact_id: Uuid,
        suggested_company_id: Option<Uuid>,
        ctx: &AuditCtx,
    ) -> AppResult<LinkRow> {
        let link: LinkRow = sqlx::query_as(
            "INSERT INTO contact_sync_links \
             (tenant_id, connection_id, provider, source_account_email, external_id, etag, \
              contact_id, last_synced_at, suggested_company_id) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), $8) \
             RETURNING id, external_id, contact_id, etag, deleted_in_source_at",
        )
        .bind(tenant_id)
        .bind(connection_id)
        .bind(&connection.provider)
        .bind(&connection.account_email)
        .bind(&record.external_id)
        .bind(&record.etag)
        .bind(contact_id)
        .bind(suggested_company_id)
        .fetch_one(&mut *conn)
        .await?;
        audit_write(
            &mut *conn,
            tenant_id,
            ctx,
            AuditAction::Create,
            "contact_sync_links",
            Some(link.id),
            None,
            Some(json!({
                "event": "contact_sync.linked",
                "provider": connection.provider,
                "external_id": record.external_id,
                "contact_id": contact_id,
                "suggested_company_id": suggested_company_id,
            })),
        )
        .await?;
        Ok(link)
    }

    async fn flag_deleted(
        &self,
        tenant_id: TenantId,
        link: &LinkRow,
        ctx: &AuditCtx,
    ) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let flagged = sqlx::query(
            "UPDATE contact_sync_links SET deleted_in_source_at = NOW(), updated_at = NOW() \
             WHERE tenant_id = $1 AND id = $2 AND deleted_in_source_at IS NULL",
        )
        .bind(tenant_id)
        .bind(link.id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if flagged > 0 {
            audit_write(
                &mut *tx,
                tenant_id,
                ctx,
                AuditAction::Update,
                "contact_sync_links",
                Some(link.id),
                None,
                Some(json!({
                    "event": "contact_sync.deleted_in_source",
                    "external_id": link.external_id,
                    "contact_id": link.contact_id,
                    "contact": "kept",
                })),
            )
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Apply the field rules in the module doc. Returns whether anything was
    /// written.
    #[allow(clippy::too_many_arguments)]
    async fn apply_fields(
        &self,
        conn: &mut sqlx::PgConnection,
        tenant_id: TenantId,
        contact_id: Uuid,
        record: &SourceContact,
        mapped: &MappedContact,
        labels: &[String],
        pass: Pass,
        ctx: &AuditCtx,
    ) -> AppResult<bool> {
        let current: ContactRow = sqlx::query_as(
            "SELECT first_name, last_name, email, title, department, company_id, company_name, tags \
             FROM contacts WHERE tenant_id = $1 AND id = $2 FOR UPDATE",
        )
        .bind(tenant_id)
        .bind(contact_id)
        .fetch_optional(&mut *conn)
        .await?
        .ok_or_else(|| AppError::NotFound("contact".to_string()))?;
        let locked: HashSet<String> = sqlx::query_scalar(
            "SELECT field FROM contact_field_locks WHERE tenant_id = $1 AND contact_id = $2",
        )
        .bind(tenant_id)
        .bind(contact_id)
        .fetch_all(&mut *conn)
        .await?
        .into_iter()
        .collect();
        let has_company_link: bool = current.company_id.is_some()
            || sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM contact_companies WHERE tenant_id = $1 AND contact_id = $2)",
            )
            .bind(tenant_id)
            .bind(contact_id)
            .fetch_one(&mut *conn)
            .await?;

        let open = |field: &str| !locked.contains(field);
        // The value to write, or None to leave the column alone.
        let choose =
            |field: &str, current: Option<&str>, incoming: Option<&str>, fill_only: bool| {
                let incoming = incoming.filter(|v| !v.is_empty())?;
                if !open(field) || current == Some(incoming) {
                    return None;
                }
                let current_empty = current.is_none_or(str::is_empty);
                (current_empty || !fill_only).then(|| incoming.to_string())
            };
        let fill_only = pass == Pass::FirstLink;
        // The mapping's fallback names (organisation, email, "(no name)") exist
        // so a nameless record can be CREATED; they never overwrite a name.
        let source_named = record.given_name.is_some()
            || record.family_name.is_some()
            || record.display_name.is_some();

        let first_name = source_named
            .then(|| {
                choose(
                    fields::FIRST_NAME,
                    Some(&current.first_name),
                    Some(&mapped.first_name),
                    fill_only,
                )
            })
            .flatten();
        let last_name = source_named
            .then(|| {
                choose(
                    fields::LAST_NAME,
                    Some(&current.last_name),
                    Some(&mapped.last_name),
                    fill_only,
                )
            })
            .flatten();
        let email = choose(
            fields::EMAIL,
            current.email.as_deref(),
            mapped.email.as_deref(),
            true,
        );
        let title = choose(
            fields::TITLE,
            current.title.as_deref(),
            mapped.title.as_deref(),
            fill_only,
        );
        let department = choose(
            fields::DEPARTMENT,
            current.department.as_deref(),
            mapped.department.as_deref(),
            fill_only,
        );
        let company_name = if has_company_link {
            None
        } else {
            choose(
                fields::COMPANY_NAME,
                current.company_name.as_deref(),
                mapped.company_name.as_deref(),
                fill_only,
            )
        };
        let current_tags = current.tags.clone().unwrap_or_default();
        let new_tags: Vec<String> = if open(fields::TAGS) {
            labels
                .iter()
                .filter(|l| !current_tags.contains(l))
                .cloned()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect()
        } else {
            Vec::new()
        };

        let existing_phones: Vec<PhoneRow> = sqlx::query_as(
            "SELECT phone_type, number, extension, is_primary FROM contact_phones \
             WHERE tenant_id = $1 AND contact_id = $2 ORDER BY sort_order, created_at",
        )
        .bind(tenant_id)
        .bind(contact_id)
        .fetch_all(&mut *conn)
        .await?;
        let known: HashSet<String> = existing_phones
            .iter()
            .filter_map(|p| phone_key(&p.number))
            .collect();
        let added: Vec<_> = if open(fields::PHONES) {
            mapped
                .phones
                .iter()
                .filter(|p| phone_key(&p.number).is_none_or(|k| !known.contains(&k)))
                .collect()
        } else {
            Vec::new()
        };

        let scalar_change = first_name.is_some()
            || last_name.is_some()
            || email.is_some()
            || title.is_some()
            || department.is_some()
            || company_name.is_some()
            || !new_tags.is_empty();
        if !scalar_change && added.is_empty() {
            return Ok(false);
        }

        let before: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(c) FROM contacts c WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(contact_id)
        .fetch_optional(&mut *conn)
        .await?;
        if scalar_change {
            sqlx::query(
                "UPDATE contacts SET \
                    first_name = COALESCE($3, first_name), \
                    last_name = COALESCE($4, last_name), \
                    email = COALESCE($5, email), \
                    title = COALESCE($6, title), \
                    department = COALESCE($7, department), \
                    company_name = COALESCE($8, company_name), \
                    tags = COALESCE(tags, '{}') || $9::text[], \
                    updated_at = NOW() \
                 WHERE tenant_id = $1 AND id = $2",
            )
            .bind(tenant_id)
            .bind(contact_id)
            .bind(first_name)
            .bind(last_name)
            .bind(email)
            .bind(title)
            .bind(department)
            .bind(company_name)
            .bind(&new_tags)
            .execute(&mut *conn)
            .await?;
        }
        if !added.is_empty() {
            let had_phones = !existing_phones.is_empty();
            let entries: Vec<ContactPhoneInput> = existing_phones
                .iter()
                .map(|p| ContactPhoneInput {
                    phone_type: PhoneType::from_str(&p.phone_type).unwrap_or_default(),
                    number: Some(p.number.clone()),
                    extension: p.extension.clone(),
                    is_primary: p.is_primary,
                })
                .chain(added.iter().map(|p| ContactPhoneInput {
                    phone_type: PhoneType::from_str(p.phone_type.as_str()).unwrap_or_default(),
                    number: Some(p.number.clone()),
                    extension: None,
                    // The contact's existing primary stays primary.
                    is_primary: !had_phones && p.is_primary,
                }))
                .collect();
            self.contacts
                .replace_contact_phones_in(&mut *conn, tenant_id, contact_id, &entries)
                .await?;
            sqlx::query("UPDATE contacts SET updated_at = NOW() WHERE tenant_id = $1 AND id = $2")
                .bind(tenant_id)
                .bind(contact_id)
                .execute(&mut *conn)
                .await?;
        }
        let after: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(c) FROM contacts c WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(contact_id)
        .fetch_optional(&mut *conn)
        .await?;
        audit_write(
            &mut *conn,
            tenant_id,
            ctx,
            AuditAction::Update,
            "contacts",
            Some(contact_id),
            before,
            after,
        )
        .await?;
        Ok(true)
    }
}

impl Snapshot {
    /// A contact this pass created is a match target for the records after
    /// it, so two source records for one person do not create two contacts.
    fn remember(&mut self, contact_id: Uuid, record: &SourceContact, link: LinkRow) {
        let mapped = map_contact(record);
        self.locals.push(LocalContact::from_values(
            contact_id,
            mapped.email.as_deref(),
            mapped.phones.iter().map(|p| p.number.as_str()),
            &format!("{} {}", mapped.first_name, mapped.last_name),
            mapped.company_name.as_deref(),
            true,
        ));
        self.links.insert(link.external_id.clone(), link);
    }

    fn mark_linked(&mut self, contact_id: Uuid, link: LinkRow) {
        if let Some(local) = self.locals.iter_mut().find(|l| l.contact_id == contact_id) {
            local.linked = true;
        }
        self.links.insert(link.external_id.clone(), link);
    }
}

fn create_request(mapped: &MappedContact, labels: &[String]) -> CreateContactRequest {
    CreateContactRequest {
        company_id: None,
        company_name: mapped.company_name.clone(),
        first_name: mapped.first_name.clone(),
        last_name: mapped.last_name.clone(),
        email: mapped.email.clone(),
        phone: None,
        mobile: None,
        fax: None,
        title: mapped.title.clone(),
        department: mapped.department.clone(),
        contact_type: ContactType::default(),
        preferred_contact_method: PreferredContactMethod::default(),
        timezone: None,
        custom_fields: json!({}),
        tags: labels
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        notes: None,
        create_portal_access: false,
        phones: Some(
            mapped
                .phones
                .iter()
                .map(|p| ContactPhoneInput {
                    phone_type: PhoneType::from_str(p.phone_type.as_str()).unwrap_or_default(),
                    number: Some(p.number.clone()),
                    extension: None,
                    is_primary: p.is_primary,
                })
                .collect(),
        ),
        companies: None,
    }
}

/// The incoming record as the review queue's side-by-side renders it.
fn source_snapshot(
    record: &SourceContact,
    mapped: &MappedContact,
    labels: &[String],
) -> serde_json::Value {
    json!({
        "external_id": record.external_id,
        "display_name": record.display_name,
        "first_name": mapped.first_name,
        "last_name": mapped.last_name,
        "email": mapped.email,
        "emails": record.emails,
        "phones": mapped.phones.iter().map(|p| json!({
            "number": p.number,
            "phone_type": p.phone_type.as_str(),
            "is_primary": p.is_primary,
        })).collect::<Vec<_>>(),
        "company_name": mapped.company_name,
        "title": mapped.title,
        "department": mapped.department,
        "labels": labels,
        "dropped": mapped.dropped,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every lockable field is one the mapping writes, so a lock can never
    /// name a field the sync does not touch and quietly protect nothing.
    #[test]
    fn the_lockable_fields_are_the_fields_a_sync_writes() {
        let source = include_str!("sync.rs");
        for field in fields::ALL {
            let constant = format!("fields::{}", field.to_uppercase());
            assert!(
                source.matches(&constant).count() >= 1,
                "{field} is lockable but never consulted by apply_fields"
            );
        }
    }
}
