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
//! # A person's "stop" wins (PMS-1214)
//!
//! A record a person unlinked from a contact is skipped rather than re-linked
//! by its email, and a record whose imported data was removed on request is
//! recognised by [`external_id_digest`] and never imported again, across a
//! disconnect and reconnect of the same account.
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
use sha2::{Digest, Sha256};
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
    /// Records a person unlinked, or whose imported data was removed on
    /// request (PMS-1214). Never re-linked, never re-imported.
    pub excluded: u32,
    /// Links newly flagged as deleted in the source.
    pub deleted_in_source: u32,
    pub failed: u32,
    /// Records the source returned for this pass.
    pub total: u32,
    /// Stopped at a checkpoint because a person cancelled the run (PMS-1215).
    /// Nothing after the checkpoint was applied and the cursor did not move.
    pub cancelled: bool,
    /// What did not land, per record, capped at [`MAX_RECORDED_FAILURES`].
    pub failures: Vec<RecordFailure>,
}

/// One record that could not be applied, and why.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RecordFailure {
    pub external_id: String,
    pub reason: String,
}

/// Enough to see the shape of a failure without letting one broken import
/// grow a run row without bound. `failed` still counts every one.
pub const MAX_RECORDED_FAILURES: usize = 50;

/// How many records between progress writes. Each checkpoint is one UPDATE
/// that also reports whether the run was cancelled.
const CHECKPOINT_EVERY: usize = 25;

impl SyncReport {
    /// Records that were read and deliberately not imported: outside the
    /// selection, unlinked or removed, or already answered by a reviewer.
    pub fn skipped(&self) -> u32 {
        self.not_selected + self.excluded + self.already_reviewed
    }

    /// Whether the pass wrote anything at all. The idempotency test's
    /// question.
    pub fn changed_anything(&self) -> bool {
        self.created + self.linked + self.updated + self.queued + self.deleted_in_source > 0
    }
}

#[derive(sqlx::FromRow)]
struct ConnectionRow {
    provider: String,
    sync_status: String,
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
    /// External ids a reviewer chose not to import (PMS-1215). A skip is about
    /// the record, not the pairs it was asked about: a contact created later
    /// that also matches it is not a reason to ask again.
    skipped: HashSet<String>,
    /// External ids a person unlinked from this connection.
    unlinked: HashSet<String>,
    /// [`external_id_digest`]s of records whose data was removed on request.
    suppressed: HashSet<String>,
    /// Company name key to the ids carrying it.
    companies: HashMap<String, Vec<Uuid>>,
}

#[derive(Clone)]
pub struct ContactSyncEngine {
    db: Database,
    contacts: ContactService,
}

/// What the sync will do with one record, decided from the snapshot alone.
///
/// The one decision both [`ContactSyncEngine::apply_record`] and
/// [`ContactSyncEngine::preview`] act on, so a preview cannot drift from the
/// import it previews (PMS-1242): the import performs the plan, the preview
/// counts it.
enum Plan<'a> {
    /// A person unlinked it or had its data removed (PMS-1214).
    Excluded,
    /// Deleted in the source, linked, and not flagged yet.
    FlagDeleted(&'a LinkRow),
    /// Carries none of the selected labels.
    NotSelected,
    /// Linked, and its etag says nothing changed.
    Unchanged,
    /// Linked, and changed in the source.
    Update(&'a LinkRow),
    /// A reviewer already answered it.
    AlreadyReviewed,
    /// Matches exactly one contact by email.
    Link(Uuid),
    /// Questions to put to a reviewer, minus any already answered.
    Review(Vec<(Uuid, super::matching::MatchReason)>),
    /// Nobody Mokosh holds; the company suggestion, if exactly one matches.
    Create(Option<Uuid>),
}

fn plan<'a>(
    record: &SourceContact,
    selected: &BTreeSet<String>,
    snapshot: &'a Snapshot,
    mapped: &MappedContact,
) -> Plan<'a> {
    // A person said stop (PMS-1214): an unlinked record is not re-linked by
    // its email a minute later, and a removed one is not imported back.
    // Checked before anything else, deletion included, because there is
    // nothing left of either for a deletion to flag.
    if snapshot.unlinked.contains(&record.external_id)
        || snapshot
            .suppressed
            .contains(&external_id_digest(&record.external_id))
    {
        return Plan::Excluded;
    }
    let link = snapshot.links.get(&record.external_id);

    // A deletion is honoured whatever the selection: the link exists because
    // the record was once selected.
    if record.deleted {
        return match link {
            Some(link) if link.deleted_in_source_at.is_none() => Plan::FlagDeleted(link),
            _ => Plan::Unchanged,
        };
    }
    if !record.group_ids.iter().any(|g| selected.contains(g)) {
        return Plan::NotSelected;
    }
    if let Some(link) = link {
        if link.etag.is_some() && link.etag == record.etag && link.deleted_in_source_at.is_none() {
            return Plan::Unchanged;
        }
        return Plan::Update(link);
    }
    if snapshot.skipped.contains(&record.external_id) {
        return Plan::AlreadyReviewed;
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
        MatchDecision::Link(contact_id) => Plan::Link(contact_id),
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
                Plan::AlreadyReviewed
            } else {
                Plan::Review(open)
            }
        }
        MatchDecision::Create => Plan::Create(
            mapped
                .company_name
                .as_deref()
                .and_then(name_key)
                .and_then(|key| snapshot.companies.get(&key))
                .and_then(|ids| match ids.as_slice() {
                    [only] => Some(*only),
                    _ => None,
                }),
        ),
    }
}

/// What importing one record would do, as the preview reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreviewOutcome {
    /// A new contact.
    Create,
    /// Linked to the one contact its email matches.
    Link,
    /// Put to a reviewer: nothing is created or linked until they answer.
    Review,
    /// Already imported; an import only updates it.
    Imported,
    /// Unlinked, removed on request, or skipped by a reviewer; not imported.
    Excluded,
}

/// One record in the preview: its labels and its outcome, and deliberately
/// nothing that names the person. A client totals any combination of labels
/// from these without another read of the account.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PreviewRecord {
    pub group_ids: Vec<String>,
    pub outcome: PreviewOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PreviewGroup {
    pub id: String,
    pub name: String,
    pub member_count: Option<u32>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct PreviewTotals {
    pub contacts: u32,
    pub create: u32,
    pub link: u32,
    pub review: u32,
    pub imported: u32,
    pub excluded: u32,
}

impl PreviewTotals {
    fn add(&mut self, outcome: PreviewOutcome) {
        self.contacts += 1;
        match outcome {
            PreviewOutcome::Create => self.create += 1,
            PreviewOutcome::Link => self.link += 1,
            PreviewOutcome::Review => self.review += 1,
            PreviewOutcome::Imported => self.imported += 1,
            PreviewOutcome::Excluded => self.excluded += 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ImportPreview {
    pub groups: Vec<PreviewGroup>,
    /// The labels the totals were simulated for.
    pub selection: Vec<String>,
    pub records: Vec<PreviewRecord>,
    /// Exact for `selection`: each record counted once, however many of its
    /// labels are selected.
    pub totals: PreviewTotals,
}

/// Whether the import made the contact or found it (migration 228). Removal of
/// imported data (PSA-70 K) deletes only the first kind.
#[derive(Clone, Copy, PartialEq, Eq)]
enum LinkOrigin {
    Created,
    Linked,
}

impl LinkOrigin {
    fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Linked => "linked",
        }
    }
}

/// How a removed record is recognised without being named
/// (`contact_sync_suppressions.external_id_sha256`, migration 228).
pub fn external_id_digest(external_id: &str) -> String {
    format!("{:x}", Sha256::digest(external_id.as_bytes()))
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
    Excluded,
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
        self.run_tracked(tenant_id, connection_id, source, None)
            .await
    }

    /// [`Self::run`], writing progress to `contact_sync_runs` row `run_id`
    /// every [`CHECKPOINT_EVERY`] records and stopping at the first checkpoint
    /// after a cancel was requested (PMS-1215).
    pub async fn run_tracked(
        &self,
        tenant_id: TenantId,
        connection_id: Uuid,
        source: &dyn ContactSyncProvider,
        run_id: Option<Uuid>,
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
            total: u32::try_from(changes.contacts.len()).unwrap_or(u32::MAX),
            ..SyncReport::default()
        };
        if let Some(run_id) = run_id {
            self.checkpoint(tenant_id, run_id, &report, 0).await?;
        }
        let mut snapshot = self
            .snapshot(tenant_id, connection_id, &connection.provider)
            .await?;
        let ctx = AuditCtx::system(tenant_id.get());
        let mut seen: HashSet<&str> = HashSet::new();

        for (index, record) in changes.contacts.iter().enumerate() {
            if let Some(run_id) = run_id {
                if index > 0
                    && index % CHECKPOINT_EVERY == 0
                    && self.checkpoint(tenant_id, run_id, &report, index).await?
                {
                    report.cancelled = true;
                    break;
                }
            }
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
                Ok(Outcome::Excluded) => report.excluded += 1,
                Ok(Outcome::DeletedInSource) => report.deleted_in_source += 1,
                Err(e) => {
                    report.failed += 1;
                    tracing::warn!(
                        connection_id = %connection_id,
                        external_id = %record.external_id,
                        "contact sync could not apply a record: {e}"
                    );
                    if report.failures.len() < MAX_RECORDED_FAILURES {
                        report.failures.push(RecordFailure {
                            external_id: record.external_id.clone(),
                            reason: e.to_string().chars().take(300).collect(),
                        });
                    }
                }
            }
        }

        // A cancel stops here: no tombstones from a read that was not
        // walked, no cursor moved past records that were never applied, and
        // the connection says what it said before this run began.
        if report.cancelled {
            let mut tx = self.db.begin_with_tenant(tenant_id).await?;
            sqlx::query(
                "UPDATE contact_sync_connections SET sync_status = $3, updated_at = NOW() \
                 WHERE tenant_id = $1 AND id = $2",
            )
            .bind(tenant_id)
            .bind(connection_id)
            .bind(&connection.sync_status)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            return Ok(report);
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

        if let Some(run_id) = run_id {
            self.checkpoint(tenant_id, run_id, &report, changes.contacts.len())
                .await?;
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

    /// A reviewer linked a queued record to a contact (PMS-1215), on the
    /// caller's transaction. The same first-link rule the sync uses: only
    /// empty fields are filled, from the snapshot the reviewer compared.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn link_reviewed(
        &self,
        conn: &mut sqlx::PgConnection,
        tenant_id: TenantId,
        connection_id: Uuid,
        external_id: &str,
        etag: Option<&str>,
        snapshot: &serde_json::Value,
        contact_id: Uuid,
        ctx: &AuditCtx,
    ) -> AppResult<()> {
        let connection = Self::connection_in(&mut *conn, tenant_id, connection_id).await?;
        let (record, mapped, labels) = from_snapshot(external_id, etag, snapshot);
        self.apply_fields(
            &mut *conn,
            tenant_id,
            contact_id,
            &record,
            &mapped,
            &labels,
            Pass::FirstLink,
            ctx,
        )
        .await?;
        self.insert_link(
            &mut *conn,
            tenant_id,
            connection_id,
            &connection,
            &record,
            contact_id,
            LinkOrigin::Linked,
            None,
            ctx,
        )
        .await?;
        Ok(())
    }

    /// A reviewer decided a queued record is nobody Mokosh holds (PMS-1215):
    /// create it exactly as the sync would have.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn create_reviewed(
        &self,
        conn: &mut sqlx::PgConnection,
        tenant_id: TenantId,
        connection_id: Uuid,
        external_id: &str,
        etag: Option<&str>,
        snapshot: &serde_json::Value,
        ctx: &AuditCtx,
    ) -> AppResult<Uuid> {
        let connection = Self::connection_in(&mut *conn, tenant_id, connection_id).await?;
        let (record, mapped, labels) = from_snapshot(external_id, etag, snapshot);
        let suggestion = match mapped.company_name.as_deref().and_then(name_key) {
            Some(key) => {
                let companies: Vec<(Uuid, String)> =
                    sqlx::query_as("SELECT id, name FROM companies WHERE tenant_id = $1")
                        .bind(tenant_id)
                        .fetch_all(&mut *conn)
                        .await?;
                match companies
                    .into_iter()
                    .filter(|(_, name)| name_key(name).as_deref() == Some(key.as_str()))
                    .map(|(id, _)| id)
                    .collect::<Vec<_>>()
                    .as_slice()
                {
                    [only] => Some(*only),
                    _ => None,
                }
            }
            None => None,
        };
        let request = create_request(&mapped, &labels);
        let contact_id = self
            .contacts
            .import_contact_in(&mut *conn, tenant_id, &request, ctx)
            .await?;
        self.insert_link(
            &mut *conn,
            tenant_id,
            connection_id,
            &connection,
            &record,
            contact_id,
            LinkOrigin::Created,
            suggestion,
            ctx,
        )
        .await?;
        Ok(contact_id)
    }

    async fn connection_in(
        conn: &mut sqlx::PgConnection,
        tenant_id: TenantId,
        connection_id: Uuid,
    ) -> AppResult<ConnectionRow> {
        sqlx::query_as(
            "SELECT provider, sync_status, account_email, is_active, sync_token, selected_groups, disconnected_at \
             FROM contact_sync_connections WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(connection_id)
        .fetch_optional(&mut *conn)
        .await?
        .ok_or_else(|| AppError::NotFound("contact sync connection".to_string()))
    }

    /// Write progress onto the run. Returns whether a cancel was requested.
    async fn checkpoint(
        &self,
        tenant_id: TenantId,
        run_id: Uuid,
        report: &SyncReport,
        processed: usize,
    ) -> AppResult<bool> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let cancel: Option<bool> = sqlx::query_scalar(
            "UPDATE contact_sync_runs SET \
                total = $3, full_read = $4, processed = $5, created = $6, linked = $7, \
                updated = $8, queued_for_review = $9, skipped = $10, deleted_in_source = $11, \
                failed_records = $12, failures = $13, heartbeat_at = NOW() \
             WHERE tenant_id = $1 AND id = $2 \
             RETURNING cancel_requested_at IS NOT NULL",
        )
        .bind(tenant_id)
        .bind(run_id)
        .bind(i32::try_from(report.total).unwrap_or(i32::MAX))
        .bind(report.full_read)
        .bind(i32::try_from(processed).unwrap_or(i32::MAX))
        .bind(report.created as i32)
        .bind(report.linked as i32)
        .bind(report.updated as i32)
        .bind(report.queued as i32)
        .bind(report.skipped() as i32)
        .bind(report.deleted_in_source as i32)
        .bind(report.failed as i32)
        .bind(serde_json::to_value(&report.failures).unwrap_or_default())
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(cancel.unwrap_or(false))
    }

    async fn load_connection(
        &self,
        tenant_id: TenantId,
        connection_id: Uuid,
    ) -> AppResult<ConnectionRow> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query_as(
            "SELECT provider, sync_status, account_email, is_active, sync_token, selected_groups, disconnected_at \
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

    async fn snapshot(
        &self,
        tenant_id: TenantId,
        connection_id: Uuid,
        provider: &str,
    ) -> AppResult<Snapshot> {
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
        let skipped: Vec<String> = sqlx::query_scalar(
            "SELECT DISTINCT external_id FROM contact_sync_candidates \
             WHERE tenant_id = $1 AND connection_id = $2 AND status = 'skipped'",
        )
        .bind(tenant_id)
        .bind(connection_id)
        .fetch_all(&mut *tx)
        .await?;
        let unlinked: Vec<String> = sqlx::query_scalar(
            "SELECT external_id FROM contact_sync_links \
             WHERE tenant_id = $1 AND connection_id = $2 AND unlink_reason = 'unlinked'",
        )
        .bind(tenant_id)
        .bind(connection_id)
        .fetch_all(&mut *tx)
        .await?;
        let suppressed: Vec<String> = sqlx::query_scalar(
            "SELECT external_id_sha256 FROM contact_sync_suppressions \
             WHERE tenant_id = $1 AND provider = $2",
        )
        .bind(tenant_id)
        .bind(provider)
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
            skipped: skipped.into_iter().collect(),
            unlinked: unlinked.into_iter().collect(),
            suppressed: suppressed.into_iter().collect(),
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
        let mapped = map_contact(record);
        let labels = || -> Vec<String> {
            record
                .group_ids
                .iter()
                .filter(|g| selected.contains(*g))
                .filter_map(|g| label_names.get(g).cloned())
                .collect()
        };
        match plan(record, selected, snapshot, &mapped) {
            Plan::Excluded => Ok(Outcome::Excluded),
            Plan::NotSelected => Ok(Outcome::NotSelected),
            Plan::Unchanged => Ok(Outcome::Unchanged),
            Plan::AlreadyReviewed => Ok(Outcome::AlreadyReviewed),
            Plan::FlagDeleted(link) => {
                self.flag_deleted(tenant_id, link, ctx).await?;
                Ok(Outcome::DeletedInSource)
            }
            Plan::Update(link) => {
                let mut tx = self.db.begin_with_tenant(tenant_id).await?;
                let changed = self
                    .apply_fields(
                        &mut tx,
                        tenant_id,
                        link.contact_id,
                        record,
                        &mapped,
                        &labels(),
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
                Ok(if changed {
                    Outcome::Updated
                } else {
                    Outcome::Unchanged
                })
            }
            Plan::Link(contact_id) => {
                let mut tx = self.db.begin_with_tenant(tenant_id).await?;
                self.apply_fields(
                    &mut tx,
                    tenant_id,
                    contact_id,
                    record,
                    &mapped,
                    &labels(),
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
                        LinkOrigin::Linked,
                        None,
                        ctx,
                    )
                    .await?;
                tx.commit().await?;
                Ok(Outcome::Linked { contact_id, link })
            }
            Plan::Review(open) => {
                let snapshot_json = source_snapshot(record, &mapped, &labels());
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
            Plan::Create(suggestion) => {
                let request = create_request(&mapped, &labels());
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
                        LinkOrigin::Created,
                        suggestion,
                        ctx,
                    )
                    .await?;
                tx.commit().await?;
                Ok(Outcome::Created { contact_id, link })
            }
        }
    }

    /// What importing would do, without doing it (PMS-1242, PSA-70 E).
    ///
    /// Reads the whole account once and runs every record through [`plan`],
    /// the same decision the import makes, against the same snapshot, writing
    /// nothing: no link, no candidate, no run, no sync token. A record the
    /// simulation would create or link is remembered in the snapshot exactly
    /// as the import remembers it, so two records for one new address preview
    /// as one create and one review, the way they import.
    ///
    /// `selection` limits the simulation to records carrying one of those
    /// labels, which is what makes its totals exact for that selection. `None`
    /// simulates every record carrying ANY offered label, so a client can show
    /// per-label figures from one read.
    pub async fn preview(
        &self,
        tenant_id: TenantId,
        connection_id: Uuid,
        source: &dyn ContactSyncProvider,
        selection: Option<&BTreeSet<String>>,
    ) -> AppResult<ImportPreview> {
        let connection = self.load_connection(tenant_id, connection_id).await?;
        if connection.disconnected_at.is_some() || !connection.is_active {
            return Err(AppError::Conflict(
                "This contact sync connection is not active.".to_string(),
            ));
        }
        let groups = source.list_groups().await?;
        let changes = source.changes_since(None).await?;
        let offered: BTreeSet<String> = groups.iter().map(|g| g.id.clone()).collect();
        let considered: BTreeSet<String> = match selection {
            Some(selection) => selection.intersection(&offered).cloned().collect(),
            None => offered.clone(),
        };

        let mut snapshot = self
            .snapshot(tenant_id, connection_id, &connection.provider)
            .await?;
        let mut records = Vec::new();
        let mut totals = PreviewTotals::default();
        for record in changes.contacts.iter().filter(|r| !r.deleted) {
            let mapped = map_contact(record);
            let planned = plan(record, &considered, &snapshot, &mapped);
            let outcome = match &planned {
                Plan::NotSelected | Plan::FlagDeleted(_) => None,
                Plan::Excluded | Plan::AlreadyReviewed => Some(PreviewOutcome::Excluded),
                Plan::Unchanged | Plan::Update(_) => Some(PreviewOutcome::Imported),
                Plan::Link(_) => Some(PreviewOutcome::Link),
                Plan::Review(_) => Some(PreviewOutcome::Review),
                Plan::Create(_) => Some(PreviewOutcome::Create),
            };
            let simulated_link = match planned {
                Plan::Link(contact_id) => Some((contact_id, false)),
                Plan::Create(_) => Some((Uuid::new_v4(), true)),
                _ => None,
            };
            if let Some((contact_id, created)) = simulated_link {
                let link = LinkRow {
                    id: Uuid::new_v4(),
                    external_id: record.external_id.clone(),
                    contact_id,
                    etag: record.etag.clone(),
                    deleted_in_source_at: None,
                };
                if created {
                    snapshot.remember(contact_id, record, link);
                } else {
                    snapshot.mark_linked(contact_id, link);
                }
            }
            let Some(outcome) = outcome else {
                continue;
            };
            totals.add(outcome);
            records.push(PreviewRecord {
                group_ids: record
                    .group_ids
                    .iter()
                    .filter(|g| offered.contains(*g))
                    .cloned()
                    .collect(),
                outcome,
            });
        }
        Ok(ImportPreview {
            groups: groups
                .into_iter()
                .map(|g| PreviewGroup {
                    id: g.id,
                    name: g.name,
                    member_count: g.member_count,
                })
                .collect(),
            selection: considered.into_iter().collect(),
            records,
            totals,
        })
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
        origin: LinkOrigin,
        suggested_company_id: Option<Uuid>,
        ctx: &AuditCtx,
    ) -> AppResult<LinkRow> {
        let link: LinkRow = sqlx::query_as(
            "INSERT INTO contact_sync_links \
             (tenant_id, connection_id, provider, source_account_email, external_id, etag, \
              contact_id, last_synced_at, suggested_company_id, origin) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), $8, $9) \
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
        .bind(origin.as_str())
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
                "origin": origin.as_str(),
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

/// The record a reviewer saw, rebuilt from its [`source_snapshot`]. Only
/// what the snapshot holds: enough to apply the same mapping the sync would,
/// never a second read of the source.
fn from_snapshot(
    external_id: &str,
    etag: Option<&str>,
    snapshot: &serde_json::Value,
) -> (SourceContact, MappedContact, Vec<String>) {
    let text = |key: &str| {
        snapshot
            .get(key)
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string)
    };
    let strings = |key: &str| -> Vec<String> {
        snapshot
            .get(key)
            .and_then(|v| v.as_array())
            .map(|items| {
                items
                    .iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };
    let phones: Vec<super::mapping::MappedPhone> = snapshot
        .get("phones")
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|p| {
                    Some(super::mapping::MappedPhone {
                        number: p.get("number")?.as_str()?.to_string(),
                        phone_type: super::mapping::MappedPhoneType::from_label(
                            p.get("phone_type").and_then(|t| t.as_str()),
                        ),
                        is_primary: p
                            .get("is_primary")
                            .and_then(|b| b.as_bool())
                            .unwrap_or(false),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let mapped = MappedContact {
        first_name: text("first_name").unwrap_or_else(|| "(no name)".to_string()),
        last_name: text("last_name").unwrap_or_default(),
        email: text("email"),
        phones,
        company_name: text("company_name"),
        title: text("title"),
        department: text("department"),
        dropped: strings("dropped"),
    };
    let record = SourceContact {
        external_id: external_id.to_string(),
        etag: etag.map(str::to_string),
        display_name: text("display_name"),
        given_name: text("first_name"),
        family_name: text("last_name"),
        emails: strings("emails"),
        phones: vec![],
        organization: mapped.company_name.clone(),
        title: mapped.title.clone(),
        department: mapped.department.clone(),
        group_ids: vec![],
        photo_url: None,
        deleted: false,
    };
    (record, mapped, strings("labels"))
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
