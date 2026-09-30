//! PMS-1213 (PSA-70 phase 3): one sync, against a fixture account.
//!
//! The People API's wire format is pinned in `contact_sync::google`'s own
//! tests against a stub server. What is pinned HERE is what a sync does to the
//! CRM: which records link, which queue, which become contacts, and that
//! running it again changes nothing. The source is an in-memory fake so every
//! case is exact; the database runs as the unprivileged app role, so a query
//! that forgot its tenant scope reads nothing and fails loudly.

mod common;

use mokosh_test::mokosh_test;
use std::collections::VecDeque;
use std::sync::Mutex;

use async_trait::async_trait;
use mokosh_server::db::Database;
use mokosh_server::modules::auth::TenantId;
use mokosh_server::modules::contact_sync::provider::{
    ContactSyncProvider, SourceChanges, SourceContact, SourceError, SourceGroup, SourcePhone,
    SourceResult,
};
use mokosh_server::modules::contact_sync::sync::{ContactSyncEngine, PreviewTotals, SyncReport};
use sqlx::PgPool;
use uuid::Uuid;

const CLIENTS: &str = "contactGroups/clients";
const FRIENDS: &str = "contactGroups/friends";

/// An address book that answers from a script and remembers what cursor it
/// was handed.
struct FakeSource {
    reads: Mutex<VecDeque<SourceResult<SourceChanges>>>,
    tokens: Mutex<Vec<Option<String>>>,
}

impl FakeSource {
    fn new(reads: Vec<SourceResult<SourceChanges>>) -> Self {
        Self {
            reads: Mutex::new(reads.into()),
            tokens: Mutex::new(Vec::new()),
        }
    }

    fn push(&self, read: SourceResult<SourceChanges>) {
        self.reads.lock().unwrap().push_back(read);
    }
}

#[async_trait]
impl ContactSyncProvider for FakeSource {
    fn id(&self) -> &'static str {
        "google"
    }

    async fn list_groups(&self) -> SourceResult<Vec<SourceGroup>> {
        Ok(vec![
            SourceGroup {
                id: CLIENTS.into(),
                name: "Clients".into(),
                member_count: None,
            },
            SourceGroup {
                id: FRIENDS.into(),
                name: "Friends".into(),
                member_count: None,
            },
        ])
    }

    async fn changes_since(&self, sync_token: Option<&str>) -> SourceResult<SourceChanges> {
        self.tokens
            .lock()
            .unwrap()
            .push(sync_token.map(str::to_string));
        self.reads
            .lock()
            .unwrap()
            .pop_front()
            .expect("the fixture scripted no further read")
    }
}

fn person(external_id: &str, etag: &str, given: &str, family: &str) -> SourceContact {
    SourceContact {
        external_id: external_id.into(),
        etag: Some(etag.into()),
        display_name: Some(format!("{given} {family}")),
        given_name: Some(given.into()),
        family_name: Some(family.into()),
        emails: vec![],
        phones: vec![],
        organization: None,
        title: None,
        department: None,
        group_ids: vec![CLIENTS.into()],
        note: None,
        photo: None,
        dropped_properties: vec![],
        deleted: false,
    }
}

fn read(
    contacts: Vec<SourceContact>,
    token: &str,
    was_full_resync: bool,
) -> SourceResult<SourceChanges> {
    Ok(SourceChanges {
        contacts,
        next_sync_token: Some(token.into()),
        was_full_resync,
    })
}

struct Fixture {
    db: Database,
    pool: PgPool,
    connection_id: Uuid,
    tenant: TenantId,
}

impl Fixture {
    async fn new(pool: PgPool, selected: &[&str]) -> Self {
        let connection_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO contact_sync_connections \
             (id, tenant_id, provider, account_email, selected_groups) \
             VALUES ($1, $2, 'google', 'ops@msp.example', $3)",
        )
        .bind(connection_id)
        .bind(common::DEFAULT_TENANT_ID)
        .bind(serde_json::json!(selected))
        .execute(&pool)
        .await
        .expect("seed connection");
        let app_pool = common::build_app_role_pool(&pool).await;
        Self {
            db: Database::from_pools(app_pool, pool.clone()),
            pool,
            connection_id,
            tenant: TenantId::from_trusted(common::DEFAULT_TENANT_ID),
        }
    }

    async fn sync(&self, source: &FakeSource) -> Result<SyncReport, String> {
        ContactSyncEngine::new(self.db.clone())
            .run(self.tenant, self.connection_id, source)
            .await
            .map_err(|e| e.to_string())
    }

    async fn contact(
        &self,
        first: &str,
        last: &str,
        email: Option<&str>,
        company_name: Option<&str>,
    ) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO contacts (id, tenant_id, first_name, last_name, email, company_name) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(id)
        .bind(common::DEFAULT_TENANT_ID)
        .bind(first)
        .bind(last)
        .bind(email)
        .bind(company_name)
        .execute(&self.pool)
        .await
        .expect("seed contact");
        id
    }

    async fn phone(&self, contact_id: Uuid, number: &str) {
        sqlx::query(
            "INSERT INTO contact_phones (tenant_id, contact_id, phone_type, number, is_primary) \
             VALUES ($1, $2, 'work', $3, TRUE)",
        )
        .bind(common::DEFAULT_TENANT_ID)
        .bind(contact_id)
        .bind(number)
        .execute(&self.pool)
        .await
        .expect("seed phone");
    }

    async fn scalar<T>(&self, sql: &str) -> T
    where
        T: for<'r> sqlx::Decode<'r, sqlx::Postgres> + sqlx::Type<sqlx::Postgres> + Send + Unpin,
    {
        sqlx::query_scalar(sql)
            .fetch_one(&self.pool)
            .await
            .unwrap_or_else(|e| panic!("{sql}: {e}"))
    }

    async fn link_contact(&self, external_id: &str) -> Uuid {
        sqlx::query_scalar(
            "SELECT contact_id FROM contact_sync_links WHERE connection_id = $1 AND external_id = $2",
        )
        .bind(self.connection_id)
        .bind(external_id)
        .fetch_one(&self.pool)
        .await
        .expect("a link for the record")
    }

    /// Everything a sync could have written, as one comparable value.
    async fn state(&self) -> String {
        self.scalar::<String>(
            "SELECT concat_ws('|', \
                (SELECT count(*) FROM contacts), \
                (SELECT max(updated_at) FROM contacts), \
                (SELECT count(*) FROM contact_phones), \
                (SELECT string_agg(external_id || ':' || coalesce(etag, '') || ':' || coalesce(deleted_in_source_at::text, '') || ':' || updated_at::text, ',' ORDER BY external_id) FROM contact_sync_links), \
                (SELECT string_agg(external_id || ':' || candidate_contact_id || ':' || match_reason || ':' || status, ',' ORDER BY external_id, candidate_contact_id) FROM contact_sync_candidates), \
                (SELECT count(*) FROM audit_log))",
        )
        .await
    }
}

/// The fixture account: one exact email, one phone, one name-and-company, one
/// new person at a known company, and one outside the selected label.
fn fixture_account() -> Vec<SourceContact> {
    let mut ada = person("people/c1", "e1", "Ada", "Lovelace");
    ada.emails = vec!["ADA+crm@acme.example".into()];
    ada.title = Some("Analyst".into());

    let mut grace = person("people/c2", "e1", "Grace", "H");
    grace.phones = vec![SourcePhone {
        number: "(415) 555-0000".into(),
        canonical: Some("+14155550000".into()),
        label: Some("work".into()),
        is_primary: true,
    }];

    let mut sam = person("people/c3", "e1", "Sam", "Smith");
    sam.organization = Some("Acme Ltd".into());

    let mut nora = person("people/c4", "e1", "Nora", "New");
    nora.emails = vec!["nora@new.example".into(), "nora@home.example".into()];
    nora.organization = Some("acme ltd".into());
    nora.phones = vec![SourcePhone {
        number: "+44 20 7946 0000".into(),
        canonical: Some("+442079460000".into()),
        label: Some("mobile".into()),
        is_primary: false,
    }];

    let mut friend = person("people/c5", "e1", "Pal", "Personal");
    friend.emails = vec!["pal@friends.example".into()];
    friend.group_ids = vec![FRIENDS.into()];

    vec![ada, grace, sam, nora, friend]
}

/// The phase's "done when": the expected links, candidates and creates, and a
/// second run that changes nothing.
#[mokosh_test]
async fn a_sync_links_queues_and_creates_and_a_second_run_changes_nothing(pool: PgPool) {
    let f = Fixture::new(pool, &[CLIENTS]).await;
    let ada = f
        .contact("Ada", "Lovelace", Some("ada@acme.example"), None)
        .await;
    let grace = f.contact("Grace", "Hopper", None, None).await;
    f.phone(grace, "+14155550000").await;
    let sam = f.contact("Sam", "Smith", None, Some("Acme Ltd")).await;
    let acme = common::seed_company_named(&f.pool, "Acme Ltd").await;

    let source = FakeSource::new(vec![read(fixture_account(), "t1", false)]);
    let report = f.sync(&source).await.expect("first sync");
    assert_eq!(
        report,
        SyncReport {
            full_read: true,
            created: 1,
            linked: 1,
            queued: 2,
            not_selected: 1,
            total: 5,
            ..SyncReport::default()
        }
    );

    // Exact email, plus-addressed and cased differently: linked, filled only
    // where empty, and tagged with the selected label.
    assert_eq!(f.link_contact("people/c1").await, ada);
    let (title, email, tags): (Option<String>, Option<String>, Vec<String>) =
        sqlx::query_as("SELECT title, email, tags FROM contacts WHERE id = $1")
            .bind(ada)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(title.as_deref(), Some("Analyst"));
    assert_eq!(
        email.as_deref(),
        Some("ada@acme.example"),
        "the stored address is not rewritten"
    );
    assert_eq!(tags, vec!["Clients"]);

    // Phone and name-plus-company: questions, never merges.
    let candidates: Vec<(String, Uuid, String)> = sqlx::query_as(
        "SELECT external_id, candidate_contact_id, match_reason FROM contact_sync_candidates \
         WHERE status = 'open' ORDER BY external_id",
    )
    .fetch_all(&f.pool)
    .await
    .unwrap();
    assert_eq!(
        candidates,
        vec![
            ("people/c2".into(), grace, "phone".into()),
            ("people/c3".into(), sam, "name_company".into()),
        ]
    );

    // No match: created, company free text with a suggestion and no link.
    let nora = f.link_contact("people/c4").await;
    #[derive(sqlx::FromRow)]
    struct Created {
        email: Option<String>,
        company_id: Option<Uuid>,
        company_name: Option<String>,
        tags: Vec<String>,
        mobile: Option<String>,
    }
    let Created {
        email,
        company_id,
        company_name,
        tags,
        mobile,
    } = sqlx::query_as(
        "SELECT email, company_id, company_name, tags, mobile FROM contacts WHERE id = $1",
    )
    .bind(nora)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!(
        email.as_deref(),
        Some("nora@new.example"),
        "the primary email wins"
    );
    assert_eq!(company_id, None, "a company is never linked from free text");
    assert_eq!(company_name.as_deref(), Some("acme ltd"));
    assert_eq!(tags, vec!["Clients"]);
    assert_eq!(mobile.as_deref(), Some("+442079460000"));
    let suggested: Option<Uuid> = sqlx::query_scalar(
        "SELECT suggested_company_id FROM contact_sync_links WHERE external_id = 'people/c4'",
    )
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!(suggested, Some(acme));

    // Outside the selected label: nothing, not even a tag.
    assert_eq!(
        f.scalar::<i64>("SELECT count(*) FROM contacts WHERE email = 'pal@friends.example'")
            .await,
        0
    );
    assert_eq!(
        f.scalar::<i64>("SELECT count(*) FROM contacts WHERE 'Friends' = ANY(tags)")
            .await,
        0
    );

    let (status, token): (String, Option<String>) = sqlx::query_as(
        "SELECT sync_status, sync_token FROM contact_sync_connections WHERE id = $1",
    )
    .bind(f.connection_id)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!((status.as_str(), token.as_deref()), ("success", Some("t1")));

    // The same account again, handed back in full: nothing moves.
    let before = f.state().await;
    source.push(read(fixture_account(), "t1", false));
    let again = f.sync(&source).await.expect("second sync");
    assert!(!again.changed_anything(), "{again:?}");
    assert_eq!(again.unchanged, 2);
    assert_eq!(again.awaiting_review, 2);
    assert_eq!(f.state().await, before, "the second run wrote something");
    assert_eq!(
        *source.tokens.lock().unwrap(),
        vec![None, Some("t1".to_string())]
    );
}

/// An expired cursor is a clean full read: what is gone is flagged, and no
/// Mokosh contact is changed or removed (PSA-70 I).
#[mokosh_test]
async fn an_expired_cursor_resyncs_and_flags_what_is_gone_without_touching_contacts(pool: PgPool) {
    let f = Fixture::new(pool, &[CLIENTS]).await;
    let mut kept = person("people/k", "e1", "Kept", "Person");
    kept.emails = vec!["kept@acme.example".into()];
    let mut gone = person("people/g", "e1", "Gone", "Person");
    gone.emails = vec!["gone@acme.example".into()];

    let source = FakeSource::new(vec![read(vec![kept.clone(), gone.clone()], "t1", false)]);
    f.sync(&source).await.expect("initial import");
    let gone_contact = f.link_contact("people/g").await;
    let contact_before: String =
        sqlx::query_scalar("SELECT to_jsonb(c)::text FROM contacts c WHERE id = $1")
            .bind(gone_contact)
            .fetch_one(&f.pool)
            .await
            .unwrap();

    source.push(read(vec![kept.clone()], "t2", true));
    let report = f.sync(&source).await.expect("resync");
    assert!(report.full_read);
    assert_eq!(report.deleted_in_source, 1);
    assert_eq!(report.unchanged, 1);

    let flagged: bool = sqlx::query_scalar(
        "SELECT deleted_in_source_at IS NOT NULL FROM contact_sync_links WHERE external_id = 'people/g'",
    )
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert!(flagged);
    let contact_after: String =
        sqlx::query_scalar("SELECT to_jsonb(c)::text FROM contacts c WHERE id = $1")
            .bind(gone_contact)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(
        contact_after, contact_before,
        "a deletion in the source changes no Mokosh field"
    );
    assert_eq!(
        f.scalar::<Option<String>>(&format!(
            "SELECT sync_token FROM contact_sync_connections WHERE id = '{}'",
            f.connection_id
        ))
        .await
        .as_deref(),
        Some("t2")
    );

    // A delta naming a deletion flags it too, once.
    let mut deleted = person("people/k", "e2", "", "");
    deleted.deleted = true;
    deleted.group_ids.clear();
    source.push(read(vec![deleted.clone()], "t3", false));
    assert_eq!(f.sync(&source).await.unwrap().deleted_in_source, 1);
    source.push(read(vec![deleted], "t4", false));
    assert!(!f.sync(&source).await.unwrap().changed_anything());
    assert_eq!(f.scalar::<i64>("SELECT count(*) FROM contacts").await, 2);
}

/// A field a human locked is not overwritten; an unlocked one follows the
/// source; the address is never replaced (PSA-70 H).
#[mokosh_test]
async fn a_changed_source_respects_locks_and_never_replaces_the_email(pool: PgPool) {
    let f = Fixture::new(pool, &[CLIENTS]).await;
    let mut ada = person("people/c1", "e1", "Ada", "Lovelace");
    ada.emails = vec!["ada@acme.example".into()];
    ada.title = Some("Analyst".into());
    ada.department = Some("Engines".into());
    let source = FakeSource::new(vec![read(vec![ada.clone()], "t1", false)]);
    f.sync(&source).await.expect("import");
    let contact = f.link_contact("people/c1").await;

    sqlx::query(
        "INSERT INTO contact_field_locks (tenant_id, contact_id, field) VALUES ($1, $2, 'title')",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(contact)
    .execute(&f.pool)
    .await
    .unwrap();

    let mut changed = ada.clone();
    changed.etag = Some("e2".into());
    changed.given_name = Some("Augusta Ada".into());
    changed.title = Some("Countess".into());
    changed.department = None;
    changed.emails = vec!["ada@newdomain.example".into()];
    source.push(read(vec![changed], "t2", false));
    let report = f.sync(&source).await.expect("update");
    assert_eq!(report.updated, 1);

    let row: (String, Option<String>, Option<String>, Option<String>) =
        sqlx::query_as("SELECT first_name, title, department, email FROM contacts WHERE id = $1")
            .bind(contact)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(row.0, "Augusta Ada", "an unlocked field follows the source");
    assert_eq!(
        row.1.as_deref(),
        Some("Analyst"),
        "a locked field is left alone"
    );
    assert_eq!(
        row.2.as_deref(),
        Some("Engines"),
        "a value the source dropped is not erased"
    );
    assert_eq!(
        row.3.as_deref(),
        Some("ada@acme.example"),
        "the address is never replaced"
    );
}

/// A rate limit is `throttled` and a refused credential `reconnect_required`;
/// neither moves the cursor or writes a contact.
#[mokosh_test]
async fn a_source_failure_is_recorded_by_its_kind_and_keeps_the_cursor(pool: PgPool) {
    let f = Fixture::new(pool, &[CLIENTS]).await;
    let source = FakeSource::new(vec![
        read(vec![], "t1", false),
        Err(SourceError::Throttled),
        Err(SourceError::Unauthorized),
    ]);
    f.sync(&source).await.expect("first read");
    for expected in ["throttled", "reconnect_required"] {
        assert!(f.sync(&source).await.is_err());
        let (status, token): (String, Option<String>) = sqlx::query_as(
            "SELECT sync_status, sync_token FROM contact_sync_connections WHERE id = $1",
        )
        .bind(f.connection_id)
        .fetch_one(&f.pool)
        .await
        .unwrap();
        assert_eq!((status.as_str(), token.as_deref()), (expected, Some("t1")));
    }
    assert_eq!(f.scalar::<i64>("SELECT count(*) FROM contacts").await, 0);
}

/// A blank selection is "not chosen yet", never "import everything"
/// (PSA-70 E): the source is not even read.
#[mokosh_test]
async fn nothing_is_imported_before_a_label_is_chosen(pool: PgPool) {
    let f = Fixture::new(pool, &[]).await;
    let source = FakeSource::new(vec![read(fixture_account(), "t1", false)]);
    let refused = f.sync(&source).await.unwrap_err();
    assert!(
        refused.contains("Choose at least one Google label"),
        "{refused}"
    );
    assert!(source.tokens.lock().unwrap().is_empty());
    assert_eq!(f.scalar::<i64>("SELECT count(*) FROM contacts").await, 0);
}

/// PMS-1216 phase 10: the awkward account, driven through the real engine.
///
/// The ticket asks for verification against a real Google account holding
/// deliberately awkward data, "not fixtures alone", and that half needs a person
/// with an account and a browser. This is the half that does not: every SHAPE the
/// ticket names in one account, through `ContactSyncEngine::run` against the
/// RLS-bound app role, asserting what lands in `contacts` rather than what the
/// mapper returned.
///
/// The mapper's own tests already cover "Björk" and "王小明" as pure functions
/// (`contact_sync::mapping`), which is why this is not a second copy of them: what
/// is unpinned is whether such a record survives the whole path, where
/// `contacts.first_name` and `last_name` are `NOT NULL`, the matcher builds keys
/// from names, and the audit and link rows are written per record. A run is where
/// an empty `last_name` or a non-ASCII key would actually fail.
///
/// Anything that fails here would have failed against the real account too, so
/// the manual pass starts from a known-good baseline instead of debugging the
/// parser through a consent screen.
#[mokosh_test]
async fn the_awkward_account_imports_through_the_engine(pool: PgPool) {
    let f = Fixture::new(pool, &[CLIENTS]).await;

    // A Mokosh contact the twin records below should both resolve to.
    let existing = f
        .contact("Ada", "Lovelace", Some("ada@acme.example"), None)
        .await;

    // Several emails and several phones, primary first in each list, which is
    // how every source says "primary" here.
    let mut many = person("people/many", "e1", "Grace", "Hopper");
    many.emails = vec!["grace@work.example".into(), "grace@home.example".into()];
    many.phones = vec![
        SourcePhone {
            number: "(415) 555-0100".into(),
            canonical: Some("+14155550100".into()),
            label: Some("work".into()),
            is_primary: true,
        },
        SourcePhone {
            number: "+44 20 7946 0000".into(),
            canonical: Some("+442079460000".into()),
            label: Some("mobile".into()),
            is_primary: false,
        },
    ];

    // No email at all: nothing to match on by address, so it is a create.
    let mut no_email = person("people/no-email", "e1", "Nomail", "Person");
    no_email.emails = vec![];

    // A single name. `contacts.first_name` is NOT NULL and `last_name` is too,
    // so the whole name goes in the first and the last is empty rather than a
    // guess being split out of it.
    let mut single = person("people/single", "e1", "Prince", "");
    single.given_name = Some("Prince".into());
    single.family_name = None;
    single.display_name = Some("Prince".into());
    single.emails = vec!["prince@paisley.example".into()];

    // A non-Latin script name, which has to survive the key building and the
    // column, not only the mapper.
    let mut cjk = person("people/cjk", "e1", "", "");
    cjk.given_name = None;
    cjk.family_name = None;
    cjk.display_name = Some("王小明".into());
    cjk.emails = vec!["wang@example.cn".into()];

    // Two records for one Mokosh contact: the exact address links, and the
    // second record carrying the same address is a question rather than a
    // second contact.
    let mut twin_a = person("people/twin-a", "e1", "Ada", "Lovelace");
    twin_a.emails = vec!["ada@acme.example".into()];
    let mut twin_b = person("people/twin-b", "e1", "A.", "Lovelace");
    twin_b.emails = vec!["ada@acme.example".into()];

    // Outside every group: not in the selection, so not imported at all.
    let mut ungrouped = person("people/ungrouped", "e1", "Not", "Selected");
    ungrouped.group_ids = vec![];
    ungrouped.emails = vec!["nobody@elsewhere.example".into()];

    let account = vec![many, no_email, single, cjk, twin_a, twin_b, ungrouped];
    let source = FakeSource::new(vec![read(account.clone(), "t1", false)]);
    let report = f.sync(&source).await.expect("the awkward account imports");

    assert_eq!(
        (report.not_selected, report.failed, report.total),
        (1, 0, 7),
        "the ungrouped record is skipped and nothing fails: {report:?}"
    );
    assert_eq!(
        report.created + report.linked + report.queued,
        6,
        "every selected record is accounted for: {report:?}"
    );

    // The single name kept whole, in the column that is NOT NULL.
    let (first, last): (String, String) = sqlx::query_as(
        "SELECT first_name, last_name FROM contacts c          JOIN contact_sync_links l ON l.contact_id = c.id          WHERE l.external_id = $1",
    )
    .bind("people/single")
    .fetch_one(&f.pool)
    .await
    .expect("the single-name contact landed");
    assert_eq!(
        (first.as_str(), last.as_str()),
        ("Prince", ""),
        "a single name is kept whole rather than split by a guess"
    );

    // The non-Latin name, byte for byte, after a round trip through the keys,
    // the column and Postgres' own collation.
    let cjk_first: String = sqlx::query_scalar(
        "SELECT c.first_name FROM contacts c          JOIN contact_sync_links l ON l.contact_id = c.id          WHERE l.external_id = $1",
    )
    .bind("people/cjk")
    .fetch_one(&f.pool)
    .await
    .expect("the non-Latin contact landed");
    assert_eq!(cjk_first, "王小明");

    // Several phones: both numbers are kept, the primary one first.
    let phones: Vec<(String, bool)> = sqlx::query_as(
        "SELECT p.number, p.is_primary FROM contact_phones p          JOIN contact_sync_links l ON l.contact_id = p.contact_id          WHERE l.external_id = $1 ORDER BY p.is_primary DESC, p.number",
    )
    .bind("people/many")
    .fetch_all(&f.pool)
    .await
    .expect("read the phones");
    assert_eq!(phones.len(), 2, "both numbers survive: {phones:?}");
    assert!(phones[0].1, "the primary number is the primary row");

    // One contact, not two, for the twin records: the first linked and the
    // second became a question.
    assert_eq!(f.link_contact("people/twin-a").await, existing);
    let twin_b_open: i64 = f
        .scalar(
            "SELECT count(*) FROM contact_sync_candidates              WHERE external_id = 'people/twin-b' AND status = 'open'",
        )
        .await;
    assert_eq!(
        twin_b_open, 1,
        "the second record is asked about, not merged"
    );
    assert_eq!(
        f.scalar::<i64>("SELECT count(*) FROM contacts WHERE email = 'ada@acme.example'")
            .await,
        1,
        "two records for one address must not become two contacts"
    );

    // Nothing was imported for the record outside every group.
    assert_eq!(
        f.scalar::<i64>(
            "SELECT count(*) FROM contact_sync_links WHERE external_id = 'people/ungrouped'"
        )
        .await,
        0
    );

    // The second run changes nothing, which is the ticket's own "same sync
    // twice" run and the property every awkward shape above has to preserve.
    let before = f.state().await;
    source.push(read(account, "t2", false));
    let second = f.sync(&source).await.expect("second sync");
    assert_eq!(
        (second.created, second.linked, second.queued, second.failed),
        (0, 0, 0, 0),
        "a second run of the awkward account changes nothing: {second:?}"
    );
    assert_eq!(before, f.state().await, "no row moved on the second run");
}

/// PMS-1358: the label filter is re-applied on every sync, and a contact that
/// LEAVES the selected label is kept rather than deleted.
///
/// David's requirement was to import only the label that names his clients, and
/// the half that is easy to get wrong is what happens later: a contact moved out
/// of that label must stop being updated (the MSP no longer agreed to hold its
/// data) without being tombstoned (the MSP still holds the contact). The second
/// read here is a FULL one, which is where a tombstone would come from: the
/// record is present in the read, so `seen` covers it, and the filter is the only
/// thing that decides not to apply it.
#[mokosh_test]
async fn a_contact_that_leaves_the_selected_label_is_kept_and_stops_being_updated(pool: PgPool) {
    let f = Fixture::new(pool, &[CLIENTS]).await;
    let ada = f
        .contact("Ada", "Lovelace", Some("ada@acme.example"), None)
        .await;

    let mut inside = person("people/c1", "e1", "Ada", "Lovelace");
    inside.emails = vec!["ada@acme.example".into()];
    inside.title = Some("Analyst".into());
    let source = FakeSource::new(vec![read(vec![inside], "t1", false)]);
    assert_eq!(
        f.sync(&source).await.expect("the first sync"),
        SyncReport {
            full_read: true,
            linked: 1,
            total: 1,
            ..SyncReport::default()
        }
    );
    assert_eq!(f.link_contact("people/c1").await, ada);

    // The same person in Friends instead, with a new etag and a new title, so a
    // record that WAS applied would be visibly different afterwards.
    let mut moved = person("people/c1", "e2", "Ada", "Lovelace");
    moved.emails = vec!["ada@acme.example".into()];
    moved.title = Some("Countess".into());
    moved.group_ids = vec![FRIENDS.into()];
    source.push(read(vec![moved], "t2", true));
    assert_eq!(
        f.sync(&source).await.expect("the second sync"),
        SyncReport {
            full_read: true,
            not_selected: 1,
            total: 1,
            ..SyncReport::default()
        }
    );

    #[derive(sqlx::FromRow)]
    struct After {
        title: Option<String>,
        tags: Vec<String>,
    }
    let after: After = sqlx::query_as("SELECT title, tags FROM contacts WHERE id = $1")
        .bind(ada)
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        after.title.as_deref(),
        Some("Analyst"),
        "the record left the selection, so nothing about it is written"
    );
    assert_eq!(
        after.tags,
        vec!["Clients"],
        "the tag the import agreed to is kept; a sync that no longer applies the record does not \
         retag it, and Friends was never selected so it could not become a tag either"
    );

    let (etag, deleted): (Option<String>, Option<chrono::DateTime<chrono::Utc>>) = sqlx::query_as(
        "SELECT etag, deleted_in_source_at FROM contact_sync_links WHERE external_id = $1",
    )
    .bind("people/c1")
    .fetch_one(&f.pool)
    .await
    .expect("the link survives");
    assert_eq!(
        etag.as_deref(),
        Some("e1"),
        "the etag is the one that was applied, not the one that was skipped"
    );
    assert!(
        deleted.is_none(),
        "leaving a label is not being deleted in the source, and a full read must not say it is"
    );
    assert_eq!(f.scalar::<i64>("SELECT count(*) FROM contacts").await, 1);
}

/// PMS-1433: iCloud's delta carries group membership on the group card, not
/// the contact's own, so an incremental run whose card set held no group card
/// for a record reports `group_ids: []` even though the contact's real
/// membership has not changed. An already-linked contact must keep syncing
/// its own-card edits on such a delta instead of being routed to
/// `Plan::NotSelected` on the strength of an empty `group_ids` alone.
#[mokosh_test]
async fn a_linked_contact_keeps_syncing_on_a_delta_with_no_group_card(pool: PgPool) {
    let f = Fixture::new(pool, &[CLIENTS]).await;

    let mut linked = person("people/c1", "e1", "Jane", "Doe");
    linked.emails = vec!["jane@acme.example".into()];
    let source = FakeSource::new(vec![read(vec![linked], "t1", false)]);
    assert_eq!(
        f.sync(&source).await.expect("the first sync"),
        SyncReport {
            full_read: true,
            created: 1,
            total: 1,
            ..SyncReport::default()
        }
    );
    let jane = f.link_contact("people/c1").await;

    // A phone-number edit only: a new etag, no group card in this delta, so
    // `group_ids` arrives empty even though Jane is still in Clients.
    let mut edited = person("people/c1", "e2", "Jane", "Doe");
    edited.emails = vec!["jane@acme.example".into()];
    edited.group_ids = vec![];
    edited.phones = vec![SourcePhone {
        number: "+14155551234".into(),
        canonical: Some("+14155551234".into()),
        label: Some("mobile".into()),
        is_primary: true,
    }];
    source.push(read(vec![edited], "t2", false));
    assert_eq!(
        f.sync(&source).await.expect("the incremental sync"),
        SyncReport {
            full_read: false,
            updated: 1,
            total: 1,
            ..SyncReport::default()
        },
        "an empty group_ids on an incremental delta must not route an already-linked record to NotSelected"
    );

    #[derive(sqlx::FromRow)]
    struct After {
        phones: i64,
    }
    let after: After = sqlx::query_as(
        "SELECT (SELECT count(*) FROM contact_phones WHERE contact_id = $1) AS phones",
    )
    .bind(jane)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!(after.phones, 1, "the phone-number edit was applied");

    let etag: Option<String> =
        sqlx::query_scalar("SELECT etag FROM contact_sync_links WHERE external_id = $1")
            .bind("people/c1")
            .fetch_one(&f.pool)
            .await
            .expect("the link");
    assert_eq!(
        etag.as_deref(),
        Some("e2"),
        "the link's etag advanced with the applied edit"
    );
}

/// PMS-1433: the fix above must not mask a genuine deselection. A contact
/// removed from every selected group still resolves to `Plan::NotSelected`
/// even on an incremental delta, because the group card that changed to drop
/// the member is itself present in that delta and reports the membership
/// (`group_ids`) explicitly, just no longer including a selected group.
#[mokosh_test]
async fn a_contact_dropped_from_every_selected_group_on_a_delta_is_still_not_selected(
    pool: PgPool,
) {
    let f = Fixture::new(pool, &[CLIENTS]).await;

    let mut linked = person("people/c1", "e1", "Jane", "Doe");
    linked.emails = vec!["jane@acme.example".into()];
    let source = FakeSource::new(vec![read(vec![linked], "t1", false)]);
    assert_eq!(
        f.sync(&source).await.expect("the first sync"),
        SyncReport {
            full_read: true,
            created: 1,
            total: 1,
            ..SyncReport::default()
        }
    );
    let jane = f.link_contact("people/c1").await;

    // The provider reports the group card that changed: Jane moved out of
    // Clients into Friends, a real membership answer, not an absent one.
    let mut moved = person("people/c1", "e2", "Jane", "Doe");
    moved.emails = vec!["jane@acme.example".into()];
    moved.group_ids = vec![FRIENDS.into()];
    source.push(read(vec![moved], "t2", false));
    assert_eq!(
        f.sync(&source).await.expect("the incremental sync"),
        SyncReport {
            full_read: false,
            not_selected: 1,
            total: 1,
            ..SyncReport::default()
        },
        "a record whose delta explicitly reports its (non-selected) groups is still refused"
    );

    let etag: Option<String> =
        sqlx::query_scalar("SELECT etag FROM contact_sync_links WHERE external_id = $1")
            .bind("people/c1")
            .fetch_one(&f.pool)
            .await
            .expect("the link survives");
    assert_eq!(
        etag.as_deref(),
        Some("e1"),
        "the deselected edit was never applied"
    );
    assert_eq!(
        jane,
        f.link_contact("people/c1").await,
        "the link is untouched, not deleted"
    );
}

/// A question a human answered is not asked again when the record changes.
#[mokosh_test]
async fn an_answered_question_is_not_asked_again(pool: PgPool) {
    let f = Fixture::new(pool, &[CLIENTS]).await;
    let grace = f.contact("Grace", "Hopper", None, None).await;
    f.phone(grace, "+14155550000").await;
    let mut record = person("people/c2", "e1", "G", "H");
    record.phones = vec![SourcePhone {
        number: "+1 415 555 0000".into(),
        canonical: None,
        label: None,
        is_primary: true,
    }];
    let source = FakeSource::new(vec![read(vec![record.clone()], "t1", false)]);
    assert_eq!(f.sync(&source).await.unwrap().queued, 1);

    sqlx::query("UPDATE contact_sync_candidates SET status = 'skipped', resolved_at = NOW()")
        .execute(&f.pool)
        .await
        .unwrap();
    record.etag = Some("e2".into());
    source.push(read(vec![record], "t2", false));
    let report = f.sync(&source).await.unwrap();
    assert_eq!(report.already_reviewed, 1);
    assert_eq!(
        f.scalar::<i64>("SELECT count(*) FROM contact_sync_candidates WHERE status = 'open'")
            .await,
        0
    );
}

/// Two source records for one address, neither known to Mokosh: the first is
/// created, the second is a question, never a second contact.
#[mokosh_test]
async fn two_records_for_one_address_do_not_create_two_contacts(pool: PgPool) {
    let f = Fixture::new(pool, &[CLIENTS]).await;
    let mut one = person("people/a", "e1", "Jo", "Smith");
    one.emails = vec!["jo+work@acme.example".into()];
    let mut two = person("people/b", "e1", "Jo", "Smith");
    two.emails = vec!["jo@acme.example".into()];
    let source = FakeSource::new(vec![read(vec![one, two], "t1", false)]);
    let report = f.sync(&source).await.unwrap();
    assert_eq!((report.created, report.queued), (1, 1));
    assert_eq!(f.scalar::<i64>("SELECT count(*) FROM contacts").await, 1);
    assert_eq!(
        f.scalar::<String>("SELECT match_reason FROM contact_sync_candidates")
            .await,
        "email_ambiguous"
    );
}

/// PMS-1242: the preview says what the import will do, and writes nothing.
/// Previewed, then imported: the counts agree.
#[mokosh_test]
async fn a_preview_writes_nothing_and_agrees_with_the_import(pool: PgPool) {
    let f = Fixture::new(pool, &[CLIENTS]).await;
    f.contact("Ada", "Lovelace", Some("ada@acme.example"), None)
        .await;
    let grace = f.contact("Grace", "Hopper", None, None).await;
    f.phone(grace, "+14155550000").await;
    f.contact("Sam", "Smith", None, Some("Acme Ltd")).await;
    // A second new record for Nora's address: one create, one question.
    let mut twin = person("people/c6", "e1", "Nora", "Twin");
    twin.emails = vec!["nora@new.example".into()];
    let mut account = fixture_account();
    account.push(twin);

    let source = FakeSource::new(vec![
        read(account.clone(), "unused", false),
        read(account.clone(), "unused", false),
        read(account, "t1", false),
    ]);
    let engine = ContactSyncEngine::new(f.db.clone());
    let before = f.state().await;

    // Every labelled record, Friends included: per-label figures from one read.
    let everything = engine
        .preview(f.tenant, f.connection_id, &source, None)
        .await
        .expect("preview");
    assert_eq!(
        everything.totals,
        PreviewTotals {
            contacts: 6,
            create: 2,
            link: 1,
            review: 3,
            imported: 0,
            excluded: 0
        }
    );
    assert_eq!(everything.groups.len(), 2);
    let friends = everything
        .records
        .iter()
        .filter(|r| r.group_ids == vec![FRIENDS.to_string()])
        .count();
    assert_eq!(friends, 1);

    // Narrowed to Clients: exact for that selection.
    let clients: std::collections::BTreeSet<String> = [CLIENTS.to_string()].into();
    let narrowed = engine
        .preview(f.tenant, f.connection_id, &source, Some(&clients))
        .await
        .expect("preview");
    assert_eq!(
        narrowed.totals,
        PreviewTotals {
            contacts: 5,
            create: 1,
            link: 1,
            review: 3,
            imported: 0,
            excluded: 0
        }
    );
    let serialized = serde_json::to_string(&narrowed).unwrap();
    for personal in ["nora@new.example", "Lovelace", "+1415"] {
        assert!(
            !serialized.contains(personal),
            "the preview names nobody: {personal}"
        );
    }
    assert_eq!(f.state().await, before, "a preview writes nothing");
    assert_eq!(
        f.scalar::<Option<String>>(&format!(
            "SELECT sync_token FROM contact_sync_connections WHERE id = '{}'",
            f.connection_id
        ))
        .await,
        None,
        "not even the cursor"
    );

    // Now import exactly that selection.
    let report = f.sync(&source).await.expect("import");
    assert_eq!(
        (report.created, report.linked, report.queued),
        (
            narrowed.totals.create,
            narrowed.totals.link,
            narrowed.totals.review
        ),
        "{report:?}"
    );
}
