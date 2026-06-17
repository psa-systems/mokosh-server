//! On-demand QA walkthrough dataset seeding (PMS-331).
//!
//! Unlike the lazy first-visit demo seed ([`super::service::SeedService`]),
//! this is an **operator-triggered** seed (run via `mokosh-bootstrap qa-seed
//! --tenant <id>`) that loads a small but realistic, *related* dataset into a
//! **dedicated QA tenant only**, so the staging walkthrough (PMS-326) can
//! exercise list sorting, filtering, pagination, grouping, reports, and
//! relationship features that an empty tenant cannot.
//!
//! # Hard guardrail (fail closed)
//!
//! The seed and teardown MUST only ever touch a tenant explicitly marked QA.
//! [`confirm_qa_tenant`] is called first by both entry points and **refuses
//! (error, zero writes)** unless the target tenant's `settings->>'is_qa'`
//! parses to `true`. A tenant whose `settings->>'environment'` is
//! `production` is rejected outright even if mismarked, and a missing tenant
//! row also fails closed. There is no flag that lets the seed run against an
//! unmarked tenant, so pointing it at production or a real customer tenant
//! can never write anything.
//!
//! # Shape of the dataset
//!
//! Everything is QA-prefixed (`QA-` in names, `qa-seed` tag where the entity
//! carries tags) so it is trivially searchable and removable:
//!
//! - 8 companies across every [`CompanyType`] (client/prospect/vendor/
//!   partner), some with full addresses, a parent with two children, and
//!   account managers.
//! - ~16 contacts spread across those companies, varied roles, one primary
//!   per company, varied phones/emails.
//! - 35 tickets (enough to paginate the primary list at the default 25/page)
//!   cycling every priority and status, several companies/contacts/assignees,
//!   staggered dates, and a mix of billable/non-billable.
//! - 2 projects with phases and tasks, varied status and budget.
//! - 8 time entries with fractional hours, billable and non-billable, linked
//!   to tickets and projects.
//! - One contract of every type, and two invoices with multiple line items
//!   plus payments (one paid in full, one partial).
//!
//! # Idempotency and teardown
//!
//! [`qa_seed`] is idempotent: if any `QA-` company already exists in the
//! tenant it skips without inserting, so re-running never duplicates.
//! [`qa_teardown`] removes the dataset (and the QA lookup rows it created) in
//! FK-dependency order, leaving the tenant's stock configuration intact.

use std::fmt;

use chrono::{Duration, NaiveDate, Utc};
use rust_decimal::Decimal;
use uuid::Uuid;

use crate::db::Database;
use crate::modules::audit::AuditCtx;
use crate::modules::auth::TenantId;
use crate::modules::billing::{
    BillingService, CreateInvoiceLineRequest, CreateInvoiceRequest, CreatePaymentRequest,
    InvoiceLineType, PaymentMethod,
};
use crate::modules::contacts::{
    Address, CompanyStatus, CompanyType, ContactService, ContactType, CreateCompanyRequest,
    CreateContactRequest, PreferredContactMethod,
};
use crate::modules::contracts::{ContractsService, CreateContractRequest};
use crate::modules::projects::{
    CreateProjectRequest, CreateTaskRequest, ProjectsService, UpsertProjectPhaseRequest,
    UpsertTaskStatusRequest,
};
use crate::modules::tickets::{CreateTicketRequest, TicketService, TicketSource};
use crate::modules::time_tracking::{
    CreateTimeEntryRequest, TimeTrackingService, UpsertWorkTypeRequest,
};
use crate::utils::error::{AppError, AppResult};

/// Name prefix applied to every QA record that has a name, so operators can
/// find and bulk-remove the dataset at a glance.
const QA_PREFIX: &str = "QA-";
/// Tag applied to every QA record that carries a `tags` column.
const QA_TAG: &str = "qa-seed";
/// Number of tickets to seed. Larger than the default page size (25) so the
/// primary ticket list paginates, but still "small".
const QA_TICKET_COUNT: usize = 35;

/// Summary of what a seed or teardown run did, for operator-facing output.
#[derive(Debug, Default, Clone)]
pub struct QaReport {
    pub skipped: bool,
    pub companies: usize,
    pub contacts: usize,
    pub tickets: usize,
    pub projects: usize,
    pub phases: usize,
    pub tasks: usize,
    pub time_entries: usize,
    pub contracts: usize,
    pub invoices: usize,
    pub payments: usize,
}

impl fmt::Display for QaReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.skipped {
            return write!(
                f,
                "QA dataset already present; nothing written (idempotent skip)."
            );
        }
        write!(
            f,
            "companies={} contacts={} tickets={} projects={} phases={} tasks={} \
             time_entries={} contracts={} invoices={} payments={}",
            self.companies,
            self.contacts,
            self.tickets,
            self.projects,
            self.phases,
            self.tasks,
            self.time_entries,
            self.contracts,
            self.invoices,
            self.payments,
        )
    }
}

/// Fail-closed guardrail. Returns `Ok(())` ONLY when `tenant_id` is an
/// existing tenant explicitly marked QA (`settings->>'is_qa' = true`) and not
/// flagged as a production environment. Every other case errors with zero
/// writes:
///
/// - tenant row does not exist,
/// - `settings` is null / missing the `is_qa` key / `is_qa` is not `true`,
/// - `settings->>'environment'` is `production`.
///
/// Mark a QA tenant explicitly before seeding, e.g.:
/// `UPDATE tenants SET settings = jsonb_set(COALESCE(settings,'{}'::jsonb),
/// '{is_qa}', 'true'::jsonb, true) WHERE id = '<qa-tenant-id>';`
pub async fn confirm_qa_tenant(db: &Database, tenant_id: Uuid) -> AppResult<()> {
    // `tenants` is the RLS-exempt isolation root (migration 038), so reading
    // the marker on the migrator pool is correct and avoids needing a tenant
    // GUC just to look up the tenant's own settings.
    let settings: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT settings FROM tenants WHERE id = $1")
            .bind(tenant_id)
            .fetch_optional(db.migrator_pool())
            .await?;

    let settings = match settings {
        Some(s) => s,
        None => {
            return Err(AppError::BadRequest(format!(
                "QA seed refused: tenant {tenant_id} does not exist (fail closed, zero writes)."
            )));
        }
    };

    let environment = settings
        .get("environment")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if environment.eq_ignore_ascii_case("production") || environment.eq_ignore_ascii_case("prod") {
        return Err(AppError::Forbidden(format!(
            "QA seed refused: tenant {tenant_id} is marked environment=production. \
             The QA seed must never run against production (fail closed, zero writes)."
        )));
    }

    let is_qa = settings
        .get("is_qa")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if !is_qa {
        return Err(AppError::Forbidden(format!(
            "QA seed refused: tenant {tenant_id} is not marked as QA \
             (settings->>'is_qa' must be true). Refusing to write to a tenant whose QA status \
             cannot be confirmed (fail closed, zero writes)."
        )));
    }

    Ok(())
}

/// Seed the QA dataset into `tenant_id`. Confirms the QA marker first
/// (fail closed) and is idempotent: a no-op if the dataset is already present.
pub async fn qa_seed(db: &Database, tenant_id: Uuid) -> AppResult<QaReport> {
    confirm_qa_tenant(db, tenant_id).await?;
    QaSeeder::new(db.clone()).seed(tenant_id).await
}

/// Remove the QA dataset (and the QA lookup rows it created) from `tenant_id`.
/// Confirms the QA marker first (fail closed). Safe to run repeatedly.
pub async fn qa_teardown(db: &Database, tenant_id: Uuid) -> AppResult<QaReport> {
    confirm_qa_tenant(db, tenant_id).await?;
    teardown(db, tenant_id).await
}

/// Bundles the service layer the seed drives. Cheap to construct (each
/// service holds an `Arc`/`Clone` `Database`).
struct QaSeeder {
    db: Database,
    contacts: ContactService,
    tickets: TicketService,
    projects: ProjectsService,
    time: TimeTrackingService,
    contracts: ContractsService,
    billing: BillingService,
}

impl QaSeeder {
    fn new(db: Database) -> Self {
        Self {
            contacts: ContactService::new(db.clone()),
            tickets: TicketService::new(db.clone()),
            projects: ProjectsService::new(db.clone()),
            time: TimeTrackingService::new(db.clone()),
            contracts: ContractsService::new(db.clone()),
            billing: BillingService::new(db.clone()),
            db,
        }
    }

    async fn seed(&self, tid: Uuid) -> AppResult<QaReport> {
        // Idempotency: any pre-existing QA company means we have already
        // seeded this tenant. Bail without writing so re-runs never duplicate.
        if self.qa_companies_exist(tid).await? {
            return Ok(QaReport {
                skipped: true,
                ..Default::default()
            });
        }

        // The seed must be attributed to a real user in the tenant (tickets
        // record a creator, time entries a user). Fail clearly if the QA
        // tenant has no users yet rather than inserting orphaned rows.
        let user_id = self.first_user(tid).await?;
        let tenant = TenantId::from_trusted(tid);
        let ctx = AuditCtx::system(tid);

        let priorities = self.ticket_priority_ids(tid).await?;
        let statuses = self.ticket_status_ids(tid).await?;
        let work_type_id = self.ensure_qa_work_type(tenant).await?;
        let task_status_id = self.ensure_qa_task_status(tenant).await?;

        let mut report = QaReport::default();

        // --- Companies (across every type; one parent with two children) ---
        let parent = self
            .contacts
            .create_company(tenant, &qa_company_parent(user_id), &ctx)
            .await?;
        report.companies += 1;

        let mut company_ids: Vec<Uuid> = vec![parent.id];
        for spec in qa_company_specs(user_id, parent.id) {
            let c = self.contacts.create_company(tenant, &spec, &ctx).await?;
            company_ids.push(c.id);
            report.companies += 1;
        }

        // --- Contacts (>=1 per company, one primary each) ---
        let mut primary_contact: Vec<Uuid> = Vec::with_capacity(company_ids.len());
        for (i, &company_id) in company_ids.iter().enumerate() {
            let reqs = qa_contacts_for(company_id, i);
            let mut first = None;
            for req in &reqs {
                let contact = self.contacts.create_contact(tenant, req, &ctx).await?;
                report.contacts += 1;
                if first.is_none() {
                    first = Some(contact.id);
                }
            }
            primary_contact.push(first.expect("each company seeds >=1 contact"));
        }

        // --- Tickets (paginating primary list, every status/priority/date) ---
        let now = Utc::now();
        for i in 0..QA_TICKET_COUNT {
            let ci = i % company_ids.len();
            let company_id = company_ids[ci];
            let contact_id = primary_contact[ci];
            let priority_id = priorities.get(i % priorities.len().max(1)).copied();
            let req = qa_ticket(i, company_id, contact_id, priority_id, user_id);
            let ticket = self
                .tickets
                .create_ticket(tenant, user_id, &req, &ctx)
                .await?;
            report.tickets += 1;

            // create_ticket always applies the tenant's default status and
            // stamps created_at = NOW(). Restamp here to spread tickets across
            // every status (incl. closed) and across the last ~70 days so the
            // status filter, the open/closed split, and date-range filters all
            // have something to discriminate.
            if let Some(&status_id) = statuses.get(i % statuses.len().max(1)) {
                let created_at = now - Duration::days((i as i64) * 2);
                self.restamp_ticket(tid, ticket.id, status_id, created_at)
                    .await?;
            }
        }

        // --- Projects with phases and tasks ---
        for (pi, spec) in qa_project_specs(&company_ids, user_id)
            .into_iter()
            .enumerate()
        {
            let project = self.projects.create_project(tenant, &spec, &ctx).await?;
            report.projects += 1;

            for phase_spec in qa_phase_specs(pi) {
                let phase = self
                    .projects
                    .create_project_phase(tenant, project.id, &phase_spec, &ctx)
                    .await?;
                report.phases += 1;

                for task_spec in qa_task_specs(pi, phase.id, task_status_id, user_id) {
                    self.projects
                        .create_task(tenant, project.id, &task_spec, &ctx)
                        .await?;
                    report.tasks += 1;
                }
            }
        }

        // --- Time entries (fractional hours, billable + non-billable) ---
        // Fetch the freshly-seeded QA project ids so entries can link to them.
        let project_ids = self.qa_project_ids(tid).await?;
        let ticket_ids = self.qa_ticket_ids(tid).await?;
        for spec in qa_time_entries(
            user_id,
            work_type_id,
            &company_ids,
            &ticket_ids,
            &project_ids,
        ) {
            self.time.create_time_entry(tenant, &spec, &ctx).await?;
            report.time_entries += 1;
        }

        // --- One contract of every type ---
        for spec in qa_contract_specs(&company_ids) {
            self.contracts.create_contract(tenant, &spec, &ctx).await?;
            report.contracts += 1;
        }

        // --- Invoices with line items + payments ---
        for (inv_spec, pay_fraction) in qa_invoice_specs(&company_ids) {
            let total: Decimal = inv_spec
                .lines
                .iter()
                .map(|l| l.quantity * l.unit_price)
                .sum();
            let company_id = inv_spec.company_id;
            let invoice = self.billing.create_invoice(tenant, &inv_spec, &ctx).await?;
            report.invoices += 1;

            if let Some(fraction) = pay_fraction {
                let amount = (total * fraction).round_dp(2);
                let pay = CreatePaymentRequest {
                    invoice_id: Some(invoice.id),
                    company_id,
                    payment_date: today() - Duration::days(2),
                    amount,
                    payment_method: PaymentMethod::Check,
                    reference_number: Some(format!("{QA_PREFIX}PAY-{}", report.payments + 1)),
                    gateway_transaction_id: None,
                    notes: Some("QA seed payment".to_string()),
                };
                self.billing.create_payment(tenant, &pay, &ctx).await?;
                report.payments += 1;
            }
        }

        Ok(report)
    }

    // --- Lookup helpers -----------------------------------------------------

    async fn qa_companies_exist(&self, tid: Uuid) -> AppResult<bool> {
        let mut tx = self.db.begin_with_tenant(tid).await?;
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM companies WHERE tenant_id = $1 AND name LIKE $2)",
        )
        .bind(tid)
        .bind(format!("{QA_PREFIX}%"))
        .fetch_one(&mut *tx)
        .await?;
        Ok(exists)
    }

    async fn first_user(&self, tid: Uuid) -> AppResult<Uuid> {
        let mut tx = self.db.begin_with_tenant(tid).await?;
        let id: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM users WHERE tenant_id = $1 ORDER BY created_at LIMIT 1",
        )
        .bind(tid)
        .fetch_optional(&mut *tx)
        .await?;
        id.ok_or_else(|| {
            AppError::BadRequest(format!(
                "QA seed refused: tenant {tid} has no users to attribute records to. \
                 Provision at least one user in the QA tenant first."
            ))
        })
    }

    async fn ticket_priority_ids(&self, tid: Uuid) -> AppResult<Vec<Uuid>> {
        let mut tx = self.db.begin_with_tenant(tid).await?;
        let ids: Vec<Uuid> = sqlx::query_scalar(
            "SELECT id FROM ticket_priorities WHERE tenant_id = $1 ORDER BY sort_order",
        )
        .bind(tid)
        .fetch_all(&mut *tx)
        .await?;
        Ok(ids)
    }

    async fn ticket_status_ids(&self, tid: Uuid) -> AppResult<Vec<Uuid>> {
        let mut tx = self.db.begin_with_tenant(tid).await?;
        let ids: Vec<Uuid> = sqlx::query_scalar(
            "SELECT id FROM ticket_statuses WHERE tenant_id = $1 ORDER BY sort_order",
        )
        .bind(tid)
        .fetch_all(&mut *tx)
        .await?;
        Ok(ids)
    }

    /// Create a dedicated QA work type (name-prefixed so teardown can remove
    /// it). Time entries require a work_type_id that exists in the tenant.
    async fn ensure_qa_work_type(&self, tenant: TenantId) -> AppResult<Uuid> {
        let req = UpsertWorkTypeRequest {
            name: format!("{QA_PREFIX}Consulting"),
            description: Some("QA seed work type".to_string()),
            default_billable: true,
            default_rate: Some(Decimal::new(15000, 2)),
            is_active: true,
            sort_order: 100,
        };
        let ctx = AuditCtx::system(tenant.get());
        let wt = self.time.create_work_type(tenant, &req, &ctx).await?;
        Ok(wt.id)
    }

    /// Reuse an existing task status if the tenant has one (copy_default_config
    /// seeds them), else create a QA one. Tasks require a status_id.
    async fn ensure_qa_task_status(&self, tenant: TenantId) -> AppResult<Uuid> {
        let mut tx = self.db.begin_with_tenant(tenant).await?;
        let existing: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM task_statuses WHERE tenant_id = $1 ORDER BY sort_order LIMIT 1",
        )
        .bind(tenant)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        if let Some(id) = existing {
            return Ok(id);
        }
        let req = UpsertTaskStatusRequest {
            name: format!("{QA_PREFIX}Open"),
            color: "#3b82f6".to_string(),
            is_completed: false,
            sort_order: 100,
        };
        let ctx = AuditCtx::system(tenant.get());
        let st = self.projects.create_task_status(tenant, &req, &ctx).await?;
        Ok(st.id)
    }

    async fn qa_project_ids(&self, tid: Uuid) -> AppResult<Vec<Uuid>> {
        let mut tx = self.db.begin_with_tenant(tid).await?;
        let ids: Vec<Uuid> =
            sqlx::query_scalar("SELECT id FROM projects WHERE tenant_id = $1 AND name LIKE $2")
                .bind(tid)
                .bind(format!("{QA_PREFIX}%"))
                .fetch_all(&mut *tx)
                .await?;
        Ok(ids)
    }

    async fn qa_ticket_ids(&self, tid: Uuid) -> AppResult<Vec<Uuid>> {
        let mut tx = self.db.begin_with_tenant(tid).await?;
        let ids: Vec<Uuid> =
            sqlx::query_scalar("SELECT id FROM tickets WHERE tenant_id = $1 AND title LIKE $2")
                .bind(tid)
                .bind(format!("{QA_PREFIX}%"))
                .fetch_all(&mut *tx)
                .await?;
        Ok(ids)
    }

    /// Spread a freshly-created ticket across a non-default status and a past
    /// created date. Mirrors what `update_ticket` does internally for status.
    async fn restamp_ticket(
        &self,
        tid: Uuid,
        ticket_id: Uuid,
        status_id: Uuid,
        created_at: chrono::DateTime<Utc>,
    ) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tid).await?;
        sqlx::query(
            "UPDATE tickets SET status_id = $1, created_at = $2, updated_at = $2 \
             WHERE tenant_id = $3 AND id = $4",
        )
        .bind(status_id)
        .bind(created_at)
        .bind(tid)
        .bind(ticket_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }
}

/// Remove the QA dataset for `tenant_id` in FK-dependency order. Runs in a
/// single tenant-scoped transaction so it is all-or-nothing. Returns counts of
/// the primary entities removed.
async fn teardown(db: &Database, tid: Uuid) -> AppResult<QaReport> {
    let like = format!("{QA_PREFIX}%");
    let qa_companies = "SELECT id FROM companies WHERE tenant_id = $1 AND name LIKE $2";

    let mut tx = db.begin_with_tenant(tid).await?;
    let mut report = QaReport::default();

    macro_rules! del {
        ($sql:expr) => {{
            sqlx::query($sql)
                .bind(tid)
                .bind(&like)
                .execute(&mut *tx)
                .await?
                .rows_affected() as usize
        }};
    }

    // Leaves first, then their parents, then companies (contacts/sites cascade
    // on company delete; see scripts/wipe_demo_seed.sql).
    report.payments = del!(&format!(
        "DELETE FROM payments WHERE tenant_id = $1 AND company_id IN ({qa_companies})"
    ));
    del!(&format!(
        "DELETE FROM invoice_lines WHERE invoice_id IN \
         (SELECT id FROM invoices WHERE tenant_id = $1 AND company_id IN ({qa_companies}))"
    ));
    report.invoices = del!(&format!(
        "DELETE FROM invoices WHERE tenant_id = $1 AND company_id IN ({qa_companies})"
    ));
    report.time_entries = del!(&format!(
        "DELETE FROM time_entries WHERE tenant_id = $1 AND company_id IN ({qa_companies})"
    ));
    report.tasks = del!(&format!(
        "DELETE FROM tasks WHERE tenant_id = $1 AND project_id IN \
         (SELECT id FROM projects WHERE tenant_id = $1 AND company_id IN ({qa_companies}))"
    ));
    report.phases = del!(&format!(
        "DELETE FROM project_phases WHERE tenant_id = $1 AND project_id IN \
         (SELECT id FROM projects WHERE tenant_id = $1 AND company_id IN ({qa_companies}))"
    ));
    report.projects = del!(&format!(
        "DELETE FROM projects WHERE tenant_id = $1 AND company_id IN ({qa_companies})"
    ));
    del!(&format!(
        "DELETE FROM contract_items WHERE tenant_id = $1 AND contract_id IN \
         (SELECT id FROM contracts WHERE tenant_id = $1 AND company_id IN ({qa_companies}))"
    ));
    report.tickets = del!(&format!(
        "DELETE FROM tickets WHERE tenant_id = $1 AND company_id IN ({qa_companies})"
    ));
    report.contracts = del!(&format!(
        "DELETE FROM contracts WHERE tenant_id = $1 AND company_id IN ({qa_companies})"
    ));
    // Count contacts before deleting their companies (they cascade).
    report.contacts = sqlx::query_scalar::<_, i64>(&format!(
        "SELECT COUNT(*) FROM contacts WHERE tenant_id = $1 AND company_id IN ({qa_companies})"
    ))
    .bind(tid)
    .bind(&like)
    .fetch_one(&mut *tx)
    .await? as usize;
    report.companies = del!("DELETE FROM companies WHERE tenant_id = $1 AND name LIKE $2");

    // QA lookup rows created by the seed.
    del!("DELETE FROM work_types WHERE tenant_id = $1 AND name LIKE $2");
    del!("DELETE FROM task_statuses WHERE tenant_id = $1 AND name LIKE $2");

    tx.commit().await?;
    Ok(report)
}

// --- Data builders ----------------------------------------------------------

fn today() -> NaiveDate {
    Utc::now().date_naive()
}

fn qa_address(city: &str, state: &str) -> Address {
    Address {
        line1: Some("100 QA Plaza".to_string()),
        line2: None,
        city: Some(city.to_string()),
        state: Some(state.to_string()),
        postal_code: Some("00001".to_string()),
        country: Some("US".to_string()),
    }
}

fn qa_company(
    name: &str,
    company_type: CompanyType,
    status: CompanyStatus,
    parent: Option<Uuid>,
    account_manager: Option<Uuid>,
    address: Option<Address>,
) -> CreateCompanyRequest {
    CreateCompanyRequest {
        name: name.to_string(),
        parent_company_id: parent,
        company_type,
        status,
        industry: Some("Information Technology".to_string()),
        website: Some("https://example.com".to_string()),
        phone: Some("+1-555-0100".to_string()),
        fax: None,
        address,
        billing_address: None,
        tax_id: None,
        account_number: None,
        account_manager_id: account_manager,
        sla_id: None,
        payment_terms: Some("net30".to_string()),
        tax_exempt: false,
        custom_fields: serde_json::Value::Null,
        tags: vec![QA_TAG.to_string()],
        notes: Some("QA walkthrough seed company. Safe to delete via qa-teardown.".to_string()),
        portal_enabled: true,
    }
}

fn qa_company_parent(account_manager: Uuid) -> CreateCompanyRequest {
    qa_company(
        "QA-Northwind Traders",
        CompanyType::Client,
        CompanyStatus::Active,
        None,
        Some(account_manager),
        Some(qa_address("Seattle", "WA")),
    )
}

fn qa_company_specs(account_manager: Uuid, parent: Uuid) -> Vec<CreateCompanyRequest> {
    vec![
        qa_company(
            "QA-Globex Corporation",
            CompanyType::Client,
            CompanyStatus::Active,
            None,
            Some(account_manager),
            Some(qa_address("Austin", "TX")),
        ),
        qa_company(
            "QA-Initech LLC",
            CompanyType::Prospect,
            CompanyStatus::Prospect,
            None,
            None,
            None,
        ),
        qa_company(
            "QA-Umbrella Supplies",
            CompanyType::Vendor,
            CompanyStatus::Active,
            None,
            None,
            Some(qa_address("Raccoon City", "OH")),
        ),
        qa_company(
            "QA-Stark Industries",
            CompanyType::Partner,
            CompanyStatus::Active,
            None,
            Some(account_manager),
            None,
        ),
        qa_company(
            "QA-Wayne Enterprises",
            CompanyType::Client,
            CompanyStatus::Inactive,
            None,
            None,
            Some(qa_address("Gotham", "NJ")),
        ),
        qa_company(
            "QA-Northwind Subsidiary A",
            CompanyType::Client,
            CompanyStatus::Active,
            Some(parent),
            Some(account_manager),
            None,
        ),
        qa_company(
            "QA-Northwind Subsidiary B",
            CompanyType::Client,
            CompanyStatus::Active,
            Some(parent),
            None,
            None,
        ),
    ]
}

fn qa_contacts_for(company_id: Uuid, idx: usize) -> Vec<CreateContactRequest> {
    let people: &[(&str, &str, &str, ContactType, PreferredContactMethod)] = &[
        (
            "Alice",
            "Anderson",
            "Account Director",
            ContactType::Primary,
            PreferredContactMethod::Email,
        ),
        (
            "Bob",
            "Baker",
            "IT Manager",
            ContactType::Technical,
            PreferredContactMethod::Phone,
        ),
        (
            "Carol",
            "Chen",
            "Accounts Payable",
            ContactType::Billing,
            PreferredContactMethod::Mobile,
        ),
    ];
    // Two contacts per company, rotating roles so types vary across the set.
    let n = 2 + (idx % 2); // 2 or 3 contacts
    (0..n)
        .map(|j| {
            let (first, last, title, ctype, method) = people[(idx + j) % people.len()];
            CreateContactRequest {
                company_id,
                first_name: format!("QA-{first}"),
                last_name: format!("{last}{idx}{j}"),
                email: Some(format!(
                    "qa.{}.{}.{}@example.com",
                    first.to_lowercase(),
                    idx,
                    j
                )),
                phone: Some("+1-555-0101".to_string()),
                mobile: Some("+1-555-0202".to_string()),
                fax: None,
                title: Some(title.to_string()),
                department: Some("Operations".to_string()),
                contact_type: ctype,
                preferred_contact_method: method,
                timezone: Some("America/New_York".to_string()),
                custom_fields: serde_json::Value::Null,
                tags: vec![QA_TAG.to_string()],
                notes: None,
                create_portal_access: false,
            }
        })
        .collect()
}

fn qa_ticket(
    i: usize,
    company_id: Uuid,
    contact_id: Uuid,
    priority_id: Option<Uuid>,
    user_id: Uuid,
) -> CreateTicketRequest {
    let sources = [
        TicketSource::Portal,
        TicketSource::Email,
        TicketSource::Phone,
        TicketSource::Api,
        TicketSource::Internal,
    ];
    let titles = [
        "Email not syncing on mobile",
        "VPN drops every few minutes",
        "Request new laptop for hire",
        "Printer offline in finance",
        "Password reset for shared mailbox",
        "Server disk space warning",
        "Onboard new employee accounts",
        "Wi-Fi slow in conference room",
    ];
    CreateTicketRequest {
        title: format!("{QA_PREFIX}#{:02} {}", i + 1, titles[i % titles.len()]),
        description: Some("QA walkthrough seed ticket. Demonstrates list/filter/sort.".to_string()),
        priority_id,
        type_id: None,
        category_id: None,
        queue_id: None,
        source: sources[i % sources.len()],
        company_id,
        contact_id: Some(contact_id),
        site_id: None,
        // Assign roughly two thirds of tickets so the "unassigned" filter has
        // rows too.
        assigned_to_id: if i.is_multiple_of(3) {
            None
        } else {
            Some(user_id)
        },
        team_id: None,
        contract_id: None,
        sla_id: None,
        scheduled_start: None,
        scheduled_end: None,
        estimated_hours: Some(1.0 + (i % 4) as f64),
        is_billable: i.is_multiple_of(2),
        asset_id: None,
        custom_fields: serde_json::Value::Null,
        tags: vec![QA_TAG.to_string()],
    }
}

fn qa_project_specs(company_ids: &[Uuid], manager: Uuid) -> Vec<CreateProjectRequest> {
    vec![
        CreateProjectRequest {
            name: "QA-Network Refresh".to_string(),
            description: Some("QA seed project: switch and AP refresh.".to_string()),
            project_number: Some("QA-PRJ-001".to_string()),
            company_id: company_ids.first().copied(),
            contract_id: None,
            project_type: "client".to_string(),
            status: "active".to_string(),
            project_manager_id: Some(manager),
            start_date: Some(today() - Duration::days(20)),
            target_end_date: Some(today() + Duration::days(40)),
            actual_end_date: None,
            budget_hours: Some(Decimal::new(8000, 2)),
            budget_amount: Some(Decimal::new(2500000, 2)),
            billing_method: "fixed_price".to_string(),
            hourly_rate: None,
            is_billable: true,
        },
        CreateProjectRequest {
            name: "QA-Microsoft 365 Migration".to_string(),
            description: Some("QA seed project: tenant-to-tenant migration.".to_string()),
            project_number: Some("QA-PRJ-002".to_string()),
            company_id: company_ids.get(1).copied(),
            contract_id: None,
            project_type: "client".to_string(),
            status: "planning".to_string(),
            project_manager_id: Some(manager),
            start_date: Some(today() - Duration::days(5)),
            target_end_date: Some(today() + Duration::days(60)),
            actual_end_date: None,
            budget_hours: Some(Decimal::new(12000, 2)),
            budget_amount: Some(Decimal::new(4000000, 2)),
            billing_method: "time_and_materials".to_string(),
            hourly_rate: Some(Decimal::new(15000, 2)),
            is_billable: true,
        },
    ]
}

fn qa_phase_specs(project_idx: usize) -> Vec<UpsertProjectPhaseRequest> {
    vec![
        UpsertProjectPhaseRequest {
            name: format!("QA-Discovery (P{})", project_idx + 1),
            description: Some("Assess current state.".to_string()),
            sort_order: 1,
            start_date: Some(today() - Duration::days(10)),
            end_date: Some(today() + Duration::days(5)),
            status: "in_progress".to_string(),
        },
        UpsertProjectPhaseRequest {
            name: format!("QA-Execution (P{})", project_idx + 1),
            description: Some("Implement changes.".to_string()),
            sort_order: 2,
            start_date: Some(today() + Duration::days(6)),
            end_date: Some(today() + Duration::days(30)),
            status: "not_started".to_string(),
        },
    ]
}

fn qa_task_specs(
    project_idx: usize,
    phase_id: Uuid,
    status_id: Uuid,
    assignee: Uuid,
) -> Vec<CreateTaskRequest> {
    let priorities = ["low", "medium", "high"];
    (0..2)
        .map(|j| CreateTaskRequest {
            title: format!("QA-Task P{}.{}", project_idx + 1, j + 1),
            description: Some("QA seed task.".to_string()),
            status_id,
            phase_id: Some(phase_id),
            parent_task_id: None,
            priority: priorities[(project_idx + j) % priorities.len()].to_string(),
            assigned_to_id: Some(assignee),
            estimated_hours: Some(Decimal::new(400 + (j as i64) * 150, 2)),
            start_date: Some(today() - Duration::days(3)),
            due_date: Some(today() + Duration::days(7 + j as i64)),
            sort_order: j as i32,
        })
        .collect()
}

fn qa_time_entries(
    user_id: Uuid,
    work_type_id: Uuid,
    company_ids: &[Uuid],
    ticket_ids: &[Uuid],
    project_ids: &[Uuid],
) -> Vec<CreateTimeEntryRequest> {
    // Fractional hours (in minutes) and an alternating billable flag.
    let durations = [90, 45, 135, 30, 200, 60, 75, 105];
    durations
        .iter()
        .enumerate()
        .map(|(i, &minutes)| {
            let link_to_project = i % 2 == 1 && !project_ids.is_empty();
            CreateTimeEntryRequest {
                user_id,
                date: today() - Duration::days((i as i64) % 14),
                start_time: None,
                end_time: None,
                duration_minutes: Some(minutes),
                work_type_id,
                ticket_id: if link_to_project {
                    None
                } else {
                    ticket_ids.get(i % ticket_ids.len().max(1)).copied()
                },
                project_id: if link_to_project {
                    project_ids.get(i % project_ids.len()).copied()
                } else {
                    None
                },
                task_id: None,
                company_id: company_ids[i % company_ids.len()],
                notes: Some("QA seed time entry.".to_string()),
                work_category: None,
                is_billable: i % 3 != 0,
                hourly_rate: Some(Decimal::new(15000, 2)),
            }
        })
        .collect()
}

fn qa_contract_specs(company_ids: &[Uuid]) -> Vec<CreateContractRequest> {
    let types = [
        ("managed_services", "monthly", 350000i64),
        ("block_hours", "one_time", 500000),
        ("time_and_materials", "monthly", 0),
        ("fixed_price", "one_time", 1500000),
        ("warranty", "annually", 120000),
    ];
    types
        .iter()
        .enumerate()
        .map(|(i, &(ctype, cycle, amount))| CreateContractRequest {
            contract_number: Some(format!("QA-CON-{:03}", i + 1)),
            name: format!("QA-{} Agreement", ctype),
            company_id: company_ids[i % company_ids.len()],
            contract_type: ctype.to_string(),
            status: "active".to_string(),
            start_date: today() - Duration::days(30),
            end_date: Some(today() + Duration::days(335)),
            auto_renew: i % 2 == 0,
            billing_cycle: cycle.to_string(),
            billing_amount: if amount > 0 {
                Some(Decimal::new(amount, 2))
            } else {
                None
            },
            sla_id: None,
            signed_date: Some(today() - Duration::days(30)),
            signed_by_contact_id: None,
            notes: Some("QA seed contract.".to_string()),
        })
        .collect()
}

/// Two invoices, each with multiple line items. The `Option<Decimal>` is the
/// fraction of the total to record as a payment (full vs partial vs none).
fn qa_invoice_specs(company_ids: &[Uuid]) -> Vec<(CreateInvoiceRequest, Option<Decimal>)> {
    let company_a = company_ids.first().copied().unwrap_or_default();
    let company_b = company_ids.get(1).copied().unwrap_or(company_a);
    vec![
        (
            CreateInvoiceRequest {
                company_id: company_a,
                billing_contact_id: None,
                contract_id: None,
                invoice_date: today() - Duration::days(20),
                due_date: today() + Duration::days(10),
                payment_terms: Some("net30".to_string()),
                payment_term_id: None,
                tax_amount: Some(Decimal::new(5000, 2)),
                discount_amount: None,
                currency: Some("USD".to_string()),
                notes: Some("QA seed invoice (paid in full).".to_string()),
                po_number: Some("QA-PO-1".to_string()),
                lines: vec![
                    CreateInvoiceLineRequest {
                        line_type: InvoiceLineType::Service,
                        description: "QA-Managed services - June".to_string(),
                        quantity: Decimal::new(100, 2),
                        unit_price: Decimal::new(350000, 2),
                        ticket_id: None,
                        project_id: None,
                        sort_order: 1,
                    },
                    CreateInvoiceLineRequest {
                        line_type: InvoiceLineType::TimeEntry,
                        description: "QA-Onsite support hours".to_string(),
                        quantity: Decimal::new(400, 2),
                        unit_price: Decimal::new(15000, 2),
                        ticket_id: None,
                        project_id: None,
                        sort_order: 2,
                    },
                ],
            },
            Some(Decimal::ONE),
        ),
        (
            CreateInvoiceRequest {
                company_id: company_b,
                billing_contact_id: None,
                contract_id: None,
                invoice_date: today() - Duration::days(8),
                due_date: today() + Duration::days(22),
                payment_terms: Some("net30".to_string()),
                payment_term_id: None,
                tax_amount: None,
                discount_amount: Some(Decimal::new(2500, 2)),
                currency: Some("USD".to_string()),
                notes: Some("QA seed invoice (partially paid).".to_string()),
                po_number: Some("QA-PO-2".to_string()),
                lines: vec![
                    CreateInvoiceLineRequest {
                        line_type: InvoiceLineType::Product,
                        description: "QA-Firewall appliance".to_string(),
                        quantity: Decimal::new(200, 2),
                        unit_price: Decimal::new(80000, 2),
                        ticket_id: None,
                        project_id: None,
                        sort_order: 1,
                    },
                    CreateInvoiceLineRequest {
                        line_type: InvoiceLineType::Service,
                        description: "QA-Installation".to_string(),
                        quantity: Decimal::new(100, 2),
                        unit_price: Decimal::new(50000, 2),
                        ticket_id: None,
                        project_id: None,
                        sort_order: 2,
                    },
                ],
            },
            Some(Decimal::new(5, 1)), // 0.5 -> partial payment
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    // The primary ticket list paginates at 25/page; the seed must exceed that
    // so the walkthrough can exercise pagination. Enforced at compile time.
    const _: () = assert!(QA_TICKET_COUNT > 25);

    #[test]
    fn every_company_spec_is_qa_prefixed_and_tagged() {
        let mgr = Uuid::new_v4();
        let parent = Uuid::new_v4();
        let mut specs = vec![qa_company_parent(mgr)];
        specs.extend(qa_company_specs(mgr, parent));
        assert_eq!(specs.len(), 8, "8 companies across every type");
        for spec in &specs {
            assert!(
                spec.name.starts_with(QA_PREFIX),
                "name {} not QA-",
                spec.name
            );
            assert!(spec.tags.iter().any(|t| t == QA_TAG));
        }
        // Covers every CompanyType variant.
        assert!(specs.iter().any(|s| s.company_type == CompanyType::Client));
        assert!(specs
            .iter()
            .any(|s| s.company_type == CompanyType::Prospect));
        assert!(specs.iter().any(|s| s.company_type == CompanyType::Vendor));
        assert!(specs.iter().any(|s| s.company_type == CompanyType::Partner));
        // Two children link to the parent.
        assert_eq!(
            specs
                .iter()
                .filter(|s| s.parent_company_id == Some(parent))
                .count(),
            2
        );
    }

    #[test]
    fn contract_specs_cover_every_type() {
        let companies: Vec<Uuid> = (0..8).map(|_| Uuid::new_v4()).collect();
        let specs = qa_contract_specs(&companies);
        let types: Vec<&str> = specs.iter().map(|s| s.contract_type.as_str()).collect();
        for t in [
            "managed_services",
            "block_hours",
            "time_and_materials",
            "fixed_price",
            "warranty",
        ] {
            assert!(types.contains(&t), "missing contract type {t}");
        }
    }

    #[test]
    fn time_entries_have_fractional_and_mixed_billable() {
        let companies: Vec<Uuid> = (0..8).map(|_| Uuid::new_v4()).collect();
        let tickets: Vec<Uuid> = (0..5).map(|_| Uuid::new_v4()).collect();
        let projects: Vec<Uuid> = (0..2).map(|_| Uuid::new_v4()).collect();
        let entries = qa_time_entries(
            Uuid::new_v4(),
            Uuid::new_v4(),
            &companies,
            &tickets,
            &projects,
        );
        assert!(entries.iter().any(|e| e.is_billable));
        assert!(entries.iter().any(|e| !e.is_billable));
        // At least one fractional-hour entry (not a whole multiple of 60).
        assert!(entries
            .iter()
            .any(|e| e.duration_minutes.unwrap_or(0) % 60 != 0));
    }
}
