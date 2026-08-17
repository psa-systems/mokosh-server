//! On-demand showcase demo dataset seeding (PMS-620).
//!
//! The Mokosh showcase video (assigned to Nate) needs the app to look
//! *actively used* - many clients, several live projects, and a couple of
//! weeks of already-approved time - not the three-row first-visit demo seed
//! ([`super::service::SeedService`]) nor the QA walkthrough set
//! ([`super::qa`]), which was sized for list/filter/pagination testing rather
//! than the create -> time -> approve -> report recording flow.
//!
//! This is an **operator-triggered** seed run from the server binary:
//!
//! - `mokosh-server showcase-seed     --tenant <id>`  create the dataset
//! - `mokosh-server showcase-refresh  --tenant <id>`  reset it for a new take
//! - `mokosh-server showcase-teardown --tenant <id>`  remove it
//!
//! # Hard guardrail (fail closed)
//!
//! Like the QA seed, both entry points call [`confirm_showcase_tenant`] first
//! and **refuse (error, zero writes)** unless the target tenant's
//! `settings->>'is_showcase'` parses to `true`, and never against a tenant
//! whose `settings->>'environment'` is `production`. Mark a throwaway showcase
//! tenant explicitly before seeding, e.g.:
//! `UPDATE tenants SET settings = jsonb_set(COALESCE(settings,'{}'::jsonb),
//! '{is_showcase}', 'true'::jsonb, true) WHERE id = '<showcase-tenant-id>';`
//!
//! # Shape of the dataset
//!
//! Everything is `SHOWCASE-` prefixed (and `showcase`-tagged where the entity
//! carries tags) so it is trivially searchable and removable:
//!
//! - [`SHOWCASE_CLIENT_COUNT`] MSP-generic client companies, one primary
//!   contact each.
//! - [`SHOWCASE_PROJECT_COUNT`] active/planning/completed projects across the
//!   first few clients, each with two phases and tasks.
//! - A handful of tickets spread across clients (best-effort: skipped if the
//!   tenant lacks default status/priority/queue config).
//! - Roughly two weeks of prior time entries for the operator user - last week
//!   Monday..Friday and this week Monday..today - all submitted and
//!   **approved** for both weeks, so the timesheet reads as approved history
//!   and the billable entries are `ready_to_bill` for a report.
//!
//! # Idempotency, refresh, and teardown
//!
//! [`showcase_seed`] is idempotent: if any `SHOWCASE-` company already exists
//! it skips without inserting, so re-running never duplicates.
//! [`showcase_refresh`] tears the dataset down and re-seeds it in one call so a
//! recording take can be reset without manual DB surgery. [`showcase_teardown`]
//! removes the dataset (and the lookup rows it created) in FK-dependency order,
//! leaving the tenant's stock configuration intact.

use std::fmt;

use chrono::{Datelike, Duration, NaiveDate, Utc};
use rust_decimal::Decimal;
use uuid::Uuid;

use crate::db::Database;
use crate::modules::audit::AuditCtx;
use crate::modules::auth::TenantId;
use crate::modules::contacts::{
    CompanyStatus, CompanyType, ContactService, ContactType, CreateCompanyRequest,
    CreateContactRequest, PreferredContactMethod,
};
use crate::modules::projects::{
    CreateProjectRequest, CreateTaskRequest, ProjectsService, UpsertProjectPhaseRequest,
    UpsertTaskStatusRequest,
};
use crate::modules::tickets::{CreateTicketRequest, TicketService, TicketSource};
use crate::modules::time_tracking::{
    CreateTimeEntryRequest, TimeTrackingService, UpsertWorkTypeRequest,
};
use crate::utils::error::{AppError, AppResult};

/// Name prefix applied to every showcase record that has a name, so operators
/// can find and bulk-remove the dataset at a glance.
const SHOWCASE_PREFIX: &str = "SHOWCASE-";
/// Tag applied to every showcase record that carries a `tags` column.
const SHOWCASE_TAG: &str = "showcase";
/// Number of client companies to seed. "~20 clients" per PMS-620 so the client
/// list reads as real usage.
const SHOWCASE_CLIENT_COUNT: usize = 20;
/// Number of projects to seed. "~5 projects" per PMS-620.
const SHOWCASE_PROJECT_COUNT: usize = 5;
/// Number of tickets to seed (best-effort; needs default ticket config).
const SHOWCASE_TICKET_COUNT: usize = 24;

/// Summary of what a seed / refresh / teardown run did, for operator output.
#[derive(Debug, Default, Clone)]
pub struct ShowcaseReport {
    pub skipped: bool,
    pub companies: usize,
    pub contacts: usize,
    pub tickets: usize,
    pub projects: usize,
    pub phases: usize,
    pub tasks: usize,
    pub time_entries: usize,
    /// Weeks whose timesheets were submitted and approved (this week + last
    /// week = 2 when entries landed in both).
    pub approved_weeks: usize,
}

impl fmt::Display for ShowcaseReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.skipped {
            return write!(
                f,
                "showcase dataset already present; nothing written (idempotent skip)."
            );
        }
        write!(
            f,
            "companies={} contacts={} tickets={} projects={} phases={} tasks={} \
             time_entries={} approved_weeks={}",
            self.companies,
            self.contacts,
            self.tickets,
            self.projects,
            self.phases,
            self.tasks,
            self.time_entries,
            self.approved_weeks,
        )
    }
}

/// Fail-closed guardrail. Returns `Ok(())` ONLY when `tenant_id` is an existing
/// tenant explicitly marked showcase (`settings->>'is_showcase' = true`) and
/// not flagged as a production environment. Every other case errors with zero
/// writes:
///
/// - tenant row does not exist,
/// - `settings` is null / missing the `is_showcase` key / it is not `true`,
/// - `settings->>'environment'` is `production`.
pub async fn confirm_showcase_tenant(db: &Database, tenant_id: Uuid) -> AppResult<()> {
    // `tenants` is the RLS-exempt isolation root (migration 038), so reading the
    // marker on the migrator pool is correct and avoids needing a tenant GUC
    // just to look up the tenant's own settings.
    let settings: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT settings FROM tenants WHERE id = $1")
            .bind(tenant_id)
            .fetch_optional(db.migrator_pool())
            .await?;

    let settings = match settings {
        Some(s) => s,
        None => {
            return Err(AppError::BadRequest(format!(
                "Showcase seed refused: tenant {tenant_id} does not exist (fail closed, zero writes)."
            )));
        }
    };

    let environment = settings
        .get("environment")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if environment.eq_ignore_ascii_case("production") || environment.eq_ignore_ascii_case("prod") {
        return Err(AppError::Forbidden(format!(
            "Showcase seed refused: tenant {tenant_id} is marked environment=production. \
             The showcase seed must never run against production (fail closed, zero writes)."
        )));
    }

    let is_showcase = settings
        .get("is_showcase")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if !is_showcase {
        return Err(AppError::Forbidden(format!(
            "Showcase seed refused: tenant {tenant_id} is not marked as showcase \
             (settings->>'is_showcase' must be true). Refusing to write to a tenant whose \
             showcase status cannot be confirmed (fail closed, zero writes)."
        )));
    }

    Ok(())
}

/// Seed the showcase dataset into `tenant_id`. Confirms the showcase marker
/// first (fail closed) and is idempotent: a no-op if the dataset is present.
pub async fn showcase_seed(db: &Database, tenant_id: Uuid) -> AppResult<ShowcaseReport> {
    confirm_showcase_tenant(db, tenant_id).await?;
    ShowcaseSeeder::new(db.clone()).seed(tenant_id).await
}

/// Reset the showcase dataset for a fresh recording take: tear it down (if
/// present) and seed it again, in one call. Confirms the showcase marker first.
pub async fn showcase_refresh(db: &Database, tenant_id: Uuid) -> AppResult<ShowcaseReport> {
    confirm_showcase_tenant(db, tenant_id).await?;
    teardown(db, tenant_id).await?;
    ShowcaseSeeder::new(db.clone()).seed(tenant_id).await
}

/// Remove the showcase dataset (and the lookup rows it created) from
/// `tenant_id`. Confirms the showcase marker first. Safe to run repeatedly.
pub async fn showcase_teardown(db: &Database, tenant_id: Uuid) -> AppResult<ShowcaseReport> {
    confirm_showcase_tenant(db, tenant_id).await?;
    teardown(db, tenant_id).await
}

/// Bundles the service layer the seed drives. Cheap to construct (each service
/// holds an `Arc`/`Clone` `Database`).
struct ShowcaseSeeder {
    db: Database,
    contacts: ContactService,
    tickets: TicketService,
    projects: ProjectsService,
    time: TimeTrackingService,
}

impl ShowcaseSeeder {
    fn new(db: Database) -> Self {
        Self {
            contacts: ContactService::new(db.clone()),
            tickets: TicketService::new(db.clone()),
            projects: ProjectsService::new(db.clone()),
            time: TimeTrackingService::new(db.clone()),
            db,
        }
    }

    async fn seed(&self, tid: Uuid) -> AppResult<ShowcaseReport> {
        // Idempotency: any pre-existing SHOWCASE- company means we have already
        // seeded this tenant. Bail without writing so re-runs never duplicate.
        if self.companies_exist(tid).await? {
            return Ok(ShowcaseReport {
                skipped: true,
                ..Default::default()
            });
        }

        // The seed must be attributed to a real user (tickets record a creator,
        // time entries a user, timesheets an approver). Fail clearly if the
        // tenant has no users rather than inserting orphaned rows.
        let user_id = self.first_user(tid).await?;
        let tenant = TenantId::from_trusted(tid);
        let ctx = AuditCtx::system(tid);

        let work_type_id = self.ensure_work_type(tenant).await?;
        let task_status_id = self.ensure_task_status(tenant).await?;

        let mut report = ShowcaseReport::default();

        // --- Client companies (MSP-generic, one primary contact each) ---
        let mut company_ids: Vec<Uuid> = Vec::with_capacity(SHOWCASE_CLIENT_COUNT);
        for (i, name) in showcase_client_names().into_iter().enumerate() {
            let company = self
                .contacts
                .create_company(tenant, &showcase_company(name, user_id), &ctx)
                .await?;
            report.companies += 1;

            self.contacts
                .create_contact(tenant, &showcase_contact(company.id, i), &ctx)
                .await?;
            report.contacts += 1;

            company_ids.push(company.id);
        }

        // --- Projects with phases and tasks (across the first few clients) ---
        for (pi, spec) in showcase_project_specs(&company_ids, user_id)
            .into_iter()
            .enumerate()
        {
            let project = self.projects.create_project(tenant, &spec, &ctx).await?;
            report.projects += 1;

            for phase_spec in showcase_phase_specs(pi) {
                let phase = self
                    .projects
                    .create_project_phase(tenant, project.id, &phase_spec, &ctx)
                    .await?;
                report.phases += 1;

                for task_spec in showcase_task_specs(pi, phase.id, task_status_id, user_id) {
                    self.projects
                        .create_task(tenant, project.id, &task_spec, &ctx)
                        .await?;
                    report.tasks += 1;
                }
            }
        }

        // --- Tickets (best-effort: needs the tenant's default ticket config) ---
        let priorities = self.ticket_priority_ids(tid).await?;
        for i in 0..SHOWCASE_TICKET_COUNT {
            let company_id = company_ids[i % company_ids.len()];
            let priority_id = priorities.get(i % priorities.len().max(1)).copied();
            let req = showcase_ticket(i, company_id, priority_id, user_id);
            match self
                .tickets
                .create_ticket(tenant, user_id, &req, &ctx)
                .await
            {
                Ok(_) => report.tickets += 1,
                Err(e) => {
                    tracing::warn!(error = %e, tenant_id = %tid, "showcase ticket seeding skipped");
                }
            }
        }

        // --- Time entries: last week + this week, then submit + approve both ---
        let project_ids = self.project_ids(tid).await?;
        let this_monday = monday_of(Utc::now().date_naive());
        let last_monday = this_monday - Duration::days(7);

        for spec in showcase_time_entries(
            user_id,
            work_type_id,
            &company_ids,
            &project_ids,
            this_monday,
            last_monday,
        ) {
            self.time.create_time_entry(tenant, &spec, &ctx).await?;
            report.time_entries += 1;
        }

        // Approve both weeks: submit moves the week's draft entries to pending,
        // approve moves pending -> approved and flips billable entries to
        // ready_to_bill (report-ready). Self-approved by the seed user.
        for anchor in [last_monday, this_monday] {
            self.time.submit_timesheet(tenant, user_id, anchor).await?;
            self.time
                .approve_timesheet(tenant, user_id, user_id, anchor)
                .await?;
            report.approved_weeks += 1;
        }

        Ok(report)
    }

    // --- Lookup helpers -----------------------------------------------------

    async fn companies_exist(&self, tid: Uuid) -> AppResult<bool> {
        let mut tx = self.db.begin_with_tenant(tid).await?;
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM companies WHERE tenant_id = $1 AND name LIKE $2)",
        )
        .bind(tid)
        .bind(format!("{SHOWCASE_PREFIX}%"))
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
                "Showcase seed refused: tenant {tid} has no users to attribute records to. \
                 Provision at least one user in the showcase tenant first."
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

    /// Create a dedicated showcase work type (name-prefixed so teardown can
    /// remove it). Time entries require a work_type_id that exists in the
    /// tenant.
    async fn ensure_work_type(&self, tenant: TenantId) -> AppResult<Uuid> {
        let req = UpsertWorkTypeRequest {
            name: format!("{SHOWCASE_PREFIX}Consulting"),
            description: Some("Showcase seed work type".to_string()),
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
    /// seeds them), else create a showcase one. Tasks require a status_id.
    async fn ensure_task_status(&self, tenant: TenantId) -> AppResult<Uuid> {
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
            name: format!("{SHOWCASE_PREFIX}Open"),
            color: "#3b82f6".to_string(),
            is_completed: false,
            sort_order: 100,
        };
        let ctx = AuditCtx::system(tenant.get());
        let st = self.projects.create_task_status(tenant, &req, &ctx).await?;
        Ok(st.id)
    }

    async fn project_ids(&self, tid: Uuid) -> AppResult<Vec<Uuid>> {
        let mut tx = self.db.begin_with_tenant(tid).await?;
        let ids: Vec<Uuid> =
            sqlx::query_scalar("SELECT id FROM projects WHERE tenant_id = $1 AND name LIKE $2")
                .bind(tid)
                .bind(format!("{SHOWCASE_PREFIX}%"))
                .fetch_all(&mut *tx)
                .await?;
        Ok(ids)
    }
}

/// Remove the showcase dataset for `tenant_id` in FK-dependency order. Runs in
/// a single tenant-scoped transaction so it is all-or-nothing. Returns counts
/// of the primary entities removed.
async fn teardown(db: &Database, tid: Uuid) -> AppResult<ShowcaseReport> {
    let like = format!("{SHOWCASE_PREFIX}%");
    let companies = "SELECT id FROM companies WHERE tenant_id = $1 AND name LIKE $2";

    let mut tx = db.begin_with_tenant(tid).await?;
    let mut report = ShowcaseReport::default();

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

    // Leaves first, then their parents, then companies (contacts cascade on
    // company delete; see scripts/wipe_demo_seed.sql).
    report.time_entries = del!(&format!(
        "DELETE FROM time_entries WHERE tenant_id = $1 AND company_id IN ({companies})"
    ));
    report.tasks = del!(&format!(
        "DELETE FROM tasks WHERE tenant_id = $1 AND project_id IN \
         (SELECT id FROM projects WHERE tenant_id = $1 AND company_id IN ({companies}))"
    ));
    report.phases = del!(&format!(
        "DELETE FROM project_phases WHERE tenant_id = $1 AND project_id IN \
         (SELECT id FROM projects WHERE tenant_id = $1 AND company_id IN ({companies}))"
    ));
    report.projects = del!(&format!(
        "DELETE FROM projects WHERE tenant_id = $1 AND company_id IN ({companies})"
    ));
    report.tickets = del!(&format!(
        "DELETE FROM tickets WHERE tenant_id = $1 AND company_id IN ({companies})"
    ));
    // Count contacts before deleting their companies (they cascade).
    report.contacts = sqlx::query_scalar::<_, i64>(&format!(
        "SELECT COUNT(*) FROM contacts WHERE tenant_id = $1 AND company_id IN ({companies})"
    ))
    .bind(tid)
    .bind(&like)
    .fetch_one(&mut *tx)
    .await? as usize;
    report.companies = del!("DELETE FROM companies WHERE tenant_id = $1 AND name LIKE $2");

    // Showcase lookup rows created by the seed.
    del!("DELETE FROM work_types WHERE tenant_id = $1 AND name LIKE $2");
    del!("DELETE FROM task_statuses WHERE tenant_id = $1 AND name LIKE $2");

    tx.commit().await?;
    Ok(report)
}

// --- Data builders ----------------------------------------------------------

fn today() -> NaiveDate {
    Utc::now().date_naive()
}

/// The Monday on or before `date` (ISO week start), matching the timesheet
/// week anchor `TimeTrackingService::submit_timesheet` derives internally.
fn monday_of(date: NaiveDate) -> NaiveDate {
    let from_monday = date.weekday().num_days_from_monday() as i64;
    date - Duration::days(from_monday)
}

/// [`SHOWCASE_CLIENT_COUNT`] MSP-generic, obviously-fake client names. No
/// industry-specific assumptions: every client is a generic business an MSP
/// might serve, and the seed logic sets a generic IT industry field.
fn showcase_client_names() -> Vec<&'static str> {
    let names = [
        "SHOWCASE-Northwind Traders",
        "SHOWCASE-Globex Corporation",
        "SHOWCASE-Initech",
        "SHOWCASE-Umbrella Group",
        "SHOWCASE-Stark Industries",
        "SHOWCASE-Wayne Enterprises",
        "SHOWCASE-Soylent Corp",
        "SHOWCASE-Hooli",
        "SHOWCASE-Pied Piper",
        "SHOWCASE-Vandelay Industries",
        "SHOWCASE-Wonka Industries",
        "SHOWCASE-Cyberdyne Systems",
        "SHOWCASE-Gekko & Co",
        "SHOWCASE-Bluth Company",
        "SHOWCASE-Dunder Mifflin",
        "SHOWCASE-Prestige Worldwide",
        "SHOWCASE-Massive Dynamic",
        "SHOWCASE-Nakatomi Trading",
        "SHOWCASE-Oscorp Holdings",
        "SHOWCASE-Tyrell Corp",
    ];
    debug_assert_eq!(names.len(), SHOWCASE_CLIENT_COUNT);
    names.to_vec()
}

fn showcase_company(name: &str, account_manager: Uuid) -> CreateCompanyRequest {
    CreateCompanyRequest {
        name: name.to_string(),
        parent_company_id: None,
        company_type: CompanyType::Client,
        status: CompanyStatus::Active,
        industry: Some("Information Technology".to_string()),
        website: Some("https://example.com".to_string()),
        phone: Some("+1-555-0100".to_string()),
        fax: None,
        address: None,
        billing_address: None,
        tax_id: None,
        account_number: None,
        account_manager_id: Some(account_manager),
        sla_id: None,
        payment_terms: Some("net30".to_string()),
        tax_exempt: false,
        custom_fields: serde_json::Value::Null,
        tags: vec![SHOWCASE_TAG.to_string()],
        notes: Some("Showcase demo client. Safe to delete via showcase-teardown.".to_string()),
        portal_enabled: true,
    }
}

fn showcase_contact(company_id: Uuid, idx: usize) -> CreateContactRequest {
    let people: &[(&str, &str, &str, ContactType, PreferredContactMethod)] = &[
        (
            "Alice",
            "Anderson",
            "IT Director",
            ContactType::Primary,
            PreferredContactMethod::Email,
        ),
        (
            "Bob",
            "Baker",
            "Operations Manager",
            ContactType::Technical,
            PreferredContactMethod::Phone,
        ),
        (
            "Carol",
            "Chen",
            "Finance Lead",
            ContactType::Billing,
            PreferredContactMethod::Mobile,
        ),
    ];
    let (first, last, title, ctype, method) = people[idx % people.len()];
    CreateContactRequest {
        company_id: Some(company_id),
        company_name: None,
        first_name: format!("SHOWCASE-{first}"),
        last_name: format!("{last}{idx}"),
        email: Some(format!(
            "showcase.{}.{idx}@example.com",
            first.to_lowercase()
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
        tags: vec![SHOWCASE_TAG.to_string()],
        notes: None,
        create_portal_access: false,
    }
}

fn showcase_project_specs(company_ids: &[Uuid], manager: Uuid) -> Vec<CreateProjectRequest> {
    // (name, status, billing_method, hourly_rate?) - MSP-generic engagements.
    let specs: &[(&str, &str, &str, bool)] = &[
        ("SHOWCASE-Network Refresh", "active", "fixed_price", false),
        (
            "SHOWCASE-Microsoft 365 Migration",
            "active",
            "time_and_materials",
            true,
        ),
        (
            "SHOWCASE-Firewall Deployment",
            "active",
            "fixed_price",
            false,
        ),
        (
            "SHOWCASE-Backup & DR Implementation",
            "planning",
            "time_and_materials",
            true,
        ),
        (
            "SHOWCASE-Help Desk Onboarding",
            "completed",
            "fixed_price",
            false,
        ),
    ];
    debug_assert_eq!(specs.len(), SHOWCASE_PROJECT_COUNT);
    specs
        .iter()
        .enumerate()
        .map(
            |(i, &(name, status, billing_method, tm))| CreateProjectRequest {
                name: name.to_string(),
                description: Some("Showcase seed project.".to_string()),
                project_number: Some(format!("SHOWCASE-PRJ-{:03}", i + 1)),
                company_id: company_ids.get(i % company_ids.len().max(1)).copied(),
                contract_id: None,
                project_type: "client".to_string(),
                status: status.to_string(),
                project_manager_id: Some(manager),
                start_date: Some(today() - Duration::days(20)),
                target_end_date: Some(today() + Duration::days(40)),
                actual_end_date: if status == "completed" {
                    Some(today() - Duration::days(2))
                } else {
                    None
                },
                budget_hours: Some(Decimal::new(8000, 2)),
                budget_amount: Some(Decimal::new(2500000, 2)),
                billing_method: billing_method.to_string(),
                hourly_rate: if tm {
                    Some(Decimal::new(15000, 2))
                } else {
                    None
                },
                is_billable: true,
                default_due_business_days: None,
            },
        )
        .collect()
}

fn showcase_phase_specs(project_idx: usize) -> Vec<UpsertProjectPhaseRequest> {
    vec![
        UpsertProjectPhaseRequest {
            name: format!("SHOWCASE-Discovery (P{})", project_idx + 1),
            description: Some("Assess current state.".to_string()),
            sort_order: 1,
            start_date: Some(today() - Duration::days(10)),
            end_date: Some(today() + Duration::days(5)),
            status: "in_progress".to_string(),
        },
        UpsertProjectPhaseRequest {
            name: format!("SHOWCASE-Execution (P{})", project_idx + 1),
            description: Some("Implement changes.".to_string()),
            sort_order: 2,
            start_date: Some(today() + Duration::days(6)),
            end_date: Some(today() + Duration::days(30)),
            status: "not_started".to_string(),
        },
    ]
}

fn showcase_task_specs(
    project_idx: usize,
    phase_id: Uuid,
    status_id: Uuid,
    assignee: Uuid,
) -> Vec<CreateTaskRequest> {
    let priorities = ["low", "medium", "high"];
    (0..2)
        .map(|j| CreateTaskRequest {
            title: format!("SHOWCASE-Task P{}.{}", project_idx + 1, j + 1),
            description: Some("Showcase seed task.".to_string()),
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

fn showcase_ticket(
    i: usize,
    company_id: Uuid,
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
        title: format!(
            "{SHOWCASE_PREFIX}#{:02} {}",
            i + 1,
            titles[i % titles.len()]
        ),
        description: Some("Showcase seed ticket.".to_string()),
        priority_id,
        source: sources[i % sources.len()],
        company_id,
        contact_id: None,
        assigned_to_id: if i.is_multiple_of(3) {
            None
        } else {
            Some(user_id)
        },
        estimated_hours: Some(1.0 + (i % 4) as f64),
        is_billable: i.is_multiple_of(2),
        tags: vec![SHOWCASE_TAG.to_string()],
        ..Default::default()
    }
}

/// Roughly two weeks of prior time entries for the operator user: last week
/// Monday..Friday and this week Monday..today, two entries per day (one against
/// a project, one against a client), all billable so the approved weeks are
/// report-ready. Whole-hour durations well under the 24h/day cap.
fn showcase_time_entries(
    user_id: Uuid,
    work_type_id: Uuid,
    company_ids: &[Uuid],
    project_ids: &[Uuid],
    this_monday: NaiveDate,
    last_monday: NaiveDate,
) -> Vec<CreateTimeEntryRequest> {
    let mut entries = Vec::new();
    let today = today();
    // Two prior full-ish weeks: last week Mon..Fri, this week Mon..today.
    let weeks = [(last_monday, 5i64), (this_monday, 5i64)];
    let mut n = 0usize;
    for (monday, workdays) in weeks {
        for d in 0..workdays {
            let date = monday + Duration::days(d);
            if date > today {
                break; // never log time in the future within the current week
            }
            // Entry A: against a project (T&M / fixed) - 3h.
            entries.push(CreateTimeEntryRequest {
                user_id,
                date,
                start_time: None,
                end_time: None,
                duration_minutes: Some(180),
                worked_minutes: None,
                billable_minutes: None,
                work_type_id,
                ticket_id: None,
                project_id: project_ids.get(n % project_ids.len().max(1)).copied(),
                task_id: None,
                company_id: company_ids[n % company_ids.len()],
                notes: Some("Showcase seed: project work.".to_string()),
                work_category: None,
                is_billable: true,
                hourly_rate: Some(Decimal::new(15000, 2)),
            });
            n += 1;
            // Entry B: against a client, no project - 2h30m (fractional).
            entries.push(CreateTimeEntryRequest {
                user_id,
                date,
                start_time: None,
                end_time: None,
                duration_minutes: Some(150),
                worked_minutes: None,
                billable_minutes: None,
                work_type_id,
                ticket_id: None,
                project_id: None,
                task_id: None,
                company_id: company_ids[n % company_ids.len()],
                notes: Some("Showcase seed: client support.".to_string()),
                work_category: None,
                is_billable: true,
                hourly_rate: Some(Decimal::new(15000, 2)),
            });
            n += 1;
        }
    }
    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    // PMS-620 acceptance: "~20 clients" and "~5 projects". Enforced at compile
    // time so a future edit that regresses the volume fails the build.
    const _: () = assert!(SHOWCASE_CLIENT_COUNT == 20);
    const _: () = assert!(SHOWCASE_PROJECT_COUNT == 5);

    #[test]
    fn client_names_match_count_and_are_prefixed() {
        let names = showcase_client_names();
        assert_eq!(names.len(), SHOWCASE_CLIENT_COUNT, "~20 clients");
        for name in &names {
            assert!(
                name.starts_with(SHOWCASE_PREFIX),
                "name {name} not prefixed"
            );
        }
        // All obviously-fake, distinct names.
        let mut sorted = names.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), names.len(), "client names must be distinct");
    }

    #[test]
    fn project_specs_match_count_and_are_prefixed_and_billable() {
        let companies: Vec<Uuid> = (0..SHOWCASE_CLIENT_COUNT).map(|_| Uuid::new_v4()).collect();
        let specs = showcase_project_specs(&companies, Uuid::new_v4());
        assert_eq!(specs.len(), SHOWCASE_PROJECT_COUNT, "~5 projects");
        for spec in &specs {
            assert!(spec.name.starts_with(SHOWCASE_PREFIX));
            assert!(spec.company_id.is_some(), "project linked to a client");
        }
        // Mix of statuses reads as real usage (active + planning + completed).
        assert!(specs.iter().any(|s| s.status == "active"));
        assert!(specs.iter().any(|s| s.status == "planning"));
        assert!(specs.iter().any(|s| s.status == "completed"));
    }

    #[test]
    fn time_entries_span_this_week_and_last_week_all_billable() {
        // Anchor on the real current week so the future-date guard never trims
        // away "this week", independent of the machine clock.
        let this_monday = monday_of(today());
        let last_monday = this_monday - Duration::days(7);
        let companies: Vec<Uuid> = (0..SHOWCASE_CLIENT_COUNT).map(|_| Uuid::new_v4()).collect();
        let projects: Vec<Uuid> = (0..SHOWCASE_PROJECT_COUNT)
            .map(|_| Uuid::new_v4())
            .collect();
        let entries = showcase_time_entries(
            Uuid::new_v4(),
            Uuid::new_v4(),
            &companies,
            &projects,
            this_monday,
            last_monday,
        );
        assert!(!entries.is_empty(), "seed produces time entries");
        // Every entry is billable so approved weeks are report-ready.
        assert!(entries.iter().all(|e| e.is_billable));
        // Entries land in both the last-week and this-week ranges.
        let last_end = last_monday + Duration::days(7);
        let this_end = this_monday + Duration::days(7);
        assert!(
            entries
                .iter()
                .any(|e| e.date >= last_monday && e.date < last_end),
            "some entries fall in last week"
        );
        assert!(
            entries
                .iter()
                .any(|e| e.date >= this_monday && e.date < this_end),
            "some entries fall in this week"
        );
        // At least one fractional-hour entry (not a whole multiple of 60).
        assert!(entries
            .iter()
            .any(|e| e.duration_minutes.unwrap_or(0) % 60 != 0));
    }

    #[test]
    fn monday_of_returns_week_start() {
        // Wednesday 2026-07-01 -> Monday 2026-06-29.
        let wed = NaiveDate::from_ymd_opt(2026, 7, 1).unwrap();
        assert_eq!(
            monday_of(wed),
            NaiveDate::from_ymd_opt(2026, 6, 29).unwrap()
        );
        // A Monday maps to itself.
        let mon = NaiveDate::from_ymd_opt(2026, 6, 29).unwrap();
        assert_eq!(monday_of(mon), mon);
    }
}
