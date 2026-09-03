//! Demo-data payloads seeded into a brand-new account (PMS-157, PMS-710).
//!
//! The demo CONTENT (company / contact / ticket / project / SLA names, titles,
//! descriptions) lives in the committed `demo_seed.json` bundle, embedded at
//! compile time. This module maps that bundle into the same `Create*Request`
//! DTOs the public API accepts, so seeding still goes through the real service
//! methods (validation, FK checks, per-tenant config defaults, audit rows)
//! instead of hand-rolled INSERTs. Data-driven so the demo set can change
//! without touching Rust; the load is create-only and non-destructive, distinct
//! from the wipe-and-replace `data_transfer` import.
//!
//! PMS-710 widened the set from one company / two contacts / three tickets to a
//! small but connected PSA example - two companies, four contacts, one service
//! SLA (attached to a company), two projects (one with a phase and a task), and
//! five tickets - so a new production account can see how the objects relate.
//! Human content stays in the JSON; the structural fields
//! (dates, budgets, billing method, tags, FK wiring) live in the builders here
//! so the bundle stays readable. Cross-references are by index into the bundle
//! arrays; the loader resolves them to real ids as it creates each row.

use std::sync::OnceLock;

use chrono::{Duration, Utc};
use rust_decimal::Decimal;
use serde::Deserialize;
use uuid::Uuid;

use mokosh_types::contacts::{
    CompanyStatus, CompanyType, ContactCompanyLinkInput, ContactPhoneInput, ContactType,
    CreateCompanyRequest, CreateContactRequest, PhoneType, PreferredContactMethod,
};
use mokosh_types::tickets::CreateTicketRequest;

use crate::modules::projects::{CreateProjectRequest, UpsertProjectPhaseRequest};
use crate::modules::sla::UpsertSlaPolicyRequest;

/// The committed demo-seed bundle. It carries only the human-meaningful content;
/// structural defaults (tags, phone, dates, `..Default`) stay in the builders
/// below so the bundle stays readable and small.
const DEMO_SEED_JSON: &str = include_str!("demo_seed.json");

#[derive(Deserialize)]
struct DemoSeed {
    companies: Vec<DemoCompany>,
    contacts: Vec<DemoContact>,
    sla: DemoSla,
    projects: Vec<DemoProject>,
    tickets: Vec<DemoTicket>,
}

#[derive(Deserialize)]
struct DemoCompany {
    name: String,
    industry: String,
    website: String,
    phone: String,
    notes: String,
}

#[derive(Deserialize)]
struct DemoContact {
    company_index: usize,
    first_name: String,
    last_name: String,
    email: String,
    title: String,
}

#[derive(Deserialize)]
struct DemoSla {
    name: String,
    description: String,
    /// Which company (by bundle index) this SLA is applied to.
    company_index: usize,
}

#[derive(Deserialize)]
struct DemoProject {
    company_index: usize,
    name: String,
    description: String,
    /// One of the project status strings the projects service accepts
    /// (`active`, `planning`, ...).
    status: String,
    /// Optional first phase; `None` seeds a project with no phases.
    phase_name: Option<String>,
    /// Optional single task under the phase; needs a phase and a tenant task
    /// status to be created (best-effort in the loader).
    task_title: Option<String>,
}

#[derive(Deserialize)]
struct DemoTicket {
    company_index: usize,
    contact_index: usize,
    title: String,
    description: String,
}

/// Parse the embedded bundle once. A malformed bundle is a committed bug, caught
/// by `demo_seed_bundle_parses_to_the_expected_shape` below and by the
/// integration seed tests; the panic surfaces it loudly at first use.
fn demo_seed() -> &'static DemoSeed {
    static SEED: OnceLock<DemoSeed> = OnceLock::new();
    SEED.get_or_init(|| {
        serde_json::from_str(DEMO_SEED_JSON).expect("embedded demo_seed.json is valid")
    })
}

/// The service SLA policy to create. Names are obviously-fake so an operator can
/// tell demo rows from real data at a glance.
pub fn demo_sla() -> UpsertSlaPolicyRequest {
    let s = &demo_seed().sla;
    UpsertSlaPolicyRequest {
        name: s.name.clone(),
        description: Some(s.description.clone()),
        business_hours_id: None,
        is_default: false,
    }
}

/// The bundle index of the company the SLA attaches to.
pub fn demo_sla_company_index() -> usize {
    demo_seed().sla.company_index
}

/// The sample client companies. `sla_policy_id` is stamped onto the company the
/// bundle's `sla.company_index` points at, so the demo shows an SLA attached to
/// a client; the others carry no SLA.
pub fn demo_companies(sla_policy_id: Uuid) -> Vec<CreateCompanyRequest> {
    let sla_idx = demo_sla_company_index();
    demo_seed()
        .companies
        .iter()
        .enumerate()
        .map(|(i, c)| CreateCompanyRequest {
            name: c.name.clone(),
            parent_company_id: None,
            company_type: CompanyType::default(),
            status: CompanyStatus::default(),
            industry: Some(c.industry.clone()),
            website: Some(c.website.clone()),
            phone: Some(c.phone.clone()),
            fax: None,
            address: None,
            billing_address: None,
            tax_id: None,
            account_number: None,
            account_manager_id: None,
            sla_id: (i == sla_idx).then_some(sla_policy_id),
            payment_terms: None,
            tax_exempt: false,
            custom_fields: serde_json::Value::Null,
            tags: vec!["demo".to_string()],
            notes: Some(c.notes.clone()),
            portal_enabled: true,
        })
        .collect()
}

/// Index of the demo contact that shows off the PMS-806 collections: linked to
/// BOTH bundle companies and carrying two phone types, so the feature is
/// visible in demo data instead of only in tests.
pub const fn demo_multi_company_contact_index() -> usize {
    0
}

/// The demo contacts, each linked to its bundle company via `company_ids`
/// (indexed by the contact's `company_index`).
///
/// One contact (see [`demo_multi_company_contact_index`]) drives the PMS-806
/// child lists directly; the rest keep the scalar `company_id` / `phone` shape,
/// so the bundle exercises both write paths.
pub fn demo_contacts(company_ids: &[Uuid]) -> Vec<CreateContactRequest> {
    demo_seed()
        .contacts
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let multi = i == demo_multi_company_contact_index() && company_ids.len() >= 2;
            CreateContactRequest {
                company_id: if multi {
                    None
                } else {
                    company_ids.get(c.company_index).copied()
                },
                company_name: None,
                first_name: c.first_name.clone(),
                last_name: c.last_name.clone(),
                email: Some(c.email.clone()),
                phone: if multi {
                    None
                } else {
                    Some("+1-555-0100".to_string())
                },
                mobile: None,
                fax: None,
                title: Some(c.title.clone()),
                department: None,
                contact_type: ContactType::default(),
                preferred_contact_method: PreferredContactMethod::default(),
                timezone: None,
                custom_fields: serde_json::Value::Null,
                tags: vec!["demo".to_string()],
                notes: None,
                create_portal_access: false,
                phones: multi.then(|| {
                    vec![
                        ContactPhoneInput {
                            phone_type: PhoneType::Work,
                            number: Some("+15550100".to_string()),
                            extension: Some("204".to_string()),
                            is_primary: true,
                        },
                        ContactPhoneInput {
                            phone_type: PhoneType::Mobile,
                            number: Some("+15550188".to_string()),
                            extension: None,
                            is_primary: false,
                        },
                    ]
                }),
                companies: multi.then(|| {
                    vec![
                        ContactCompanyLinkInput {
                            company_id: company_ids[c.company_index],
                            title: Some(c.title.clone()),
                            is_primary: true,
                        },
                        ContactCompanyLinkInput {
                            company_id: company_ids[1 - c.company_index],
                            title: Some("Consulting IT Director".to_string()),
                            is_primary: false,
                        },
                    ]
                }),
            }
        })
        .collect()
}

/// A demo project plus its optional phase and task title. The loader creates the
/// project (required), then best-effort adds the phase and, if the tenant has a
/// task status, one task under it.
pub struct DemoProjectBuild {
    pub request: CreateProjectRequest,
    pub phase: Option<UpsertProjectPhaseRequest>,
    pub task_title: Option<String>,
}

/// The demo projects, linked to their bundle company via `company_ids` and
/// managed by the seeding user. Structural fields (dates, budget, billing) are
/// set here to sensible, obviously-illustrative values.
pub fn demo_projects(company_ids: &[Uuid], manager_id: Uuid) -> Vec<DemoProjectBuild> {
    let today = Utc::now().date_naive();
    demo_seed()
        .projects
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let request = CreateProjectRequest {
                name: p.name.clone(),
                description: Some(p.description.clone()),
                project_number: Some(format!("DEMO-PRJ-{:03}", i + 1)),
                company_id: company_ids.get(p.company_index).copied(),
                contract_id: None,
                project_type: "client".to_string(),
                status: p.status.clone(),
                project_manager_id: Some(manager_id),
                start_date: Some(today),
                target_end_date: Some(today + Duration::days(30)),
                actual_end_date: None,
                budget_hours: Some(Decimal::new(4000, 2)),
                budget_amount: Some(Decimal::new(1000000, 2)),
                billing_method: "time_and_materials".to_string(),
                hourly_rate: Some(Decimal::new(15000, 2)),
                is_billable: true,
                default_due_business_days: None,
            };
            let phase = p.phase_name.as_ref().map(|name| UpsertProjectPhaseRequest {
                name: name.clone(),
                description: Some("Example project phase.".to_string()),
                sort_order: 0,
                start_date: Some(today),
                end_date: Some(today + Duration::days(14)),
                status: "in_progress".to_string(),
            });
            DemoProjectBuild {
                request,
                phase,
                task_title: p.task_title.clone(),
            }
        })
        .collect()
}

/// The sample tickets. Priority, status, and queue are left unset so
/// `create_ticket` fills in the tenant's configured defaults (the per-tenant
/// NOT-NULL config FKs a static bundle cannot carry). Each ticket links its
/// bundle company and contact so the demo shows the company -> contact -> ticket
/// relationship. `sla_id` is left unset: the SLA subsystem assigns due dates
/// from the applicable policy, and the durable "this client is on an SLA"
/// relationship is carried by the company's `sla_id`, not the ticket's.
pub fn demo_tickets(company_ids: &[Uuid], contact_ids: &[Uuid]) -> Vec<CreateTicketRequest> {
    demo_seed()
        .tickets
        .iter()
        .filter_map(|t| {
            // A ticket needs a company; skip any whose index does not resolve
            // (only possible from a malformed bundle, which the tests catch).
            let company_id = company_ids.get(t.company_index).copied()?;
            Some(CreateTicketRequest {
                title: t.title.clone(),
                description: Some(t.description.clone()),
                company_id,
                contact_id: contact_ids.get(t.contact_index).copied(),
                is_billable: true,
                tags: vec!["demo".to_string()],
                ..Default::default()
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demo_seed_bundle_parses_to_the_expected_shape() {
        // The embedded bundle must parse and carry exactly the PMS-710 baseline
        // the seed service + integration tests expect, so a malformed edit is
        // caught in CI, not at seed time.
        let seed = demo_seed();
        assert_eq!(seed.companies.len(), 2, "two demo companies");
        assert_eq!(seed.contacts.len(), 4, "four demo contacts");
        assert_eq!(seed.projects.len(), 2, "two demo projects");
        assert_eq!(seed.tickets.len(), 5, "five demo tickets");
        assert_eq!(seed.companies[0].name, "Northwind Traders (Demo)");

        // Every cross-reference index is in range.
        assert!(seed.contacts.iter().all(|c| c.company_index < 2));
        assert!(seed.projects.iter().all(|p| p.company_index < 2));
        assert!(seed.tickets.iter().all(|t| t.company_index < 2));
        assert!(seed.tickets.iter().all(|t| t.contact_index < 4));
        assert!(seed.sla.company_index < 2);

        // The builders wire the FKs and produce the DTOs the service layer
        // consumes; smoke-check the mapping and the relationships.
        let sla_id = Uuid::new_v4();
        let companies = demo_companies(sla_id);
        assert_eq!(companies.len(), 2);
        assert_eq!(companies[demo_sla_company_index()].sla_id, Some(sla_id));
        assert!(companies
            .iter()
            .enumerate()
            .all(|(i, c)| (i == demo_sla_company_index()) == (c.sla_id == Some(sla_id))));

        let company_ids: Vec<Uuid> = (0..2).map(|_| Uuid::new_v4()).collect();
        let contacts = demo_contacts(&company_ids);
        assert_eq!(contacts.len(), 4);
        assert_eq!(contacts[0].first_name, "Alice");
        // PMS-806: every contact except the multi-company demo one keeps the
        // scalar single-company shape.
        assert!(contacts
            .iter()
            .zip(&seed.contacts)
            .enumerate()
            .filter(|(i, _)| *i != demo_multi_company_contact_index())
            .all(|(_, (dto, src))| dto.company_id == Some(company_ids[src.company_index])));

        // PMS-806: the demo bundle ships one contact linked to BOTH companies
        // and carrying two phone types, so the feature is visible in demo data.
        let multi = &contacts[demo_multi_company_contact_index()];
        assert!(
            multi.company_id.is_none(),
            "links drive the write, not the FK"
        );
        let links = multi.companies.as_ref().expect("multi-company links");
        assert_eq!(links.len(), 2);
        assert_eq!(links[0].company_id, company_ids[0]);
        assert!(links[0].is_primary);
        assert_eq!(links[1].company_id, company_ids[1]);
        assert!(!links[1].is_primary);
        let phones = multi.phones.as_ref().expect("typed phone list");
        assert_eq!(phones.len(), 2);
        assert_eq!(phones[0].phone_type, PhoneType::Work);
        assert!(phones[0].is_primary);
        assert_eq!(phones[1].phone_type, PhoneType::Mobile);

        let manager = Uuid::new_v4();
        let projects = demo_projects(&company_ids, manager);
        assert_eq!(projects.len(), 2);
        assert_eq!(projects[0].request.status, "active");
        assert!(projects[0].phase.is_some(), "active project has a phase");
        assert_eq!(
            projects[0].task_title.as_deref(),
            Some("Inventory current mailboxes and shared drives")
        );
        assert!(projects[1].phase.is_none(), "planning project has no phase");

        let contact_ids: Vec<Uuid> = (0..4).map(|_| Uuid::new_v4()).collect();
        let tickets = demo_tickets(&company_ids, &contact_ids);
        assert_eq!(tickets.len(), 5);
        assert!(tickets.iter().all(|t| company_ids.contains(&t.company_id)));
        assert!(tickets
            .iter()
            .all(|t| t.contact_id.is_some_and(|c| contact_ids.contains(&c))));
    }
}
