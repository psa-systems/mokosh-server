//! Demo-data payloads seeded into a brand-new account (PMS-157).
//!
//! The demo CONTENT (company / contact / ticket names, titles, descriptions)
//! lives in the committed `demo_seed.json` bundle, embedded at compile time
//! (PMS-651, the service-layer seed-bundle slice). This module maps that bundle
//! into the same `Create*Request` DTOs the public API accepts, so seeding still
//! goes through the real service methods (validation, FK checks, per-tenant
//! config defaults, audit rows) instead of hand-rolled INSERTs. Data-driven so
//! the demo set can change without touching Rust; the load is create-only and
//! non-destructive, distinct from the wipe-and-replace `data_transfer` import.
//! Only `contacts` and `tickets` have real create paths today, so the demo set
//! is one client company, two contacts, and three tickets that link to them.

use std::sync::OnceLock;

use serde::Deserialize;
use uuid::Uuid;

use mokosh_types::contacts::{
    CompanyStatus, CompanyType, ContactType, CreateCompanyRequest, CreateContactRequest,
    PreferredContactMethod,
};
use mokosh_types::tickets::CreateTicketRequest;

/// The committed demo-seed bundle. It carries only the human-meaningful content;
/// structural defaults (tags, phone, portal flags, `..Default`) stay in the
/// builders below so the bundle stays readable and small.
const DEMO_SEED_JSON: &str = include_str!("demo_seed.json");

#[derive(Deserialize)]
struct DemoSeed {
    company: DemoCompany,
    contacts: Vec<DemoContact>,
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
    first_name: String,
    last_name: String,
    email: String,
    title: String,
}

#[derive(Deserialize)]
struct DemoTicket {
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

/// The sample client company. Names are obviously-fake so an operator can
/// tell demo rows from real data at a glance.
pub fn demo_company() -> CreateCompanyRequest {
    let c = &demo_seed().company;
    CreateCompanyRequest {
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
        sla_id: None,
        payment_terms: None,
        tax_exempt: false,
        custom_fields: serde_json::Value::Null,
        tags: vec!["demo".to_string()],
        notes: Some(c.notes.clone()),
        portal_enabled: true,
    }
}

/// Primary contact at the demo company (the first bundle contact).
pub fn demo_contact_primary(company_id: Uuid) -> CreateContactRequest {
    demo_contact(company_id, 0)
}

/// Secondary contact at the demo company (the second bundle contact).
pub fn demo_contact_secondary(company_id: Uuid) -> CreateContactRequest {
    demo_contact(company_id, 1)
}

fn demo_contact(company_id: Uuid, index: usize) -> CreateContactRequest {
    let c = &demo_seed().contacts[index];
    CreateContactRequest {
        company_id: Some(company_id),
        company_name: None,
        first_name: c.first_name.clone(),
        last_name: c.last_name.clone(),
        email: Some(c.email.clone()),
        phone: Some("+1-555-0100".to_string()),
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
    }
}

/// The sample tickets from the bundle. Priority, status, and queue are left
/// unset so `create_ticket` fills in the tenant's configured defaults (the
/// per-tenant NOT-NULL config FKs a static bundle cannot carry). `contact_id`
/// links the given contact so the demo shows the company -> contact -> ticket
/// relationship.
pub fn demo_tickets(company_id: Uuid, contact_id: Uuid) -> Vec<CreateTicketRequest> {
    demo_seed()
        .tickets
        .iter()
        .map(|t| CreateTicketRequest {
            title: t.title.clone(),
            description: Some(t.description.clone()),
            company_id,
            contact_id: Some(contact_id),
            is_billable: true,
            tags: vec!["demo".to_string()],
            ..Default::default()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demo_seed_bundle_parses_to_the_expected_shape() {
        // The embedded bundle must parse and carry exactly the demo baseline the
        // seed service + integration tests expect (one company, two contacts,
        // three tickets), so a malformed edit is caught in CI, not at seed time.
        let seed = demo_seed();
        assert_eq!(seed.company.name, "Acme Corporation (Demo)");
        assert_eq!(seed.contacts.len(), 2, "two demo contacts");
        assert_eq!(seed.tickets.len(), 3, "three demo tickets");

        // The builders wire the FKs and produce the DTOs the service layer
        // consumes; smoke-check the mapping and the company/contact/ticket links.
        let company = demo_company();
        assert_eq!(company.name, "Acme Corporation (Demo)");
        assert_eq!(company.tags, vec!["demo".to_string()]);

        let cid = Uuid::new_v4();
        let primary = demo_contact_primary(cid);
        assert_eq!(primary.company_id, Some(cid));
        assert_eq!(primary.first_name, "Alice");
        assert_eq!(demo_contact_secondary(cid).first_name, "Bob");

        let contact_id = Uuid::new_v4();
        let tickets = demo_tickets(cid, contact_id);
        assert_eq!(tickets.len(), 3);
        assert!(tickets
            .iter()
            .all(|t| t.company_id == cid && t.contact_id == Some(contact_id)));
    }
}
