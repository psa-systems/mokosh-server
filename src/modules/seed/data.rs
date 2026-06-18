//! Demo-data payloads seeded into a brand-new account (PMS-157).
//!
//! The builders return the same `Create*Request` DTOs the public API
//! accepts, so seeding goes through the real service methods (validation,
//! FK checks, audit rows) instead of hand-rolled INSERTs. Only `contacts`
//! and `tickets` have real create paths today, so the demo set is one
//! client company, two contacts, and three tickets that link to them.

use uuid::Uuid;

use mokosh_types::contacts::{
    CompanyStatus, CompanyType, ContactType, CreateCompanyRequest, CreateContactRequest,
    PreferredContactMethod,
};
use mokosh_types::tickets::{CreateTicketRequest, TicketSource};

/// The sample client company. Names are obviously-fake so an operator can
/// tell demo rows from real data at a glance.
pub fn demo_company() -> CreateCompanyRequest {
    CreateCompanyRequest {
        name: "Acme Corporation (Demo)".to_string(),
        parent_company_id: None,
        company_type: CompanyType::default(),
        status: CompanyStatus::default(),
        industry: Some("Information Technology".to_string()),
        website: Some("https://example.com".to_string()),
        phone: Some("+1-555-0100".to_string()),
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
        notes: Some(
            "Sample company created automatically to show how Mokosh works. \
             Safe to edit or delete."
                .to_string(),
        ),
        portal_enabled: true,
    }
}

/// Primary contact at the demo company.
pub fn demo_contact_primary(company_id: Uuid) -> CreateContactRequest {
    demo_contact(
        company_id,
        "Alice",
        "Anderson",
        "alice.anderson@example.com",
        "IT Director",
    )
}

/// Secondary contact at the demo company.
pub fn demo_contact_secondary(company_id: Uuid) -> CreateContactRequest {
    demo_contact(
        company_id,
        "Bob",
        "Baker",
        "bob.baker@example.com",
        "Operations Manager",
    )
}

fn demo_contact(
    company_id: Uuid,
    first_name: &str,
    last_name: &str,
    email: &str,
    title: &str,
) -> CreateContactRequest {
    CreateContactRequest {
        company_id: Some(company_id),
        company_name: None,
        first_name: first_name.to_string(),
        last_name: last_name.to_string(),
        email: Some(email.to_string()),
        phone: Some("+1-555-0100".to_string()),
        mobile: None,
        fax: None,
        title: Some(title.to_string()),
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

/// Three sample tickets spanning a few everyday MSP scenarios. Priority,
/// status, and queue are left unset so `create_ticket` fills in the
/// tenant's configured defaults. `contact_id` links the first contact so
/// the demo shows the company -> contact -> ticket relationship.
pub fn demo_tickets(company_id: Uuid, contact_id: Uuid) -> Vec<CreateTicketRequest> {
    let specs = [
        (
            "Welcome to Mokosh - here's a sample ticket",
            "This is an example ticket. Open it to see how Mokosh tracks work, \
             then close or delete it when you're done exploring.",
        ),
        (
            "Laptop won't connect to Wi-Fi",
            "Demo ticket: a contact reports their laptop cannot join the office \
             wireless network after the latest update.",
        ),
        (
            "Request: onboard a new employee",
            "Demo ticket: provision accounts, email, and hardware for a new hire \
             starting next week.",
        ),
    ];
    specs
        .into_iter()
        .map(|(title, description)| CreateTicketRequest {
            title: title.to_string(),
            description: Some(description.to_string()),
            priority_id: None,
            type_id: None,
            category_id: None,
            queue_id: None,
            source: TicketSource::default(),
            company_id,
            contact_id: Some(contact_id),
            site_id: None,
            assigned_to_id: None,
            team_id: None,
            contract_id: None,
            sla_id: None,
            scheduled_start: None,
            scheduled_end: None,
            estimated_hours: None,
            is_billable: true,
            asset_id: None,
            custom_fields: serde_json::Value::Null,
            tags: vec!["demo".to_string()],
        })
        .collect()
}
