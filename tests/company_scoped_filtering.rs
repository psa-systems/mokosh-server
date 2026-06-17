//! Company-scoped list filtering verification suite (PMS-401).
//!
//! The frontend company context cards (MAPPS-249 / c2-viewall-scoped-fe)
//! fetch company-scoped previews by passing `?company_id={id}` to the
//! global list endpoints (`/tickets`, `/contracts`, `/projects`,
//! `/assets`, `/invoices`). PMS-401 audits the backend support those
//! calls depend on. This suite is the executable form of that audit and a
//! regression guard for three properties every one of those five
//! endpoints must hold:
//!
//!   1. With `?company_id=A` the list returns ONLY company A's rows (no
//!      cross-company bleed). AC #1.
//!   2. The paginated `total` reflects the company-filtered count: the
//!      COUNT query applies the same `company_id` condition as the data
//!      query, so the Statistics card counts (which read `meta.total`)
//!      match the rows shown. AC #2 / #4.
//!   3. An unknown `company_id` yields an EMPTY filtered list with
//!      `total = 0`, never a silent fall-back to the unfiltered
//!      all-companies list. AC #1.
//!
//! Properties 1-3 are proven at the service layer (the `company_id`
//! WHERE/COUNT clause lives there, below row mapping), seeding two
//! companies with a known per-company row count and asserting the
//! filtered read against each.
//!
//! AC #3 (a MALFORMED `company_id` fails query deserialization cleanly
//! with 400 rather than dropping the filter) is a property of the
//! `Query<Filter>` extractor, so it is proven at the HTTP layer in
//! `malformed_company_id_is_rejected_with_400`.
//!
//! Note for maintainers: the audit found no backend gap. Every one of the
//! five endpoints already applies `company_id` to BOTH its data and count
//! queries (tickets `service.rs` `build_ticket_filter_sql`, contracts /
//! assets share one `where_clause`, projects / invoices build parallel
//! data/count clauses). No new endpoints are needed and the c2 work is
//! purely client-side routing.

mod common;

use chrono::NaiveDate;
use mokosh_server::modules::assets::{AssetFilter, AssetsService};
use mokosh_server::modules::auth::TenantId;
use mokosh_server::modules::billing::{BillingService, InvoiceFilter};
use mokosh_server::modules::contracts::{ContractFilter, ContractsService};
use mokosh_server::modules::projects::{ProjectFilter, ProjectsService};
use mokosh_server::modules::tickets::{TicketFilter, TicketService};
use mokosh_server::utils::pagination::PaginationParams;
use mokosh_server::Database;
use sqlx::PgPool;
use uuid::Uuid;

fn tenant() -> TenantId {
    TenantId::from_trusted(common::DEFAULT_TENANT_ID)
}

/// A page large enough that every seeded fixture row falls on page 1, so
/// `data.len()` equals the full filtered set and can be compared to
/// `total`.
fn all() -> PaginationParams {
    PaginationParams {
        page: 1,
        per_page: 100,
        sort: None,
        sort_dir: "desc".to_string(),
    }
}

/// Seed a company with the given display name under the default tenant.
async fn seed_company_named(pool: &PgPool, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(common::DEFAULT_TENANT_ID)
        .bind(name)
        .execute(pool)
        .await
        .expect("seed company");
    id
}

#[sqlx::test]
async fn tickets_list_is_company_scoped(pool: PgPool) {
    // created_by_id is NOT NULL -> a user must exist.
    let (user, _, _) = common::seed_admin(&pool).await;
    let a = seed_company_named(&pool, "Company A").await;
    let b = seed_company_named(&pool, "Company B").await;

    // The seed migration provisions default ticket statuses/priorities/
    // queues for the default tenant; reuse any one of each.
    let status: Uuid =
        sqlx::query_scalar("SELECT id FROM ticket_statuses WHERE tenant_id = $1 LIMIT 1")
            .bind(common::DEFAULT_TENANT_ID)
            .fetch_one(&pool)
            .await
            .expect("seeded ticket status");
    let priority: Uuid =
        sqlx::query_scalar("SELECT id FROM ticket_priorities WHERE tenant_id = $1 LIMIT 1")
            .bind(common::DEFAULT_TENANT_ID)
            .fetch_one(&pool)
            .await
            .expect("seeded ticket priority");
    let queue: Uuid =
        sqlx::query_scalar("SELECT id FROM ticket_queues WHERE tenant_id = $1 LIMIT 1")
            .bind(common::DEFAULT_TENANT_ID)
            .fetch_one(&pool)
            .await
            .expect("seeded ticket queue");

    // Two tickets for A, one for B.
    for (company, num) in [(a, "T-1"), (a, "T-2"), (b, "T-3")] {
        sqlx::query(
            r#"INSERT INTO tickets
               (id, tenant_id, ticket_number, title, status_id, priority_id, queue_id,
                company_id, created_by_id)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"#,
        )
        .bind(Uuid::new_v4())
        .bind(common::DEFAULT_TENANT_ID)
        .bind(num)
        .bind(format!("Ticket {num}"))
        .bind(status)
        .bind(priority)
        .bind(queue)
        .bind(company)
        .bind(user)
        .execute(&pool)
        .await
        .expect("seed ticket");
    }

    let svc = TicketService::new(Database::from_pool(pool.clone()));

    let scoped = TicketFilter {
        company_id: Some(a),
        ..Default::default()
    };
    let (rows, total) = svc
        .list_tickets(tenant(), &scoped, &all())
        .await
        .expect("list tickets for company A");
    assert_eq!(rows.len(), 2, "only company A's two tickets are returned");
    assert_eq!(total, 2, "count query reflects the company-filtered total");
    assert!(
        rows.iter().all(|t| t.company_id == a),
        "no cross-company bleed"
    );

    let unknown = TicketFilter {
        company_id: Some(Uuid::new_v4()),
        ..Default::default()
    };
    let (rows, total) = svc
        .list_tickets(tenant(), &unknown, &all())
        .await
        .expect("list tickets for unknown company");
    assert!(rows.is_empty(), "unknown company yields an empty list");
    assert_eq!(
        total, 0,
        "unknown company yields total 0, not all-companies"
    );
}

#[sqlx::test]
async fn contracts_list_is_company_scoped(pool: PgPool) {
    let a = seed_company_named(&pool, "Company A").await;
    let b = seed_company_named(&pool, "Company B").await;

    for (company, num) in [(a, "C-1"), (a, "C-2"), (b, "C-3")] {
        sqlx::query(
            r#"INSERT INTO contracts
               (id, tenant_id, contract_number, name, company_id, contract_type, status,
                start_date, billing_cycle)
               VALUES ($1, $2, $3, $4, $5, 'managed_services', 'active', '2026-01-01', 'monthly')"#,
        )
        .bind(Uuid::new_v4())
        .bind(common::DEFAULT_TENANT_ID)
        .bind(num)
        .bind(format!("Contract {num}"))
        .bind(company)
        .execute(&pool)
        .await
        .expect("seed contract");
    }

    let svc = ContractsService::new(Database::from_pool(pool.clone()));

    let scoped = ContractFilter {
        company_id: Some(a),
        ..Default::default()
    };
    let (rows, total) = svc
        .list_contracts(tenant(), &scoped, &all())
        .await
        .expect("list contracts for company A");
    assert_eq!(rows.len(), 2);
    assert_eq!(total, 2);
    assert!(rows.iter().all(|c| c.company_id == a));

    let unknown = ContractFilter {
        company_id: Some(Uuid::new_v4()),
        ..Default::default()
    };
    let (rows, total) = svc
        .list_contracts(tenant(), &unknown, &all())
        .await
        .expect("list contracts for unknown company");
    assert!(rows.is_empty());
    assert_eq!(total, 0);
}

#[sqlx::test]
async fn projects_list_is_company_scoped(pool: PgPool) {
    let a = seed_company_named(&pool, "Company A").await;
    let b = seed_company_named(&pool, "Company B").await;

    for (company, name) in [(a, "P-1"), (a, "P-2"), (b, "P-3")] {
        sqlx::query(
            r#"INSERT INTO projects
               (id, tenant_id, name, company_id, project_type, status)
               VALUES ($1, $2, $3, $4, 'client', 'active')"#,
        )
        .bind(Uuid::new_v4())
        .bind(common::DEFAULT_TENANT_ID)
        .bind(name)
        .bind(company)
        .execute(&pool)
        .await
        .expect("seed project");
    }

    let svc = ProjectsService::new(Database::from_pool(pool.clone()));

    let scoped = ProjectFilter {
        company_id: Some(a),
        ..Default::default()
    };
    let (rows, total) = svc
        .list_projects(tenant(), &scoped, &all())
        .await
        .expect("list projects for company A");
    assert_eq!(rows.len(), 2);
    assert_eq!(total, 2);
    assert!(rows.iter().all(|p| p.company_id == Some(a)));

    let unknown = ProjectFilter {
        company_id: Some(Uuid::new_v4()),
        ..Default::default()
    };
    let (rows, total) = svc
        .list_projects(tenant(), &unknown, &all())
        .await
        .expect("list projects for unknown company");
    assert!(rows.is_empty());
    assert_eq!(total, 0);
}

#[sqlx::test]
async fn assets_list_is_company_scoped(pool: PgPool) {
    let a = seed_company_named(&pool, "Company A").await;
    let b = seed_company_named(&pool, "Company B").await;

    // asset_type_id is NOT NULL; reuse a seeded default asset type.
    let asset_type: Uuid =
        sqlx::query_scalar("SELECT id FROM asset_types WHERE tenant_id = $1 LIMIT 1")
            .bind(common::DEFAULT_TENANT_ID)
            .fetch_one(&pool)
            .await
            .expect("seeded asset type");

    for (company, tag) in [(a, "A-1"), (a, "A-2"), (b, "A-3")] {
        sqlx::query(
            r#"INSERT INTO assets
               (id, tenant_id, name, asset_type_id, company_id)
               VALUES ($1, $2, $3, $4, $5)"#,
        )
        .bind(Uuid::new_v4())
        .bind(common::DEFAULT_TENANT_ID)
        .bind(format!("Asset {tag}"))
        .bind(asset_type)
        .bind(company)
        .execute(&pool)
        .await
        .expect("seed asset");
    }

    let svc = AssetsService::with_encryption_key(Database::from_pool(pool.clone()), [0u8; 32]);

    let scoped = AssetFilter {
        company_id: Some(a),
        ..Default::default()
    };
    let (rows, total) = svc
        .list_assets(tenant(), &scoped, &all())
        .await
        .expect("list assets for company A");
    assert_eq!(rows.len(), 2);
    assert_eq!(total, 2);
    assert!(rows.iter().all(|a_row| a_row.company_id == a));

    let unknown = AssetFilter {
        company_id: Some(Uuid::new_v4()),
        ..Default::default()
    };
    let (rows, total) = svc
        .list_assets(tenant(), &unknown, &all())
        .await
        .expect("list assets for unknown company");
    assert!(rows.is_empty());
    assert_eq!(total, 0);
}

#[sqlx::test]
async fn invoices_list_is_company_scoped(pool: PgPool) {
    let a = seed_company_named(&pool, "Company A").await;
    let b = seed_company_named(&pool, "Company B").await;

    let date = NaiveDate::from_ymd_opt(2026, 1, 1).unwrap();
    for (company, num) in [(a, "INV-1"), (a, "INV-2"), (b, "INV-3")] {
        sqlx::query(
            r#"INSERT INTO invoices
               (id, tenant_id, invoice_number, company_id, status, invoice_date, due_date)
               VALUES ($1, $2, $3, $4, 'draft', $5, $5)"#,
        )
        .bind(Uuid::new_v4())
        .bind(common::DEFAULT_TENANT_ID)
        .bind(num)
        .bind(company)
        .bind(date)
        .execute(&pool)
        .await
        .expect("seed invoice");
    }

    let svc = BillingService::new(Database::from_pool(pool.clone()));

    let scoped = InvoiceFilter {
        company_id: Some(a),
        ..Default::default()
    };
    let (rows, total) = svc
        .list_invoices(tenant(), &scoped, &all())
        .await
        .expect("list invoices for company A");
    assert_eq!(rows.len(), 2);
    assert_eq!(total, 2);
    assert!(rows.iter().all(|i| i.company_id == a));

    let unknown = InvoiceFilter {
        company_id: Some(Uuid::new_v4()),
        ..Default::default()
    };
    let (rows, total) = svc
        .list_invoices(tenant(), &unknown, &all())
        .await
        .expect("list invoices for unknown company");
    assert!(rows.is_empty());
    assert_eq!(total, 0);
}

/// AC #3: a malformed `company_id` (not a UUID) must fail `Query`
/// deserialization with 400 Bad Request rather than silently dropping the
/// filter and returning the unfiltered all-companies list. Proven at the
/// HTTP layer because the rejection is a property of the `Query<Filter>`
/// extractor, not the service. Exercises all five global list endpoints.
#[sqlx::test]
async fn malformed_company_id_is_rejected_with_400(pool: PgPool) {
    let (_uid, email, pw) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;

    for path in [
        "/api/v1/tickets",
        "/api/v1/contracts",
        "/api/v1/projects",
        "/api/v1/assets",
        "/api/v1/invoices",
    ] {
        let resp = app
            .client
            .get(app.url(&format!("{path}?company_id=not-a-uuid")))
            .bearer_auth(&token)
            .send()
            .await
            .unwrap_or_else(|e| panic!("GET {path} with malformed company_id: {e}"));
        assert_eq!(
            resp.status(),
            reqwest::StatusCode::BAD_REQUEST,
            "{path} must reject a malformed company_id with 400, not drop the filter"
        );
    }
}
