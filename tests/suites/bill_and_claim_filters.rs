//! PMS-1539: narrowing the bills and claims lists server-side.
//!
//! MAPPS-1167 wants a status picker and a search box on both list pages,
//! and its own acceptance criterion rules out doing it client-side: a
//! filter over one fetched page narrows the rendered rows and lies about
//! the count. So the filter is SQL, and the count uses the same predicate
//! as the page, which is what these cases pin.

use crate::common;

use chrono::NaiveDate;
use mokosh_server::modules::audit::AuditCtx;
use mokosh_server::modules::auth::TenantId;
use mokosh_server::modules::expenses::models::{BillFilter, ExpenseFilter};
use mokosh_server::modules::expenses::service::{
    BillLineInput, CreateBillRequest, CreateExpenseRequest, ExpenseLineInput, ExpensesService,
    UpsertVendorRequest,
};
use mokosh_server::utils::pagination::PaginationParams;
use mokosh_server::Database;
use mokosh_test::mokosh_test;
use sqlx::PgPool;
use uuid::Uuid;

fn ctx() -> AuditCtx {
    AuditCtx::system(common::DEFAULT_TENANT_ID)
}

fn tenant() -> TenantId {
    TenantId::from_trusted(common::DEFAULT_TENANT_ID)
}

/// Page one, big enough that nothing is cut off by paging.
fn page_one() -> PaginationParams {
    PaginationParams {
        page: 1,
        per_page: 25,
        sort: None,
        sort_dir: "desc".to_string(),
    }
}

fn status_filter(status: &str) -> BillFilter {
    BillFilter {
        status: Some(status.to_string()),
        q: None,
    }
}

fn q_filter(q: &str) -> BillFilter {
    BillFilter {
        status: None,
        q: Some(q.to_string()),
    }
}

async fn vendor(svc: &ExpensesService, name: &str) -> Uuid {
    svc.create_vendor(
        tenant(),
        &UpsertVendorRequest {
            name: name.to_string(),
            account_number: None,
            default_currency: Some("USD".to_string()),
            notes: None,
        },
        &ctx(),
    )
    .await
    .expect("vendor")
    .id
}

async fn bill(svc: &ExpensesService, vendor_id: Uuid, number: &str) -> Uuid {
    svc.create_bill(
        tenant(),
        &CreateBillRequest {
            vendor_id,
            bill_number: Some(number.to_string()),
            issue_date: NaiveDate::from_ymd_opt(2026, 10, 23).unwrap(),
            due_date: None,
            currency: "USD".to_string(),
            notes: None,
            lines: vec![BillLineInput {
                category_id: None,
                description: "Rack space".to_string(),
                quantity_hundredths: 100,
                unit_price_minor: 50_00,
                tax_minor: 0,
                position: 0,
            }],
        },
        &ctx(),
    )
    .await
    .expect("bill")
    .bill
    .id
}

/// Status narrows the page AND the count.
///
/// The count is the half a client-side filter cannot do: a total over
/// every bill beside a filtered page pages an operator into empty pages.
#[mokosh_test]
async fn a_status_filter_narrows_the_page_and_the_count(pool: PgPool) {
    let (_admin, _email, _pw) = common::seed_admin(&pool).await;
    let svc = ExpensesService::new(Database::from_pool(pool.clone()));
    let rack = vendor(&svc, "Rack Co").await;
    let draft = bill(&svc, rack, "VEN-1").await;
    let approved = bill(&svc, rack, "VEN-2").await;
    svc.approve_bill(tenant(), approved, &ctx())
        .await
        .expect("approve");

    let (rows, total) = svc
        .list_bills(tenant(), &status_filter("approved"), &page_one())
        .await
        .expect("list");
    assert_eq!(total, 1, "the count is the filtered count");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].id, approved);

    let (rows, total) = svc
        .list_bills(tenant(), &status_filter("draft"), &page_one())
        .await
        .expect("list");
    assert_eq!((rows.len(), total), (1, 1));
    assert_eq!(rows[0].id, draft);

    // Unfiltered is still everything.
    let (rows, total) = svc
        .list_bills(tenant(), &BillFilter::default(), &page_one())
        .await
        .expect("list");
    assert_eq!((rows.len(), total), (2, 2));
}

/// A status outside the CHECK set answers an empty page, not an error.
///
/// The `InvoiceFilter` precedent: an unknown status is a client asking
/// for rows that cannot exist, which is zero rows and not a 400.
#[mokosh_test]
async fn an_unknown_status_is_an_empty_page(pool: PgPool) {
    let (_admin, _email, _pw) = common::seed_admin(&pool).await;
    let svc = ExpensesService::new(Database::from_pool(pool.clone()));
    let rack = vendor(&svc, "Rack Co").await;
    bill(&svc, rack, "VEN-1").await;

    let (rows, total) = svc
        .list_bills(tenant(), &status_filter("partially_paid"), &page_one())
        .await
        .expect("list");
    assert_eq!((rows.len(), total), (0, 0));
}

/// `q` finds a bill by its own number and by its vendor's name.
///
/// The vendor name is the second identifier, and the one an operator is
/// more likely to remember than a number printed on somebody else's
/// document.
#[mokosh_test]
async fn q_matches_the_bill_number_and_the_vendor_name(pool: PgPool) {
    let (_admin, _email, _pw) = common::seed_admin(&pool).await;
    let svc = ExpensesService::new(Database::from_pool(pool.clone()));
    let rack = vendor(&svc, "Rack Co").await;
    let fibre = vendor(&svc, "Fibre Supply").await;
    let rack_bill = bill(&svc, rack, "VEN-1001").await;
    let fibre_bill = bill(&svc, fibre, "INV-77").await;

    let (rows, total) = svc
        .list_bills(tenant(), &q_filter("1001"), &page_one())
        .await
        .expect("list");
    assert_eq!((rows.len(), total), (1, 1), "by number");
    assert_eq!(rows[0].id, rack_bill);

    let (rows, total) = svc
        .list_bills(tenant(), &q_filter("fibre"), &page_one())
        .await
        .expect("list");
    assert_eq!(
        (rows.len(), total),
        (1, 1),
        "by vendor name, case-insensitively"
    );
    assert_eq!(rows[0].id, fibre_bill);

    // Blank and whitespace are not a filter: a cleared search box leaves
    // `q=` on the URL, and reading that as `%%` would be a filter that
    // matches everything by accident.
    for blank in ["", "   "] {
        let (rows, total) = svc
            .list_bills(tenant(), &q_filter(blank), &page_one())
            .await
            .expect("list");
        assert_eq!((rows.len(), total), (2, 2), "{blank:?}");
    }
}

/// Status and `q` apply together, as AND.
#[mokosh_test]
async fn the_two_filters_narrow_together(pool: PgPool) {
    let (_admin, _email, _pw) = common::seed_admin(&pool).await;
    let svc = ExpensesService::new(Database::from_pool(pool.clone()));
    let rack = vendor(&svc, "Rack Co").await;
    let fibre = vendor(&svc, "Fibre Supply").await;
    let rack_approved = bill(&svc, rack, "VEN-1").await;
    svc.approve_bill(tenant(), rack_approved, &ctx())
        .await
        .expect("approve");
    let fibre_approved = bill(&svc, fibre, "VEN-2").await;
    svc.approve_bill(tenant(), fibre_approved, &ctx())
        .await
        .expect("approve");
    bill(&svc, rack, "VEN-3").await; // Rack Co, still draft.

    let filter = BillFilter {
        status: Some("approved".to_string()),
        q: Some("Rack".to_string()),
    };
    let (rows, total) = svc
        .list_bills(tenant(), &filter, &page_one())
        .await
        .expect("list");
    assert_eq!(
        (rows.len(), total),
        (1, 1),
        "approved AND Rack Co, not either"
    );
    assert_eq!(rows[0].id, rack_approved);
}

/// A filtered total survives paging: page two of a filtered set holds the
/// filtered remainder, and the total is still the filtered count.
#[mokosh_test]
async fn a_filtered_total_is_the_one_paging_uses(pool: PgPool) {
    let (_admin, _email, _pw) = common::seed_admin(&pool).await;
    let svc = ExpensesService::new(Database::from_pool(pool.clone()));
    let rack = vendor(&svc, "Rack Co").await;
    let fibre = vendor(&svc, "Fibre Supply").await;
    for n in 0..3 {
        let id = bill(&svc, rack, &format!("VEN-{n}")).await;
        svc.approve_bill(tenant(), id, &ctx())
            .await
            .expect("approve");
    }
    // Two the filter excludes, which is what a stale count would include.
    bill(&svc, fibre, "INV-1").await;
    bill(&svc, fibre, "INV-2").await;

    let one_per_page = PaginationParams {
        page: 2,
        per_page: 2,
        sort: None,
        sort_dir: "desc".to_string(),
    };
    let (rows, total) = svc
        .list_bills(tenant(), &status_filter("approved"), &one_per_page)
        .await
        .expect("list");
    assert_eq!(total, 3, "three approved, not five bills");
    assert_eq!(
        rows.len(),
        1,
        "and page two of two-per-page holds the third"
    );
}

// ── Claims ───────────────────────────────────────────────────────────────

async fn claim(svc: &ExpensesService, user_id: Uuid, description: &str) -> Uuid {
    svc.create_expense(
        tenant(),
        user_id,
        &CreateExpenseRequest {
            incurred_on: NaiveDate::from_ymd_opt(2026, 10, 23).unwrap(),
            currency: "USD".to_string(),
            notes: None,
            lines: vec![ExpenseLineInput {
                category_id: None,
                description: description.to_string(),
                amount_minor: 32_50,
                tax_minor: 0,
                position: 0,
            }],
        },
        &ctx(),
    )
    .await
    .expect("claim")
    .expense
    .id
}

/// A claim is found by what it was FOR, which is written on its lines.
///
/// A claim has no number of its own, so the line description is what
/// somebody remembers; `notes` is searched too, for the claims that carry
/// one.
#[mokosh_test]
async fn a_claim_is_found_by_its_line_description(pool: PgPool) {
    let (admin, _email, _pw) = common::seed_admin(&pool).await;
    let svc = ExpensesService::new(Database::from_pool(pool.clone()));
    let taxi = claim(&svc, admin, "Taxi to site").await;
    let _hotel = claim(&svc, admin, "Hotel, two nights").await;

    let filter = ExpenseFilter {
        status: None,
        q: Some("taxi".to_string()),
    };
    let (rows, total) = svc
        .list_expenses(tenant(), None, &filter, &page_one())
        .await
        .expect("list");
    assert_eq!((rows.len(), total), (1, 1), "case-insensitive on the line");
    assert_eq!(rows[0].id, taxi);
}

/// The submitter scope applies first: a filter narrows what that caller
/// could already see and never widens it (PMS-1535).
#[mokosh_test]
async fn a_filter_cannot_widen_the_submitter_scope(pool: PgPool) {
    let (admin, _email, _pw) = common::seed_admin(&pool).await;
    let (tech, _email, _pw) = common::seed_user(
        &pool,
        common::DEFAULT_TENANT_ID,
        "tech@example.com",
        "technician",
    )
    .await;
    let svc = ExpensesService::new(Database::from_pool(pool.clone()));
    claim(&svc, admin, "Taxi to site").await;
    let theirs = claim(&svc, tech, "Taxi to the other site").await;

    let filter = ExpenseFilter {
        status: None,
        q: Some("taxi".to_string()),
    };
    let (rows, total) = svc
        .list_expenses(tenant(), Some(tech), &filter, &page_one())
        .await
        .expect("list");
    assert_eq!(
        (rows.len(), total),
        (1, 1),
        "both claims match the text; one is theirs"
    );
    assert_eq!(rows[0].id, theirs);

    // Finance sees both, same filter.
    let (rows, total) = svc
        .list_expenses(tenant(), None, &filter, &page_one())
        .await
        .expect("list");
    assert_eq!((rows.len(), total), (2, 2));
}

/// Status narrows claims through their five states.
#[mokosh_test]
async fn a_claim_status_filter_follows_the_lifecycle(pool: PgPool) {
    let (admin, _email, _pw) = common::seed_admin(&pool).await;
    let svc = ExpensesService::new(Database::from_pool(pool.clone()));
    let draft = claim(&svc, admin, "Taxi to site").await;
    let submitted = claim(&svc, admin, "Hotel, two nights").await;
    svc.submit_expense(tenant(), submitted, &ctx())
        .await
        .expect("submit");

    for (status, expected) in [("draft", draft), ("submitted", submitted)] {
        let filter = ExpenseFilter {
            status: Some(status.to_string()),
            q: None,
        };
        let (rows, total) = svc
            .list_expenses(tenant(), None, &filter, &page_one())
            .await
            .expect("list");
        assert_eq!((rows.len(), total), (1, 1), "{status}");
        assert_eq!(rows[0].id, expected, "{status}");
    }
}
