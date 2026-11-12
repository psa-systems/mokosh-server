//! PMS-1536: recording what the MSP has paid a vendor.
//!
//! `bills.status` had allowed `paid` since migration 279 with nothing able
//! to set it, and `paid_minor` was read by five queries and written by
//! none, so a bill the MSP had settled stayed `approved` forever.
//!
//! These cases pin the writer and the four refusals. They drive the
//! service rather than HTTP, because the rule under test is arithmetic and
//! lifecycle rather than a gate; `expense_claim_gates` is where the role
//! half lives.

use crate::common;

use chrono::NaiveDate;
use mokosh_server::modules::audit::AuditCtx;
use mokosh_server::modules::auth::TenantId;
use mokosh_server::modules::expenses::service::{
    BillLineInput, CreateBillRequest, ExpensesService, RecordBillPaymentRequest,
    UpsertVendorRequest,
};
use mokosh_server::utils::error::AppError;
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

/// A bill for 70.00: one line of 1 x 50.00 and one of 2 x 10.00.
fn bill_body(vendor_id: Uuid) -> CreateBillRequest {
    CreateBillRequest {
        vendor_id,
        bill_number: Some("VEN-9001".to_string()),
        issue_date: NaiveDate::from_ymd_opt(2026, 10, 23).unwrap(),
        due_date: Some(NaiveDate::from_ymd_opt(2026, 11, 23).unwrap()),
        currency: "USD".to_string(),
        notes: None,
        lines: vec![
            BillLineInput {
                category_id: None,
                description: "Rack space".to_string(),
                quantity_hundredths: 100,
                unit_price_minor: 50_00,
                tax_minor: 0,
                position: 0,
            },
            BillLineInput {
                category_id: None,
                description: "Cross connects".to_string(),
                quantity_hundredths: 200,
                unit_price_minor: 10_00,
                tax_minor: 0,
                position: 1,
            },
        ],
    }
}

fn payment(amount_minor: i64) -> RecordBillPaymentRequest {
    RecordBillPaymentRequest {
        paid_on: NaiveDate::from_ymd_opt(2026, 11, 1).unwrap(),
        amount_minor,
        payment_method: "ach".to_string(),
        reference: Some("ACH-77".to_string()),
        notes: None,
    }
}

/// Create a vendor and an APPROVED bill for 70.00.
async fn approved_bill(svc: &ExpensesService) -> Uuid {
    let vendor = svc
        .create_vendor(
            tenant(),
            &UpsertVendorRequest {
                name: "Rack Co".to_string(),
                account_number: None,
                default_currency: Some("USD".to_string()),
                notes: None,
            },
            &ctx(),
        )
        .await
        .expect("vendor");
    let bill = svc
        .create_bill(tenant(), &bill_body(vendor.id), &ctx())
        .await
        .expect("bill");
    svc.approve_bill(tenant(), bill.bill.id, &ctx())
        .await
        .expect("approve");
    bill.bill.id
}

/// A payment that covers the total moves the bill to `paid`, and the
/// paid total comes from the rows.
#[mokosh_test]
async fn a_payment_that_covers_the_total_pays_the_bill(pool: PgPool) {
    let (_admin, _email, _pw) = common::seed_admin(&pool).await;
    let svc = ExpensesService::new(Database::from_pool(pool.clone()));
    let id = approved_bill(&svc).await;

    let result = svc
        .record_bill_payment(tenant(), id, &payment(70_00), &ctx())
        .await
        .expect("record the payment");

    assert_eq!(result.bill.paid_minor, 70_00);
    assert_eq!(
        result.bill.status, "paid",
        "the status the model has known since migration 279 finally has a writer"
    );
    assert_eq!(result.payments.len(), 1);
    assert_eq!(result.payments[0].amount_minor, 70_00);
    assert_eq!(result.payments[0].payment_method, "ach");

    let listed = svc
        .list_bill_payments(tenant(), id)
        .await
        .expect("list payments");
    assert_eq!(listed.len(), 1, "and the payment is kept as a row");
    assert_eq!(listed[0].reference.as_deref(), Some("ACH-77"));
}

/// Two part payments add up, and the bill stays `approved` until they
/// cover it.
#[mokosh_test]
async fn part_payments_add_up_and_leave_the_bill_approved(pool: PgPool) {
    let (_admin, _email, _pw) = common::seed_admin(&pool).await;
    let svc = ExpensesService::new(Database::from_pool(pool.clone()));
    let id = approved_bill(&svc).await;

    let first = svc
        .record_bill_payment(tenant(), id, &payment(30_00), &ctx())
        .await
        .expect("first payment");
    assert_eq!(first.bill.paid_minor, 30_00);
    assert_eq!(
        first.bill.status, "approved",
        "part paid is not paid, and the bills CHECK has no partially_paid"
    );

    let second = svc
        .record_bill_payment(tenant(), id, &payment(40_00), &ctx())
        .await
        .expect("second payment");
    assert_eq!(
        second.bill.paid_minor, 70_00,
        "the total is the sum of the rows, not a counter each call nudges"
    );
    assert_eq!(second.bill.status, "paid");
    assert_eq!(
        svc.list_bill_payments(tenant(), id)
            .await
            .expect("list")
            .len(),
        2
    );
}

/// A draft bill cannot be paid: approval is where the bill is checked
/// against what was ordered.
#[mokosh_test]
async fn a_draft_bill_cannot_be_paid(pool: PgPool) {
    let (_admin, _email, _pw) = common::seed_admin(&pool).await;
    let svc = ExpensesService::new(Database::from_pool(pool.clone()));
    let vendor = svc
        .create_vendor(
            tenant(),
            &UpsertVendorRequest {
                name: "Rack Co".to_string(),
                account_number: None,
                default_currency: None,
                notes: None,
            },
            &ctx(),
        )
        .await
        .expect("vendor");
    let bill = svc
        .create_bill(tenant(), &bill_body(vendor.id), &ctx())
        .await
        .expect("bill");

    let err = svc
        .record_bill_payment(tenant(), bill.bill.id, &payment(70_00), &ctx())
        .await
        .expect_err("a draft cannot be paid");
    let AppError::Conflict(message) = &err else {
        panic!("a client-stated conflict is not a server fault: {err:?}");
    };
    assert!(
        message.contains("Approve it first"),
        "the refusal names the step that is missing: {message}"
    );
    assert_eq!(
        svc.get_bill(tenant(), bill.bill.id)
            .await
            .expect("read")
            .bill
            .paid_minor,
        0,
        "and nothing was written"
    );
}

/// A void bill cannot be paid, and the refusal says it was voided.
#[mokosh_test]
async fn a_void_bill_cannot_be_paid(pool: PgPool) {
    let (_admin, _email, _pw) = common::seed_admin(&pool).await;
    let svc = ExpensesService::new(Database::from_pool(pool.clone()));
    let id = approved_bill(&svc).await;
    svc.void_bill(tenant(), id, &ctx()).await.expect("void");

    let err = svc
        .record_bill_payment(tenant(), id, &payment(70_00), &ctx())
        .await
        .expect_err("a void bill cannot be paid");
    let AppError::Conflict(message) = &err else {
        panic!("expected a conflict: {err:?}");
    };
    assert!(message.contains("voided"), "{message}");
}

/// Zero and negative amounts are refused: a vendor refund is a credit,
/// not a negative payment.
#[mokosh_test]
async fn a_payment_must_be_above_zero(pool: PgPool) {
    let (_admin, _email, _pw) = common::seed_admin(&pool).await;
    let svc = ExpensesService::new(Database::from_pool(pool.clone()));
    let id = approved_bill(&svc).await;

    for amount in [0, -500] {
        let err = svc
            .record_bill_payment(tenant(), id, &payment(amount), &ctx())
            .await
            .expect_err("not a payment");
        assert!(
            matches!(err, AppError::Validation { .. }),
            "{amount} is a field problem, not a conflict: {err:?}"
        );
    }
    assert_eq!(
        svc.get_bill(tenant(), id).await.expect("read").bill.status,
        "approved"
    );
}

/// Paying more than remains is refused, naming what remains.
///
/// A duplicate payment is settled with the vendor; recording it would
/// leave `paid_minor > total_minor` and `status` meaning neither one
/// thing nor the other.
#[mokosh_test]
async fn a_payment_over_the_balance_is_refused_naming_what_remains(pool: PgPool) {
    let (_admin, _email, _pw) = common::seed_admin(&pool).await;
    let svc = ExpensesService::new(Database::from_pool(pool.clone()));
    let id = approved_bill(&svc).await;
    svc.record_bill_payment(tenant(), id, &payment(50_00), &ctx())
        .await
        .expect("first payment");

    let err = svc
        .record_bill_payment(tenant(), id, &payment(50_00), &ctx())
        .await
        .expect_err("that is more than remains");
    let AppError::Conflict(message) = &err else {
        panic!("expected a conflict: {err:?}");
    };
    assert!(
        message.contains("2000"),
        "the refusal names what remains, in the minor units the caller sent: {message}"
    );

    let bill = svc.get_bill(tenant(), id).await.expect("read").bill;
    assert_eq!(bill.paid_minor, 50_00, "and the first payment stands alone");
    assert_eq!(bill.status, "approved");
}

/// An unknown bill id is a 404 on both routes, not an empty list.
#[mokosh_test]
async fn an_unknown_bill_is_not_an_empty_payment_list(pool: PgPool) {
    let (_admin, _email, _pw) = common::seed_admin(&pool).await;
    let svc = ExpensesService::new(Database::from_pool(pool.clone()));

    let err = svc
        .list_bill_payments(tenant(), Uuid::new_v4())
        .await
        .expect_err("there is no such bill");
    assert!(
        matches!(&err, AppError::NotFound(what) if what == "Bill"),
        "an empty list would read as paid nothing yet: {err:?}"
    );
}

/// A bad payment method is refused by name rather than by a 23514 from
/// the CHECK.
#[mokosh_test]
async fn an_unknown_payment_method_is_refused_by_name(pool: PgPool) {
    let (_admin, _email, _pw) = common::seed_admin(&pool).await;
    let svc = ExpensesService::new(Database::from_pool(pool.clone()));
    let id = approved_bill(&svc).await;

    let mut request = payment(70_00);
    request.payment_method = "bitcoin".to_string();
    let err = svc
        .record_bill_payment(tenant(), id, &request, &ctx())
        .await
        .expect_err("not a method the CHECK allows");
    assert!(
        matches!(err, AppError::Validation { .. }),
        "a constraint violation here would surface as a 500: {err:?}"
    );

    // And the set the server does accept all work.
    for method in ["check", "credit_card", "ach", "wire", "cash", "other"] {
        let mut request = payment(10_00);
        request.payment_method = method.to_string();
        // 70.00 total, so seven payments of 10.00 fit exactly.
        svc.record_bill_payment(tenant(), id, &request, &ctx())
            .await
            .unwrap_or_else(|e| panic!("{method} is in the CHECK set: {e:?}"));
    }
}
