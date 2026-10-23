//! MAPPS-1100 Phase B workflow test: create vendor -> create bill ->
//! approve bill -> create expense -> submit -> approve -> reimburse
//! (immutable thereafter).
//!
//! Pins the lifecycle every leaf in the subsystem has to carry: an
//! `approved` bill cannot be re-approved, a `rejected` expense cannot
//! be reimbursed, and a `reimbursed` expense refuses every further
//! transition (per the MAPPS-1100 scoping that reimbursement is
//! terminal and a correction is a reversing expense).

use crate::common;

use mokosh_test::mokosh_test;
use sqlx::PgPool;
use uuid::Uuid;

use chrono::NaiveDate;

use mokosh_server::modules::audit::AuditCtx;
use mokosh_server::modules::auth::TenantId;
use mokosh_server::modules::expenses::service::{
    BillLineInput, CreateBillRequest, CreateExpenseRequest, ExpenseLineInput, ExpensesService,
    UpsertExpenseCategoryRequest, UpsertVendorRequest,
};
use mokosh_server::utils::error::AppError;
use mokosh_server::Database;

fn ctx() -> AuditCtx {
    AuditCtx::system(common::DEFAULT_TENANT_ID)
}

fn vendor_body(name: &str) -> UpsertVendorRequest {
    UpsertVendorRequest {
        name: name.to_string(),
        account_number: None,
        default_currency: Some("USD".to_string()),
        notes: None,
    }
}

fn category_body(name: &str) -> UpsertExpenseCategoryRequest {
    UpsertExpenseCategoryRequest {
        name: name.to_string(),
        is_active: true,
    }
}

fn bill_body(vendor_id: Uuid) -> CreateBillRequest {
    CreateBillRequest {
        vendor_id,
        bill_number: Some("INV-001".to_string()),
        issue_date: NaiveDate::from_ymd_opt(2026, 10, 23).unwrap(),
        due_date: Some(NaiveDate::from_ymd_opt(2026, 11, 23).unwrap()),
        currency: "USD".to_string(),
        notes: None,
        lines: vec![
            BillLineInput {
                category_id: None,
                description: "Hosting".to_string(),
                quantity_hundredths: 100,
                unit_price_minor: 50_00,
                tax_minor: 0,
                position: 0,
            },
            BillLineInput {
                category_id: None,
                description: "Add-ons".to_string(),
                quantity_hundredths: 200,
                unit_price_minor: 10_00,
                tax_minor: 2_00,
                position: 0,
            },
        ],
    }
}

fn expense_body() -> CreateExpenseRequest {
    CreateExpenseRequest {
        incurred_on: NaiveDate::from_ymd_opt(2026, 10, 23).unwrap(),
        currency: "USD".to_string(),
        notes: None,
        lines: vec![ExpenseLineInput {
            category_id: None,
            description: "Taxi".to_string(),
            amount_minor: 32_50,
            tax_minor: 0,
            position: 0,
        }],
    }
}

#[mokosh_test]
async fn vendor_bill_expense_reimburse_workflow(pool: PgPool) {
    let (admin_id, _email, _pw) = common::seed_admin(&pool).await;
    let svc = ExpensesService::new(Database::from_pool(pool.clone()));
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);

    // Vendor + category are the prerequisite leaves.
    let vendor = svc
        .create_vendor(tenant, &vendor_body("Hosting Co"), &ctx())
        .await
        .expect("vendor");
    let _category = svc
        .create_expense_category(tenant, &category_body("Travel"), &ctx())
        .await
        .expect("category");

    // Bill: lines total 50 + 20 = 70 subtotal, 2 tax, 72 total.
    let bill = svc
        .create_bill(tenant, &bill_body(vendor.id), &ctx())
        .await
        .expect("bill");
    assert_eq!(bill.bill.vendor_id, vendor.id);
    assert_eq!(bill.lines.len(), 2);
    assert_eq!(bill.bill.subtotal_minor, 70_00, "subtotal from lines");
    assert_eq!(bill.bill.tax_minor, 2_00);
    assert_eq!(bill.bill.total_minor, 72_00);
    assert_eq!(bill.bill.status, "draft");

    // Approve moves draft -> approved; a second approve is a conflict.
    let approved = svc
        .approve_bill(tenant, bill.bill.id, &ctx())
        .await
        .expect("approve");
    assert_eq!(approved.status, "approved");
    let reapprove = svc.approve_bill(tenant, bill.bill.id, &ctx()).await;
    assert!(
        matches!(reapprove, Err(AppError::Conflict(_))),
        "an approved bill cannot be re-approved: {reapprove:?}"
    );

    // Void from approved: fine.
    let voided = svc
        .void_bill(tenant, bill.bill.id, &ctx())
        .await
        .expect("void");
    assert_eq!(voided.status, "void");

    // Expense flow against the same admin as submitter + approver.
    let expense = svc
        .create_expense(tenant, admin_id, &expense_body(), &ctx())
        .await
        .expect("expense");
    assert_eq!(expense.expense.status, "draft");
    assert_eq!(expense.expense.subtotal_minor, 32_50);
    assert_eq!(expense.expense.total_minor, 32_50);
    assert_eq!(expense.lines.len(), 1);

    // draft -> submitted -> approved -> reimbursed.
    let submitted = svc
        .submit_expense(tenant, expense.expense.id, &ctx())
        .await
        .expect("submit");
    assert_eq!(submitted.status, "submitted");

    // Reimburse before approve is a conflict (allowed_from = ["approved"]).
    let too_early = svc
        .reimburse_expense(tenant, expense.expense.id, &ctx())
        .await;
    assert!(
        matches!(too_early, Err(AppError::Conflict(_))),
        "cannot reimburse a submitted expense: {too_early:?}"
    );

    let approved_exp = svc
        .approve_expense(tenant, expense.expense.id, admin_id, &ctx())
        .await
        .expect("approve expense");
    assert_eq!(approved_exp.status, "approved");
    assert_eq!(approved_exp.approver_id, Some(admin_id));
    assert!(approved_exp.approved_at.is_some());

    let reimbursed = svc
        .reimburse_expense(tenant, expense.expense.id, &ctx())
        .await
        .expect("reimburse");
    assert_eq!(reimbursed.status, "reimbursed");
    assert!(reimbursed.reimbursed_at.is_some());

    // Reimbursed is terminal: every further transition refuses.
    for next in ["submit", "approve", "reject", "reimburse"] {
        let err = match next {
            "submit" => svc.submit_expense(tenant, expense.expense.id, &ctx()).await,
            "approve" => {
                svc.approve_expense(tenant, expense.expense.id, admin_id, &ctx())
                    .await
            }
            "reject" => svc.reject_expense(tenant, expense.expense.id, &ctx()).await,
            "reimburse" => {
                svc.reimburse_expense(tenant, expense.expense.id, &ctx())
                    .await
            }
            _ => unreachable!(),
        };
        assert!(
            matches!(err, Err(AppError::Conflict(_))),
            "a reimbursed expense must refuse {next:?}: {err:?}"
        );
    }
}

#[mokosh_test]
async fn rejected_expense_cannot_be_reimbursed(pool: PgPool) {
    let (admin_id, _, _) = common::seed_admin(&pool).await;
    let svc = ExpensesService::new(Database::from_pool(pool.clone()));
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);

    let expense = svc
        .create_expense(tenant, admin_id, &expense_body(), &ctx())
        .await
        .expect("expense");
    svc.submit_expense(tenant, expense.expense.id, &ctx())
        .await
        .expect("submit");
    let rejected = svc
        .reject_expense(tenant, expense.expense.id, &ctx())
        .await
        .expect("reject");
    assert_eq!(rejected.status, "rejected");
    let reimburse = svc
        .reimburse_expense(tenant, expense.expense.id, &ctx())
        .await;
    assert!(
        matches!(reimburse, Err(AppError::Conflict(_))),
        "a rejected expense cannot be reimbursed: {reimburse:?}"
    );
}

#[mokosh_test]
async fn bill_create_rejects_unknown_vendor(pool: PgPool) {
    let _ = common::seed_admin(&pool).await;
    let svc = ExpensesService::new(Database::from_pool(pool.clone()));
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);
    let req = bill_body(Uuid::new_v4());
    let r = svc.create_bill(tenant, &req, &ctx()).await;
    assert!(
        matches!(r, Err(AppError::NotFound(_))),
        "unknown vendor must 404: {r:?}"
    );
}
