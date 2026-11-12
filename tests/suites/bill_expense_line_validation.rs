//! PMS-1550: a negative line amount is rejected at the API boundary, before
//! any row is written.
//!
//! `BillTotals::from_lines` and the `bills_payments_amount_positive` /
//! `request.amount_minor <= 0` payment checks both assume a bill or claim's
//! total is never negative. Without a request-level check, a negative
//! `unit_price_minor`/`amount_minor` line produces a bill that can never be
//! paid down to zero (every allowed payment is positive, so it only makes
//! the balance more negative). The fix is a 422 at `POST /bills` and
//! `POST /expenses`, before the row exists at all.

use crate::common;

use mokosh_server::db::Database;
use mokosh_server::modules::audit::AuditCtx;
use mokosh_server::modules::auth::TenantId;
use mokosh_server::modules::expenses::service::{ExpensesService, UpsertVendorRequest};
use mokosh_test::mokosh_test;
use serde_json::json;
use sqlx::PgPool;

/// `error.errors[]` as `(field, code)` pairs, sorted for a stable assertion.
fn field_codes(body: &serde_json::Value) -> Vec<(String, String)> {
    let mut pairs: Vec<(String, String)> = body["error"]["errors"]
        .as_array()
        .expect("a 422 body carries error.errors[]")
        .iter()
        .map(|e| {
            (
                e["field"].as_str().unwrap_or_default().to_string(),
                e["code"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect();
    pairs.sort();
    pairs
}

/// The exact failing scenario from the issue: a $50.00 negative unit price
/// on an otherwise-valid bill line.
#[mokosh_test]
async fn a_bill_with_a_negative_unit_price_is_rejected(pool: PgPool) {
    let (_admin, admin_email, admin_password) = common::seed_admin(&pool).await;

    let svc = ExpensesService::new(Database::from_pool(pool.clone()));
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);
    let vendor = svc
        .create_vendor(
            tenant,
            &UpsertVendorRequest {
                name: "Hosting Co".to_string(),
                account_number: None,
                default_currency: Some("USD".to_string()),
                notes: None,
            },
            &AuditCtx::system(common::DEFAULT_TENANT_ID),
        )
        .await
        .expect("vendor");

    let app = common::boot(pool).await;
    let token = common::login(&app, &admin_email, &admin_password).await;

    let resp = app
        .client
        .post(app.url("/api/v1/bills"))
        .bearer_auth(&token)
        .json(&json!({
            "vendor_id": vendor.id,
            "issue_date": "2026-10-23",
            "currency": "USD",
            "lines": [{
                "description": "Hosting",
                "quantity_hundredths": 100,
                "unit_price_minor": -5000,
                "tax_minor": 0,
            }],
        }))
        .send()
        .await
        .expect("send create");

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "a negative unit price must not reach the service layer"
    );
    let body: serde_json::Value = resp.json().await.expect("error JSON");
    assert_eq!(
        field_codes(&body),
        vec![("lines[0].unit_price_minor".to_string(), "range".to_string())]
    );

    let bills: i64 = sqlx::query_scalar("SELECT count(*) FROM bills")
        .fetch_one(&app.pool)
        .await
        .expect("count bills");
    assert_eq!(bills, 0, "no bill row was written");
}

/// Every other non-positive/negative shape on a bill line: zero quantity,
/// negative quantity, negative tax.
#[mokosh_test]
async fn other_non_positive_bill_line_fields_are_also_rejected(pool: PgPool) {
    let (_admin, admin_email, admin_password) = common::seed_admin(&pool).await;

    let svc = ExpensesService::new(Database::from_pool(pool.clone()));
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);
    let vendor = svc
        .create_vendor(
            tenant,
            &UpsertVendorRequest {
                name: "Hosting Co".to_string(),
                account_number: None,
                default_currency: Some("USD".to_string()),
                notes: None,
            },
            &AuditCtx::system(common::DEFAULT_TENANT_ID),
        )
        .await
        .expect("vendor");

    let app = common::boot(pool).await;
    let token = common::login(&app, &admin_email, &admin_password).await;

    for (quantity_hundredths, unit_price_minor, tax_minor, expected_field) in [
        (0, 50_00, 0, "lines[0].quantity_hundredths"),
        (-100, 50_00, 0, "lines[0].quantity_hundredths"),
        (100, 50_00, -1, "lines[0].tax_minor"),
    ] {
        let resp = app
            .client
            .post(app.url("/api/v1/bills"))
            .bearer_auth(&token)
            .json(&json!({
                "vendor_id": vendor.id,
                "issue_date": "2026-10-23",
                "currency": "USD",
                "lines": [{
                    "description": "Hosting",
                    "quantity_hundredths": quantity_hundredths,
                    "unit_price_minor": unit_price_minor,
                    "tax_minor": tax_minor,
                }],
            }))
            .send()
            .await
            .expect("send create");

        assert_eq!(
            resp.status(),
            reqwest::StatusCode::UNPROCESSABLE_ENTITY,
            "quantity={quantity_hundredths} price={unit_price_minor} tax={tax_minor}"
        );
        let body: serde_json::Value = resp.json().await.expect("error JSON");
        assert_eq!(
            field_codes(&body),
            vec![(expected_field.to_string(), "range".to_string())]
        );
    }
}

/// The identical shape for an expense claim line: a negative `amount_minor`.
#[mokosh_test]
async fn an_expense_with_a_negative_amount_is_rejected(pool: PgPool) {
    let (_admin, admin_email, admin_password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &admin_email, &admin_password).await;

    let resp = app
        .client
        .post(app.url("/api/v1/expenses"))
        .bearer_auth(&token)
        .json(&json!({
            "incurred_on": "2026-10-23",
            "currency": "USD",
            "lines": [{
                "description": "Taxi",
                "amount_minor": -3250,
            }],
        }))
        .send()
        .await
        .expect("send create");

    assert_eq!(resp.status(), reqwest::StatusCode::UNPROCESSABLE_ENTITY);
    let body: serde_json::Value = resp.json().await.expect("error JSON");
    assert_eq!(
        field_codes(&body),
        vec![("lines[0].amount_minor".to_string(), "range".to_string())]
    );

    let claims: i64 = sqlx::query_scalar("SELECT count(*) FROM expenses")
        .fetch_one(&app.pool)
        .await
        .expect("count expenses");
    assert_eq!(claims, 0, "no expense row was written");
}
