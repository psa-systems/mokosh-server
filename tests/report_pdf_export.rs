//! PMS-876: the report export serves PDF as well as CSV.
//!
//! PMS-99 shipped the CSV half and closed, so the PDF half had no owning issue
//! for months and the handler's own doc comment pointed at a closed one. These
//! tests pin the second format on every report that has a first, and pin the
//! two things a new output format most easily gets wrong: a permission gate
//! that only guards the old branch, and bytes that carry the right
//! `Content-Type` without being a document a reader will open.

mod common;

use mokosh_test::mokosh_test;
use printpdf::PdfDocument;
use reqwest::StatusCode;
use sqlx::PgPool;
use uuid::Uuid;

/// Every registry key `GET /reports/{key}/export` serves. Seven, not the five
/// PMS-876 was written against: `projects` and `clients` joined the registry
/// afterwards.
const EXPORTABLE: &[&str] = &[
    "dashboard",
    "tickets",
    "time",
    "request-types",
    "billing",
    "projects",
    "clients",
];

async fn export(
    app: &common::TestApp,
    token: &str,
    key: &str,
    format: &str,
) -> (StatusCode, reqwest::header::HeaderMap, Vec<u8>) {
    let resp = app
        .client
        .get(app.url(&format!("/api/v1/reports/{key}/export?format={format}")))
        .bearer_auth(token)
        .send()
        .await
        .unwrap_or_else(|e| panic!("export {key} as {format}: {e}"));
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp.bytes().await.expect("body").to_vec();
    (status, headers, body)
}

fn header<'a>(headers: &'a reqwest::header::HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// Every exportable report answers `format=pdf` with a PDF.
///
/// The admin role clears both finance gates, so this covers the seven keys
/// rather than the five a technician could reach; the gates themselves are
/// asserted by the role matrix in `rbac_route_coverage.rs`.
#[mokosh_test]
async fn every_exportable_report_serves_a_pdf(pool: PgPool) {
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;

    for key in EXPORTABLE {
        let (status, headers, body) = export(&app, &token, key, "pdf").await;
        assert_eq!(status, StatusCode::OK, "{key} should export as PDF");
        assert_eq!(
            header(&headers, "content-type"),
            Some("application/pdf"),
            "{key} content type"
        );
        assert_eq!(
            header(&headers, "content-disposition"),
            Some(format!("attachment; filename=\"{key}.pdf\"").as_str()),
            "{key} is offered as a download, not rendered under a /export URL"
        );
        // The header is a claim; these are the bytes behind it. A reader opens
        // a file that starts with the magic and ends with a trailer, so
        // asserting the status alone would pass on an empty body.
        assert!(
            body.starts_with(b"%PDF-"),
            "{key} did not return a PDF: {:?}",
            &body[..body.len().min(32)]
        );
        assert!(
            body.windows(5).any(|w| w == b"%%EOF"),
            "{key} PDF is truncated"
        );
    }
}

/// PMS-1200: `pdf_for_billing` used to print a raw `Decimal` with
/// `.to_string()`, so a whole-dollar total read as `1200` with no `.00` and
/// no currency. It now goes through the promoted `money()` formatter like
/// every other money value this repo renders.
#[mokosh_test]
async fn billing_pdf_prints_money_through_the_shared_formatter(pool: PgPool) {
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &pw).await;

    sqlx::query(
        r#"INSERT INTO invoices
           (id, tenant_id, invoice_number, company_id, status,
            invoice_date, due_date, subtotal, total, amount_paid, balance_due, currency)
           VALUES ($1, $2, 'PDF-BILL-1', $3, 'sent',
                   CURRENT_DATE, CURRENT_DATE + 30, 1200, 1200, 0, 1200, 'USD')"#,
    )
    .bind(Uuid::new_v4())
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company_id)
    .execute(&pool)
    .await
    .expect("seed a whole-dollar invoice");

    let (status, _headers, body) = export(&app, &token, "billing", "pdf").await;
    assert_eq!(status, StatusCode::OK);
    let text = extracted_text(&body);
    assert!(
        text.contains("1200.00 USD"),
        "PMS-1200: a whole-dollar total must render as 1200.00 USD, not a bare 1200: {text}"
    );
    assert!(
        !text.contains("Invoiced: 1200\n") && !text.contains("Invoiced 1200"),
        "PMS-1200: the raw Decimal must not appear unformatted: {text}"
    );
}

/// The custom report still refuses, and for the reason it always did: adding a
/// second format does not give a GET a body to carry a report spec in.
#[mokosh_test]
async fn the_custom_report_still_refuses_a_pdf(pool: PgPool) {
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;

    let (status, _headers, body) = export(&app, &token, "custom", "pdf").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let text = String::from_utf8_lossy(&body);
    assert!(
        text.contains("travels in a request body"),
        "the message should still explain why: {text}"
    );
}

/// A format outside the implemented set is still a 400, and the message names
/// both formats rather than only the one that used to exist.
#[mokosh_test]
async fn an_unimplemented_format_is_still_a_400(pool: PgPool) {
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;

    let (status, _headers, body) = export(&app, &token, "tickets", "xlsx").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let text = String::from_utf8_lossy(&body);
    assert!(
        text.contains("pdf"),
        "the message lists what is served: {text}"
    );
}

/// Case is not significant, the way it never was for `csv`.
#[mokosh_test]
async fn the_format_is_matched_case_insensitively(pool: PgPool) {
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;

    let (status, headers, _body) = export(&app, &token, "tickets", "PDF").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(header(&headers, "content-type"), Some("application/pdf"));
}

/// The CSV branch is untouched. PMS-876 assumed it carried a
/// `Content-Disposition` filename convention for the PDF to match; it carries
/// none, and it does not gain one here, because it is an existing response the
/// SPA already consumes.
#[mokosh_test]
async fn the_csv_export_is_unchanged(pool: PgPool) {
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;

    let (status, headers, body) = export(&app, &token, "tickets", "csv").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        header(&headers, "content-type"),
        Some("text/csv; charset=utf-8")
    );
    assert!(
        headers.get("content-disposition").is_none(),
        "CSV gained a header this issue was not meant to give it"
    );
    assert!(!body.is_empty());
}

/// PMS-1418: every exported PDF states when it was generated, in the same
/// place regardless of whether it already carries its own date-range
/// subtitle. Before this, `pdf_for_dashboard`, `pdf_for_billing`,
/// `pdf_for_projects` and `pdf_for_clients` printed no date at all.
#[mokosh_test]
async fn every_exported_pdf_states_when_it_was_generated(pool: PgPool) {
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;

    for key in EXPORTABLE {
        let (status, _headers, body) = export(&app, &token, key, "pdf").await;
        assert_eq!(status, StatusCode::OK, "{key} should export as PDF");
        let text = extracted_text(&body);
        assert!(
            text.contains("Generated "),
            "{key} PDF should state when it was generated: {text}"
        );
    }
}

/// PMS-1418: the billing PDF states whether it covers one client or all of
/// them, even though `BillingReportResponse` (and the PDF export it feeds)
/// never printed a scope before.
#[mokosh_test]
async fn billing_pdf_states_its_client_scope(pool: PgPool) {
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &pw).await;

    let company_name: String = sqlx::query_scalar("SELECT name FROM companies WHERE id = $1")
        .bind(company_id)
        .fetch_one(&pool)
        .await
        .expect("the seeded company");

    let (status, _headers, all_pdf) = export(&app, &token, "billing", "pdf").await;
    assert_eq!(status, StatusCode::OK);
    let all_text = extracted_text(&all_pdf);
    assert!(
        all_text.contains("All clients"),
        "no company_id should read as every client: {all_text}"
    );

    let resp = app
        .client
        .get(app.url(&format!(
            "/api/v1/reports/billing/export?format=pdf&company_id={company_id}"
        )))
        .bearer_auth(&token)
        .send()
        .await
        .expect("export billing scoped to a company");
    assert_eq!(resp.status(), StatusCode::OK);
    let scoped_bytes = resp.bytes().await.expect("body");
    let scoped_text = extracted_text(&scoped_bytes);
    assert!(
        scoped_text.contains(&company_name),
        "a company_id should name the company it scopes to: {scoped_text}"
    );
}

/// Read the text back out of rendered bytes, through printpdf's own parser so
/// this reads what a PDF reader reads (the pattern `document_bill_to.rs` uses).
fn extracted_text(bytes: &[u8]) -> String {
    let mut warnings = Vec::new();
    PdfDocument::parse(bytes, &printpdf::PdfParseOptions::default(), &mut warnings)
        .expect("the served bytes parse as a PDF")
        .extract_text()
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join("\n")
}

/// PMS-1196: `pdf_for_tickets`'s "Assignee" column and `pdf_for_time`'s "User"
/// column used to print the raw `Uuid`, while the CSV export of the same data
/// honestly wrote `assignee_id` / `user_id`. Both now resolve a display name,
/// with the CSV export left untouched (it still writes the ids under their id
/// column names).
#[mokosh_test]
async fn pdf_columns_name_the_user_instead_of_printing_a_uuid(pool: PgPool) {
    let (admin_id, email, pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &pw).await;

    let status_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM ticket_statuses WHERE tenant_id = $1 AND is_closed = FALSE LIMIT 1",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(&pool)
    .await
    .expect("an open ticket status");
    let priority_id: Uuid =
        sqlx::query_scalar("SELECT id FROM ticket_priorities WHERE tenant_id = $1 LIMIT 1")
            .bind(common::DEFAULT_TENANT_ID)
            .fetch_one(&pool)
            .await
            .expect("a ticket priority");
    let queue_id: Uuid =
        sqlx::query_scalar("SELECT id FROM ticket_queues WHERE tenant_id = $1 LIMIT 1")
            .bind(common::DEFAULT_TENANT_ID)
            .fetch_one(&pool)
            .await
            .expect("a ticket queue");

    // A ticket assigned to the seeded admin, so `pdf_for_tickets`'s "Opened by
    // assignee" table has a resolvable assignee to name.
    sqlx::query(
        r#"INSERT INTO tickets
           (id, tenant_id, ticket_number, title, status_id, priority_id,
            queue_id, company_id, created_by_id, assigned_to_id)
           VALUES ($1, $2, 'PDF-1', 'Seed ticket', $3, $4, $5, $6, $7, $7)"#,
    )
    .bind(Uuid::new_v4())
    .bind(common::DEFAULT_TENANT_ID)
    .bind(status_id)
    .bind(priority_id)
    .bind(queue_id)
    .bind(company_id)
    .bind(admin_id)
    .execute(&pool)
    .await
    .expect("seed assigned ticket");

    // A time entry logged by the same admin, so `pdf_for_time`'s "Minutes by
    // user" table has a resolvable user to name, and the "Minutes by work
    // type" table (PMS-1207) has a resolvable work type to name.
    let (work_type_id, work_type_name): (Uuid, String) =
        sqlx::query_as("SELECT id, name FROM work_types WHERE tenant_id = $1 LIMIT 1")
            .bind(common::DEFAULT_TENANT_ID)
            .fetch_one(&pool)
            .await
            .expect("a seeded work type");
    sqlx::query(
        r#"INSERT INTO time_entries
           (id, tenant_id, user_id, date, duration_minutes, work_type_id, company_id)
           VALUES ($1, $2, $3, CURRENT_DATE, 60, $4, $5)"#,
    )
    .bind(Uuid::new_v4())
    .bind(common::DEFAULT_TENANT_ID)
    .bind(admin_id)
    .bind(work_type_id)
    .bind(company_id)
    .execute(&pool)
    .await
    .expect("seed time entry");

    let uuid_shaped = admin_id.to_string();
    let work_type_uuid_shaped = work_type_id.to_string();

    let (status, _headers, tickets_pdf) = export(&app, &token, "tickets", "pdf").await;
    assert_eq!(status, StatusCode::OK);
    let tickets_text = extracted_text(&tickets_pdf);
    assert!(
        tickets_text.contains("Test Admin"),
        "tickets PDF should name the assignee: {tickets_text}"
    );
    assert!(
        !tickets_text.contains(&uuid_shaped),
        "tickets PDF should not print the assignee's raw id: {tickets_text}"
    );

    let (status, _headers, time_pdf) = export(&app, &token, "time", "pdf").await;
    assert_eq!(status, StatusCode::OK);
    let time_text = extracted_text(&time_pdf);
    assert!(
        time_text.contains("Test Admin"),
        "time PDF should name the user: {time_text}"
    );
    assert!(
        !time_text.contains(&uuid_shaped),
        "time PDF should not print the user's raw id: {time_text}"
    );
    assert!(
        time_text.contains(&work_type_name),
        "time PDF should name the work type (PMS-1207): {time_text}"
    );
    assert!(
        !time_text.contains(&work_type_uuid_shaped),
        "time PDF should not print the work type's raw id: {time_text}"
    );
}
