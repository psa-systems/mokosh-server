//! PMS-876: the report export serves PDF as well as CSV.
//!
//! PMS-99 shipped the CSV half and closed, so the PDF half had no owning issue
//! for months and the handler's own doc comment pointed at a closed one. These
//! tests pin the second format on every report that has a first, and pin the
//! two things a new output format most easily gets wrong: a permission gate
//! that only guards the old branch, and bytes that carry the right
//! `Content-Type` without being a document a reader will open.

mod common;

use reqwest::StatusCode;
use sqlx::PgPool;

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
#[sqlx::test]
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

/// The custom report still refuses, and for the reason it always did: adding a
/// second format does not give a GET a body to carry a report spec in.
#[sqlx::test]
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
#[sqlx::test]
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
#[sqlx::test]
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
#[sqlx::test]
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
