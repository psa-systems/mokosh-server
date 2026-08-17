//! Integration test: PMS-732 measured duration per client-request type.
//!
//! The chain under test is time_entries -> tickets -> form_submissions ->
//! form_definitions -> kb_articles, which only exists for a ticket that came
//! from a client request. These tests therefore build the ticket the real way,
//! through the PMS-730 magic link, rather than inserting a submission row
//! directly: a ticket that never went through a request form is exactly the
//! case the report has to exclude, so faking the link would test the wrong
//! thing.

mod common;

use chrono::NaiveDate;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

/// Create a request form with a KB article attached, and return
/// `(form_id, article_id)`.
async fn seed_form(
    app: &common::TestApp,
    token: &str,
    pool: &PgPool,
    author_id: Uuid,
    name: &str,
    slug: &str,
) -> (String, Uuid) {
    let article_id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO kb_articles
           (id, tenant_id, title, slug, content, visibility, status, author_id)
           VALUES ($1, $2, $3, $4, 'Procedure.', 'internal', 'published', $5)"#,
    )
    .bind(article_id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(format!("How to: {name}"))
    .bind(format!("how-to-{slug}"))
    .bind(author_id)
    .execute(pool)
    .await
    .expect("seed kb article");

    let resp = app
        .client
        .post(app.url("/api/v1/forms"))
        .bearer_auth(token)
        .json(&json!({
            "name": name,
            "slug": slug,
            "kb_article_id": article_id,
            "fields": [{
                "name": "employee_name",
                "label": "Employee name",
                "field_type": "text",
                "is_required": true,
                "sort_order": 1
            }]
        }))
        .send()
        .await
        .expect("send create form");
    assert!(resp.status().is_success(), "create form should 2xx");
    let body: serde_json::Value = resp.json().await.expect("create form JSON");
    (
        body["id"].as_str().expect("form id").to_string(),
        article_id,
    )
}

/// Drive the real PMS-730 flow: issue a link, recover the token from the
/// queued email, submit it, and return the created ticket's id.
async fn request_ticket(
    app: &common::TestApp,
    token: &str,
    pool: &PgPool,
    form_id: &str,
    company_id: Uuid,
    who: &str,
) -> Uuid {
    let resp = app
        .client
        .post(app.url("/api/v1/form-request-links"))
        .bearer_auth(token)
        .json(&json!({
            "form_definition_id": form_id,
            "company_id": company_id,
            "recipient_email": "client@example.com"
        }))
        .send()
        .await
        .expect("send issue link");
    assert!(resp.status().is_success(), "issue link should 2xx");

    let body_text: String = sqlx::query_scalar(
        "SELECT body FROM notifications WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 1",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(pool)
    .await
    .expect("a request-link email was queued");
    let link_token = body_text
        .split("/request-forms/")
        .nth(1)
        .expect("the queued email carries the link")
        .split_whitespace()
        .next()
        .expect("the link has a token")
        .to_string();

    let resp = app
        .client
        .post(app.url(&format!("/api/v1/public/request-forms/{link_token}")))
        .json(&json!({"payload": {"employee_name": who}}))
        .send()
        .await
        .expect("send submission");
    assert_eq!(resp.status(), reqwest::StatusCode::CREATED);
    let receipt: serde_json::Value = resp.json().await.expect("receipt JSON");
    let ticket_number = receipt["ticket_number"].as_str().expect("ticket number");

    sqlx::query_scalar("SELECT id FROM tickets WHERE ticket_number = $1")
        .bind(ticket_number)
        .fetch_one(pool)
        .await
        .expect("the submission created a ticket")
}

/// Track `minutes` against `ticket_id` on `date`.
async fn track_time(
    pool: &PgPool,
    user_id: Uuid,
    company_id: Uuid,
    ticket_id: Uuid,
    date: NaiveDate,
    minutes: i32,
) {
    let work_type_id: Uuid =
        sqlx::query_scalar("SELECT id FROM work_types WHERE tenant_id = $1 LIMIT 1")
            .bind(common::DEFAULT_TENANT_ID)
            .fetch_one(pool)
            .await
            .expect("a seeded work type");
    sqlx::query(
        r#"INSERT INTO time_entries
           (tenant_id, user_id, date, duration_minutes, work_type_id, ticket_id, company_id)
           VALUES ($1, $2, $3, $4, $5, $6, $7)"#,
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(user_id)
    .bind(date)
    .bind(minutes)
    .bind(work_type_id)
    .bind(ticket_id)
    .bind(company_id)
    .execute(pool)
    .await
    .expect("insert time entry");
}

fn day(y: i32, m: u32, d: u32) -> NaiveDate {
    NaiveDate::from_ymd_opt(y, m, d).expect("valid date")
}

async fn report(app: &common::TestApp, token: &str, query: &str) -> serde_json::Value {
    let resp = app
        .client
        .get(app.url(&format!("/api/v1/reports/request-types{query}")))
        .bearer_auth(token)
        .send()
        .await
        .expect("send request-types report");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    resp.json().await.expect("report JSON")
}

fn row<'a>(report: &'a serde_json::Value, name: &str) -> &'a serde_json::Value {
    report["request_types"]
        .as_array()
        .expect("request_types[]")
        .iter()
        .find(|r| r["form_name"].as_str() == Some(name))
        .unwrap_or_else(|| panic!("no row for {name} in {report}"))
}

#[sqlx::test]
async fn time_aggregates_by_request_type_and_respects_the_period(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let (starter_form, _) =
        seed_form(&app, &token, &pool, admin_id, "New starter", "new-starter").await;
    let starter_a = request_ticket(&app, &token, &pool, &starter_form, company_id, "Dana").await;
    let starter_b = request_ticket(&app, &token, &pool, &starter_form, company_id, "Ravi").await;

    // Two tickets inside the window, 90 and 30 minutes, plus one entry the day
    // BEFORE the window opens and one the day AFTER it closes.
    track_time(&pool, admin_id, company_id, starter_a, day(2026, 3, 10), 90).await;
    track_time(&pool, admin_id, company_id, starter_b, day(2026, 3, 20), 30).await;
    track_time(
        &pool,
        admin_id,
        company_id,
        starter_a,
        day(2026, 2, 28),
        999,
    )
    .await;
    track_time(&pool, admin_id, company_id, starter_b, day(2026, 4, 1), 999).await;

    let march = report(&app, &token, "?from=2026-03-01&to=2026-03-31").await;
    assert_eq!(march["from"].as_str(), Some("2026-03-01"));
    assert_eq!(march["to"].as_str(), Some("2026-03-31"));

    let starter = row(&march, "New starter");
    assert_eq!(
        starter["total_minutes"].as_i64(),
        Some(120),
        "only the two in-period entries count"
    );
    assert_eq!(
        starter["ticket_count"].as_i64(),
        Some(2),
        "the sample is the tickets with time in the period"
    );
    assert_eq!(starter["average_minutes"].as_f64(), Some(60.0));
    assert!(
        starter["kb_article_id"].is_string(),
        "the row carries the article the estimate belongs on"
    );

    // The boundary days are inclusive on both ends.
    let edges = report(&app, &token, "?from=2026-02-28&to=2026-04-01").await;
    assert_eq!(
        row(&edges, "New starter")["total_minutes"].as_i64(),
        Some(2118),
        "a widened window picks up both boundary entries"
    );
}

#[sqlx::test]
async fn a_request_type_with_no_tracked_time_reports_no_data_not_zero(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let (tracked_form, _) =
        seed_form(&app, &token, &pool, admin_id, "New starter", "new-starter").await;
    // A second request type that exists, has been requested, but has never had
    // time tracked against it.
    let (untracked_form, untracked_article) =
        seed_form(&app, &token, &pool, admin_id, "Departure", "departure").await;

    let ticket = request_ticket(&app, &token, &pool, &tracked_form, company_id, "Dana").await;
    request_ticket(&app, &token, &pool, &untracked_form, company_id, "Ravi").await;
    track_time(&pool, admin_id, company_id, ticket, day(2026, 3, 10), 45).await;

    let march = report(&app, &token, "?from=2026-03-01&to=2026-03-31").await;

    let tracked = row(&march, "New starter");
    assert_eq!(tracked["total_minutes"].as_i64(), Some(45));

    // The distinction the acceptance criterion asks for: no data is null, not
    // a confident zero. A zero would read as "these take no time".
    let untracked = row(&march, "Departure");
    assert!(
        untracked["total_minutes"].is_null(),
        "expected null, got {}",
        untracked["total_minutes"]
    );
    assert!(untracked["ticket_count"].is_null());
    assert!(untracked["average_minutes"].is_null());

    // The same distinction on the article surface.
    let resp = app
        .client
        .get(app.url(&format!(
            "/api/v1/kb/articles/{untracked_article}/measured-duration"
        )))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send measured-duration");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("measured duration JSON");
    assert!(body["total_minutes"].is_null());
    assert!(body["average_minutes"].is_null());
    assert!(
        body["from"].is_string() && body["to"].is_string(),
        "the period is always stated, so the number is never ambiguous"
    );
}

#[sqlx::test]
async fn the_article_surfaces_the_measured_duration_and_excludes_ad_hoc_tickets(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let (form_id, article_id) =
        seed_form(&app, &token, &pool, admin_id, "New starter", "new-starter").await;
    let requested = request_ticket(&app, &token, &pool, &form_id, company_id, "Dana").await;
    track_time(
        &pool,
        admin_id,
        company_id,
        requested,
        day(2026, 3, 10),
        120,
    )
    .await;

    // An ad-hoc ticket of the same shape, created directly rather than from a
    // request form, with a lot of time on it. It has no submission row, so it
    // must not skew the measurement (PMS-732's "report only over tickets that
    // came from a client request submission").
    let adhoc: serde_json::Value = app
        .client
        .post(app.url("/api/v1/tickets"))
        .bearer_auth(&token)
        .json(&json!({
            "title": "Ad-hoc onboarding",
            "company_id": company_id,
            "procedure_kb_article_id": article_id,
            "custom_fields": {}
        }))
        .send()
        .await
        .expect("send create adhoc ticket")
        .json()
        .await
        .expect("adhoc ticket JSON");
    let adhoc_id = Uuid::parse_str(adhoc["id"].as_str().expect("adhoc id")).expect("adhoc uuid");
    track_time(
        &pool,
        admin_id,
        company_id,
        adhoc_id,
        day(2026, 3, 11),
        9000,
    )
    .await;

    let resp = app
        .client
        .get(app.url(&format!(
            "/api/v1/kb/articles/{article_id}/measured-duration?from=2026-03-01&to=2026-03-31"
        )))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send measured-duration");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("measured duration JSON");

    assert_eq!(
        body["total_minutes"].as_i64(),
        Some(120),
        "the ad-hoc ticket's 9000 minutes must not skew the request-type measurement"
    );
    assert_eq!(body["ticket_count"].as_i64(), Some(1));
    assert_eq!(body["average_minutes"].as_f64(), Some(120.0));

    // An article nobody has linked a request type to is a 404 only when the
    // article itself is missing; a real article with no request type is data,
    // not an error.
    let missing = app
        .client
        .get(app.url(&format!(
            "/api/v1/kb/articles/{}/measured-duration",
            Uuid::new_v4()
        )))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send measured-duration for a missing article");
    assert_eq!(missing.status(), reqwest::StatusCode::NOT_FOUND);
}

/// PMS-772: the report is discoverable in the registry and exportable through
/// the shared exporter, and the registry names the one key that is not.
#[sqlx::test]
async fn the_report_is_registered_and_exports_csv(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let (form, _) = seed_form(&app, &token, &pool, admin_id, "New starter", "new-starter").await;
    let ticket = request_ticket(&app, &token, &pool, &form, company_id, "Dana").await;
    track_time(&pool, admin_id, company_id, ticket, day(2026, 3, 10), 90).await;
    // A request type with no tracked time, so the export has to carry the
    // no-data case too.
    seed_form(&app, &token, &pool, admin_id, "Departure", "departure").await;

    let registry: serde_json::Value = app
        .client
        .get(app.url("/api/v1/reports"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send list reports")
        .json()
        .await
        .expect("registry JSON");
    let entries = registry.as_array().expect("registry is an array");
    let descriptor = entries
        .iter()
        .find(|r| r["key"] == "request-types")
        .unwrap_or_else(|| panic!("registry lists request-types, got {registry}"));
    let params: Vec<&str> = descriptor["parameters"]
        .as_array()
        .expect("parameters[]")
        .iter()
        .filter_map(|p| p["name"].as_str())
        .collect();
    assert_eq!(
        params,
        vec!["from", "to"],
        "the date parameters are advertised"
    );

    // Every key the registry advertises exports, except the ones whose
    // descriptions say they do not and why.
    let custom = entries
        .iter()
        .find(|r| r["key"] == "custom")
        .expect("custom");
    let reason = custom["description"].as_str().expect("description");
    assert!(
        reason.contains("cannot") && reason.contains("POST body"),
        "the registry states why custom cannot be exported, got {reason}"
    );

    let resp =
        app.client
            .get(app.url(
                "/api/v1/reports/request-types/export?format=csv&from=2026-03-01&to=2026-03-31",
            ))
            .bearer_auth(&token)
            .send()
            .await
            .expect("send request-types export");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "export is not a 404"
    );
    let csv = resp.text().await.expect("csv body");

    let header = csv
        .lines()
        .find(|l| l.starts_with("request_type,"))
        .unwrap_or_else(|| panic!("no data header in {csv}"));
    let columns: Vec<&str> = header.split(',').collect();
    assert!(
        columns.contains(&"count"),
        "the grouped-count column is named count, got {header}"
    );
    assert!(
        !columns.contains(&"ticket_count"),
        "no fourth spelling of count, got {header}"
    );

    assert!(
        csv.contains("New starter,new-starter,How to: New starter,1,90,90.0"),
        "the measured row is exported, got {csv}"
    );
    assert!(
        csv.contains("Departure,departure,How to: Departure,,,\n"),
        "no data stays empty rather than becoming a zero measurement, got {csv}"
    );
    assert!(
        csv.contains("from,to\n2026-03-01,2026-03-31"),
        "the period is stated, got {csv}"
    );
}
