//! PMS-737: one client request covering several people.
//!
//! The shape is a parent ticket with a child per person, because every
//! per-ticket mechanism is per person: the SLA clock, the time entries, the
//! billing and the technician's checklist. Five starters on one ticket would
//! make the PMS-732 measured duration an average over requests rather than
//! over people, which is what that report exists to measure.
//!
//! The parent is a container by decision: no SLA, no assignee, no time.

mod common;

use mokosh_test::mokosh_test;
use reqwest::StatusCode;
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

struct Fixture {
    app: common::TestApp,
    pool: PgPool,
    admin_id: Uuid,
    token: String,
    form_id: String,
    company_id: Uuid,
}

impl Fixture {
    async fn new(pool: PgPool) -> Self {
        let (admin_id, email, password) = common::seed_admin(&pool).await;
        let company_id = common::seed_company(&pool).await;
        let app = common::boot(pool.clone()).await;
        let token = common::login(&app, &email, &password).await;
        let form_id: String = {
            let resp = app
                .client
                .post(app.url("/api/v1/forms"))
                .bearer_auth(&token)
                .json(&json!({
                    "name": "New starter",
                    "slug": "new-starter",
                    "fields": [{
                        "name": "first_name",
                        "label": "First name",
                        "field_type": "text",
                        "is_required": true,
                        "sort_order": 1
                    }],
                }))
                .send()
                .await
                .expect("create form");
            assert!(resp.status().is_success(), "create form");
            let body: Value = resp.json().await.expect("form json");
            body["id"].as_str().expect("form id").to_string()
        };
        Self {
            app,
            pool,
            admin_id,
            token,
            form_id,
            company_id,
        }
    }

    /// Issue a link for `people`, and return the magic token and the response.
    async fn issue(&self, people: Option<i32>) -> (StatusCode, Value, Option<String>) {
        let mut body = json!({
            "form_definition_id": self.form_id,
            "company_id": self.company_id,
            "recipient_email": "client@example.com",
        });
        if let Some(people) = people {
            body["people"] = json!(people);
        }
        let resp = self
            .app
            .client
            .post(self.app.url("/api/v1/form-request-links"))
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await
            .expect("issue link");
        let status = resp.status();
        let issued: Value = resp.json().await.unwrap_or(Value::Null);
        if !status.is_success() {
            return (status, issued, None);
        }
        let mail: String = sqlx::query_scalar(
            "SELECT body FROM notifications WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 1",
        )
        .bind(common::DEFAULT_TENANT_ID)
        .fetch_one(&self.pool)
        .await
        .expect("a request-link email was queued");
        let token = mail
            .split("/request-forms/")
            .nth(1)
            .expect("the queued email carries the link")
            .split_whitespace()
            .next()
            .expect("the link has a token")
            .to_string();
        (status, issued, Some(token))
    }

    async fn submit(&self, link: &str, name: &str) -> (StatusCode, Value) {
        let resp = self
            .app
            .client
            .post(
                self.app
                    .url(&format!("/api/v1/public/request-forms/{link}")),
            )
            .json(&json!({ "payload": { "first_name": name } }))
            .send()
            .await
            .expect("submit");
        let status = resp.status();
        (status, resp.json().await.unwrap_or(Value::Null))
    }

    async fn read_form(&self, link: &str) -> (StatusCode, Value) {
        let resp = self
            .app
            .client
            .get(
                self.app
                    .url(&format!("/api/v1/public/request-forms/{link}")),
            )
            .send()
            .await
            .expect("read form");
        let status = resp.status();
        (status, resp.json().await.unwrap_or(Value::Null))
    }

    async fn tickets(&self) -> Vec<(Uuid, String, Option<Uuid>, Option<Uuid>, Option<Uuid>)> {
        sqlx::query_as(
            "SELECT id, title, parent_ticket_id, sla_id, assigned_to_id FROM tickets \
             WHERE tenant_id = $1 ORDER BY created_at",
        )
        .bind(common::DEFAULT_TENANT_ID)
        .fetch_all(&self.pool)
        .await
        .expect("tickets")
    }
}

/// The case the issue was filed for: one link for five people produces one
/// parent and a child per submission, and the sixth is refused.
#[mokosh_test]
async fn a_link_for_several_people_files_a_child_per_person(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let (status, issued, link) = f.issue(Some(3)).await;
    assert!(status.is_success(), "{issued}");
    assert_eq!(issued["people"], 3);
    assert_eq!(issued["submissions_remaining"], 3);
    let parent_id = Uuid::parse_str(issued["parent_ticket_id"].as_str().expect("parent id"))
        .expect("parent uuid");
    assert!(issued["parent_ticket_number"].is_string(), "{issued}");
    let link = link.expect("token");

    // The parent exists from the moment the request is issued, with nothing
    // on it: no SLA clock, no assignee, no due dates.
    let parent = &f.tickets().await[0];
    assert_eq!(parent.0, parent_id);
    assert!(parent.1.contains("3 people"), "{}", parent.1);
    assert_eq!((parent.2, parent.3, parent.4), (None, None, None));

    for (index, name) in ["Jane", "Omar", "Priya"].iter().enumerate() {
        let (status, form) = f.read_form(&link).await;
        assert_eq!(status, StatusCode::OK, "{form}");
        assert_eq!(form["people"], 3);
        assert_eq!(form["person_number"], index as i64 + 1, "{form}");

        let (status, receipt) = f.submit(&link, name).await;
        assert_eq!(status, StatusCode::CREATED, "{name}: {receipt}");
        assert_eq!(receipt["submissions_remaining"], 2 - index as i64);
        assert!(receipt["ticket_number"].is_string());
    }

    let (status, refused) = f.submit(&link, "Fourth").await;
    assert_eq!(status, StatusCode::GONE, "{refused}");
    let (status, _) = f.read_form(&link).await;
    assert_eq!(status, StatusCode::GONE, "a spent link shows no form");

    let tickets = f.tickets().await;
    assert_eq!(tickets.len(), 4, "one parent and three children");
    for child in &tickets[1..] {
        assert_eq!(child.2, Some(parent_id), "every child names the parent");
    }
    // Each person is their own submission, which is what the PMS-732 report
    // counts.
    let submissions: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM form_submissions WHERE tenant_id = $1 AND ticket_id IS NOT NULL",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(&f.pool)
    .await
    .expect("submissions");
    assert_eq!(submissions, 3);
}

/// The ordinary request is untouched: one person, one ticket, no parent, and
/// the link is spent after one submission.
#[mokosh_test]
async fn a_single_person_link_is_unchanged(pool: PgPool) {
    let f = Fixture::new(pool).await;
    for people in [None, Some(1)] {
        let (status, issued, link) = f.issue(people).await;
        assert!(status.is_success(), "{issued}");
        assert_eq!(issued["people"], 1);
        assert!(issued["parent_ticket_id"].is_null(), "{issued}");
        let link = link.expect("token");

        let (status, form) = f.read_form(&link).await;
        assert_eq!(status, StatusCode::OK, "{form}");
        assert_eq!(
            (form["people"].clone(), form["person_number"].clone()),
            (json!(1), json!(1))
        );

        let (status, receipt) = f.submit(&link, "Solo").await;
        assert_eq!(status, StatusCode::CREATED, "{receipt}");
        assert_eq!(receipt["submissions_remaining"], 0);
        let (status, _) = f.submit(&link, "Again").await;
        assert_eq!(status, StatusCode::GONE);
    }

    let tickets = f.tickets().await;
    assert_eq!(tickets.len(), 2, "one ticket per link, no parents");
    assert!(tickets.iter().all(|t| t.2.is_none()));
}

/// The count is bounded: a request for no people or for hundreds is refused,
/// and nothing is issued.
#[mokosh_test]
async fn the_number_of_people_is_bounded(pool: PgPool) {
    let f = Fixture::new(pool).await;
    for people in [0, -1, 51, 5_000] {
        let (status, body, _) = f.issue(Some(people)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{people}: {body}");
    }
    let links: i64 = sqlx::query_scalar("SELECT count(*) FROM form_request_tokens")
        .fetch_one(&f.pool)
        .await
        .expect("links");
    assert_eq!(links, 0);
    assert!(f.tickets().await.is_empty(), "no parent for a refused link");
}

/// PMS-732 stays an average over PEOPLE: time is recorded on children, the
/// parent has none, and the report counts the children.
#[mokosh_test]
async fn the_measured_duration_averages_over_children(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let (_, _, link) = f.issue(Some(2)).await;
    let link = link.expect("token");
    f.submit(&link, "Jane").await;
    f.submit(&link, "Omar").await;

    let work_type: Uuid = sqlx::query_scalar(
        "INSERT INTO work_types (tenant_id, name) VALUES ($1, 'Onboarding') RETURNING id",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(&f.pool)
    .await
    .expect("work type");
    let children: Vec<Uuid> = f
        .tickets()
        .await
        .into_iter()
        .filter(|t| t.2.is_some())
        .map(|t| t.0)
        .collect();
    assert_eq!(children.len(), 2);
    for (child, minutes) in children.iter().zip([40, 60]) {
        sqlx::query(
            "INSERT INTO time_entries (tenant_id, user_id, date, duration_minutes, work_type_id, \
                                       company_id, ticket_id, is_billable, billing_status) \
             VALUES ($1, $2, CURRENT_DATE, $3, $4, $5, $6, TRUE, 'ready_to_bill')",
        )
        .bind(common::DEFAULT_TENANT_ID)
        .bind(f.admin_id)
        .bind(minutes)
        .bind(work_type)
        .bind(f.company_id)
        .bind(child)
        .execute(&f.pool)
        .await
        .expect("time entry");
    }

    let resp = f
        .app
        .client
        .get(f.app.url("/api/v1/reports/request-types"))
        .bearer_auth(&f.token)
        .send()
        .await
        .expect("report");
    assert_eq!(resp.status(), StatusCode::OK);
    let report: Value = resp.json().await.expect("report json");
    let row = report["request_types"]
        .as_array()
        .expect("rows")
        .iter()
        .find(|r| r["form_name"] == "New starter")
        .expect("the request type");
    assert_eq!(row["ticket_count"], 2, "the two children, not the parent");
    assert_eq!(row["total_minutes"], 100);
    assert_eq!(row["average_minutes"], 50.0, "minutes per PERSON: {row}");
}
