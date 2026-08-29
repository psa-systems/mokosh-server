//! PMS-942: employee time and client work are different things, and the
//! schema now says which a row is.
//!
//! What these pin is the boundary, not the plumbing: which entries can exist,
//! which company they are allowed to name, and which of them a client invoice
//! is allowed to see. The interesting cases are the ones the issue originally
//! proposed to get wrong - a billable client call logged with no ticket is the
//! client's time, not the MSP's - and the ones the old NOT NULL made
//! impossible, like stopping a timer that was never pointed at anybody.

mod common;

use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

/// The tenant's own internal company (PMS-413), which migration 062 creates
/// for every tenant and which MAPPS-243 sends as the company on a General
/// entry.
async fn own_company(pool: &PgPool) -> Uuid {
    sqlx::query_scalar::<_, Option<Uuid>>("SELECT own_company_id FROM tenants WHERE id = $1")
        .bind(common::DEFAULT_TENANT_ID)
        .fetch_one(pool)
        .await
        .expect("read the tenant")
        .expect("migration 062 gives every tenant an internal company")
}

/// The first active work type, which the seed migration supplies.
async fn work_type(app: &common::TestApp, token: &str) -> Uuid {
    let body: serde_json::Value = app
        .client
        .get(app.url("/api/v1/work-types"))
        .bearer_auth(token)
        .send()
        .await
        .expect("list work types")
        .json()
        .await
        .expect("work types json");
    Uuid::parse_str(body["data"][0]["id"].as_str().expect("a seeded work type"))
        .expect("work type id")
}

fn entry_body(user_id: Uuid, work_type_id: Uuid) -> serde_json::Value {
    json!({
        "user_id": user_id,
        "date": "2026-06-15",
        "duration_minutes": 60,
        "work_type_id": work_type_id,
    })
}

/// The case the old `company_id NOT NULL` forbade outright: an employee logs an
/// hour of the MSP's own time, naming nobody.
#[sqlx::test]
async fn employee_time_names_no_company_at_all(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;
    let work_type_id = work_type(&app, &token).await;

    let response = app
        .client
        .post(app.url("/api/v1/time-entries"))
        .bearer_auth(&token)
        .json(&entry_body(admin_id, work_type_id))
        .send()
        .await
        .expect("create employee time");
    assert_eq!(response.status(), 200, "{:?}", response.text().await);
    let body: serde_json::Value = response.json().await.expect("entry json");
    let entry = &body;
    assert_eq!(entry["entry_kind"], "employee");
    assert!(entry["company_id"].is_null(), "{entry}");
    // Employee time bills nobody, whatever the request or the work type's
    // default said.
    assert_eq!(entry["is_billable"], false);
    assert_eq!(entry["billable_minutes"], 0);
    assert!(entry["total_amount"].is_null(), "{entry}");
    // The hours themselves are untouched: this is the MSP's own time, not
    // nothing.
    assert_eq!(entry["worked_minutes"], 60);
}

/// The tenant's own internal company is the signal today's client already
/// sends for a General entry, so it resolves to employee time with no change
/// on the client side. The company it named is left on the row.
#[sqlx::test]
async fn the_internal_company_still_means_the_msps_own_time(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let internal = own_company(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;
    let work_type_id = work_type(&app, &token).await;

    let mut body = entry_body(admin_id, work_type_id);
    body["company_id"] = json!(internal);
    let entry: serde_json::Value = app
        .client
        .post(app.url("/api/v1/time-entries"))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .expect("create overhead time")
        .json()
        .await
        .expect("entry json");
    assert_eq!(entry["entry_kind"], "employee", "{entry}");
    assert_eq!(entry["company_id"], json!(internal));
    assert_eq!(entry["is_billable"], false);
}

/// The regression the issue's original backfill would have caused. A billable
/// call for a customer, logged with no ticket, is the CLIENT's time. Deciding
/// it from the absence of a ticket would move those hours onto the MSP's own
/// books and off the invoice.
#[sqlx::test]
async fn a_client_call_with_no_ticket_is_still_the_clients_time(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;
    let work_type_id = work_type(&app, &token).await;

    let mut body = entry_body(admin_id, work_type_id);
    body["company_id"] = json!(company_id);
    body["is_billable"] = json!(true);
    let entry: serde_json::Value = app
        .client
        .post(app.url("/api/v1/time-entries"))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .expect("create client time")
        .json()
        .await
        .expect("entry json");
    assert_eq!(entry["entry_kind"], "client", "{entry}");
    assert_eq!(entry["is_billable"], true);
    // `general` is a statement about the kind of work, not about whether
    // anybody is paying for it. It must not have been read as the axis.
    assert_eq!(entry["work_category"], "general");
}

/// Both contradictions are refused by name, so a caller reads which field is
/// wrong instead of a database constraint's.
#[sqlx::test]
async fn the_two_contradictions_are_refused_as_bad_requests(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let (ticket_id, _note_id) = common::seed_ticket_and_note(&pool, admin_id, company_id).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;
    let work_type_id = work_type(&app, &token).await;

    // Employee time carrying a client's ticket.
    let mut body = entry_body(admin_id, work_type_id);
    body["entry_kind"] = json!("employee");
    body["ticket_id"] = json!(ticket_id);
    body["company_id"] = json!(company_id);
    let response = app
        .client
        .post(app.url("/api/v1/time-entries"))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .expect("post employee time with a ticket");
    assert_eq!(response.status(), 400, "{:?}", response.text().await);

    // Client work naming no client.
    let mut body = entry_body(admin_id, work_type_id);
    body["entry_kind"] = json!("client");
    let response = app
        .client
        .post(app.url("/api/v1/time-entries"))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .expect("post client work with no company");
    assert_eq!(response.status(), 400, "{:?}", response.text().await);
}

/// An update cannot move an entry between the MSP's books and a client's.
/// There is no `entry_kind` or `company_id` on the update request, so the only
/// way to try is to attach a ticket to employee time.
#[sqlx::test]
async fn an_update_cannot_turn_employee_time_into_client_work(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let (ticket_id, _note_id) = common::seed_ticket_and_note(&pool, admin_id, company_id).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;
    let work_type_id = work_type(&app, &token).await;

    let created: serde_json::Value = app
        .client
        .post(app.url("/api/v1/time-entries"))
        .bearer_auth(&token)
        .json(&entry_body(admin_id, work_type_id))
        .send()
        .await
        .expect("create employee time")
        .json()
        .await
        .expect("entry json");
    let entry_id = created["id"].as_str().expect("an id").to_string();

    let response = app
        .client
        .put(app.url(&format!("/api/v1/time-entries/{entry_id}")))
        .bearer_auth(&token)
        .json(&json!({ "ticket_id": ticket_id }))
        .send()
        .await
        .expect("attach a ticket to employee time");
    assert_eq!(response.status(), 400, "{:?}", response.text().await);
}

/// The timer that could not be stopped. With neither a company nor a ticket to
/// infer one from, stopping used to 400 and the elapsed time had nowhere to
/// go; the entry is the MSP's own time.
#[sqlx::test]
async fn a_timer_pointed_at_nobody_stops_into_employee_time(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let started: serde_json::Value = app
        .client
        .post(app.url("/api/v1/timers/start"))
        .bearer_auth(&token)
        .json(&json!({ "notes": "expense reports" }))
        .send()
        .await
        .expect("start a timer")
        .json()
        .await
        .expect("timer json");
    let timer_id = started["id"].as_str().expect("a timer id").to_string();

    let response = app
        .client
        .post(app.url(&format!("/api/v1/timers/{timer_id}/stop")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("stop the timer");
    assert_eq!(response.status(), 200, "{:?}", response.text().await);
    let body: serde_json::Value = response.json().await.expect("entry json");
    assert_eq!(body["entry_kind"], "employee", "{body}");
    assert!(body["company_id"].is_null(), "{body}");
    assert_eq!(body["is_billable"], false);
}

/// The MSP's own overhead time is not invoiceable to the MSP. The internal
/// company is a real `companies` row, so before PMS-942 naming it as the
/// invoice's company was enough to sweep that time onto an invoice.
#[sqlx::test]
async fn overhead_time_cannot_be_invoiced_to_the_internal_company(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let internal = own_company(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;
    let work_type_id = work_type(&app, &token).await;

    let mut body = entry_body(admin_id, work_type_id);
    body["company_id"] = json!(internal);
    app.client
        .post(app.url("/api/v1/time-entries"))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .expect("create overhead time");

    // Put it in the state a client invoice would otherwise consume, straight
    // in the database, so the test is about the kind and not about the
    // approval lifecycle PMS-944 is separately removing.
    sqlx::query(
        "UPDATE time_entries SET approval_status = 'approved', billing_status = 'ready_to_bill', \
         is_billable = TRUE WHERE tenant_id = $1",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .execute(&app.pool)
    .await
    .expect("force the entry to look billable");

    let response = app
        .client
        .post(app.url("/api/v1/invoices/from-time-entries"))
        .bearer_auth(&token)
        .json(&json!({ "company_id": internal }))
        .send()
        .await
        .expect("try to invoice the internal company");
    assert_eq!(
        response.status(),
        400,
        "employee time must not reach an invoice: {:?}",
        response.text().await
    );
}

/// The backfill, run against rows shaped the way migration 119 found them.
///
/// The statement under test is read out of the migration itself rather than
/// restated here: migrations are immutable once committed, so the file is a
/// stable thing to quote, and a copy in the test would be free to drift from
/// the SQL that actually ran on every existing database.
#[sqlx::test]
async fn the_backfill_claims_overhead_time_and_leaves_client_work_alone(pool: PgPool) {
    let (admin_id, _email, _password) = common::seed_admin(&pool).await;
    let internal = own_company(&pool).await;
    let client = common::seed_company(&pool).await;
    let (ticket_id, _note_id) = common::seed_ticket_and_note(&pool, admin_id, client).await;
    let work_type_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM work_types WHERE tenant_id = $1 ORDER BY sort_order LIMIT 1",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(&pool)
    .await
    .expect("a seeded work type");

    // Three rows as they would have existed before the column: everything is
    // `client`, because that is the DEFAULT every pre-existing row took.
    let overhead = Uuid::new_v4();
    let client_call = Uuid::new_v4();
    let internal_ticket = Uuid::new_v4();
    for (id, company, ticket) in [
        (overhead, internal, None),
        (client_call, client, None),
        // Attributed to the internal company but carrying a client's ticket.
        // The conservative conditions leave it alone, which is also what stops
        // the backfill writing a row the new constraint rejects and aborting
        // the migration mid-flight.
        (internal_ticket, internal, Some(ticket_id)),
    ] {
        sqlx::query(
            "INSERT INTO time_entries (id, tenant_id, user_id, date, duration_minutes, \
             work_type_id, company_id, ticket_id, entry_kind) \
             VALUES ($1, $2, $3, '2026-06-15', 60, $4, $5, $6, 'client')",
        )
        .bind(id)
        .bind(common::DEFAULT_TENANT_ID)
        .bind(admin_id)
        .bind(work_type_id)
        .bind(company)
        .bind(ticket)
        .execute(&pool)
        .await
        .expect("insert a pre-migration row");
    }

    let migration = include_str!("../migrations/119_time_entry_kind.sql");
    // Comments come off BEFORE the split, not after: the paragraphs explaining
    // each statement are English and contain semicolons of their own, so
    // splitting the raw file cuts a sentence in half and the statement after it
    // is never recognisable.
    let sql: String = migration
        .lines()
        .filter(|line| !line.trim_start().starts_with("--"))
        .collect::<Vec<_>>()
        .join("\n");
    let backfill = sql
        .split(';')
        .map(str::trim)
        .find(|s| s.starts_with("UPDATE time_entries"))
        .expect("the migration carries the backfill")
        .to_string();
    sqlx::query(&backfill)
        .execute(&pool)
        .await
        .expect("re-run the backfill");

    let kind = |id: Uuid| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, String>("SELECT entry_kind FROM time_entries WHERE id = $1")
                .bind(id)
                .fetch_one(&pool)
                .await
                .expect("read the kind back")
        }
    };
    assert_eq!(kind(overhead).await, "employee");
    assert_eq!(
        kind(client_call).await,
        "client",
        "a customer's time stays the customer's"
    );
    assert_eq!(
        kind(internal_ticket).await,
        "client",
        "a row carrying client work is left alone whatever company it names"
    );

    // No hours moved. The backfill only ever writes `entry_kind`.
    let total: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(duration_minutes), 0)::bigint FROM time_entries WHERE tenant_id = $1",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(&pool)
    .await
    .expect("sum the hours");
    assert_eq!(total, 180);
}
