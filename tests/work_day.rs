//! PMS-950: a day of an employee's time, from clock-in to clock-out.
//!
//! What these pin is the day as a thing the server holds: the open state lives
//! in `work_day_segments` and not in the client, a second clock-in is refused
//! the way a second active timer is, a break is a segment between two work
//! segments and is not offered when the employer does not track them, and the
//! day view reads the day's time entries by what they are attached to.

mod common;

use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

const DAY: &str = "2026-06-15";

async fn set_flag(pool: &PgPool, enabled: bool) {
    sqlx::query(
        "UPDATE module_config SET is_enabled = $2 \
         WHERE tenant_id = $1 AND module_name = 'timesheets'",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(enabled)
    .execute(pool)
    .await
    .expect("set the timesheets flag");
}

/// The PMS-943 setting the break routes read. Absent means off.
async fn track_breaks(pool: &PgPool) {
    sqlx::query(
        "INSERT INTO tenant_settings (tenant_id, category, key, value) \
         VALUES ($1, 'timesheets', 'track_breaks', 'true'::jsonb)",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .execute(pool)
    .await
    .expect("turn break tracking on");
}

async fn post(app: &common::TestApp, token: &str, path: &str) -> reqwest::Response {
    app.client
        .post(app.url(path))
        .bearer_auth(token)
        .json(&json!({}))
        .send()
        .await
        .expect("post")
}

async fn day(app: &common::TestApp, token: &str, query: &str) -> Value {
    let response = app
        .client
        .get(app.url(&format!("/api/v1/workday{query}")))
        .bearer_auth(token)
        .send()
        .await
        .expect("read the day");
    assert_eq!(response.status(), 200, "{:?}", response.text().await);
    response.json().await.expect("day json")
}

async fn work_type(app: &common::TestApp, token: &str) -> Uuid {
    let body: Value = app
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

async fn log_time(app: &common::TestApp, token: &str, body: Value) -> Value {
    let response = app
        .client
        .post(app.url("/api/v1/time-entries"))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .expect("log time");
    assert_eq!(response.status(), 200, "{:?}", response.text().await);
    response.json().await.expect("entry json")
}

/// Clock in, lunch, clock out: the day is work, break, work, and every
/// transition is answered with the segment it opened or closed.
#[sqlx::test]
async fn a_full_day_with_a_break_is_work_break_work(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    track_breaks(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let response = app
        .client
        .post(app.url("/api/v1/workday/clock-in"))
        .bearer_auth(&token)
        .json(&json!({ "date": DAY }))
        .send()
        .await
        .expect("clock in");
    assert_eq!(response.status(), 200, "{:?}", response.text().await);
    let opened: Value = response.json().await.expect("segment json");
    assert_eq!(opened["kind"], "work");
    assert_eq!(opened["date"], DAY);
    assert_eq!(opened["user_id"], admin_id.to_string());
    assert!(opened["ended_at"].is_null());

    let view = day(&app, &token, &format!("?date={DAY}")).await;
    assert_eq!(view["is_clocked_in"], true);
    assert_eq!(view["on_break"], false);
    assert_eq!(view["track_breaks"], true);

    let response = post(&app, &token, "/api/v1/workday/break/start").await;
    assert_eq!(response.status(), 200, "{:?}", response.text().await);
    let lunch: Value = response.json().await.expect("segment json");
    assert_eq!(lunch["kind"], "break");
    assert_eq!(lunch["date"], DAY, "a break stays on the day it interrupts");
    assert_eq!(day(&app, &token, "").await["on_break"], true);

    let response = post(&app, &token, "/api/v1/workday/break/end").await;
    assert_eq!(response.status(), 200, "{:?}", response.text().await);
    let back: Value = response.json().await.expect("segment json");
    assert_eq!(back["kind"], "work");
    assert!(back["ended_at"].is_null());

    let response = post(&app, &token, "/api/v1/workday/clock-out").await;
    assert_eq!(response.status(), 200, "{:?}", response.text().await);
    let closed: Value = response.json().await.expect("segment json");
    assert_eq!(
        closed["id"], back["id"],
        "clocking out closes the open segment"
    );
    assert!(!closed["ended_at"].is_null());

    let view = day(&app, &token, &format!("?date={DAY}")).await;
    assert_eq!(view["is_clocked_in"], false);
    assert_eq!(view["on_break"], false);
    let kinds: Vec<&str> = view["segments"]
        .as_array()
        .expect("segments")
        .iter()
        .map(|s| s["kind"].as_str().expect("kind"))
        .collect();
    assert_eq!(kinds, ["work", "break", "work"]);
    assert!(view["segments"]
        .as_array()
        .expect("segments")
        .iter()
        .all(|s| !s["ended_at"].is_null()));
}

/// The guard the ticket asks for by name: a second clock-in is refused the way
/// a second active timer is, and a clock-out with nothing open is refused too.
#[sqlx::test]
async fn clocking_in_twice_is_refused(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    assert_eq!(
        post(&app, &token, "/api/v1/workday/clock-in")
            .await
            .status(),
        200
    );
    let response = post(&app, &token, "/api/v1/workday/clock-in").await;
    assert_eq!(response.status(), 409, "{:?}", response.text().await);

    assert_eq!(
        post(&app, &token, "/api/v1/workday/clock-out")
            .await
            .status(),
        200
    );
    let response = post(&app, &token, "/api/v1/workday/clock-out").await;
    assert_eq!(response.status(), 409, "{:?}", response.text().await);
}

/// The open state is the server's, not the client's: a day view with no date
/// finds the day of the open segment, even when that day is not today.
#[sqlx::test]
async fn the_open_day_survives_a_reload(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let response = app
        .client
        .post(app.url("/api/v1/workday/clock-in"))
        .bearer_auth(&token)
        .json(&json!({ "date": DAY }))
        .send()
        .await
        .expect("clock in");
    assert_eq!(response.status(), 200, "{:?}", response.text().await);

    let view = day(&app, &token, "").await;
    assert_eq!(view["date"], DAY);
    assert_eq!(view["is_clocked_in"], true);
    assert_eq!(view["segments"].as_array().expect("segments").len(), 1);
}

/// A person may go home from lunch: clocking out while on a break closes the
/// break, and the day ends there.
#[sqlx::test]
async fn a_day_may_end_on_a_break(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    track_breaks(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    assert_eq!(
        post(&app, &token, "/api/v1/workday/clock-in")
            .await
            .status(),
        200
    );
    assert_eq!(
        post(&app, &token, "/api/v1/workday/break/start")
            .await
            .status(),
        200
    );
    let response = post(&app, &token, "/api/v1/workday/clock-out").await;
    assert_eq!(response.status(), 200, "{:?}", response.text().await);
    let closed: Value = response.json().await.expect("segment json");
    assert_eq!(closed["kind"], "break");
    assert!(!closed["ended_at"].is_null());
    assert_eq!(day(&app, &token, "").await["is_clocked_in"], false);
}

/// With break tracking off (the default), the break routes read as routes
/// that do not exist, and the day view says so, so a client offers no control.
#[sqlx::test]
async fn a_break_is_not_offered_when_tracking_is_off(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    assert_eq!(
        post(&app, &token, "/api/v1/workday/clock-in")
            .await
            .status(),
        200
    );
    assert_eq!(day(&app, &token, "").await["track_breaks"], false);
    for path in ["/api/v1/workday/break/start", "/api/v1/workday/break/end"] {
        let response = post(&app, &token, path).await;
        assert_eq!(
            response.status(),
            404,
            "{path}: {:?}",
            response.text().await
        );
    }
    // And the clock itself is unaffected.
    assert_eq!(
        post(&app, &token, "/api/v1/workday/clock-out")
            .await
            .status(),
        200
    );
}

/// The day's entries read by what they are attached to. Non-ticket,
/// non-project time is Administrative and carries `entry_kind = 'employee'`
/// (PMS-942); the gap between clocked and logged is reported, not resolved.
#[sqlx::test]
async fn the_day_breaks_down_by_ticket_project_and_administrative(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let (ticket_id, _note_id) = common::seed_ticket_and_note(&pool, admin_id, company_id).await;
    let project_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO projects (id, tenant_id, name, company_id) VALUES ($1, $2, 'Rollout', $3)",
    )
    .bind(project_id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company_id)
    .execute(&pool)
    .await
    .expect("seed a project");
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;
    let work_type_id = work_type(&app, &token).await;

    log_time(
        &app,
        &token,
        json!({
            "user_id": admin_id, "date": DAY, "duration_minutes": 30,
            "work_type_id": work_type_id, "company_id": company_id, "ticket_id": ticket_id,
        }),
    )
    .await;
    log_time(
        &app,
        &token,
        json!({
            "user_id": admin_id, "date": DAY, "duration_minutes": 60,
            "work_type_id": work_type_id, "company_id": company_id, "project_id": project_id,
        }),
    )
    .await;
    let paperwork = log_time(
        &app,
        &token,
        json!({
            "user_id": admin_id, "date": DAY, "duration_minutes": 45,
            "work_type_id": work_type_id,
        }),
    )
    .await;
    assert_eq!(paperwork["entry_kind"], "employee");
    // A day on another date must not leak into this one.
    log_time(
        &app,
        &token,
        json!({
            "user_id": admin_id, "date": "2026-06-16", "duration_minutes": 480,
            "work_type_id": work_type_id,
        }),
    )
    .await;

    let view = day(&app, &token, &format!("?date={DAY}")).await;
    let breakdown = &view["breakdown"];
    assert_eq!(breakdown["tickets"].as_array().expect("tickets").len(), 1);
    assert_eq!(breakdown["tickets"][0]["ticket_id"], ticket_id.to_string());
    assert_eq!(breakdown["tickets"][0]["minutes"], 30);
    assert!(breakdown["tickets"][0]["ticket_number"].is_string());
    assert_eq!(breakdown["projects"].as_array().expect("projects").len(), 1);
    assert_eq!(
        breakdown["projects"][0]["project_id"],
        project_id.to_string()
    );
    assert_eq!(breakdown["projects"][0]["project_name"], "Rollout");
    assert_eq!(breakdown["projects"][0]["minutes"], 60);
    assert_eq!(breakdown["administrative"]["minutes"], 45);
    assert_eq!(breakdown["administrative"]["entry_count"], 1);
    assert_eq!(breakdown["unattached"]["minutes"], 0);
    assert_eq!(view["logged_minutes"], 135);
    // Nothing was clocked on this day, so the whole of it is more logged than
    // clocked: a negative gap, reported as such.
    assert_eq!(view["clocked_minutes"], 0);
    assert_eq!(view["unlogged_minutes"], -135);
}

/// With the flag off, every route here is answered the way a nonexistent
/// route is. Not hidden in the client, not 403.
#[sqlx::test]
async fn every_work_day_route_is_gone_when_the_flag_is_off(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    set_flag(&pool, false).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let response = app
        .client
        .get(app.url("/api/v1/workday"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("read the day");
    assert_eq!(
        response.status(),
        404,
        "GET /workday must read as a route that does not exist"
    );
    for path in [
        "/api/v1/workday/clock-in",
        "/api/v1/workday/clock-out",
        "/api/v1/workday/break/start",
        "/api/v1/workday/break/end",
    ] {
        let response = post(&app, &token, path).await;
        assert_eq!(
            response.status(),
            404,
            "POST {path} must read as a route that does not exist"
        );
    }
}

/// A technician's day is their own; an admin may read anyone's.
#[sqlx::test]
async fn a_technician_sees_only_their_own_day(pool: PgPool) {
    let (admin_id, admin_email, admin_password) = common::seed_admin(&pool).await;
    let (tech_id, tech_email, tech_password) = common::seed_user(
        &pool,
        common::DEFAULT_TENANT_ID,
        "tech@example.com",
        "technician",
    )
    .await;
    let app = common::boot(pool).await;
    let admin = common::login(&app, &admin_email, &admin_password).await;
    let tech = common::login(&app, &tech_email, &tech_password).await;

    let response = app
        .client
        .get(app.url(&format!("/api/v1/workday?user_id={admin_id}")))
        .bearer_auth(&tech)
        .send()
        .await
        .expect("read another day");
    assert_eq!(response.status(), 403, "{:?}", response.text().await);

    assert_eq!(day(&app, &tech, "").await["user_id"], tech_id.to_string());
    assert_eq!(
        day(&app, &admin, &format!("?user_id={tech_id}")).await["user_id"],
        tech_id.to_string()
    );
}
