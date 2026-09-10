//! PMS-1145: a recorded work-day segment can be corrected or removed.
//!
//! Before this, five routes existed and all five acted on *now*. A clock-in at
//! the wrong time, a clock-out an hour late, a stray segment from a mis-tap:
//! permanent, and correctable only with database access. What these pin is the
//! correction as a real operation with real refusals - the day recomputing
//! from the corrected segments, the invariants that would otherwise surface as
//! a constraint violation, who the tenant's policy lets do it, and that the
//! change is recorded.

mod common;

use chrono::{DateTime, Duration, Utc};
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

const DAY: &str = "2026-06-15";

/// The correction policy is a tenant setting; absent means `owner_or_admin`.
async fn set_policy(pool: &PgPool, value: &str) {
    sqlx::query(
        "INSERT INTO tenant_settings (tenant_id, category, key, value) \
         VALUES ($1, 'timesheets', 'segment_editing', $2::jsonb) \
         ON CONFLICT (tenant_id, category, key) DO UPDATE SET value = EXCLUDED.value",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(format!("\"{value}\""))
    .execute(pool)
    .await
    .expect("set the segment-editing policy");
}

async fn clock_in(app: &common::TestApp, token: &str) -> Value {
    let response = app
        .client
        .post(app.url("/api/v1/workday/clock-in"))
        .bearer_auth(token)
        .json(&json!({ "date": DAY }))
        .send()
        .await
        .expect("clock in");
    assert_eq!(response.status(), 200, "{:?}", response.text().await);
    response.json().await.expect("segment json")
}

async fn clock_out(app: &common::TestApp, token: &str) -> Value {
    let response = app
        .client
        .post(app.url("/api/v1/workday/clock-out"))
        .bearer_auth(token)
        .json(&json!({}))
        .send()
        .await
        .expect("clock out");
    assert_eq!(response.status(), 200, "{:?}", response.text().await);
    response.json().await.expect("segment json")
}

async fn correct(app: &common::TestApp, token: &str, id: &str, body: Value) -> reqwest::Response {
    app.client
        .put(app.url(&format!("/api/v1/workday/segments/{id}")))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .expect("correct a segment")
}

async fn remove(app: &common::TestApp, token: &str, id: &str) -> reqwest::Response {
    app.client
        .delete(app.url(&format!("/api/v1/workday/segments/{id}")))
        .bearer_auth(token)
        .send()
        .await
        .expect("remove a segment")
}

async fn day(app: &common::TestApp, token: &str) -> Value {
    let response = app
        .client
        .get(app.url(&format!("/api/v1/workday?date={DAY}")))
        .bearer_auth(token)
        .send()
        .await
        .expect("read the day");
    assert_eq!(response.status(), 200, "{:?}", response.text().await);
    response.json().await.expect("day json")
}

fn id_of(segment: &Value) -> String {
    segment["id"].as_str().expect("a segment id").to_string()
}

/// The reason the feature exists: a clock-out entered an hour late is
/// corrected, and the day's own totals follow, because PMS-950 derives them
/// from the segments on every read rather than storing them.
#[sqlx::test]
async fn a_corrected_segment_changes_the_day_it_belongs_to(pool: PgPool) {
    let (_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let opened = clock_in(&app, &token).await;
    let closed = clock_out(&app, &token).await;
    let id = id_of(&closed);

    // A clean two hours, backdated: the shape of a real correction, where the
    // clock was started late or stopped late and the person knows the times.
    let started: DateTime<Utc> = "2026-06-15T09:00:00Z".parse().expect("a start");
    let ended = started + Duration::hours(2);
    let response = correct(
        &app,
        &token,
        &id,
        json!({ "started_at": started, "ended_at": ended }),
    )
    .await;
    assert_eq!(response.status(), 200, "{:?}", response.text().await);
    let corrected: Value = response.json().await.expect("segment json");
    assert_eq!(corrected["minutes"], 120);
    assert_eq!(id_of(&corrected), id, "the same segment, not a new one");
    assert_eq!(
        id_of(&opened),
        id,
        "clock-in and clock-out act on one segment"
    );

    let day = day(&app, &token).await;
    assert_eq!(day["clocked_minutes"], 120, "the day follows its segments");
    assert_eq!(day["is_clocked_in"], false);
}

/// An end before its start is refused by the service with a sentence, not by
/// the table's CHECK with a constraint name.
#[sqlx::test]
async fn a_segment_cannot_be_made_to_end_before_it_starts(pool: PgPool) {
    let (_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let id = id_of(&clock_in(&app, &token).await);
    clock_out(&app, &token).await;

    let started: DateTime<Utc> = "2026-06-15T09:00:00Z".parse().expect("a start");
    let response = correct(
        &app,
        &token,
        &id,
        json!({ "started_at": started, "ended_at": started - Duration::hours(1) }),
    )
    .await;
    assert_eq!(response.status(), 400);
    let body = response.text().await.expect("a body");
    assert!(
        body.contains("cannot end before it starts"),
        "the refusal says what is wrong: {body}"
    );
}

/// An explicit null on `ended_at` reopens a segment, which is how a clock-out
/// tapped by mistake is undone. Absent leaves the end alone; the two are
/// different requests and the double option is what tells them apart.
#[sqlx::test]
async fn an_explicit_null_reopens_a_segment_and_an_absent_field_does_not(pool: PgPool) {
    let (_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let id = id_of(&clock_in(&app, &token).await);
    clock_out(&app, &token).await;
    assert_eq!(day(&app, &token).await["is_clocked_in"], false);

    // Absent: the correction touches the date only, and the segment stays
    // closed.
    let response = correct(&app, &token, &id, json!({ "date": DAY })).await;
    assert_eq!(response.status(), 200, "{:?}", response.text().await);
    assert_eq!(
        day(&app, &token).await["is_clocked_in"],
        false,
        "an absent ended_at leaves the segment closed"
    );

    // Explicit null: the clock is running again.
    let response = correct(&app, &token, &id, json!({ "ended_at": Value::Null })).await;
    assert_eq!(response.status(), 200, "{:?}", response.text().await);
    let day = day(&app, &token).await;
    assert_eq!(day["is_clocked_in"], true, "the segment is open again");
}

/// Reopening while another segment is open would produce two open segments
/// for one person, which the partial unique index forbids. The service
/// refuses first, with a sentence that says what is in the way.
#[sqlx::test]
async fn reopening_is_refused_while_another_segment_is_open(pool: PgPool) {
    let (_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let first = id_of(&clock_in(&app, &token).await);
    clock_out(&app, &token).await;
    // A second session on the same day, left running.
    clock_in(&app, &token).await;

    let response = correct(&app, &token, &first, json!({ "ended_at": Value::Null })).await;
    assert_eq!(response.status(), 409, "{:?}", response.text().await);
}

/// Removing the open segment is how a mis-tapped clock-in is undone: it
/// leaves the person clocked out, which is what they were.
#[sqlx::test]
async fn removing_the_open_segment_leaves_the_person_clocked_out(pool: PgPool) {
    let (_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let id = id_of(&clock_in(&app, &token).await);
    assert_eq!(day(&app, &token).await["is_clocked_in"], true);

    let response = remove(&app, &token, &id).await;
    assert_eq!(response.status(), 204, "{:?}", response.text().await);

    let day = day(&app, &token).await;
    assert_eq!(day["is_clocked_in"], false);
    assert_eq!(day["clocked_minutes"], 0);
    assert_eq!(
        day["segments"].as_array().expect("segments").len(),
        0,
        "the segment is gone, not hidden"
    );

    // And the clock works again afterwards, which is the point of undoing it.
    clock_in(&app, &token).await;
}

/// `off` means nobody, the person whose day it is included. A tenant that
/// wants attendance immutable gets that, rather than a rule that quietly
/// exempts the owner.
#[sqlx::test]
async fn the_off_policy_refuses_the_owner_too(pool: PgPool) {
    let (_id, email, password) = common::seed_admin(&pool).await;
    set_policy(&pool, "off").await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let id = id_of(&clock_in(&app, &token).await);
    let response = correct(&app, &token, &id, json!({ "date": DAY })).await;
    assert_eq!(
        response.status(),
        403,
        "an admin is refused under `off`: {:?}",
        response.text().await
    );
    assert_eq!(remove(&app, &token, &id).await.status(), 403);
}

/// Under the default, a technician corrects their own and not someone else's.
/// 403 rather than 404: the segment exists and they can read the day it
/// belongs to, so pretending it is absent would be a lie they can disprove.
#[sqlx::test]
async fn a_technician_corrects_their_own_segment_only(pool: PgPool) {
    let (_admin_id, admin_email, admin_password) = common::seed_admin(&pool).await;
    let (_tech_id, tech_email, tech_password) = common::seed_user(
        &pool,
        common::DEFAULT_TENANT_ID,
        "tech@example.com",
        "technician",
    )
    .await;
    let app = common::boot(pool).await;
    let admin = common::login(&app, &admin_email, &admin_password).await;
    let tech = common::login(&app, &tech_email, &tech_password).await;

    let admins_own = id_of(&clock_in(&app, &admin).await);
    let techs_own = id_of(&clock_in(&app, &tech).await);

    let response = correct(&app, &tech, &admins_own, json!({ "date": DAY })).await;
    assert_eq!(response.status(), 403, "not the technician's segment");

    let response = correct(&app, &tech, &techs_own, json!({ "date": DAY })).await;
    assert_eq!(
        response.status(),
        200,
        "their own: {:?}",
        response.text().await
    );

    // And the default policy lets an admin correct someone else's.
    let response = correct(&app, &admin, &techs_own, json!({ "date": DAY })).await;
    assert_eq!(
        response.status(),
        200,
        "an admin under owner_or_admin: {:?}",
        response.text().await
    );
}

/// `owner_or_manager` widens it to anyone who can manage users, which a
/// technician is not, so the narrowing half of the policy still holds.
#[sqlx::test]
async fn the_manager_policy_widens_it_without_opening_it(pool: PgPool) {
    let (_admin_id, admin_email, admin_password) = common::seed_admin(&pool).await;
    let (_mgr_id, mgr_email, mgr_password) = common::seed_user(
        &pool,
        common::DEFAULT_TENANT_ID,
        "manager@example.com",
        "manager",
    )
    .await;
    let (_tech_id, tech_email, tech_password) = common::seed_user(
        &pool,
        common::DEFAULT_TENANT_ID,
        "tech2@example.com",
        "technician",
    )
    .await;
    set_policy(&pool, "owner_or_manager").await;
    let app = common::boot(pool).await;
    let admin = common::login(&app, &admin_email, &admin_password).await;
    let manager = common::login(&app, &mgr_email, &mgr_password).await;
    let tech = common::login(&app, &tech_email, &tech_password).await;

    let admins_own = id_of(&clock_in(&app, &admin).await);
    let _ = clock_in(&app, &tech).await;

    let response = correct(&app, &manager, &admins_own, json!({ "date": DAY })).await;
    assert_eq!(
        response.status(),
        200,
        "a manager may correct another's: {:?}",
        response.text().await
    );
    let response = correct(&app, &tech, &admins_own, json!({ "date": DAY })).await;
    assert_eq!(response.status(), 403, "a technician still may not");
}

/// A correction that happened is distinguishable from a day nobody touched,
/// which is the whole reason the issue asked for an audit trail from the
/// first version rather than retrofitted.
#[sqlx::test]
async fn a_correction_and_a_removal_are_both_recorded(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let id = id_of(&clock_in(&app, &token).await);
    clock_out(&app, &token).await;
    let started: DateTime<Utc> = "2026-06-15T09:00:00Z".parse().expect("a start");
    correct(
        &app,
        &token,
        &id,
        json!({ "started_at": started, "ended_at": started + Duration::hours(2) }),
    )
    .await;

    // One row of the audit table, named so clippy is not asked to reason
    // about a four-deep tuple and a reader is not either.
    type AuditRow = (String, Option<Uuid>, Option<Value>, Option<Value>);
    let rows: Vec<AuditRow> = sqlx::query_as(
        "SELECT action, user_id, old_values, new_values FROM audit_log \
         WHERE entity_type = 'work_day_segments' AND entity_id = $1 ORDER BY timestamp",
    )
    .bind(Uuid::parse_str(&id).expect("a uuid"))
    .fetch_all(&pool)
    .await
    .expect("read the audit log");

    assert_eq!(rows.len(), 1, "one row for the correction");
    let (action, actor, old, new) = &rows[0];
    assert_eq!(action, "update");
    assert_eq!(*actor, Some(admin_id), "the person who corrected it");
    let old = old.as_ref().expect("the segment as it was");
    let new = new.as_ref().expect("the segment as it is");
    assert_ne!(
        old["started_at"], new["started_at"],
        "the row carries both sides of the change"
    );

    remove(&app, &token, &id).await;
    let actions: Vec<String> = sqlx::query_scalar(
        "SELECT action FROM audit_log \
         WHERE entity_type = 'work_day_segments' AND entity_id = $1 ORDER BY timestamp",
    )
    .bind(Uuid::parse_str(&id).expect("a uuid"))
    .fetch_all(&pool)
    .await
    .expect("read the audit log");
    assert_eq!(actions, vec!["update".to_string(), "delete".to_string()]);
}

/// A segment id that belongs to nobody is a 404, and one belonging to another
/// tenant is the same 404: the correction routes are not a cross-tenant
/// existence oracle.
#[sqlx::test]
async fn an_unknown_segment_is_not_an_existence_oracle(pool: PgPool) {
    let (_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let unknown = Uuid::new_v4().to_string();
    assert_eq!(
        correct(&app, &token, &unknown, json!({ "date": DAY }))
            .await
            .status(),
        404
    );
    assert_eq!(remove(&app, &token, &unknown).await.status(), 404);
}
