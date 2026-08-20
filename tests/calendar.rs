//! Integration tests for the calendar / dispatch story (PMS-58).
//!
//! Covers the core working components the story adds on top of the
//! existing appointment / availability / time-off / on-call CRUD:
//!   * booking an appointment and finding it via the range query
//!   * a recurring appointment (`FREQ=DAILY;COUNT=3`) expanding to the
//!     expected number of occurrence instances inside a queried range,
//!     each carrying `recurrence_parent_id` pointing at the master
//!   * time-off approve and reject transitions
//!   * the dispatch endpoint returning its four aggregated sections
//!
//! Everything is driven through the HTTP API (the surfaces all exist),
//! authenticating with the legacy bearer token like the other suites.
//! Deterministic: fixed UTC instants, `COUNT`-bounded recurrence.

mod common;

use common::{boot, login, seed_admin, seed_team, seed_tenant_with_admin};
use sqlx::PgPool;
use uuid::Uuid;

/// Book a one-off appointment, then assert the bounded range query
/// (`GET /api/v1/appointments?from&to`) returns it unchanged with no
/// recurrence metadata.
#[sqlx::test]
async fn book_appointment_then_range_query_returns_it(pool: PgPool) {
    let (admin_id, email, password) = seed_admin(&pool).await;
    let app = boot(pool).await;
    let token = login(&app, &email, &password).await;

    let create_body = serde_json::json!({
        "title": "Onsite visit",
        "assigned_to_id": admin_id,
        "start_time": "2026-03-02T09:00:00Z",
        "end_time": "2026-03-02T10:00:00Z",
    });
    let created: serde_json::Value = app
        .client
        .post(app.url("/api/v1/appointments"))
        .bearer_auth(&token)
        .json(&create_body)
        .send()
        .await
        .expect("send create appointment")
        .json()
        .await
        .expect("create appointment JSON");
    let appt_id = created["id"].as_str().expect("created appointment id");
    assert_eq!(created["title"].as_str(), Some("Onsite visit"));

    let list: serde_json::Value = app
        .client
        .get(app.url("/api/v1/appointments?from=2026-03-01T00:00:00Z&to=2026-03-31T23:59:59Z"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send range query")
        .json()
        .await
        .expect("range query JSON");
    let data = list["data"].as_array().expect("range query data array");
    let found = data
        .iter()
        .find(|a| a["id"].as_str() == Some(appt_id))
        .expect("range query must return the booked appointment");
    // A one-off appointment carries no recurrence linkage.
    assert!(
        found.get("recurrence_parent_id").is_none() || found["recurrence_parent_id"].is_null(),
        "non-recurring appointment must not have recurrence_parent_id, got {found}"
    );
}

/// Reject a one-off appointment whose end is not strictly after its
/// start. The service enforces `end_time > start_time` on create.
#[sqlx::test]
async fn create_appointment_rejects_non_positive_duration(pool: PgPool) {
    let (admin_id, email, password) = seed_admin(&pool).await;
    let app = boot(pool).await;
    let token = login(&app, &email, &password).await;

    let resp = app
        .client
        .post(app.url("/api/v1/appointments"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "title": "Zero-length",
            "assigned_to_id": admin_id,
            "start_time": "2026-03-02T09:00:00Z",
            "end_time": "2026-03-02T09:00:00Z",
        }))
        .send()
        .await
        .expect("send create appointment");
    assert_eq!(
        resp.status().as_u16(),
        400,
        "end_time == start_time must be rejected"
    );
}

/// A `FREQ=DAILY;COUNT=3` master expands to exactly three occurrence
/// instances inside a range that spans the whole series, each shifted to
/// its own day and each pointing back at the master via
/// `recurrence_parent_id`. The master row itself is not emitted.
#[sqlx::test]
async fn recurring_appointment_expands_within_range(pool: PgPool) {
    let (admin_id, email, password) = seed_admin(&pool).await;
    let app = boot(pool).await;
    let token = login(&app, &email, &password).await;

    let created: serde_json::Value = app
        .client
        .post(app.url("/api/v1/appointments"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "title": "Daily standup",
            "assigned_to_id": admin_id,
            "start_time": "2026-03-02T09:00:00Z",
            "end_time": "2026-03-02T09:30:00Z",
            "recurrence_rule": "FREQ=DAILY;COUNT=3",
        }))
        .send()
        .await
        .expect("send create recurring appointment")
        .json()
        .await
        .expect("create recurring appointment JSON");
    let master_id = created["id"]
        .as_str()
        .expect("created recurring appointment id")
        .to_string();

    // Window spans the entire 3-day series.
    let list: serde_json::Value = app
        .client
        .get(app.url("/api/v1/appointments?from=2026-03-01T00:00:00Z&to=2026-03-31T23:59:59Z"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send range query")
        .json()
        .await
        .expect("range query JSON");
    let data = list["data"].as_array().expect("range query data array");

    let instances: Vec<&serde_json::Value> = data
        .iter()
        .filter(|a| a["recurrence_parent_id"].as_str() == Some(master_id.as_str()))
        .collect();
    assert_eq!(
        instances.len(),
        3,
        "FREQ=DAILY;COUNT=3 must expand to 3 occurrences, got {}: {data:?}",
        instances.len()
    );

    // Occurrences land on consecutive days at the master's time-of-day,
    // and each keeps the 30-minute duration.
    let mut starts: Vec<&str> = instances
        .iter()
        .map(|a| a["start_time"].as_str().expect("instance start_time"))
        .collect();
    starts.sort_unstable();
    assert_eq!(
        starts,
        vec![
            "2026-03-02T09:00:00Z",
            "2026-03-03T09:00:00Z",
            "2026-03-04T09:00:00Z",
        ],
        "occurrence starts must be the three consecutive days"
    );
    for inst in &instances {
        assert_eq!(
            inst["end_time"].as_str().map(|s| s.ends_with("09:30:00Z")),
            Some(true),
            "each occurrence keeps the 30-minute duration: {inst}"
        );
    }
}

/// A narrower window clips the same series: querying only the second day
/// returns exactly one occurrence. This proves expansion is bounded by
/// the requested range, not the whole series.
#[sqlx::test]
async fn recurring_expansion_is_bounded_by_range(pool: PgPool) {
    let (admin_id, email, password) = seed_admin(&pool).await;
    let app = boot(pool).await;
    let token = login(&app, &email, &password).await;

    let created: serde_json::Value = app
        .client
        .post(app.url("/api/v1/appointments"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "title": "Daily standup",
            "assigned_to_id": admin_id,
            "start_time": "2026-03-02T09:00:00Z",
            "end_time": "2026-03-02T09:30:00Z",
            "recurrence_rule": "FREQ=DAILY;COUNT=3",
        }))
        .send()
        .await
        .expect("send create recurring appointment")
        .json()
        .await
        .expect("create recurring appointment JSON");
    let master_id = created["id"].as_str().expect("master id").to_string();

    // Window covers only the middle occurrence (Mar 3).
    let list: serde_json::Value = app
        .client
        .get(app.url("/api/v1/appointments?from=2026-03-03T00:00:00Z&to=2026-03-03T23:59:59Z"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send narrow range query")
        .json()
        .await
        .expect("narrow range query JSON");
    let data = list["data"].as_array().expect("data array");
    let instances: Vec<&serde_json::Value> = data
        .iter()
        .filter(|a| a["recurrence_parent_id"].as_str() == Some(master_id.as_str()))
        .collect();
    assert_eq!(
        instances.len(),
        1,
        "a one-day window must yield exactly one occurrence, got {data:?}"
    );
    assert_eq!(
        instances[0]["start_time"].as_str(),
        Some("2026-03-03T09:00:00Z")
    );
}

/// PMS-374: a `recurrence_rule` that is not a parseable RFC 5545 RRULE is
/// rejected with 422 and nothing is persisted. The follow-up range query
/// must surface no appointment at all (neither the master nor any expanded
/// occurrence), proving the create was a no-op.
#[sqlx::test]
async fn create_appointment_rejects_invalid_recurrence_rule(pool: PgPool) {
    let (admin_id, email, password) = seed_admin(&pool).await;
    let app = boot(pool).await;
    let token = login(&app, &email, &password).await;

    let resp = app
        .client
        .post(app.url("/api/v1/appointments"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "title": "Broken series",
            "assigned_to_id": admin_id,
            "start_time": "2026-03-02T09:00:00Z",
            "end_time": "2026-03-02T09:30:00Z",
            "recurrence_rule": "GARBAGE NOT A RULE",
        }))
        .send()
        .await
        .expect("send create with invalid recurrence_rule");
    assert_eq!(
        resp.status(),
        422,
        "a non-RFC-5545 recurrence_rule must be rejected with 422"
    );

    // Nothing was stored: a window spanning the would-be series is empty.
    let list: serde_json::Value = app
        .client
        .get(app.url("/api/v1/appointments?from=2026-03-01T00:00:00Z&to=2026-03-31T23:59:59Z"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send range query")
        .json()
        .await
        .expect("range query JSON");
    let data = list["data"].as_array().expect("range query data array");
    assert!(
        data.is_empty(),
        "no appointment may be persisted when the rule is rejected, got {data:?}"
    );
}

/// PMS-374: a valid RRULE is still accepted after the create-path guard is
/// added, and it expands as before. Guards against the validation rejecting
/// legitimate rules.
#[sqlx::test]
async fn create_appointment_accepts_valid_recurrence_rule(pool: PgPool) {
    let (admin_id, email, password) = seed_admin(&pool).await;
    let app = boot(pool).await;
    let token = login(&app, &email, &password).await;

    let resp = app
        .client
        .post(app.url("/api/v1/appointments"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "title": "Daily standup",
            "assigned_to_id": admin_id,
            "start_time": "2026-03-02T09:00:00Z",
            "end_time": "2026-03-02T09:30:00Z",
            "recurrence_rule": "FREQ=DAILY;COUNT=3",
        }))
        .send()
        .await
        .expect("send create with valid recurrence_rule");
    assert_eq!(
        resp.status(),
        200,
        "a valid RFC 5545 recurrence_rule must still be accepted"
    );
}

/// Time off can be approved and rejected through the approval endpoint.
/// Both transitions are manager-gated; the seeded super_admin qualifies.
#[sqlx::test]
async fn time_off_approve_and_reject(pool: PgPool) {
    let (admin_id, email, password) = seed_admin(&pool).await;
    let app = boot(pool).await;
    let token = login(&app, &email, &password).await;

    // Helper: create a pending time-off request for the admin.
    let create_time_off = |start: &str, end: &str| {
        let body = serde_json::json!({
            "user_id": admin_id,
            "start_date": start,
            "end_date": end,
            "type": "vacation",
        });
        app.client
            .post(app.url("/api/v1/time-off"))
            .bearer_auth(&token)
            .json(&body)
            .send()
    };

    // APPROVE path.
    let to_approve: serde_json::Value = create_time_off("2026-04-01", "2026-04-03")
        .await
        .expect("send create time-off (approve)")
        .json()
        .await
        .expect("create time-off JSON");
    assert_eq!(to_approve["status"].as_str(), Some("pending"));
    let approve_id = to_approve["id"].as_str().expect("time-off id");

    let approved: serde_json::Value = app
        .client
        .post(app.url(&format!("/api/v1/time-off/{approve_id}/approval")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "status": "approved" }))
        .send()
        .await
        .expect("send approve time-off")
        .json()
        .await
        .expect("approve time-off JSON");
    assert_eq!(
        approved["status"].as_str(),
        Some("approved"),
        "approval must flip status to approved"
    );
    assert_eq!(
        approved["approved_by_id"].as_str(),
        Some(admin_id.to_string().as_str()),
        "approval must record the approver"
    );

    // REJECT path (separate request so the approve assertion is clean).
    let to_reject: serde_json::Value = create_time_off("2026-05-01", "2026-05-02")
        .await
        .expect("send create time-off (reject)")
        .json()
        .await
        .expect("create time-off JSON");
    let reject_id = to_reject["id"].as_str().expect("time-off id");

    let rejected: serde_json::Value = app
        .client
        .post(app.url(&format!("/api/v1/time-off/{reject_id}/approval")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "status": "rejected" }))
        .send()
        .await
        .expect("send reject time-off")
        .json()
        .await
        .expect("reject time-off JSON");
    assert_eq!(
        rejected["status"].as_str(),
        Some("rejected"),
        "rejection must flip status to rejected"
    );
}

/// The dispatch board returns its four aggregated sections for a range,
/// and the appointments section reflects an expanded recurring series
/// plus a one-off booking, while approved time off shows up and pending
/// time off does not.
#[sqlx::test]
async fn dispatch_view_aggregates_the_range(pool: PgPool) {
    let (admin_id, email, password) = seed_admin(&pool).await;
    let app = boot(pool).await;
    let token = login(&app, &email, &password).await;

    // A recurring series (3 daily occurrences in the window).
    app.client
        .post(app.url("/api/v1/appointments"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "title": "Daily standup",
            "assigned_to_id": admin_id,
            "start_time": "2026-06-01T09:00:00Z",
            "end_time": "2026-06-01T09:15:00Z",
            "recurrence_rule": "FREQ=DAILY;COUNT=3",
        }))
        .send()
        .await
        .expect("create recurring appointment")
        .error_for_status()
        .expect("recurring appointment created");

    // An approved time-off (should appear) and a pending one (should not).
    let approved_to: serde_json::Value = app
        .client
        .post(app.url("/api/v1/time-off"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "user_id": admin_id,
            "start_date": "2026-06-10",
            "end_date": "2026-06-12",
            "type": "vacation",
        }))
        .send()
        .await
        .expect("create approved-bound time-off")
        .json()
        .await
        .expect("time-off JSON");
    let approved_to_id = approved_to["id"].as_str().expect("time-off id");
    app.client
        .post(app.url(&format!("/api/v1/time-off/{approved_to_id}/approval")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "status": "approved" }))
        .send()
        .await
        .expect("approve time-off")
        .error_for_status()
        .expect("time-off approved");

    // Pending time-off (never approved) - must be excluded from dispatch.
    app.client
        .post(app.url("/api/v1/time-off"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "user_id": admin_id,
            "start_date": "2026-06-20",
            "end_date": "2026-06-21",
            "type": "sick",
        }))
        .send()
        .await
        .expect("create pending time-off")
        .error_for_status()
        .expect("pending time-off created");

    let body: serde_json::Value = app
        .client
        .get(app.url("/api/v1/dispatch?from=2026-06-01T00:00:00Z&to=2026-06-30T23:59:59Z"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send dispatch query")
        .json()
        .await
        .expect("dispatch JSON");

    // All four sections present.
    for section in ["appointments", "availability", "time_off", "on_call"] {
        assert!(
            body[section].is_array(),
            "dispatch must carry array `{section}`, got {body}"
        );
    }

    // Recurring series expanded into the appointments section.
    let appts = body["appointments"].as_array().expect("appointments array");
    let occurrences = appts
        .iter()
        .filter(|a| a["title"].as_str() == Some("Daily standup"))
        .count();
    assert_eq!(
        occurrences, 3,
        "dispatch appointments must include the 3 expanded occurrences, got {appts:?}"
    );

    // Approved time off appears; pending does not.
    let tos = body["time_off"].as_array().expect("time_off array");
    assert_eq!(
        tos.len(),
        1,
        "only the approved time-off must appear in dispatch, got {tos:?}"
    );
    assert_eq!(tos[0]["status"].as_str(), Some("approved"));
    assert_eq!(tos[0]["id"].as_str(), Some(approved_to_id));
}

// ============================================================================
// PMS-791 phase 3 / MAPPS-464: appointments carry team_id
// ============================================================================

/// PMS-791 phase 3: an appointment created with `team_id` set persists the
/// column; readback + list response both surface it. Pre-phase-3 this
/// column existed (migration 008) but no writer populated it.
#[sqlx::test]
async fn create_appointment_with_team_id_persists(pool: PgPool) {
    let (admin_id, email, password) = seed_admin(&pool).await;
    let team_id = seed_team(
        &pool,
        common::DEFAULT_TENANT_ID,
        "Field Techs",
        Some(admin_id),
    )
    .await;
    let app = boot(pool.clone()).await;
    let token = login(&app, &email, &password).await;

    let created: serde_json::Value = app
        .client
        .post(app.url("/api/v1/appointments"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "title": "Team-routed visit",
            "assigned_to_id": admin_id,
            "start_time": "2026-03-02T09:00:00Z",
            "end_time": "2026-03-02T10:00:00Z",
            "team_id": team_id,
        }))
        .send()
        .await
        .expect("send create")
        .json()
        .await
        .expect("create json");
    assert_eq!(
        created["team_id"].as_str(),
        Some(team_id.to_string().as_str()),
        "created appointment carries team_id"
    );

    let stored: Option<Uuid> =
        sqlx::query_scalar("SELECT team_id FROM appointments WHERE id = $1::uuid")
            .bind(created["id"].as_str().unwrap())
            .fetch_one(&pool)
            .await
            .expect("read team_id back from db");
    assert_eq!(
        stored,
        Some(team_id),
        "team_id persisted on the appointments row"
    );
}

/// PMS-791 phase 3 (F1 mirror): an appointment created with a `team_id`
/// belonging to another tenant is rejected 400, mirroring the ticket-side
/// PMS-406 pattern. The `validate_fk_opt(tenant_id, "teams", ...)` guard
/// in CalendarService::create_appointment is what catches it.
#[sqlx::test]
async fn create_appointment_with_wrong_tenant_team_id_returns_400(pool: PgPool) {
    let (admin_id, email, password) = seed_admin(&pool).await;
    // Team lives in a DIFFERENT tenant.
    let (tenant_b, _uid, _e, _p) = seed_tenant_with_admin(&pool, "wrong-tenant-appt-team").await;
    let stranger_team = seed_team(&pool, tenant_b, "Foreign Team", None).await;
    let app = boot(pool).await;
    let token = login(&app, &email, &password).await;

    let resp = app
        .client
        .post(app.url("/api/v1/appointments"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "title": "Should not persist",
            "assigned_to_id": admin_id,
            "start_time": "2026-03-02T09:00:00Z",
            "end_time": "2026-03-02T10:00:00Z",
            "team_id": stranger_team,
        }))
        .send()
        .await
        .expect("send create");
    assert_eq!(
        resp.status().as_u16(),
        400,
        "cross-tenant team_id must be rejected"
    );
}

/// PMS-791 phase 3: an update carrying `team_id` reassigns the
/// appointment to the new team. COALESCE semantics: omitting the field
/// leaves the stored team unchanged; sending a value overwrites.
#[sqlx::test]
async fn update_appointment_with_team_id_reassigns(pool: PgPool) {
    let (admin_id, email, password) = seed_admin(&pool).await;
    let team_a = seed_team(&pool, common::DEFAULT_TENANT_ID, "Alpha team", None).await;
    let team_b = seed_team(&pool, common::DEFAULT_TENANT_ID, "Bravo team", None).await;
    let app = boot(pool.clone()).await;
    let token = login(&app, &email, &password).await;

    // Create with team A.
    let created: serde_json::Value = app
        .client
        .post(app.url("/api/v1/appointments"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "title": "Reassign me",
            "assigned_to_id": admin_id,
            "start_time": "2026-03-02T09:00:00Z",
            "end_time": "2026-03-02T10:00:00Z",
            "team_id": team_a,
        }))
        .send()
        .await
        .expect("create")
        .json()
        .await
        .unwrap();
    let appt_id = created["id"].as_str().unwrap();

    // Reassign to team B.
    let resp = app
        .client
        .put(app.url(&format!("/api/v1/appointments/{appt_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "team_id": team_b }))
        .send()
        .await
        .expect("update");
    assert!(resp.status().is_success(), "update must succeed");

    let stored: Uuid = sqlx::query_scalar("SELECT team_id FROM appointments WHERE id = $1::uuid")
        .bind(appt_id)
        .fetch_one(&pool)
        .await
        .expect("read team_id after update");
    assert_eq!(stored, team_b, "team_id reassigned to team B");
}

/// PMS-791 phase 4 / MAPPS-465: list appointments filtered by team_id.
/// Only rows whose team_id matches are returned; NULL-team rows are
/// excluded when the filter is set.
#[sqlx::test]
async fn list_appointments_filtered_by_team_id(pool: PgPool) {
    let (admin_id, email, password) = seed_admin(&pool).await;
    let team_a = seed_team(&pool, common::DEFAULT_TENANT_ID, "Filter A", None).await;
    let team_b = seed_team(&pool, common::DEFAULT_TENANT_ID, "Filter B", None).await;
    let app = boot(pool).await;
    let token = login(&app, &email, &password).await;

    for (title, team) in [
        ("A-visit", Some(team_a)),
        ("B-visit", Some(team_b)),
        ("no-team", None),
    ] {
        let body = serde_json::json!({
            "title": title,
            "assigned_to_id": admin_id,
            "start_time": "2026-04-01T09:00:00Z",
            "end_time": "2026-04-01T10:00:00Z",
            "team_id": team,
        });
        let resp = app
            .client
            .post(app.url("/api/v1/appointments"))
            .bearer_auth(&token)
            .json(&body)
            .send()
            .await
            .expect("create");
        assert!(resp.status().is_success(), "seed {title}");
    }

    let list: serde_json::Value = app
        .client
        .get(app.url(&format!("/api/v1/appointments?team_id={team_a}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send list")
        .json()
        .await
        .expect("list json");
    let data = list["data"].as_array().expect("data array");
    assert!(
        data.iter().any(|a| a["title"].as_str() == Some("A-visit")),
        "team A appointment must appear: {data:?}"
    );
    assert!(
        !data.iter().any(|a| a["title"].as_str() == Some("B-visit")),
        "team B appointment must NOT appear: {data:?}"
    );
    assert!(
        !data.iter().any(|a| a["title"].as_str() == Some("no-team")),
        "null-team appointment must NOT appear when a specific team is filtered: {data:?}"
    );
}
