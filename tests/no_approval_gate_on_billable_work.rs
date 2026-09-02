//! PMS-944: billable client work reaches an invoice because it was logged.
//!
//! PMS-144 made weekly timesheet approval the billing gate, and it was the only
//! thing in the codebase that ever armed a time entry. David's objection is
//! that approval was being applied where it has no meaning: the rate and the
//! estimate were agreed before the work started, so the client has already
//! said yes, and on a one-person MSP the flow degenerates to submitting to
//! yourself.
//!
//! What these pin is the seam that leaves behind. An entry is armed by the
//! entry's own facts, approval keeps a lifecycle that no longer touches
//! billing, and the one surviving way to ask for sign-off on a unit of work
//! lives where timesheets do. The billable toggle gets its own case because it
//! is the way the new rule can go wrong in the expensive direction: an entry
//! that keeps the `ready_to_bill` it was created with after being marked
//! non-billable is one that gets charged to a client anyway.

mod common;

use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

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

/// The first active work type, which the seed migration supplies.
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

async fn log_time(
    app: &common::TestApp,
    token: &str,
    user_id: Uuid,
    company_id: Uuid,
    work_type_id: Uuid,
    billable: bool,
) -> Value {
    let response = app
        .client
        .post(app.url("/api/v1/time-entries"))
        .bearer_auth(token)
        .json(&json!({
            "user_id": user_id,
            "company_id": company_id,
            "work_type_id": work_type_id,
            "date": "2026-06-15",
            "duration_minutes": 60,
            "is_billable": billable,
            "hourly_rate": "150.00",
        }))
        .send()
        .await
        .expect("create time entry");
    assert_eq!(response.status(), 200, "{:?}", response.text().await);
    response.json().await.expect("entry json")
}

async fn billing_status(pool: &PgPool, entry_id: Uuid) -> String {
    sqlx::query_scalar::<_, String>("SELECT billing_status FROM time_entries WHERE id = $1")
        .bind(entry_id)
        .fetch_one(pool)
        .await
        .expect("read billing_status")
}

fn id_of(entry: &Value) -> Uuid {
    Uuid::parse_str(entry["id"].as_str().expect("entry id")).expect("entry uuid")
}

/// A billable entry is invoiceable the moment it exists. Before PMS-944 this
/// row sat at the `not_billed` default until somebody countersigned the week.
#[sqlx::test]
async fn a_billable_entry_is_armed_at_creation(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let work_type_id = work_type(&app, &token).await;

    let entry = log_time(&app, &token, admin_id, company_id, work_type_id, true).await;
    assert_eq!(entry["billing_status"], "ready_to_bill", "{entry}");
    // The approval lifecycle is untouched and still starts unsubmitted. It is
    // simply no longer what decides whether the entry can be billed.
    assert_eq!(entry["approval_status"], "draft", "{entry}");
}

/// Non-billable time is not armed, so the write is a decision about the entry
/// rather than a flag set on everything.
#[sqlx::test]
async fn a_non_billable_entry_is_not_armed(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let work_type_id = work_type(&app, &token).await;

    let entry = log_time(&app, &token, admin_id, company_id, work_type_id, false).await;
    assert_eq!(entry["billing_status"], "not_billed", "{entry}");
}

/// A stopped timer is time that was worked, so it is billed on the same terms
/// as time typed in. It has its own INSERT, which is how it could have been
/// missed.
#[sqlx::test]
async fn a_stopped_timer_is_armed_the_same_way(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let work_type_id = work_type(&app, &token).await;

    let started: Value = app
        .client
        .post(app.url("/api/v1/timers/start"))
        .bearer_auth(&token)
        .json(&json!({
            "user_id": admin_id,
            "company_id": company_id,
            "work_type_id": work_type_id,
        }))
        .send()
        .await
        .expect("start a timer")
        .json()
        .await
        .expect("timer json");
    let timer_id = started["id"].as_str().expect("timer id");

    let stopped = app
        .client
        .post(app.url(&format!("/api/v1/timers/{timer_id}/stop")))
        .bearer_auth(&token)
        .json(&json!({}))
        .send()
        .await
        .expect("stop the timer");
    assert_eq!(stopped.status(), 200, "{:?}", stopped.text().await);
    let entry: Value = stopped.json().await.expect("entry json");
    assert_eq!(entry["entry_kind"], "client", "{entry}");
    assert_eq!(entry["billing_status"], "ready_to_bill", "{entry}");
}

/// The expensive direction. Marking an entry non-billable has to take it back
/// out of the invoiceable set; leaving it armed would charge the client for
/// work somebody had just decided not to charge for.
#[sqlx::test]
async fn making_an_entry_non_billable_disarms_it(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let work_type_id = work_type(&app, &token).await;

    let entry = log_time(&app, &token, admin_id, company_id, work_type_id, true).await;
    let entry_id = id_of(&entry);

    let updated = app
        .client
        .put(app.url(&format!("/api/v1/time-entries/{entry_id}")))
        .bearer_auth(&token)
        .json(&json!({ "is_billable": false }))
        .send()
        .await
        .expect("mark it non-billable");
    assert_eq!(updated.status(), 200, "{:?}", updated.text().await);
    assert_eq!(billing_status(&pool, entry_id).await, "not_billed");

    // And back again, because a correction in either direction is ordinary.
    let updated = app
        .client
        .put(app.url(&format!("/api/v1/time-entries/{entry_id}")))
        .bearer_auth(&token)
        .json(&json!({ "is_billable": true }))
        .send()
        .await
        .expect("mark it billable again");
    assert_eq!(updated.status(), 200, "{:?}", updated.text().await);
    assert_eq!(billing_status(&pool, entry_id).await, "ready_to_bill");
}

/// An entry that is already on an invoice keeps `billed` whatever else changes.
/// Re-arming it would put the same work on a second invoice, which is the one
/// mistake in this area that reaches the client as money.
#[sqlx::test]
async fn an_invoiced_entry_is_never_re_armed(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let work_type_id = work_type(&app, &token).await;

    let entry = log_time(&app, &token, admin_id, company_id, work_type_id, true).await;
    let entry_id = id_of(&entry);

    let invoice = app
        .client
        .post(app.url("/api/v1/invoices/from-time-entries"))
        .bearer_auth(&token)
        .json(&json!({ "company_id": company_id }))
        .send()
        .await
        .expect("generate the invoice");
    assert_eq!(invoice.status(), 200, "{:?}", invoice.text().await);
    assert_eq!(billing_status(&pool, entry_id).await, "billed");

    // Edit it afterwards. The status must not move off `billed` in either
    // direction.
    for billable in [false, true] {
        let updated = app
            .client
            .put(app.url(&format!("/api/v1/time-entries/{entry_id}")))
            .bearer_auth(&token)
            .json(&json!({ "is_billable": billable }))
            .send()
            .await
            .expect("edit an invoiced entry");
        assert_eq!(updated.status(), 200, "{:?}", updated.text().await);
        assert_eq!(
            billing_status(&pool, entry_id).await,
            "billed",
            "an invoiced entry must stay billed (is_billable={billable})"
        );
    }
}

/// The one-person case David described. Timesheets off, so there is no submit
/// and no approve to reach for, and the hour still becomes an invoice.
#[sqlx::test]
async fn a_tenant_with_timesheets_off_can_still_invoice(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    set_flag(&pool, false).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let work_type_id = work_type(&app, &token).await;

    log_time(&app, &token, admin_id, company_id, work_type_id, true).await;

    // Submitting is not merely unnecessary, it is unreachable (PMS-943).
    let submit = app
        .client
        .post(app.url(&format!("/api/v1/timesheets/{admin_id}/2026-06-15/submit")))
        .bearer_auth(&token)
        .json(&json!({}))
        .send()
        .await
        .expect("try to submit a timesheet");
    assert_eq!(submit.status(), 404);

    let invoice = app
        .client
        .post(app.url("/api/v1/invoices/from-time-entries"))
        .bearer_auth(&token)
        .json(&json!({ "company_id": company_id }))
        .send()
        .await
        .expect("generate the invoice");
    assert_eq!(invoice.status(), 200, "{:?}", invoice.text().await);
    let body: Value = invoice.json().await.expect("invoice json");
    assert_eq!(body["subtotal"], "150.00", "{body}");
}

/// Approval still exists where timesheets do, and it still moves the entry
/// through its own lifecycle. What it must not do any more is touch billing:
/// the entry was already armed, and approving is not what armed it.
#[sqlx::test]
async fn approval_still_runs_and_no_longer_touches_billing(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    set_flag(&pool, true).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let work_type_id = work_type(&app, &token).await;

    let entry = log_time(&app, &token, admin_id, company_id, work_type_id, false).await;
    let entry_id = id_of(&entry);
    assert_eq!(billing_status(&pool, entry_id).await, "not_billed");

    for step in ["submit", "approve"] {
        let response = app
            .client
            .post(app.url(&format!("/api/v1/timesheets/{admin_id}/2026-06-15/{step}")))
            .bearer_auth(&token)
            .json(&json!({}))
            .send()
            .await
            .expect("run a timesheet step");
        assert_eq!(
            response.status(),
            200,
            "{step}: {:?}",
            response.text().await
        );
    }

    let approved: Value = app
        .client
        .get(app.url(&format!("/api/v1/time-entries/{entry_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("read the entry back")
        .json()
        .await
        .expect("entry json");
    assert_eq!(approved["approval_status"], "approved", "{approved}");
    // The gate PMS-144 built: this used to become `ready_to_bill` here, which
    // would have made a non-billable entry invoiceable had `is_billable` been
    // true, and made approval the only route to an invoice regardless.
    assert_eq!(
        billing_status(&pool, entry_id).await,
        "not_billed",
        "approving must not arm an entry"
    );
}

/// Approving a unit of work is an employee-facing control, so on a tenant with
/// timesheets off it is answered the way a nonexistent route is - not an empty
/// list, which reads as a feature that is present and unused.
#[sqlx::test]
async fn time_entry_approvals_are_gone_when_timesheets_are_off(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    set_flag(&pool, false).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let work_type_id = work_type(&app, &token).await;

    let entry = log_time(&app, &token, admin_id, company_id, work_type_id, true).await;
    let entry_id = id_of(&entry);
    let path = format!("/api/v1/time-entries/{entry_id}/approvals");

    let listed = app
        .client
        .get(app.url(&path))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list approvals on an entry");
    assert_eq!(listed.status(), 404);

    let created = app
        .client
        .post(app.url(&path))
        .bearer_auth(&token)
        .json(&json!({ "approver_role": "admin" }))
        .send()
        .await
        .expect("request approval on an entry");
    assert_eq!(created.status(), 404);
}

/// A quote approves a DECISION, not a unit of work, and a client signing one
/// off has nothing to do with employment. It must keep working with timesheets
/// off, or this change has removed the wrong thing.
#[sqlx::test]
async fn quote_approvals_survive_timesheets_being_off(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    set_flag(&pool, false).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    // An id that resolves to no quote. The point is which error comes back: 404
    // "Quote not found" from the parent check is the route working, whereas the
    // flag would have refused before reaching it.
    let path = format!("/api/v1/quotes/{}/approvals", Uuid::new_v4());
    let listed = app
        .client
        .get(app.url(&path))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list approvals on a quote");
    assert_eq!(listed.status(), 404);
    let body: Value = listed.json().await.expect("error json");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("Quote"),
        "the quote route must answer for itself, not be gated away: {body}"
    );
}

/// Migration 121 releases the hours the old gate is holding. The UPDATE is read
/// out of the migration file rather than restated, so this cannot pass against
/// a statement that says something else.
#[sqlx::test]
async fn the_migration_releases_held_client_time(pool: PgPool) {
    let (admin_id, _email, _password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;

    // Four rows in the states the gate left behind, plus the two the migration
    // must not touch.
    let cases: [(&str, bool, bool, &str); 5] = [
        // (label, billable, invoiced, starting billing_status)
        ("held_draft", true, false, "not_billed"),
        ("held_pending", true, false, "not_billed"),
        ("written_off", false, false, "not_billed"),
        ("already_billed", true, true, "billed"),
        ("already_armed", true, false, "ready_to_bill"),
    ];
    let mut ids = Vec::new();
    for (label, billable, invoiced, status) in cases {
        let id = Uuid::new_v4();
        sqlx::query(
            r#"
            INSERT INTO time_entries (
                id, tenant_id, user_id, date, duration_minutes, work_type_id,
                company_id, is_billable, billing_status, approval_status,
                invoice_id, notes
            )
            SELECT $1, $2, $3, CURRENT_DATE, 60,
                   (SELECT id FROM work_types WHERE tenant_id = $2 LIMIT 1),
                   $4, $5, $6, 'draft',
                   CASE WHEN $7 THEN $1 ELSE NULL END, $8
            "#,
        )
        .bind(id)
        .bind(common::DEFAULT_TENANT_ID)
        .bind(admin_id)
        .bind(company_id)
        .bind(billable)
        .bind(status)
        .bind(invoiced)
        .bind(label)
        .execute(&pool)
        .await
        .expect("seed a pre-migration entry");
        ids.push((label, id));
    }

    // An employee entry, which must stay unbillable however it is stored: this
    // is the PMS-942 line the migration is not allowed to cross.
    let employee_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO time_entries (
            id, tenant_id, user_id, date, duration_minutes, work_type_id,
            company_id, entry_kind, is_billable, billing_status, approval_status
        )
        SELECT $1, $2, $3, CURRENT_DATE, 60,
               (SELECT id FROM work_types WHERE tenant_id = $2 LIMIT 1),
               NULL, 'employee', TRUE, 'not_billed', 'draft'
        "#,
    )
    .bind(employee_id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(admin_id)
    .execute(&pool)
    .await
    .expect("seed an employee entry");

    // Re-run the migration's own statement. `--` comment lines are stripped
    // before splitting on `;` because the prose in them contains semicolons.
    let sql = include_str!("../migrations/121_release_time_held_by_approval.sql");
    let statements: Vec<String> = sql
        .lines()
        .filter(|line| !line.trim_start().starts_with("--"))
        .collect::<Vec<_>>()
        .join("\n")
        .split(';')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    assert_eq!(statements.len(), 1, "migration 121 is one UPDATE");
    sqlx::query(&statements[0])
        .execute(&pool)
        .await
        .expect("re-run migration 121");

    let expected = [
        ("held_draft", "ready_to_bill"),
        ("held_pending", "ready_to_bill"),
        ("written_off", "not_billed"),
        ("already_billed", "billed"),
        ("already_armed", "ready_to_bill"),
    ];
    for (label, want) in expected {
        let id = ids
            .iter()
            .find(|(l, _)| *l == label)
            .map(|(_, id)| *id)
            .expect("seeded label");
        assert_eq!(
            billing_status(&pool, id).await,
            want,
            "{label} must end at {want}"
        );
    }
    assert_eq!(
        billing_status(&pool, employee_id).await,
        "not_billed",
        "employee time bills nobody, whatever its columns say"
    );

    // Approval state is deliberately untouched: releasing the hours must not
    // fabricate an approval nobody gave.
    let approvals: Vec<String> =
        sqlx::query_scalar("SELECT approval_status FROM time_entries WHERE tenant_id = $1")
            .bind(common::DEFAULT_TENANT_ID)
            .fetch_all(&pool)
            .await
            .expect("read approval states");
    assert!(
        approvals.iter().all(|s| s == "draft"),
        "the migration must not touch approval_status: {approvals:?}"
    );
}
