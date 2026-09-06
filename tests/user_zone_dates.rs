//! PMS-1027 / PMS-1028: a day that defaults to "today" is today where the
//! person is, and an invoice that names no currency is issued in the
//! tenant's.
//!
//! The zone tests use two users 26 hours apart, `Pacific/Kiritimati` (+14)
//! and `Etc/GMT+12` (-12): at any instant at least one of them is on a
//! different calendar day from UTC, so a test that asserts each user
//! against `user_today` for their zone AND one of them against UTC cannot
//! pass on the UTC rule. Each assertion tolerates the request crossing a
//! day boundary by accepting `user_today` at both ends of the call.

mod common;

use chrono::{DateTime, NaiveDate, Utc};
use mokosh_types::datetime::user_today;
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

const EAST: &str = "Pacific/Kiritimati";
const WEST: &str = "Etc/GMT+12";

async fn set_zone(pool: &PgPool, user_id: Uuid, zone: &str) {
    sqlx::query("UPDATE users SET timezone = $2 WHERE id = $1")
        .bind(user_id)
        .bind(zone)
        .execute(pool)
        .await
        .expect("set the user's zone");
}

/// The dates `user_today` could have produced for `zone` during a call that
/// began at `before` and has just returned.
fn expected(before: DateTime<Utc>, zone: &str) -> Vec<NaiveDate> {
    let mut v = vec![user_today(before, zone), user_today(Utc::now(), zone)];
    v.dedup();
    v
}

fn date(v: &Value) -> NaiveDate {
    v.as_str()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("a date, got {v}"))
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

async fn seed_ready_entry(pool: &PgPool, user_id: Uuid, company_id: Uuid, work_type_id: Uuid) {
    sqlx::query(
        "INSERT INTO time_entries (id, tenant_id, user_id, date, duration_minutes, work_type_id, \
         company_id, is_billable, billing_status, hourly_rate, total_amount) \
         VALUES ($1, $2, $3, '2026-06-15', 60, $4, $5, TRUE, 'ready_to_bill', 100, 100)",
    )
    .bind(Uuid::new_v4())
    .bind(common::DEFAULT_TENANT_ID)
    .bind(user_id)
    .bind(work_type_id)
    .bind(company_id)
    .execute(pool)
    .await
    .expect("seed a billable entry");
}

async fn post(app: &common::TestApp, token: &str, path: &str, body: Value) -> Value {
    let response = app
        .client
        .post(app.url(path))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .expect("post");
    assert!(
        response.status().is_success(),
        "POST {path}: {} {:?}",
        response.status(),
        response.text().await
    );
    response.json().await.expect("json")
}

/// One admin in each zone; returns `(id, token)` pairs, east then west.
async fn two_admins(pool: &PgPool, app_pool: PgPool) -> (common::TestApp, [(Uuid, String); 2]) {
    let (east_id, east_email, east_password) = common::seed_admin(pool).await;
    let (west_id, west_email, west_password) =
        common::seed_user(pool, common::DEFAULT_TENANT_ID, "west@example.com", "admin").await;
    set_zone(pool, east_id, EAST).await;
    set_zone(pool, west_id, WEST).await;
    let app = common::boot(app_pool).await;
    let east = common::login(&app, &east_email, &east_password).await;
    let west = common::login(&app, &west_email, &west_password).await;
    (app, [(east_id, east), (west_id, west)])
}

/// An invoice built from time entries with no `invoice_date` is dated today
/// where the finance user is, and the PMS-990 due date counts from there.
#[sqlx::test]
async fn an_invoice_from_time_entries_is_dated_on_the_users_day(pool: PgPool) {
    let (app, users) = two_admins(&pool, pool.clone()).await;
    let mut dates = Vec::new();
    for ((user_id, token), zone) in users.iter().zip([EAST, WEST]) {
        let company_id = common::seed_company_named(&pool, &format!("Client {zone}")).await;
        let work_type_id = work_type(&app, token).await;
        seed_ready_entry(&pool, *user_id, company_id, work_type_id).await;
        let before = Utc::now();
        let invoice = post(
            &app,
            token,
            "/api/v1/invoices/from-time-entries",
            json!({ "company_id": company_id }),
        )
        .await;
        let invoice_date = date(&invoice["invoice_date"]);
        assert!(
            expected(before, zone).contains(&invoice_date),
            "{zone}: {invoice_date} not in {:?}",
            expected(before, zone)
        );
        // Net 30 from the corrected date, not from UTC's.
        assert_eq!(
            date(&invoice["due_date"]),
            invoice_date + chrono::Duration::days(30)
        );
        dates.push(invoice_date);
    }
    let utc = user_today(Utc::now(), "UTC");
    assert!(
        dates.iter().any(|d| *d != utc),
        "{dates:?} are both UTC's {utc}; the zone was not read"
    );
}

/// A credit note with no `issue_date` is issued today where the user is.
#[sqlx::test]
async fn a_credit_note_is_issued_on_the_users_day(pool: PgPool) {
    let (app, users) = two_admins(&pool, pool.clone()).await;
    let mut dates = Vec::new();
    for ((_, token), zone) in users.iter().zip([EAST, WEST]) {
        let company_id = common::seed_company_named(&pool, &format!("Client {zone}")).await;
        common::seed_billing_contact(&pool, company_id).await;
        let invoice = post(
            &app,
            token,
            "/api/v1/invoices",
            json!({
                "company_id": company_id,
                "invoice_date": "2026-08-01",
                "due_date": "2026-08-31",
                "lines": [{ "line_type": "service", "description": "August", "quantity": "1", "unit_price": "100" }],
            }),
        )
        .await;
        let invoice_id = invoice["id"].as_str().expect("invoice id");
        let sent = app
            .client
            .put(app.url(&format!("/api/v1/invoices/{invoice_id}")))
            .bearer_auth(token)
            .json(&json!({ "status": "sent", "skip_email": true }))
            .send()
            .await
            .expect("send the invoice");
        assert!(sent.status().is_success(), "{:?}", sent.text().await);
        let before = Utc::now();
        let note = post(
            &app,
            token,
            "/api/v1/credit-notes",
            json!({
                "invoice_id": invoice_id,
                "reason": "Billed a cancelled month",
                "lines": [{ "line_type": "adjustment", "description": "August", "quantity": "1", "unit_price": "40" }],
            }),
        )
        .await;
        let issue_date = date(&note["issue_date"]);
        assert!(
            expected(before, zone).contains(&issue_date),
            "{zone}: {issue_date} not in {:?}",
            expected(before, zone)
        );
        dates.push(issue_date);
    }
    let utc = user_today(Utc::now(), "UTC");
    assert!(
        dates.iter().any(|d| *d != utc),
        "{dates:?} are both UTC's {utc}"
    );
}

/// A stopped timer's entry is dated by the day it is where the timer's
/// owner is.
#[sqlx::test]
async fn a_stopped_timer_is_dated_on_its_owners_day(pool: PgPool) {
    let (app, users) = two_admins(&pool, pool.clone()).await;
    let mut dates = Vec::new();
    for ((_, token), zone) in users.iter().zip([EAST, WEST]) {
        let company_id = common::seed_company_named(&pool, &format!("Client {zone}")).await;
        let work_type_id = work_type(&app, token).await;
        let timer = post(
            &app,
            token,
            "/api/v1/timers/start",
            json!({ "company_id": company_id, "work_type_id": work_type_id }),
        )
        .await;
        let timer_id = timer["id"].as_str().expect("timer id");
        let before = Utc::now();
        let entry = post(
            &app,
            token,
            &format!("/api/v1/timers/{timer_id}/stop"),
            json!({}),
        )
        .await;
        let entry_date = date(&entry["date"]);
        assert!(
            expected(before, zone).contains(&entry_date),
            "{zone}: {entry_date} not in {:?}",
            expected(before, zone)
        );
        dates.push(entry_date);
    }
    let utc = user_today(Utc::now(), "UTC");
    assert!(
        dates.iter().any(|d| *d != utc),
        "{dates:?} are both UTC's {utc}"
    );
}

/// Read-time expiry compares `valid_until` with the READER's day. Two
/// quotes: one valid through UTC's today (the east reader is already past it
/// from 10:00 UTC), one valid through UTC's yesterday (the west reader is
/// still on it until 12:00 UTC). Between them, at every hour of the day at
/// least one verdict differs from the UTC rule's.
#[sqlx::test]
async fn a_quote_expires_on_the_readers_day(pool: PgPool) {
    let (app, [(_, east), (_, west)]) = two_admins(&pool, pool.clone()).await;
    let company_id = common::seed_company(&pool).await;
    let utc = user_today(Utc::now(), "UTC");

    let mut quote_ids = Vec::new();
    for _ in 0..2 {
        let quote = post(
            &app,
            &east,
            "/api/v1/quotes",
            json!({
                "company_id": company_id,
                "title": "Network build",
                "lines": [{ "line_type": "service", "description": "Build", "quantity": "1", "unit_price": "500" }],
            }),
        )
        .await;
        quote_ids.push(Uuid::parse_str(quote["id"].as_str().expect("quote id")).expect("uuid"));
    }
    for (quote_id, until) in quote_ids.iter().zip([utc, utc - chrono::Duration::days(1)]) {
        sqlx::query("UPDATE quotes SET status = 'sent', valid_until = $2 WHERE id = $1")
            .bind(quote_id)
            .bind(until)
            .execute(&pool)
            .await
            .expect("send the quote with a validity");
    }

    let mut disagreed_with_utc = false;
    for (quote_id, until) in quote_ids.iter().zip([utc, utc - chrono::Duration::days(1)]) {
        for (token, zone) in [(&east, EAST), (&west, WEST)] {
            let before = Utc::now();
            let response = app
                .client
                .get(app.url(&format!("/api/v1/quotes/{quote_id}")))
                .bearer_auth(token)
                .send()
                .await
                .expect("read the quote");
            assert_eq!(response.status(), 200, "{:?}", response.text().await);
            let quote: Value = response.json().await.expect("quote json");
            let status = quote["status"].as_str().expect("status");
            let verdicts: Vec<&str> = expected(before, zone)
                .into_iter()
                .map(|today| if until < today { "expired" } else { "sent" })
                .collect();
            assert!(
                verdicts.contains(&status),
                "{zone} reading a quote valid through {until}: {status}, expected one of {verdicts:?}"
            );
            let utc_verdict = if until < utc { "expired" } else { "sent" };
            if status != utc_verdict {
                disagreed_with_utc = true;
            }
        }
    }
    assert!(
        disagreed_with_utc,
        "every verdict matched the UTC rule; the reader's zone was not read"
    );
}

/// An invoice that names no currency is issued in the tenant's default,
/// and one that names a currency keeps it.
#[sqlx::test]
async fn an_invoice_is_issued_in_the_tenants_default_currency(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let company_id = common::seed_company(&pool).await;
    let work_type_id = work_type(&app, &token).await;

    let invoice_body = |extra: Value| {
        let mut body = json!({
            "company_id": company_id,
            "invoice_date": "2026-08-01",
            "due_date": "2026-08-31",
            "lines": [{ "line_type": "service", "description": "August", "quantity": "1", "unit_price": "100" }],
        });
        body.as_object_mut()
            .unwrap()
            .extend(extra.as_object().cloned().unwrap_or_default());
        body
    };

    // Nothing configured: USD, as every writer hardcoded before.
    let before = post(&app, &token, "/api/v1/invoices", invoice_body(json!({}))).await;
    assert_eq!(before["currency"], "USD");

    sqlx::query(
        "INSERT INTO tenant_settings (tenant_id, category, key, value) \
         VALUES ($1, 'billing_prefs', 'currency', '\"CAD\"'::jsonb)",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .execute(&pool)
    .await
    .expect("set the default currency");

    let plain = post(&app, &token, "/api/v1/invoices", invoice_body(json!({}))).await;
    assert_eq!(plain["currency"], "CAD", "the setting is read");
    let named = post(
        &app,
        &token,
        "/api/v1/invoices",
        invoice_body(json!({ "currency": "EUR" })),
    )
    .await;
    assert_eq!(named["currency"], "EUR", "an explicit currency still wins");

    seed_ready_entry(&pool, admin_id, company_id, work_type_id).await;
    let from_time = post(
        &app,
        &token,
        "/api/v1/invoices/from-time-entries",
        json!({ "company_id": company_id }),
    )
    .await;
    assert_eq!(
        from_time["currency"], "CAD",
        "the time-entry writer reads it too"
    );
}
