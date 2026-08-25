//! PMS-926: the preview reports the rules the delete enforces.
//!
//! It exists because the SPA was keeping its own English copy of which tables
//! block a company delete, and that copy went stale the moment PMS-919 changed
//! them: the dialog still warned about projects, appointments and sub-companies
//! long after those started unlinking instead of blocking.
//!
//! So the property that matters is not the response shape, it is agreement:
//! `can_delete` has to predict what the delete actually does, in both
//! directions. A preview that says "safe" and then fails is worse than no
//! preview, because the user typed the company name on the strength of it.

mod common;

use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_company_named(pool: &PgPool, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(common::DEFAULT_TENANT_ID)
        .bind(name)
        .execute(pool)
        .await
        .expect("seed company");
    id
}

async fn preview(app: &common::TestApp, token: &str, company: Uuid) -> (u16, Value) {
    let resp = app
        .client
        .get(app.url(&format!(
            "/api/v1/contacts/companies/{company}/deletion-preview"
        )))
        .bearer_auth(token)
        .send()
        .await
        .expect("preview request");
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(Value::Null))
}

async fn try_delete(app: &common::TestApp, token: &str, company: Uuid) -> u16 {
    app.client
        .delete(app.url(&format!("/api/v1/contacts/companies/{company}")))
        .bearer_auth(token)
        .send()
        .await
        .expect("delete request")
        .status()
        .as_u16()
}

/// Labels in the `blocking` array.
fn blocking_labels(body: &Value) -> Vec<String> {
    body["blocking"]
        .as_array()
        .map(|rows| {
            rows.iter()
                .map(|r| r["label"].as_str().unwrap_or_default().to_string())
                .collect()
        })
        .unwrap_or_default()
}

/// AC3, and the whole point. `can_delete` predicts the outcome, both ways.
#[sqlx::test]
async fn can_delete_predicts_what_the_delete_actually_does(pool: PgPool) {
    let (_id, email, password) = common::seed_admin(&pool).await;
    let clean = seed_company_named(&pool, "Clean Co").await;
    let blocked = seed_company_named(&pool, "Invoiced Co").await;
    sqlx::query(
        "INSERT INTO invoices (tenant_id, company_id, invoice_number, invoice_date, due_date) \
         VALUES ($1, $2, 'INV-9001', CURRENT_DATE, CURRENT_DATE + 30)",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(blocked)
    .execute(&pool)
    .await
    .expect("seed invoice");

    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let (_, clean_body) = preview(&app, &token, clean).await;
    assert_eq!(clean_body["can_delete"], true, "{clean_body}");
    let (_, blocked_body) = preview(&app, &token, blocked).await;
    assert_eq!(blocked_body["can_delete"], false, "{blocked_body}");

    // And the predictions hold against the real endpoint.
    assert_eq!(
        try_delete(&app, &token, blocked).await,
        400,
        "can_delete=false must mean the delete is refused"
    );
    assert_eq!(
        try_delete(&app, &token, clean).await,
        200,
        "can_delete=true must mean the delete succeeds; a preview that promises \
         a delete and then fails is worse than no preview"
    );
}

/// AC4, and the reason the existing page counts could not be reused. The guard
/// counts ALL tickets; `open_ticket_count` on the company response counts only
/// open ones. A company with closed tickets and none open is still refused.
#[sqlx::test]
async fn closed_tickets_block_and_the_preview_says_so(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company = seed_company_named(&pool, "Closed Co").await;
    let (ticket_id, _) = common::seed_ticket_and_note(&pool, admin_id, company).await;
    // `closed_at` alone is what `open_ticket_count` filters on, and it is the
    // only part of "closed" this test needs; `status_id` is a FK to
    // `ticket_statuses` and setting it correctly would test nothing extra here.
    sqlx::query("UPDATE tickets SET closed_at = NOW() WHERE id = $1")
        .bind(ticket_id)
        .execute(&pool)
        .await
        .expect("close the ticket");

    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let (_, body) = preview(&app, &token, company).await;
    assert_eq!(
        body["can_delete"], false,
        "a closed ticket still blocks: {body}"
    );
    assert!(
        blocking_labels(&body).contains(&"tickets".to_string()),
        "and the preview names it, which `open_ticket_count` could not: {body}"
    );
    assert_eq!(
        try_delete(&app, &token, company).await,
        400,
        "the prediction holds"
    );
}

/// AC3's split. PMS-920 distinguishes records that must be KEPT from ones the
/// author could clear, and the preview carries that distinction so a client
/// cannot tell somebody to delete their invoices.
#[sqlx::test]
async fn a_retained_blocker_is_marked_apart_from_a_removable_one(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company = seed_company_named(&pool, "Mixed Co").await;
    common::seed_ticket_and_note(&pool, admin_id, company).await;
    sqlx::query(
        "INSERT INTO invoices (tenant_id, company_id, invoice_number, invoice_date, due_date) \
         VALUES ($1, $2, 'INV-9002', CURRENT_DATE, CURRENT_DATE + 30)",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company)
    .execute(&pool)
    .await
    .expect("seed invoice");

    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;
    let (_, body) = preview(&app, &token, company).await;

    let rows = body["blocking"].as_array().expect("blocking array");
    let retained: Vec<&str> = rows
        .iter()
        .filter(|r| r["retained"] == true)
        .filter_map(|r| r["label"].as_str())
        .collect();
    let removable: Vec<&str> = rows
        .iter()
        .filter(|r| r["retained"] == false)
        .filter_map(|r| r["label"].as_str())
        .collect();

    assert!(
        retained.contains(&"invoices"),
        "an invoice is kept, never cleared to enable a delete: {body}"
    );
    assert!(
        removable.contains(&"tickets"),
        "a ticket can legitimately be reassigned first: {body}"
    );
}

/// AC2. What unlinks is reported as unlinking, not as blocking. This is the
/// exact drift MAPPS-577 reported: the dialog warned that projects and
/// sub-companies block, months after PMS-919 made them unlink.
#[sqlx::test]
async fn what_unlinks_is_not_reported_as_blocking(pool: PgPool) {
    let (_id, email, password) = common::seed_admin(&pool).await;
    let parent = seed_company_named(&pool, "Parent Co").await;
    sqlx::query(
        "INSERT INTO companies (id, tenant_id, name, parent_company_id) \
         VALUES ($1, $2, 'Child Co', $3)",
    )
    .bind(Uuid::new_v4())
    .bind(common::DEFAULT_TENANT_ID)
    .bind(parent)
    .execute(&pool)
    .await
    .expect("seed child");
    sqlx::query("INSERT INTO projects (tenant_id, name, company_id) VALUES ($1, 'P', $2)")
        .bind(common::DEFAULT_TENANT_ID)
        .bind(parent)
        .execute(&pool)
        .await
        .expect("seed project");

    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;
    let (_, body) = preview(&app, &token, parent).await;

    let unlinked: Vec<&str> = body["unlinked"]
        .as_array()
        .expect("unlinked array")
        .iter()
        .filter_map(|r| r["label"].as_str())
        .collect();
    assert!(unlinked.contains(&"projects"), "{body}");
    assert!(unlinked.contains(&"sub-companies"), "{body}");

    let blocking = blocking_labels(&body);
    assert!(
        !blocking.contains(&"projects".to_string())
            && !blocking.contains(&"sub-companies".to_string()),
        "PMS-919 made these unlink; reporting them as blockers is the stale copy \
         this endpoint exists to replace: {body}"
    );
    assert_eq!(body["can_delete"], true, "{body}");
    assert_eq!(try_delete(&app, &token, parent).await, 200);
}

/// AC6. The tenant's own company is refused for its ROLE, so an empty blocker
/// list beside a delete that still fails would be a lie.
#[sqlx::test]
async fn the_own_company_reports_its_role_rather_than_an_empty_list(pool: PgPool) {
    let (_id, email, password) = common::seed_admin(&pool).await;
    let own = seed_company_named(&pool, "Our MSP").await;
    sqlx::query("UPDATE tenants SET own_company_id = $1 WHERE id = $2")
        .bind(own)
        .bind(common::DEFAULT_TENANT_ID)
        .execute(&pool)
        .await
        .expect("point the tenant at its own company");

    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;
    let (_, body) = preview(&app, &token, own).await;

    assert_eq!(body["is_own_company"], true, "{body}");
    assert_eq!(
        body["can_delete"], false,
        "nothing references it, and it still cannot be deleted: {body}"
    );
    assert_eq!(try_delete(&app, &token, own).await, 400);
}

/// AC5. Tenant-scoped: a company in another tenant is not previewable, so this
/// cannot be used to probe ids.
#[sqlx::test]
async fn the_preview_cannot_see_another_tenants_company(pool: PgPool) {
    let (_id, email, password) = common::seed_admin(&pool).await;
    let (other_tenant, _, _, _) = common::seed_tenant_with_admin(&pool, "other-msp").await;
    let theirs = Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, 'Theirs')")
        .bind(theirs)
        .bind(other_tenant)
        .execute(&pool)
        .await
        .expect("seed other tenant company");

    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;
    let (status, _) = preview(&app, &token, theirs).await;
    assert_eq!(status, 404, "not found, rather than an empty preview");
}

/// AC7. A preview changes nothing.
#[sqlx::test]
async fn the_preview_has_no_side_effects(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company = seed_company_named(&pool, "Read Only Co").await;
    common::seed_ticket_and_note(&pool, admin_id, company).await;

    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    for _ in 0..3 {
        let (status, _) = preview(&app, &token, company).await;
        assert_eq!(status, 200);
    }

    let tickets: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tickets WHERE company_id = $1")
        .bind(company)
        .fetch_one(&app.pool)
        .await
        .expect("count tickets");
    assert_eq!(tickets, 1, "previewing must not touch anything");
    let still_there: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM companies WHERE id = $1")
        .bind(company)
        .fetch_one(&app.pool)
        .await
        .expect("count companies");
    assert_eq!(still_there, 1);
}

/// AC2, structurally. Every table that can block a delete appears in the
/// preview's source list, so a table cannot start blocking without the preview
/// learning about it. This is the guard against the drift that caused MAPPS-577.
#[test]
fn every_blocker_in_the_refusal_is_also_in_the_preview() {
    use mokosh_server::modules::contacts::COMPANY_BLOCKERS;

    // The refusal message matches on the constraint name; the preview counts
    // the table. One row carries both, so they cannot disagree.
    for b in COMPANY_BLOCKERS {
        assert!(
            !b.table.is_empty(),
            "{} has no table for the preview to count",
            b.label
        );
        assert!(!b.label.is_empty(), "{} has no human label", b.table);
    }

    // The tables the delete's own SQL and guard can refuse on. If a new one is
    // added to `delete_company` without landing here, the preview would call a
    // blocked company deletable.
    for expected in [
        "invoices",
        "payments",
        "contracts",
        "time_entries",
        "mileage_entries",
        "tickets",
        "assets",
        "quotes",
        "credential_vault",
    ] {
        assert!(
            COMPANY_BLOCKERS.iter().any(|b| b.table == expected),
            "`{expected}` blocks a company delete but is missing from \
             COMPANY_BLOCKERS, so the preview would report the company as \
             deletable and the delete would then fail"
        );
    }
}
