//! Integration tests for PMS-315: mileage entries (Log Time "Mileage" mode).
//!
//! Covers:
//! - CRUD over `/api/v1/mileage-entries` (create, get, list, update, delete).
//! - A billable mileage entry inherits the tenant's default rate card
//!   `default_per_mile_rate` when no explicit rate is supplied, and prices
//!   `total_amount = distance_miles * rate_per_mile`.
//! - `POST /api/v1/invoices/from-time-entries` sweeps BOTH time and mileage
//!   entries: the generated invoice carries a `time_entry` line and a
//!   `mileage` line, the mileage description renders the route, and the
//!   subtotal sums both.
//! - Tenant isolation: a mileage entry in tenant A is invisible to tenant B
//!   (service layer, mirroring tests/contracts.rs).

mod common;

use chrono::NaiveDate;
use mokosh_server::modules::audit::AuditCtx;
use mokosh_server::modules::auth::TenantId;
use mokosh_server::modules::mileage_tracking::{
    CreateMileageEntryRequest, MileageTrackingService, UpdateMileageEntryRequest,
};
use mokosh_server::utils::error::AppError;
use mokosh_server::utils::pagination::PaginationParams;
use mokosh_server::Database;
use sqlx::PgPool;
use uuid::Uuid;

// PMS-318 sweep: create_mileage_entry now writes a Create audit row, so the
// service signature carries an AuditCtx. A default ctx suffices for tests.
fn actx() -> AuditCtx {
    AuditCtx {
        tenant_id: Some(common::DEFAULT_TENANT_ID),
        user_id: None,
        ip: None,
        user_agent: None,
    }
}

/// Read a money/decimal JSON field regardless of whether `rust_decimal`
/// serialized it as a JSON number or a string.
fn num(v: &serde_json::Value) -> f64 {
    v.as_f64()
        .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        .unwrap_or_else(|| panic!("not a numeric JSON value: {v:?}"))
}

fn approx(a: f64, b: f64) -> bool {
    (a - b).abs() < 0.005
}

/// Seed a billable work type under the default tenant; returns its id.
async fn seed_work_type(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO work_types (id, tenant_id, name, default_billable, default_rate)
        VALUES ($1, $2, 'Mileage Test Work', TRUE, 150.00)
        "#,
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .execute(pool)
    .await
    .expect("seed work type");
    id
}

/// Seed one billable, ready-to-bill time entry directly (mirrors billing.rs).
async fn seed_ready_time_entry(
    pool: &PgPool,
    user_id: Uuid,
    company_id: Uuid,
    work_type_id: Uuid,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO time_entries (
            id, tenant_id, user_id, date, duration_minutes, work_type_id,
            company_id, is_billable, billing_status, invoice_id,
            hourly_rate, total_amount
        )
        VALUES ($1, $2, $3, CURRENT_DATE, 60, $4, $5,
                TRUE, 'ready_to_bill', NULL, 150.00, 150.00)
        "#,
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(user_id)
    .bind(work_type_id)
    .bind(company_id)
    .execute(pool)
    .await
    .expect("seed ready time entry");
    id
}

#[sqlx::test]
async fn mileage_entry_crud_and_listing(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    // Create with an explicit per-mile rate.
    let resp = app
        .client
        .post(app.url("/api/v1/mileage-entries"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "user_id": admin_id,
            "date": "2026-06-16",
            "distance_miles": "42.5",
            "start_address": "1 Main St",
            "end_address": "9 Elm Ave",
            "company_id": company_id,
            "is_billable": true,
            "rate_per_mile": "0.6700"
        }))
        .send()
        .await
        .expect("create mileage entry");
    assert!(
        resp.status().is_success(),
        "create should 2xx, got {}",
        resp.status()
    );
    let created: serde_json::Value = resp.json().await.expect("created JSON");
    let id = created["id"].as_str().expect("entry id").to_string();
    assert!(approx(num(&created["distance_miles"]), 42.5));
    assert!(approx(num(&created["rate_per_mile"]), 0.67));
    // total = 42.5 * 0.67 = 28.475 -> NUMERIC(10,2) rounds to 28.48.
    assert!(approx(num(&created["total_amount"]), 28.48));
    assert_eq!(created["billing_status"].as_str(), Some("ready_to_bill"));

    // Get by id.
    let got: serde_json::Value = app
        .client
        .get(app.url(&format!("/api/v1/mileage-entries/{id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("get mileage entry")
        .json()
        .await
        .expect("get JSON");
    assert_eq!(got["start_address"].as_str(), Some("1 Main St"));

    // List shows it.
    let list: serde_json::Value = app
        .client
        .get(app.url("/api/v1/mileage-entries"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list mileage entries")
        .json()
        .await
        .expect("list JSON");
    let items = list["data"].as_array().expect("data array");
    assert_eq!(items.len(), 1, "exactly the one created entry");

    // Update the distance; total re-prices off the same rate.
    let updated: serde_json::Value = app
        .client
        .put(app.url(&format!("/api/v1/mileage-entries/{id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "distance_miles": "10.00" }))
        .send()
        .await
        .expect("update mileage entry")
        .json()
        .await
        .expect("update JSON");
    assert!(approx(num(&updated["distance_miles"]), 10.0));
    // 10 * 0.67 = 6.70.
    assert!(approx(num(&updated["total_amount"]), 6.70));

    // Delete, then a get 404s.
    let del = app
        .client
        .delete(app.url(&format!("/api/v1/mileage-entries/{id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("delete mileage entry");
    assert!(del.status().is_success(), "delete should 2xx");
    let after = app
        .client
        .get(app.url(&format!("/api/v1/mileage-entries/{id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("get after delete");
    assert_eq!(after.status(), reqwest::StatusCode::NOT_FOUND);
}

#[sqlx::test]
async fn billable_mileage_inherits_default_rate_card_rate(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;

    // The seed migration inserts a default rate card; give it a per-mile rate.
    sqlx::query(
        "UPDATE rate_cards SET default_per_mile_rate = 0.5000 \
         WHERE tenant_id = $1 AND is_default = TRUE",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .execute(&pool)
    .await
    .expect("set default per-mile rate");

    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    // No explicit rate_per_mile -> inherits the default rate card's rate.
    let created: serde_json::Value = app
        .client
        .post(app.url("/api/v1/mileage-entries"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "user_id": admin_id,
            "date": "2026-06-16",
            "distance_miles": "20.00",
            "company_id": company_id,
            "is_billable": true
        }))
        .send()
        .await
        .expect("create mileage entry")
        .json()
        .await
        .expect("created JSON");
    assert!(approx(num(&created["rate_per_mile"]), 0.5));
    // 20 * 0.5 = 10.00.
    assert!(approx(num(&created["total_amount"]), 10.0));
}

#[sqlx::test]
async fn invoice_includes_time_and_mileage_lines(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let work_type_id = seed_work_type(&pool).await;
    let _time_entry = seed_ready_time_entry(&pool, admin_id, company_id, work_type_id).await;

    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    // A billable mileage entry (becomes ready_to_bill on creation).
    let _mileage: serde_json::Value = app
        .client
        .post(app.url("/api/v1/mileage-entries"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "user_id": admin_id,
            "date": "2026-06-16",
            "distance_miles": "100.00",
            "start_address": "Office",
            "end_address": "Client Site",
            "company_id": company_id,
            "is_billable": true,
            "rate_per_mile": "0.5000"
        }))
        .send()
        .await
        .expect("create mileage entry")
        .json()
        .await
        .expect("mileage JSON");

    // Generate an invoice for the company.
    let invoice: serde_json::Value = app
        .client
        .post(app.url("/api/v1/invoices/from-time-entries"))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "company_id": company_id }))
        .send()
        .await
        .expect("generate invoice")
        .json()
        .await
        .expect("invoice JSON");

    let lines = invoice["lines"].as_array().expect("invoice lines");
    let types: Vec<&str> = lines
        .iter()
        .filter_map(|l| l["line_type"].as_str())
        .collect();
    assert!(
        types.contains(&"time_entry"),
        "invoice carries a time_entry line, got {types:?}"
    );
    assert!(
        types.contains(&"mileage"),
        "invoice carries a mileage line, got {types:?}"
    );

    let mileage_line = lines
        .iter()
        .find(|l| l["line_type"].as_str() == Some("mileage"))
        .expect("the mileage line");
    assert_eq!(
        mileage_line["description"].as_str(),
        Some("Mileage: Office \u{2192} Client Site")
    );
    // 100 mi * $0.50 = $50.00.
    assert!(approx(num(&mileage_line["total"]), 50.0));

    // Subtotal == time (150) + mileage (50) = 200.
    assert!(approx(num(&invoice["subtotal"]), 200.0));
}

#[sqlx::test]
async fn mileage_entries_are_tenant_isolated(pool: PgPool) {
    // Tenant A is the seeded default tenant; tenant B is a fresh one.
    let (admin_a, _email_a, _pw_a) = common::seed_admin(&pool).await;
    let company_a = common::seed_company(&pool).await;
    let (tenant_b, admin_b, _email_b, _pw_b) =
        common::seed_tenant_with_admin(&pool, "tenant-b").await;
    let company_b = Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, 'B Co')")
        .bind(company_b)
        .bind(tenant_b)
        .execute(&pool)
        .await
        .expect("seed company B");

    let svc = MileageTrackingService::new(Database::from_pool(pool.clone()));
    let ta = TenantId::from_trusted(common::DEFAULT_TENANT_ID);
    let tb = TenantId::from_trusted(tenant_b);

    let req_a = CreateMileageEntryRequest {
        user_id: admin_a,
        date: NaiveDate::from_ymd_opt(2026, 6, 16).unwrap(),
        distance_miles: common::dec("12.00"),
        start_address: None,
        end_address: None,
        ticket_id: None,
        project_id: None,
        task_id: None,
        company_id: company_a,
        contract_id: None,
        notes: None,
        is_billable: true,
        rate_per_mile: Some(common::dec("0.6000")),
    };
    let entry_a = svc
        .create_mileage_entry(ta, &req_a, &actx())
        .await
        .expect("create A");

    let req_b = CreateMileageEntryRequest {
        user_id: admin_b,
        company_id: company_b,
        ..req_a.clone()
    };
    let entry_b = svc
        .create_mileage_entry(tb, &req_b, &actx())
        .await
        .expect("create B");

    // Tenant B cannot read tenant A's entry.
    let cross = svc.get_mileage_entry(tb, entry_a.id).await;
    assert!(
        matches!(cross, Err(AppError::NotFound(_))),
        "tenant B reading tenant A's mileage entry must be NotFound"
    );

    // Tenant B's list only carries its own entry.
    let (items, total) = svc
        .list_mileage_entries(tb, &Default::default(), &PaginationParams::default())
        .await
        .expect("list B");
    assert_eq!(total, 1, "tenant B sees exactly its own entry");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].id, entry_b.id);

    // Tenant A still reads its own entry.
    assert!(svc.get_mileage_entry(ta, entry_a.id).await.is_ok());
}

/// PMS-315 review hardening: update_mileage_entry validates a re-associated
/// ticket_id against the tenant, exactly like create. A ticket that is not the
/// tenant's (here a non-existent id stands in for any out-of-tenant ticket,
/// which RLS makes indistinguishable from absent) is rejected before the row
/// is rewritten, so the cross-tenant link is never persisted.
#[sqlx::test]
async fn update_mileage_entry_rejects_foreign_ticket(pool: PgPool) {
    let (admin_a, _email, _pw) = common::seed_admin(&pool).await;
    let company_a = common::seed_company(&pool).await;
    let svc = MileageTrackingService::new(Database::from_pool(pool.clone()));
    let ta = TenantId::from_trusted(common::DEFAULT_TENANT_ID);

    let entry = svc
        .create_mileage_entry(
            ta,
            &CreateMileageEntryRequest {
                user_id: admin_a,
                date: NaiveDate::from_ymd_opt(2026, 6, 16).unwrap(),
                distance_miles: common::dec("12.00"),
                start_address: None,
                end_address: None,
                ticket_id: None,
                project_id: None,
                task_id: None,
                company_id: company_a,
                contract_id: None,
                notes: None,
                is_billable: true,
                rate_per_mile: Some(common::dec("0.6000")),
            },
            &actx(),
        )
        .await
        .expect("create entry");

    // Re-associating to a ticket outside the tenant is rejected with NotFound.
    let foreign_ticket = Uuid::new_v4();
    let res = svc
        .update_mileage_entry(
            ta,
            entry.id,
            &UpdateMileageEntryRequest {
                ticket_id: Some(foreign_ticket),
                ..Default::default()
            },
        )
        .await;
    assert!(
        matches!(res, Err(AppError::NotFound(_))),
        "updating with a foreign/non-tenant ticket_id must be NotFound, got {res:?}"
    );

    // The stored entry is untouched: still has no ticket linked.
    let after = svc.get_mileage_entry(ta, entry.id).await.expect("re-read");
    assert!(
        after.ticket_id.is_none(),
        "rejected update must not persist the ticket link"
    );
}

/// PMS-318 sweep: creating a mileage entry writes a `create` audit row in the
/// same tx as the INSERT, so the entry's change-history pane surfaces the
/// create event. The row is entity-scoped, has no `before` snapshot, captures
/// the inserted row in `after`, and records the ctx user as actor.
#[sqlx::test]
async fn create_mileage_entry_writes_create_audit_row(pool: PgPool) {
    let probe = pool.clone();
    let (admin_id, _email, _pw) = common::seed_admin(&pool).await;
    let company = common::seed_company(&pool).await;
    let svc = MileageTrackingService::new(Database::from_pool(pool.clone()));
    let ta = TenantId::from_trusted(common::DEFAULT_TENANT_ID);
    let ctx = AuditCtx {
        tenant_id: Some(common::DEFAULT_TENANT_ID),
        user_id: Some(admin_id),
        ip: None,
        user_agent: None,
    };

    let entry = svc
        .create_mileage_entry(
            ta,
            &CreateMileageEntryRequest {
                user_id: admin_id,
                date: NaiveDate::from_ymd_opt(2026, 6, 16).unwrap(),
                distance_miles: common::dec("12.00"),
                start_address: None,
                end_address: None,
                ticket_id: None,
                project_id: None,
                task_id: None,
                company_id: company,
                contract_id: None,
                notes: None,
                is_billable: true,
                rate_per_mile: Some(common::dec("0.6000")),
            },
            &ctx,
        )
        .await
        .expect("create entry");

    let (action, old_values, new_values, user_id): (
        String,
        Option<serde_json::Value>,
        Option<serde_json::Value>,
        Option<Uuid>,
    ) = sqlx::query_as(
        r#"SELECT action, old_values, new_values, user_id
             FROM audit_log
             WHERE entity_type = 'mileage_entries' AND entity_id = $1 AND action = 'create'"#,
    )
    .bind(entry.id)
    .fetch_one(&probe)
    .await
    .expect("a create audit row exists for the new mileage entry");

    assert_eq!(action, "create");
    assert!(old_values.is_none(), "before snapshot is NULL on a create");
    let after = new_values.expect("after snapshot present");
    assert_eq!(after["id"].as_str(), Some(entry.id.to_string().as_str()));
    assert_eq!(user_id, Some(admin_id), "actor is the ctx user");
}
