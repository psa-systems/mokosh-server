//! PMS-1061: a contact receives the customer's projection of a contract,
//! an asset and a project, never the staff type.
//!
//! The dual-plane reads (`RequireCallerContext`) scoped a contact to its
//! company and then returned `ContractResponse`, `AssetResponse` and
//! `ProjectResponse` unchanged, so a customer saw the MSP's `notes` on a
//! contract, the purchase price, network identity and assignee of an
//! asset, and the hourly rate, money budget, actuals and billing method
//! of a project. The retired portal router served trimmed types; the
//! contact arms now answer with `ContactContractResponse`,
//! `ContactAssetResponse` and `ContactProjectResponse`, which are those
//! shapes. The staff arms are unchanged, which the second half of each
//! case pins.

mod common;

use reqwest::StatusCode;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

/// Fetch as JSON, asserting the status so a refusal reads as itself.
async fn get_json(app: &common::TestApp, token: &str, path: &str) -> Value {
    let resp = app
        .client
        .get(app.url(path))
        .bearer_auth(token)
        .send()
        .await
        .expect("send");
    let status = resp.status();
    let text = resp.text().await.expect("body");
    assert_eq!(status, StatusCode::OK, "GET {path}: {text}");
    serde_json::from_str(&text).expect("JSON")
}

/// A decimal the API sends as a string, compared by value rather than scale.
fn money(v: &Value) -> rust_decimal::Decimal {
    common::dec(
        v.as_str()
            .unwrap_or_else(|| panic!("decimal string, got {v}")),
    )
}

fn keys(v: &Value) -> Vec<String> {
    v.as_object().expect("object").keys().cloned().collect()
}

/// The contact's object carries exactly the projection's keys and none of
/// the staff-only ones, on the list row and on the detail alike.
fn assert_projection(contact: &Value, staff: &Value, kept: &[&str], dropped: &[&str], what: &str) {
    for k in kept {
        assert!(
            contact.get(*k).is_some(),
            "{what}: contact response lost {k}: {contact}"
        );
    }
    for k in dropped {
        assert!(
            contact.get(*k).is_none(),
            "{what}: contact response leaks {k}: {contact}"
        );
        assert!(
            staff.get(*k).is_some(),
            "{what}: staff response is missing {k}, so the leak check proves nothing: {staff}"
        );
    }
    let extra: Vec<String> = keys(contact)
        .into_iter()
        .filter(|k| !kept.contains(&k.as_str()))
        .collect();
    assert!(
        extra.is_empty(),
        "{what}: contact response carries {extra:?}: {contact}"
    );
}

async fn seed_row(pool: &PgPool, sql: &str, id: Uuid, company_id: Uuid) {
    sqlx::query(sql)
        .bind(id)
        .bind(common::DEFAULT_TENANT_ID)
        .bind(company_id)
        .execute(pool)
        .await
        .expect("seed row");
}

#[sqlx::test]
async fn a_contract_reaches_a_contact_without_the_msps_notes(pool: PgPool) {
    let (_admin, admin_email, admin_pw) = common::seed_admin(&pool).await;
    let company = common::seed_company(&pool).await;
    let contact = common::seed_portal_contact(&pool, company, "c@x.example", &["Read-Only"]).await;
    let id = Uuid::new_v4();
    seed_row(
        &pool,
        "INSERT INTO contracts (id, tenant_id, company_id, name, contract_type, status, \
         start_date, billing_cycle, billing_amount, notes, auto_renew) \
         VALUES ($1, $2, $3, 'Managed services 2026', 'managed_services', 'active', \
         CURRENT_DATE, 'monthly', 1500, 'margin is thin, do not discount', TRUE)",
        id,
        company,
    )
    .await;

    let app = common::boot(pool.clone()).await;
    let token = common::contact_token(&app, &contact).await;
    let staff = common::login(&app, &admin_email, &admin_pw).await;
    let kept = [
        "id",
        "company_id",
        "contract_number",
        "name",
        "contract_type",
        "status",
        "start_date",
        "end_date",
        "billing_cycle",
        "billing_amount",
    ];
    let dropped = [
        "notes",
        "sla_id",
        "signed_by_contact_id",
        "signed_date",
        "auto_renew",
        "created_at",
        "updated_at",
    ];
    let contact_row = &get_json(&app, &token, "/api/v1/contracts").await["data"][0];
    let staff_row = &get_json(
        &app,
        &staff,
        &format!("/api/v1/contracts?company_id={company}"),
    )
    .await["data"][0];
    assert_projection(contact_row, staff_row, &kept, &dropped, "contract list");
    let contact_one = get_json(&app, &token, &format!("/api/v1/contracts/{id}")).await;
    let staff_one = get_json(&app, &staff, &format!("/api/v1/contracts/{id}")).await;
    assert_projection(&contact_one, &staff_one, &kept, &dropped, "contract detail");
    assert_eq!(money(&contact_one["billing_amount"]), common::dec("1500"));
    assert_eq!(staff_one["notes"], "margin is thin, do not discount");
}

#[sqlx::test]
async fn an_asset_reaches_a_contact_without_its_price_network_or_assignee(pool: PgPool) {
    let (_admin, admin_email, admin_pw) = common::seed_admin(&pool).await;
    let company = common::seed_company(&pool).await;
    let contact = common::seed_portal_contact(&pool, company, "c@x.example", &["Read-Only"]).await;
    let type_id: Uuid =
        sqlx::query_scalar("SELECT id FROM asset_types WHERE tenant_id = $1 ORDER BY name LIMIT 1")
            .bind(common::DEFAULT_TENANT_ID)
            .fetch_one(&pool)
            .await
            .expect("asset type");
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO assets (id, tenant_id, company_id, asset_type_id, asset_tag, name, status, \
         manufacturer, model, serial_number, purchase_price, ip_address, hostname, \
         mac_address, license_vendor, license_seat_count) \
         VALUES ($1, $2, $3, $4, 'LT-001', 'Laptop', 'active', 'Lenovo', 'T14', 'SN123', \
         1899.00, '10.0.0.12', 'lt-001.corp', 'aa:bb:cc:dd:ee:ff', 'Microsoft', 5)",
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company)
    .bind(type_id)
    .execute(&pool)
    .await
    .expect("seed asset");

    let app = common::boot(pool.clone()).await;
    let token = common::contact_token(&app, &contact).await;
    let staff = common::login(&app, &admin_email, &admin_pw).await;
    let kept = [
        "id",
        "company_id",
        "asset_tag",
        "name",
        "asset_type_id",
        "status",
        "manufacturer",
        "model",
        "serial_number",
        "warranty_expiry",
        "end_of_life",
    ];
    let dropped = [
        "purchase_price",
        "ip_address",
        "hostname",
        "mac_address",
        "assigned_user_id",
        "assigned_user_name",
        "license_vendor",
        "license_seat_count",
        "license_expiry",
        "itil_lifecycle_stage",
        "in_transit_ticket_id",
        "company_name",
        "created_at",
    ];
    let contact_row = &get_json(&app, &token, "/api/v1/assets").await["data"][0];
    let staff_row = &get_json(
        &app,
        &staff,
        &format!("/api/v1/assets?company_id={company}"),
    )
    .await["data"][0];
    assert_projection(contact_row, staff_row, &kept, &dropped, "asset list");
    let contact_one = get_json(&app, &token, &format!("/api/v1/assets/{id}")).await;
    let staff_one = get_json(&app, &staff, &format!("/api/v1/assets/{id}")).await;
    assert_projection(&contact_one, &staff_one, &kept, &dropped, "asset detail");
    assert_eq!(contact_one["serial_number"], "SN123");
    assert!(
        staff_one["ip_address"]
            .as_str()
            .unwrap_or("")
            .starts_with("10.0.0.12"),
        "{staff_one}"
    );
}

#[sqlx::test]
async fn a_project_reaches_a_contact_without_the_msps_rate_or_money(pool: PgPool) {
    let (_admin, admin_email, admin_pw) = common::seed_admin(&pool).await;
    let company = common::seed_company(&pool).await;
    let contact = common::seed_portal_contact(&pool, company, "c@x.example", &["Read-Only"]).await;
    let id = Uuid::new_v4();
    seed_row(
        &pool,
        "INSERT INTO projects (id, tenant_id, company_id, name, project_type, status, start_date, \
         budget_hours, budget_amount, billing_method, hourly_rate, is_billable) \
         VALUES ($1, $2, $3, 'Office migration', 'client', 'active', CURRENT_DATE, \
         40, 6000, 'time_and_materials', 150, TRUE)",
        id,
        company,
    )
    .await;

    let app = common::boot(pool.clone()).await;
    let token = common::contact_token(&app, &contact).await;
    let staff = common::login(&app, &admin_email, &admin_pw).await;
    let kept = [
        "id",
        "company_id",
        "project_number",
        "name",
        "description",
        "status",
        "start_date",
        "target_end_date",
        "actual_end_date",
        "budget_hours",
    ];
    let dropped = [
        "hourly_rate",
        "budget_amount",
        "actual_hours",
        "actual_amount",
        "billing_method",
        "is_billable",
        "project_manager_id",
        "contract_id",
        "company_name",
        "created_at",
    ];
    let contact_row = &get_json(&app, &token, "/api/v1/projects").await["data"][0];
    let staff_row = &get_json(
        &app,
        &staff,
        &format!("/api/v1/projects?company_id={company}"),
    )
    .await["data"][0];
    assert_projection(contact_row, staff_row, &kept, &dropped, "project list");
    let contact_one = get_json(&app, &token, &format!("/api/v1/projects/{id}")).await;
    let staff_one = get_json(&app, &staff, &format!("/api/v1/projects/{id}")).await;
    assert_projection(&contact_one, &staff_one, &kept, &dropped, "project detail");
    assert_eq!(money(&contact_one["budget_hours"]), common::dec("40"));
    assert_eq!(money(&staff_one["hourly_rate"]), common::dec("150"));
}
