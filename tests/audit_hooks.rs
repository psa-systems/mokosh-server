//! Integration tests: billing + contracts audit-log hooks (PMS-117).
//!
//! These exercise the in-transaction `audit_write` path wired into the
//! billing and contracts CRUD mutations. Each test drives the real HTTP
//! API as a RequireFinance-capable admin (the seeded `super_admin` passes
//! the finance role gate) and then reads `audit_log` back through an
//! independent DB query to prove the row was written with the acting user
//! and before/after snapshots.
//!
//! Coverage:
//!   1. Create an invoice, then update it -> an `entity_type = 'invoices'`,
//!      `action = 'update'` audit row exists with `user_id` set and both
//!      `old_values` / `new_values` populated.
//!   2. Create a contract, then update it -> an `entity_type =
//!      'contracts'`, `action = 'update'` audit row exists with the actor
//!      and snapshots.
//!   3. Upsert a payment-gateway config -> the audit row's `new_values`
//!      do NOT contain the secret `config_encrypted` column (SQL
//!      secret-strip), while still capturing the non-secret columns.

mod common;

use sqlx::PgPool;
use uuid::Uuid;

#[sqlx::test]
async fn invoice_create_then_update_writes_audit_rows(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    // Create an invoice with a single service line.
    let create_resp = app
        .client
        .post(app.url("/api/v1/invoices"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "company_id": company_id,
            "invoice_date": "2026-01-01",
            "due_date": "2026-01-31",
            "lines": [{
                "line_type": "service",
                "description": "Consulting",
                "quantity": "2",
                "unit_price": "100.00",
            }],
        }))
        .send()
        .await
        .expect("create invoice");
    assert!(
        create_resp.status().is_success(),
        "create invoice should 2xx, got {}",
        create_resp.status()
    );
    let invoice: serde_json::Value = create_resp.json().await.expect("invoice JSON");
    let invoice_id: Uuid = invoice["id"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .expect("created invoice id");

    // A create audit row landed for the invoice.
    let create_count: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM audit_log
           WHERE entity_type = 'invoices' AND entity_id = $1 AND action = 'create'"#,
    )
    .bind(invoice_id)
    .fetch_one(&app.pool)
    .await
    .expect("count invoice create audit rows");
    assert_eq!(create_count, 1, "invoice create writes one audit row");

    // Update the invoice (notes edit keeps it in an editable status).
    let update_resp = app
        .client
        .put(app.url(&format!("/api/v1/invoices/{invoice_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "notes": "Updated note" }))
        .send()
        .await
        .expect("update invoice");
    assert!(
        update_resp.status().is_success(),
        "update invoice should 2xx, got {}",
        update_resp.status()
    );

    // The update audit row carries the actor and before/after snapshots.
    let (action, old_values, new_values, user_id): (
        String,
        Option<serde_json::Value>,
        Option<serde_json::Value>,
        Option<Uuid>,
    ) = sqlx::query_as(
        r#"SELECT action, old_values, new_values, user_id
           FROM audit_log
           WHERE entity_type = 'invoices' AND entity_id = $1 AND action = 'update'"#,
    )
    .bind(invoice_id)
    .fetch_one(&app.pool)
    .await
    .expect("audit row for the invoice update exists");

    assert_eq!(action, "update");
    assert_eq!(user_id, Some(admin_id), "audit row records the acting user");
    let old = old_values.expect("old_values captured");
    let new = new_values.expect("new_values captured");
    assert_eq!(
        old["id"].as_str(),
        Some(invoice_id.to_string().as_str()),
        "before snapshot is the invoice row"
    );
    assert_eq!(
        new["notes"].as_str(),
        Some("Updated note"),
        "after snapshot reflects the edited notes"
    );
}

#[sqlx::test]
async fn contract_create_then_update_writes_audit_rows(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    // Create a contract.
    let create_resp = app
        .client
        .post(app.url("/api/v1/contracts"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "name": "Managed Services",
            "company_id": company_id,
            "contract_type": "managed_services",
            "start_date": "2026-01-01",
        }))
        .send()
        .await
        .expect("create contract");
    assert!(
        create_resp.status().is_success(),
        "create contract should 2xx, got {}",
        create_resp.status()
    );
    let contract: serde_json::Value = create_resp.json().await.expect("contract JSON");
    let contract_id: Uuid = contract["id"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .expect("created contract id");

    // A create audit row landed for the contract.
    let create_count: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM audit_log
           WHERE entity_type = 'contracts' AND entity_id = $1 AND action = 'create'"#,
    )
    .bind(contract_id)
    .fetch_one(&app.pool)
    .await
    .expect("count contract create audit rows");
    assert_eq!(create_count, 1, "contract create writes one audit row");

    // Rename the contract.
    let update_resp = app
        .client
        .put(app.url(&format!("/api/v1/contracts/{contract_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "name": "Managed Services Plus" }))
        .send()
        .await
        .expect("update contract");
    assert!(
        update_resp.status().is_success(),
        "update contract should 2xx, got {}",
        update_resp.status()
    );

    let (action, old_values, new_values, user_id): (
        String,
        Option<serde_json::Value>,
        Option<serde_json::Value>,
        Option<Uuid>,
    ) = sqlx::query_as(
        r#"SELECT action, old_values, new_values, user_id
           FROM audit_log
           WHERE entity_type = 'contracts' AND entity_id = $1 AND action = 'update'"#,
    )
    .bind(contract_id)
    .fetch_one(&app.pool)
    .await
    .expect("audit row for the contract update exists");

    assert_eq!(action, "update");
    assert_eq!(user_id, Some(admin_id), "audit row records the acting user");
    let old = old_values.expect("old_values captured");
    let new = new_values.expect("new_values captured");
    assert_eq!(
        old["name"].as_str(),
        Some("Managed Services"),
        "before snapshot has the original name"
    );
    assert_eq!(
        new["name"].as_str(),
        Some("Managed Services Plus"),
        "after snapshot has the new name"
    );
}

#[sqlx::test]
async fn payment_gateway_upsert_audit_strips_secret(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    // Upsert a Stripe gateway config carrying a secret in its config blob.
    let resp = app
        .client
        .put(app.url("/api/v1/payment-gateways"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "provider": "stripe",
            "is_active": true,
            "is_test_mode": true,
            "config": { "api_key": "sk_test_supersecret" },
        }))
        .send()
        .await
        .expect("upsert payment gateway");
    assert!(
        resp.status().is_success(),
        "upsert gateway should 2xx, got {}",
        resp.status()
    );
    let gateway: serde_json::Value = resp.json().await.expect("gateway JSON");
    let gateway_id: Uuid = gateway["id"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .expect("gateway id");

    // The audit row for the upsert must exist and its new_values must NOT
    // contain the secret `config_encrypted` column (SQL secret-strip),
    // while still capturing a non-secret column like `provider`.
    let new_values: Option<serde_json::Value> = sqlx::query_scalar(
        r#"SELECT new_values FROM audit_log
           WHERE entity_type = 'payment_gateway_configs' AND entity_id = $1"#,
    )
    .bind(gateway_id)
    .fetch_one(&app.pool)
    .await
    .expect("audit row for the gateway upsert exists");

    let new = new_values.expect("new_values captured");
    assert!(
        new.get("config_encrypted").is_none(),
        "new_values must not include the secret config_encrypted column, got {new}"
    );
    assert_eq!(
        new["provider"].as_str(),
        Some("stripe"),
        "non-secret columns are still captured in the snapshot"
    );
}
