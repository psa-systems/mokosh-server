//! Round-trip integration test for tenant data export -> import (PMS-647 / PMS-648).
//!
//! Seeds a tenant with a company + an FK-referencing contact, exports via
//! `GET /api/v1/data/export`, imports the envelope back (wipe-and-replace) via
//! `POST /api/v1/data/import`, and asserts the data is restored with REMAPPED
//! ids (the contact's FK follows the company's new id, proving cross-table FK
//! remap + topological load order) and that no secret column leaked into the
//! export. Runs against Postgres in CI (`integration.yml`); the local `--lib`
//! pre-commit only compiles it.

mod common;

use common::DEFAULT_TENANT_ID;
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

/// Column-name substrings that must never appear as a key in any exported row.
const SECRET_SUBSTRINGS: &[&str] = &[
    "encrypted",
    "password_hash",
    "_secret",
    "mfa_secret",
    "api_key",
    "api_secret",
    "private_key",
];

#[sqlx::test]
async fn export_import_round_trip_remaps_ids_and_leaks_no_secrets(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;

    // Company + a contact that FK-references it, so the round-trip exercises
    // cross-table FK remapping and the topological load order.
    let company_id = common::seed_company(&pool).await;
    let contact_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO contacts (id, tenant_id, company_id, first_name, last_name)
         VALUES ($1, $2, $3, 'Jane', 'Doe')",
    )
    .bind(contact_id)
    .bind(DEFAULT_TENANT_ID)
    .bind(company_id)
    .execute(&pool)
    .await
    .expect("seed contact");

    let tenant_name: String = sqlx::query_scalar("SELECT name FROM tenants WHERE id = $1")
        .bind(DEFAULT_TENANT_ID)
        .fetch_one(&pool)
        .await
        .expect("read tenant name");

    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    // --- export ---
    let export_res = app
        .client
        .get(app.url("/api/v1/data/export"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send export");
    assert!(
        export_res.status().is_success(),
        "export status {}",
        export_res.status()
    );
    let envelope: Value = export_res.json().await.expect("export json");

    let entities = envelope["entities"].as_object().expect("entities object");
    assert_eq!(entities["companies"].as_array().unwrap().len(), 1);
    assert_eq!(entities["contacts"].as_array().unwrap().len(), 1);
    // No secret column leaked into ANY entity row.
    for (table, rows) in entities {
        if let Some(arr) = rows.as_array() {
            for row in arr {
                if let Some(obj) = row.as_object() {
                    for key in obj.keys() {
                        for s in SECRET_SUBSTRINGS {
                            assert!(!key.contains(s), "secret column {key} leaked in {table}");
                        }
                    }
                }
            }
        }
    }

    // --- import (wipe-and-replace back into the same tenant) ---
    let import_res = app
        .client
        .post(app.url("/api/v1/data/import"))
        .bearer_auth(&token)
        .json(&json!({ "confirm": tenant_name, "export": envelope }))
        .send()
        .await
        .expect("send import");
    let import_status = import_res.status();
    let import_body = import_res.text().await.unwrap_or_default();
    assert!(
        import_status.is_success(),
        "import status {import_status}: {import_body}"
    );

    // --- restored with remapped ids ---
    let (new_company_id, new_company_name): (Uuid, String) =
        sqlx::query_as("SELECT id, name FROM companies WHERE tenant_id = $1")
            .bind(DEFAULT_TENANT_ID)
            .fetch_one(&pool)
            .await
            .expect("company after import");
    assert_eq!(new_company_name, "Acme Co");
    assert_ne!(new_company_id, company_id, "company id must be remapped");

    let (contact_company_fk,): (Uuid,) =
        sqlx::query_as("SELECT company_id FROM contacts WHERE tenant_id = $1")
            .bind(DEFAULT_TENANT_ID)
            .fetch_one(&pool)
            .await
            .expect("contact after import");
    assert_eq!(
        contact_company_fk, new_company_id,
        "contact FK must follow the remapped company id"
    );
}
