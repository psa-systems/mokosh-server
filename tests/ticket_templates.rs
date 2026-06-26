//! PMS-448 AC4: integration test for ticket templates.
//!
//! Pins the new-ticket pre-fill surface:
//!   - admin CRUD round-trip works and stores subject / description /
//!     category exactly as authored;
//!   - `?active_only=true` narrows the list to the picker's view;
//!   - PATCH can clear a nullable FK (explicit null) and rename;
//!   - DELETE removes the row, and a follow-up GET is 404;
//!   - the surface is admin-gated (a plain agent is forbidden).

mod common;

use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

async fn lookup_id(pool: &PgPool, table: &str) -> Uuid {
    sqlx::query_scalar(&format!(
        "SELECT id FROM {table} WHERE tenant_id = $1 LIMIT 1"
    ))
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("lookup id from {table}: {e}"))
}

#[sqlx::test]
async fn ticket_templates_crud_and_prefill(pool: PgPool) {
    let (_admin_id, admin_email, admin_pw) = common::seed_admin(&pool).await;
    let category_id = lookup_id(&pool, "ticket_categories").await;
    let priority_id = lookup_id(&pool, "ticket_priorities").await;

    // A non-admin agent in the same tenant to prove the surface is
    // admin-gated.
    let (_agent_id, agent_email, agent_pw) = common::seed_user(
        &pool,
        common::DEFAULT_TENANT_ID,
        "template-agent@example.com",
        "technician",
    )
    .await;

    let app = common::boot(pool).await;
    let admin_token = common::login(&app, &admin_email, &admin_pw).await;
    let agent_token = common::login(&app, &agent_email, &agent_pw).await;

    // AC4: author a "Server is down" template that pre-fills subject,
    // description, and category.
    let created: Value = app
        .client
        .post(app.url("/api/v1/ticket-templates"))
        .bearer_auth(&admin_token)
        .json(&serde_json::json!({
            "name": "Server is down",
            "description": "Use when a customer reports an outage.",
            "subject": "Server is down",
            "body": "Affected server:\nFirst noticed:\nImpact:",
            "category_id": category_id.to_string(),
            "priority_id": priority_id.to_string(),
        }))
        .send()
        .await
        .expect("create template")
        .json()
        .await
        .expect("create body");
    assert_eq!(created["name"], "Server is down");
    assert_eq!(created["subject"], "Server is down");
    assert_eq!(created["body"], "Affected server:\nFirst noticed:\nImpact:");
    assert_eq!(
        created["category_id"].as_str(),
        Some(category_id.to_string().as_str())
    );
    assert_eq!(
        created["priority_id"].as_str(),
        Some(priority_id.to_string().as_str())
    );
    assert_eq!(created["is_active"], true);
    let id = created["id"].as_str().expect("id").to_string();

    // A retired template that must drop out of the picker view.
    let retired: Value = app
        .client
        .post(app.url("/api/v1/ticket-templates"))
        .bearer_auth(&admin_token)
        .json(&serde_json::json!({
            "name": "Old onboarding checklist",
            "subject": "Onboarding",
            "is_active": false,
        }))
        .send()
        .await
        .expect("create retired")
        .json()
        .await
        .expect("retired body");
    let retired_id = retired["id"].as_str().expect("retired id").to_string();

    // Admin management list sees both; picker list (active_only) sees
    // only the active one.
    let all: Value = app
        .client
        .get(app.url("/api/v1/ticket-templates"))
        .bearer_auth(&admin_token)
        .send()
        .await
        .expect("list all")
        .json()
        .await
        .expect("list all body");
    assert_eq!(all.as_array().expect("array").len(), 2);

    let active: Value = app
        .client
        .get(app.url("/api/v1/ticket-templates?active_only=true"))
        .bearer_auth(&admin_token)
        .send()
        .await
        .expect("list active")
        .json()
        .await
        .expect("list active body");
    let active_arr = active.as_array().expect("array");
    assert_eq!(active_arr.len(), 1);
    assert_eq!(active_arr[0]["id"].as_str(), Some(id.as_str()));

    // The agent is forbidden from the admin-gated surface.
    let forbidden = app
        .client
        .get(app.url("/api/v1/ticket-templates"))
        .bearer_auth(&agent_token)
        .send()
        .await
        .expect("agent list");
    assert_eq!(forbidden.status().as_u16(), 403);

    // PATCH: rename and clear the priority FK (explicit null), leaving
    // the category untouched (key absent).
    let patched: Value = app
        .client
        .patch(app.url(&format!("/api/v1/ticket-templates/{id}")))
        .bearer_auth(&admin_token)
        .json(&serde_json::json!({
            "name": "Server outage",
            "priority_id": null,
        }))
        .send()
        .await
        .expect("patch")
        .json()
        .await
        .expect("patch body");
    assert_eq!(patched["name"], "Server outage");
    assert!(patched["priority_id"].is_null(), "priority FK was cleared");
    assert_eq!(
        patched["category_id"].as_str(),
        Some(category_id.to_string().as_str()),
        "category FK untouched by an absent key"
    );

    // DELETE the retired template; a follow-up GET is 404.
    let del = app
        .client
        .delete(app.url(&format!("/api/v1/ticket-templates/{retired_id}")))
        .bearer_auth(&admin_token)
        .send()
        .await
        .expect("delete");
    assert!(del.status().is_success());

    let gone = app
        .client
        .get(app.url(&format!("/api/v1/ticket-templates/{retired_id}")))
        .bearer_auth(&admin_token)
        .send()
        .await
        .expect("get deleted");
    assert_eq!(gone.status().as_u16(), 404);
}
