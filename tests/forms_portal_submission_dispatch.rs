//! Integration test: PMS-1221 (notification dispatcher wired into every
//! `TicketService`).
//!
//! `FormsService::submit_portal_form` is the ticket-creating method reached
//! by the OTHER `FormsService::with_request_links` construction site
//! (`src/api/router.rs`'s authenticated `/api/v1` mount, as opposed to the
//! public magic-link mount covered by `tests/request_forms.rs`). Before this
//! fix both sites built their `TicketService` with the bare
//! `TicketService::new(db.clone())`, so a ticket created through either path
//! carried no notification dispatcher: `automation.rs`'s `send_notification`
//! action silently fell back to the legacy mailer arm instead of queuing a
//! row in `notifications`.
//!
//! Called directly against the service (no HTTP router) because
//! `submit_portal_form` has no mounted route today (PMS-840 retired the
//! authenticated `POST /forms/{id}/submissions`); this test pins that its
//! `TicketService`, built the same way `create_api_router` builds the one at
//! the authenticated construction site, dispatches automation notifications
//! once wired.

mod common;

use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

use mokosh_server::modules::auth::TenantId;
use mokosh_server::modules::forms::FormsService;
use mokosh_server::modules::notifications::NotificationsService;
use mokosh_server::modules::tickets::TicketService;
use mokosh_server::utils::email::LogMailer;
use mokosh_server::Database;

#[sqlx::test]
async fn a_ticket_created_via_the_authenticated_portal_form_path_dispatches_a_notification(
    pool: PgPool,
) {
    let (admin_id, _email, _password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;

    let contact_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO contacts (id, tenant_id, company_id, first_name, last_name, email) \
         VALUES ($1, $2, $3, 'Portal', 'Contact', 'portal-contact@example.com')",
    )
    .bind(contact_id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company_id)
    .execute(&pool)
    .await
    .expect("seed contact");

    let form_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO form_definitions \
           (id, tenant_id, name, slug, is_active, portal_visible, created_by_id) \
         VALUES ($1, $2, 'Portal request', 'portal-request', TRUE, TRUE, $3)",
    )
    .bind(form_id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(admin_id)
    .execute(&pool)
    .await
    .expect("seed portal-visible form definition");

    sqlx::query(
        r#"INSERT INTO ticket_automation_rules
             (tenant_id, name, trigger_type, conditions, actions)
           VALUES ($1, 'Notify on new portal-form ticket', 'on_create', '[]'::jsonb, $2::jsonb)"#,
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(serde_json::json!([{
        "action_type": "send_notification",
        "params": {
            "to": "watcher@example.com",
            "subject": "New portal-form ticket",
            "body": "A portal contact submitted a request form."
        }
    }]))
    .execute(&pool)
    .await
    .expect("seed on_create automation rule");

    // Mirrors `create_api_router`'s authenticated construction site
    // (`src/api/router.rs`, `FormsService::with_request_links` under
    // `/api/v1`): a dispatcher-backed `TicketService`, not a bare
    // `TicketService::new`.
    let db = Database::from_pool(pool.clone());
    let notifications = NotificationsService::with_encryption_key(db.clone(), [0u8; 32]);
    let tickets =
        TicketService::with_dispatcher(db.clone(), Arc::new(LogMailer), notifications.clone());
    let forms_service = FormsService::with_request_links(db, notifications, tickets);

    let tenant_id = TenantId::from_trusted(common::DEFAULT_TENANT_ID);
    let receipt = forms_service
        .submit_portal_form(
            tenant_id,
            form_id,
            company_id,
            contact_id,
            &serde_json::json!({}),
        )
        .await
        .expect("portal form submission creates a ticket");
    assert!(
        !receipt.ticket_number.is_empty(),
        "the submission returns the created ticket's number"
    );

    let (subject, recipient): (String, Option<String>) = sqlx::query_as(
        "SELECT subject, recipient FROM notifications \
         WHERE tenant_id = $1 AND recipient = 'watcher@example.com' \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(&pool)
    .await
    .expect(
        "the ticket created via the authenticated portal-form path must \
         dispatch the on_create send_notification action through the queue",
    );
    assert_eq!(subject, "New portal-form ticket");
    assert_eq!(recipient.as_deref(), Some("watcher@example.com"));
}
