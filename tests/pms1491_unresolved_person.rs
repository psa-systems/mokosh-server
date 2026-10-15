//! PMS-1491: extends the PMS-1477 unresolved-person-name sweep (see
//! `tests/pms1477_unresolved_person.rs`) to the tickets and approvals
//! surfaces. Same contract: a response logs once, at INFO, naming the
//! surface and the ids whose name it could not resolve; a `NULL` id
//! (nobody assigned / nobody decided yet) is not a failure and logs
//! nothing.

mod common;

use mokosh_server::modules::approvals::{ApprovalTarget, ApprovalsService};
use mokosh_server::modules::auth::TenantId;
use mokosh_server::modules::tickets::TicketService;
use mokosh_server::utils::pagination::PaginationParams;
use mokosh_server::Database;
use mokosh_test::mokosh_test;
use sqlx::PgPool;
use std::io;
use std::sync::{Arc, Mutex};
use tracing_subscriber::fmt::MakeWriter;
use uuid::Uuid;

/// An in-memory writer `tracing_subscriber::fmt` can target, so a test can
/// read back exactly what was logged rather than trusting libtest capture.
#[derive(Clone, Default)]
struct LogBuf(Arc<Mutex<Vec<u8>>>);

impl io::Write for LogBuf {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for LogBuf {
    type Writer = LogBuf;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

impl LogBuf {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).expect("log output is valid UTF-8")
    }
}

async fn capture_logs<F, Fut>(body: F) -> String
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let buf = LogBuf::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(buf.clone())
        .with_ansi(false)
        .with_env_filter(tracing_subscriber::EnvFilter::new("info"))
        .finish();
    let guard = tracing::subscriber::set_default(subscriber);
    body().await;
    drop(guard);
    buf.text()
}

/// Inserts a user row, then deletes it bypassing the FK check, the same way
/// `tests/pms1477_unresolved_person.rs` does: `created_by_id`/`approver_user_id`
/// etc. reference `users(id)` with no `ON DELETE` action, so a deleted row
/// has to exist long enough to be referenced first.
async fn seed_user(pool: &PgPool, tenant_id: Uuid, first_name: &str, last_name: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name, role, status) \
         VALUES ($1, $2, $3, 'x', $4, $5, 'admin', 'active')",
    )
    .bind(id)
    .bind(tenant_id)
    .bind(format!("pms1491-{id}@example.com"))
    .bind(first_name)
    .bind(last_name)
    .execute(pool)
    .await
    .expect("insert user");
    id
}

async fn delete_user_bypassing_fk(pool: &PgPool, id: Uuid) {
    let mut conn = pool.acquire().await.expect("acquire connection");
    sqlx::query("SET session_replication_role = replica")
        .execute(&mut *conn)
        .await
        .expect("disable triggers for this connection");
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(id)
        .execute(&mut *conn)
        .await
        .expect("delete the user row, bypassing the FK check");
    sqlx::query("SET session_replication_role = default")
        .execute(&mut *conn)
        .await
        .expect("restore default trigger behavior");
}

async fn seed_minimal_ticket(
    pool: &PgPool,
    tenant_id: Uuid,
    company_id: Uuid,
    created_by_id: Uuid,
    assigned_to_id: Option<Uuid>,
) -> Uuid {
    let status_id: Uuid =
        sqlx::query_scalar("SELECT id FROM ticket_statuses WHERE tenant_id = $1 LIMIT 1")
            .bind(tenant_id)
            .fetch_one(pool)
            .await
            .expect("status");
    let priority_id: Uuid =
        sqlx::query_scalar("SELECT id FROM ticket_priorities WHERE tenant_id = $1 LIMIT 1")
            .bind(tenant_id)
            .fetch_one(pool)
            .await
            .expect("priority");
    let queue_id: Uuid =
        sqlx::query_scalar("SELECT id FROM ticket_queues WHERE tenant_id = $1 LIMIT 1")
            .bind(tenant_id)
            .fetch_one(pool)
            .await
            .expect("queue");
    let ticket_id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO tickets
           (id, tenant_id, ticket_number, title, status_id, priority_id,
            queue_id, company_id, created_by_id, assigned_to_id)
           VALUES ($1, $2, $3, 'PMS-1491 fixture', $4, $5, $6, $7, $8, $9)"#,
    )
    .bind(ticket_id)
    .bind(tenant_id)
    .bind(format!("T-{}", &ticket_id.to_string()[..8]))
    .bind(status_id)
    .bind(priority_id)
    .bind(queue_id)
    .bind(company_id)
    .bind(created_by_id)
    .bind(assigned_to_id)
    .execute(pool)
    .await
    .expect("seed ticket");
    ticket_id
}

#[mokosh_test]
async fn ticket_responses_log_unresolved_creator_and_assignee(pool: PgPool) {
    let tenant_id = common::DEFAULT_TENANT_ID;
    let company_id = common::seed_company(&pool).await;

    // Deleted-row case: the creator of this ticket is a user whose row no
    // longer exists. No assignee (NULL id) - must not appear in the log.
    let deleted_creator_id = seed_user(&pool, tenant_id, "Soon", "Deleted").await;
    let ticket_with_deleted_creator =
        seed_minimal_ticket(&pool, tenant_id, company_id, deleted_creator_id, None).await;
    delete_user_bypassing_fk(&pool, deleted_creator_id).await;

    // Empty-name case: the assignee's profile name is blank (a
    // JIT-provisioned user). Creator resolves normally.
    let normal_creator_id = seed_user(&pool, tenant_id, "Normal", "Creator").await;
    let blank_name_assignee_id = seed_user(&pool, tenant_id, "", "").await;
    let ticket_with_blank_assignee = seed_minimal_ticket(
        &pool,
        tenant_id,
        company_id,
        normal_creator_id,
        Some(blank_name_assignee_id),
    )
    .await;

    let db = Database::from_pool(pool.clone());
    let service = TicketService::new(db);
    let tenant = TenantId::from_trusted(tenant_id);
    let pagination = PaginationParams {
        page: 1,
        per_page: 25,
        sort: None,
        sort_dir: "desc".to_string(),
    };
    let filter = Default::default();

    let log = capture_logs(|| async {
        let (rows, _total) = service
            .list_ticket_responses(tenant, None, &filter, &pagination)
            .await
            .expect("list ticket responses");
        assert!(
            rows.iter()
                .any(|t| t.id == ticket_with_deleted_creator && t.created_by_name.is_empty()),
            "the deleted-creator ticket has no resolved creator name"
        );
        assert!(
            rows.iter().any(|t| t.id == ticket_with_blank_assignee
                && t.assigned_to_name.as_deref().unwrap_or("").is_empty()),
            "the blank-name-assignee ticket has no resolved assignee name"
        );
    })
    .await;

    assert!(
        log.contains("unresolved person name"),
        "expected an unresolved-person-name log line, got:\n{log}"
    );
    assert!(
        log.contains("surface=tickets.list_ticket_responses")
            || log.contains("surface=\"tickets.list_ticket_responses\""),
        "log line names the surface, got:\n{log}"
    );
    assert!(
        log.contains(&deleted_creator_id.to_string()),
        "log line names the deleted creator's id, got:\n{log}"
    );
    assert!(
        log.contains(&blank_name_assignee_id.to_string()),
        "log line names the blank-name assignee's id, got:\n{log}"
    );
    // Exactly two unresolved ids: the deleted creator and the blank-name
    // assignee. The first ticket's NULL assigned_to_id and the second
    // ticket's resolved creator must not inflate the count.
    assert!(
        log.contains("count=2"),
        "exactly the two unresolved names are counted, got:\n{log}"
    );
}

#[mokosh_test]
async fn ticket_response_unassigned_ticket_logs_nothing(pool: PgPool) {
    let tenant_id = common::DEFAULT_TENANT_ID;
    let company_id = common::seed_company(&pool).await;
    let creator_id = seed_user(&pool, tenant_id, "Normal", "Creator").await;
    let ticket_id = seed_minimal_ticket(&pool, tenant_id, company_id, creator_id, None).await;

    let db = Database::from_pool(pool.clone());
    let service = TicketService::new(db);
    let tenant = TenantId::from_trusted(tenant_id);

    let log = capture_logs(|| async {
        let resp = service
            .get_ticket_response(tenant, ticket_id)
            .await
            .expect("get ticket response");
        assert!(resp.assigned_to_name.is_none());
        assert!(!resp.created_by_name.is_empty());
    })
    .await;

    assert!(
        !log.contains("unresolved person name"),
        "a resolved creator and a NULL (unassigned) assignee are not a failed lookup, got:\n{log}"
    );
}

#[mokosh_test]
async fn approvals_log_unresolved_requester_and_approver(pool: PgPool) {
    let tenant_id = common::DEFAULT_TENANT_ID;

    // Deleted-row case: the requester's user row no longer exists.
    let deleted_requester_id = seed_user(&pool, tenant_id, "Soon", "Deleted").await;
    // Empty-name case: the approver's profile name is blank.
    let blank_name_approver_id = seed_user(&pool, tenant_id, "", "").await;

    let approval_id = Uuid::new_v4();
    let entity_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO ticket_approvals \
         (id, tenant_id, target, entity_id, requested_by_id, approver_user_id, status) \
         VALUES ($1, $2, 'time_entry', $3, $4, $5, 'pending')",
    )
    .bind(approval_id)
    .bind(tenant_id)
    .bind(entity_id)
    .bind(deleted_requester_id)
    .bind(blank_name_approver_id)
    .execute(&pool)
    .await
    .expect("seed approval");
    delete_user_bypassing_fk(&pool, deleted_requester_id).await;

    // System-issued / not-yet-decided case: decided_by is NULL on a pending
    // row. Must not appear in the log.
    let db = Database::from_pool(pool.clone());
    let service = ApprovalsService::new(db);

    let log = capture_logs(|| async {
        let rows = service
            .list_for_entity(tenant_id, ApprovalTarget::TimeEntry, entity_id)
            .await
            .expect("list approvals for entity");
        assert_eq!(rows.len(), 1);
        assert!(rows[0].requested_by_name.is_none());
        assert!(rows[0].approver_user_name.is_none());
        assert!(rows[0].decided_by_id.is_none());
    })
    .await;

    assert!(
        log.contains("unresolved person name"),
        "expected an unresolved-person-name log line, got:\n{log}"
    );
    assert!(
        log.contains(&deleted_requester_id.to_string()),
        "log line names the deleted requester's id, got:\n{log}"
    );
    assert!(
        log.contains(&blank_name_approver_id.to_string()),
        "log line names the blank-name approver's id, got:\n{log}"
    );
    assert!(
        !log.contains("surface=approvals.list_for_entity.decided_by")
            && !log.contains("surface=\"approvals.list_for_entity.decided_by\""),
        "a pending (not yet decided) row must not log the decided_by surface at all, got:\n{log}"
    );
}
