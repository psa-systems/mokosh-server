//! PMS-1477: a server response that returns a person's name (or no name)
//! logs at INFO, once per response, naming the surface and the unresolved
//! ids, for every id it was asked to resolve and could not. A `NULL` id
//! (a system-issued row) is not a failure and logs nothing.

mod common;

use mokosh_server::modules::audit::service::AuditService;
use mokosh_server::modules::auth::TenantId;
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

/// Runs `body` with a thread-local subscriber (this crate's `#[mokosh_test]`
/// uses a current-thread runtime, so this stays in effect across the
/// `.await`s inside `body`) and returns what it logged.
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

async fn insert_audit_row(pool: &PgPool, tenant_id: Uuid, user_id: Option<Uuid>) {
    sqlx::query(
        "INSERT INTO audit_log (tenant_id, user_id, action, entity_type, entity_id, timestamp) \
         VALUES ($1, $2, 'update', 'companies', $3, NOW())",
    )
    .bind(tenant_id)
    .bind(user_id)
    .bind(Uuid::new_v4())
    .execute(pool)
    .await
    .expect("insert audit_log row");
}

#[mokosh_test]
async fn unresolved_actor_logs_once_per_response_with_ids(pool: PgPool) {
    let tenant_id = common::DEFAULT_TENANT_ID;

    // A deleted user: `users.id` is referenced by `audit_log.user_id` with a
    // plain (RESTRICT) FK, so the row has to exist long enough to be
    // referenced and then be removed without going through the FK, exactly
    // as a privileged one-off cleanup would. `session_replication_role =
    // replica` (superuser-only, which `#[mokosh_test]` connects as) disables
    // trigger-backed constraint checks for this connection only.
    let deleted_user_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name, role, status) \
         VALUES ($1, $2, $3, 'x', 'Soon', 'Deleted', 'admin', 'active')",
    )
    .bind(deleted_user_id)
    .bind(tenant_id)
    .bind(format!("deleted-{deleted_user_id}@example.com"))
    .execute(&pool)
    .await
    .expect("insert soon-to-be-deleted user");
    insert_audit_row(&pool, tenant_id, Some(deleted_user_id)).await;
    {
        let mut conn = pool.acquire().await.expect("acquire connection");
        sqlx::query("SET session_replication_role = replica")
            .execute(&mut *conn)
            .await
            .expect("disable triggers for this connection");
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(deleted_user_id)
            .execute(&mut *conn)
            .await
            .expect("delete the user row, bypassing the FK check");
        sqlx::query("SET session_replication_role = default")
            .execute(&mut *conn)
            .await
            .expect("restore default trigger behavior");
    }

    // A JIT-provisioned user whose profile name is still blank: the row
    // exists, NULLIF(TRIM(...)) still collapses to NULL.
    let blank_name_user_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name, role, status) \
         VALUES ($1, $2, $3, 'x', '', '', 'admin', 'active')",
    )
    .bind(blank_name_user_id)
    .bind(tenant_id)
    .bind(format!("blank-{blank_name_user_id}@example.com"))
    .execute(&pool)
    .await
    .expect("insert blank-name user");
    insert_audit_row(&pool, tenant_id, Some(blank_name_user_id)).await;

    // A system-issued row: no actor at all. Must not appear in the log.
    insert_audit_row(&pool, tenant_id, None).await;

    let db = Database::from_pool(pool.clone());
    let service = AuditService::new(db);
    let filter = Default::default();
    let pagination = PaginationParams {
        page: 1,
        per_page: 25,
        sort: None,
        sort_dir: "desc".to_string(),
    };

    let log = capture_logs(|| async {
        let (entries, total) = service
            .list(
                Some(TenantId::from_trusted(tenant_id)),
                &filter,
                &pagination,
            )
            .await
            .expect("list audit log");
        assert_eq!(total, 3, "all three rows are visible");
        assert!(
            entries
                .iter()
                .any(|e| e.user_id == Some(deleted_user_id) && e.user_name.is_none()),
            "the deleted-user row has no resolved name"
        );
        assert!(
            entries
                .iter()
                .any(|e| e.user_id == Some(blank_name_user_id) && e.user_name.is_none()),
            "the blank-name row has no resolved name"
        );
        assert!(
            entries.iter().any(|e| e.user_id.is_none()),
            "the system-issued row is still present, just with no actor"
        );
    })
    .await;

    assert!(
        log.contains("unresolved person name"),
        "expected an unresolved-person-name log line, got:\n{log}"
    );
    assert!(
        log.contains("surface=audit.list") || log.contains("surface=\"audit.list\""),
        "log line names the surface, got:\n{log}"
    );
    assert!(
        log.contains(&deleted_user_id.to_string()),
        "log line names the deleted user's id, got:\n{log}"
    );
    assert!(
        log.contains(&blank_name_user_id.to_string()),
        "log line names the blank-name user's id, got:\n{log}"
    );
    assert!(
        log.contains("count=2"),
        "exactly the two unresolved rows are counted, got:\n{log}"
    );
}

#[mokosh_test]
async fn system_issued_row_alone_logs_nothing(pool: PgPool) {
    let tenant_id = common::DEFAULT_TENANT_ID;
    insert_audit_row(&pool, tenant_id, None).await;

    let db = Database::from_pool(pool.clone());
    let service = AuditService::new(db);
    let filter = Default::default();
    let pagination = PaginationParams {
        page: 1,
        per_page: 25,
        sort: None,
        sort_dir: "desc".to_string(),
    };

    let log = capture_logs(|| async {
        let (entries, total) = service
            .list(
                Some(TenantId::from_trusted(tenant_id)),
                &filter,
                &pagination,
            )
            .await
            .expect("list audit log");
        assert_eq!(total, 1);
        assert!(entries[0].user_id.is_none());
    })
    .await;

    assert!(
        !log.contains("unresolved person name"),
        "a NULL actor id is not a failed lookup and must not log, got:\n{log}"
    );
}
