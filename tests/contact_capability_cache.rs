//! PMS-1247: a request resolves the contact's capabilities once, however
//! many capability checks it makes.
//!
//! Kept in its own file (its own test binary) because it reads the
//! process-wide `CAPABILITY_LOADS` counter, which a concurrent test in the
//! same binary would also move.

use std::sync::atomic::Ordering;

use mokosh_server::modules::auth::caller_context::CAPABILITY_LOADS;
use mokosh_server::modules::auth::CallerContext;
use mokosh_server::modules::contact_portal::models::ContactSession;
use sqlx::PgPool;
use uuid::Uuid;

#[sqlx::test(migrations = "./migrations")]
async fn repeated_capability_checks_issue_one_query(pool: PgPool) {
    let db = mokosh_server::Database::from_pool(pool);
    let caller = CallerContext::Contact(ContactSession {
        id: Uuid::new_v4(),
        tenant_id: Uuid::new_v4(),
        company_id: Uuid::new_v4(),
        email: "cache@example.test".to_string(),
        sid: Uuid::new_v4(),
        role_cache: Default::default(),
        timezone_cache: Default::default(),
    });

    let before = CAPABILITY_LOADS.load(Ordering::Relaxed);
    assert!(!caller.has_capability("invoices:read", &db).await.unwrap());
    assert!(caller
        .require_capability("invoices:read", &db)
        .await
        .is_err());
    // A clone is what the extractor hands a handler; it shares the cache.
    let clone = caller.clone();
    assert!(!clone.has_capability("invoices:pay", &db).await.unwrap());
    assert_eq!(CAPABILITY_LOADS.load(Ordering::Relaxed) - before, 1);
}
