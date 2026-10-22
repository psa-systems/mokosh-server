//! PMS-1382: a contact-caller request resolves `today()`'s timezone once,
//! however many times `today()` is called.
//!
//! Kept in its own file (its own test binary) because it reads the
//! process-wide `TIMEZONE_LOADS` counter, which a concurrent test in the
//! same binary would also move (the same reason `contact_capability_cache`
//! is split out for `CAPABILITY_LOADS`).

use mokosh_test::mokosh_test;
use std::sync::atomic::Ordering;

use mokosh_server::modules::auth::caller_context::TIMEZONE_LOADS;
use mokosh_server::modules::auth::CallerContext;
use mokosh_server::modules::contact_portal::models::ContactSession;
use sqlx::PgPool;
use uuid::Uuid;

#[mokosh_test]
async fn repeated_today_calls_issue_one_timezone_query(pool: PgPool) {
    let db = mokosh_server::Database::from_pool(pool);
    let caller = CallerContext::Contact(ContactSession {
        id: Uuid::new_v4(),
        tenant_id: Uuid::new_v4(),
        company_id: Uuid::new_v4(),
        email: "tz-cache@example.test".to_string(),
        sid: Uuid::new_v4(),
        role_cache: Default::default(),
        timezone_cache: Default::default(),
    });

    let before = TIMEZONE_LOADS.load(Ordering::Relaxed);
    let first = caller.today(&db).await.unwrap();
    let second = caller.today(&db).await.unwrap();
    // A clone is what the extractor hands a handler; it shares the cache.
    let clone = caller.clone();
    let third = clone.today(&db).await.unwrap();

    assert_eq!(first, second);
    assert_eq!(second, third);
    assert_eq!(TIMEZONE_LOADS.load(Ordering::Relaxed) - before, 1);
}
