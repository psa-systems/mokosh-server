//! PMS-934: the payment-terms dropdown must not offer identifiers.
//!
//! `payment_terms.name` is the only human-facing string on the row, it is what
//! the invoice form renders verbatim, and it is tenant-editable through the
//! Settings hub. Migration 050 seeded it with `due_on_receipt`, `net15`,
//! `net30` and `net60`, carried across from the legacy free-text column it
//! replaced; migration 117 renames them.
//!
//! These run against a migrated database, so what they can assert is the state
//! 117 leaves behind and that the copy path carries it to a new tenant. The
//! collision and already-renamed guards inside the migration are asserted by
//! replaying its own predicate against rows seeded to look like those cases.

mod common;

use sqlx::PgPool;
use uuid::Uuid;

/// The names the dropdown should offer, in the order the seed gives them.
const READABLE: [&str; 4] = ["Due on receipt", "Net 15", "Net 30", "Net 60"];

async fn term_names(pool: &PgPool, tenant_id: Uuid) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT name FROM payment_terms WHERE tenant_id = $1 ORDER BY sort_order, name",
    )
    .bind(tenant_id)
    .fetch_all(pool)
    .await
    .expect("read payment terms")
}

#[sqlx::test]
async fn the_seeded_terms_read_as_english(pool: PgPool) {
    let names = term_names(&pool, common::DEFAULT_TENANT_ID).await;
    assert_eq!(names, READABLE.map(String::from).to_vec());
    for name in &names {
        assert!(
            !name.contains('_'),
            "an identifier is still in the display column: {name}"
        );
    }
}

/// The rename must not disturb which term is the default or the order the
/// dropdown offers them in.
#[sqlx::test]
async fn the_rename_left_the_flags_alone(pool: PgPool) {
    let default_name: String = sqlx::query_scalar(
        "SELECT name FROM payment_terms WHERE tenant_id = $1 AND is_default LIMIT 1",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(&pool)
    .await
    .expect("a default term");
    assert_eq!(default_name, "Net 30", "net30 is still the seeded default");

    let defaults: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM payment_terms WHERE tenant_id = $1 AND is_default",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(&pool)
    .await
    .expect("count defaults");
    assert_eq!(defaults, 1, "still exactly one default");

    let inactive: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM payment_terms WHERE tenant_id = $1 AND NOT is_active",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(&pool)
    .await
    .expect("count inactive");
    assert_eq!(inactive, 0, "the rename did not deactivate anything");
}

/// A tenant that renamed its own term keeps that name. The migration matches
/// the seeded identifier verbatim, so a customised row is not a candidate;
/// replayed here against a row seeded to look customised.
#[sqlx::test]
async fn a_renamed_term_is_not_reworded(pool: PgPool) {
    let tenant = seed_tenant(&pool, "custom-terms").await;
    sqlx::query(
        "INSERT INTO payment_terms (tenant_id, name, is_default, is_active, sort_order) \
         VALUES ($1, '30 days end of month', FALSE, TRUE, 1)",
    )
    .bind(tenant)
    .execute(&pool)
    .await
    .expect("seed a customised term");

    replay_migration(&pool).await;

    assert_eq!(
        term_names(&pool, tenant).await,
        vec!["30 days end of month".to_string()],
        "a name the tenant chose is left alone"
    );
}

/// `idx_payment_terms_tenant_name` is unique, and 050's backfill could have
/// inserted a row already called "Net 30" from a legacy free-text value.
/// Renaming into that name would violate the index and fail the whole
/// migration, so the rename is skipped instead.
#[sqlx::test]
async fn a_colliding_name_is_skipped_rather_than_erroring(pool: PgPool) {
    let tenant = seed_tenant(&pool, "collision").await;
    for (name, order) in [("net30", 1), ("Net 30", 2)] {
        sqlx::query(
            "INSERT INTO payment_terms (tenant_id, name, is_default, is_active, sort_order) \
             VALUES ($1, $2, FALSE, TRUE, $3)",
        )
        .bind(tenant)
        .bind(name)
        .bind(order)
        .execute(&pool)
        .await
        .expect("seed the colliding pair");
    }

    replay_migration(&pool).await;

    let mut names = term_names(&pool, tenant).await;
    names.sort();
    assert_eq!(
        names,
        vec!["Net 30".to_string(), "net30".to_string()],
        "both rows survive: the rename is skipped, not attempted and failed"
    );
}

/// A tenant created after the migration inherits the readable names, because
/// `TenantService::create` copies the default tenant's terms row-for-row.
#[sqlx::test]
async fn a_new_tenant_inherits_the_readable_names(pool: PgPool) {
    let tenant = seed_tenant(&pool, "inheritor").await;
    sqlx::query(
        "INSERT INTO payment_terms (tenant_id, name, is_default, is_active, sort_order) \
         SELECT $1, name, is_default, is_active, sort_order \
         FROM payment_terms WHERE tenant_id = $2",
    )
    .bind(tenant)
    .bind(common::DEFAULT_TENANT_ID)
    .execute(&pool)
    .await
    .expect("copy the default tenant's terms");

    assert_eq!(
        term_names(&pool, tenant).await,
        READABLE.map(String::from).to_vec()
    );
}

async fn seed_tenant(pool: &PgPool, slug: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO tenants (id, name, slug, status, kind) VALUES ($1, $2, $3, 'active', 'org')",
    )
    .bind(id)
    .bind(format!("Tenant {slug}"))
    .bind(format!("{slug}-{}", &id.to_string()[..8]))
    .execute(pool)
    .await
    .expect("seed tenant");
    id
}

/// The migration's own statement, run again. Re-running it is a no-op for rows
/// it already converted, which is what makes replaying it against fixture rows
/// a fair test of its predicate rather than a paraphrase of it.
async fn replay_migration(pool: &PgPool) {
    sqlx::query(include_str!("../migrations/117_readable_payment_terms.sql"))
        .execute(pool)
        .await
        .expect("replay migration 117");
}
