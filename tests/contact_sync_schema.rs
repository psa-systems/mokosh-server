//! PMS-1211 (PSA-70 phase 1): the contact-sync schema holds its own rules.
//!
//! Migration 220 states four things that only a database can prove: the
//! org-level decision is a unique index and not a convention, provenance
//! survives a disconnect, a contact deleted in the source is not deleted here,
//! and every new table is RLS fail-closed.

mod common;

use sqlx::PgPool;
use uuid::Uuid;

async fn seed_connection(pool: &PgPool, account: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO contact_sync_connections (id, tenant_id, provider, account_email) \
         VALUES ($1, $2, 'google', $3)",
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(account)
    .execute(pool)
    .await
    .expect("seed connection");
    id
}

async fn seed_contact(pool: &PgPool, company_id: Uuid, email: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO contacts (id, tenant_id, company_id, first_name, last_name, email) \
         VALUES ($1, $2, $3, 'Imported', 'Person', $4)",
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company_id)
    .bind(email)
    .execute(pool)
    .await
    .expect("seed contact");
    id
}

/// PSA-70 (B): org-level is the schema's rule, not the service's. A tenant
/// holds one live connection per provider.
#[sqlx::test]
async fn a_tenant_has_one_live_connection_per_provider(pool: PgPool) {
    seed_connection(&pool, "first@workspace.example").await;
    let second = sqlx::query(
        "INSERT INTO contact_sync_connections (tenant_id, provider, account_email) \
         VALUES ($1, 'google', 'second@workspace.example')",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .execute(&pool)
    .await;
    assert!(
        second.is_err(),
        "a second live Google connection must be refused"
    );

    // Disconnecting frees the slot, and the old row stays for provenance.
    sqlx::query("UPDATE contact_sync_connections SET disconnected_at = NOW() WHERE tenant_id = $1")
        .bind(common::DEFAULT_TENANT_ID)
        .execute(&pool)
        .await
        .expect("disconnect");
    seed_connection(&pool, "second@workspace.example").await;
    let rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM contact_sync_connections WHERE tenant_id = $1")
            .bind(common::DEFAULT_TENANT_ID)
            .fetch_one(&pool)
            .await
            .expect("count");
    assert_eq!(rows, 2, "the disconnected row is kept");
}

/// PSA-70 (J): deleting a connection must never delete the record of where a
/// contact came from, nor the contact.
#[sqlx::test]
async fn provenance_survives_deleting_the_connection(pool: PgPool) {
    let company = common::seed_company(&pool).await;
    let connection = seed_connection(&pool, "msp@workspace.example").await;
    let contact = seed_contact(&pool, company, "imported@client.example").await;
    sqlx::query(
        "INSERT INTO contact_sync_links \
         (tenant_id, connection_id, provider, source_account_email, external_id, contact_id) \
         VALUES ($1, $2, 'google', 'msp@workspace.example', 'people/c1', $3)",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(connection)
    .bind(contact)
    .execute(&pool)
    .await
    .expect("seed link");

    sqlx::query("DELETE FROM contact_sync_connections WHERE id = $1")
        .bind(connection)
        .execute(&pool)
        .await
        .expect("delete connection");

    let (provider, account, still_there): (String, String, Option<Uuid>) = sqlx::query_as(
        "SELECT provider, source_account_email, connection_id FROM contact_sync_links \
         WHERE contact_id = $1",
    )
    .bind(contact)
    .fetch_one(&pool)
    .await
    .expect("the link outlives its connection");
    assert_eq!(provider, "google");
    assert_eq!(account, "msp@workspace.example");
    assert_eq!(still_there, None, "the connection reference is cleared");

    let contacts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM contacts WHERE id = $1")
        .bind(contact)
        .fetch_one(&pool)
        .await
        .expect("count contacts");
    assert_eq!(contacts, 1, "the contact itself is never deleted");
}

/// PSA-70 (D): both awkward match shapes are representable, because the queue
/// is keyed on the PAIR. One Google contact matching two Mokosh contacts, and
/// two Google contacts matching one Mokosh contact.
#[sqlx::test]
async fn the_review_queue_holds_both_ambiguous_shapes(pool: PgPool) {
    let company = common::seed_company(&pool).await;
    let connection = seed_connection(&pool, "msp@workspace.example").await;
    let first = seed_contact(&pool, company, "one@client.example").await;
    let second = seed_contact(&pool, company, "two@client.example").await;

    for (external, candidate) in [
        ("people/c1", first),
        ("people/c1", second),
        ("people/c2", first),
    ] {
        sqlx::query(
            "INSERT INTO contact_sync_candidates \
             (tenant_id, connection_id, external_id, candidate_contact_id, match_reason) \
             VALUES ($1, $2, $3, $4, 'phone')",
        )
        .bind(common::DEFAULT_TENANT_ID)
        .bind(connection)
        .bind(external)
        .bind(candidate)
        .execute(&pool)
        .await
        .expect("queue a candidate");
    }

    // The same pair twice is one open question, so a re-sync does not re-ask.
    let repeat = sqlx::query(
        "INSERT INTO contact_sync_candidates \
         (tenant_id, connection_id, external_id, candidate_contact_id, match_reason) \
         VALUES ($1, $2, 'people/c1', $3, 'phone')",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(connection)
    .bind(first)
    .execute(&pool)
    .await;
    assert!(repeat.is_err(), "the same open pair must not queue twice");

    let open: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM contact_sync_candidates WHERE tenant_id = $1 AND status = 'open'",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(open, 3);
}

/// Every new table is RLS fail-closed, so the app role sees nothing without
/// the tenant GUC. The `boot_rls` role is the production posture.
#[sqlx::test]
async fn the_new_tables_are_rls_fail_closed(pool: PgPool) {
    let app = common::boot_rls(pool.clone()).await;
    for table in [
        "contact_sync_connections",
        "contact_sync_links",
        "contact_field_locks",
        "contact_sync_candidates",
    ] {
        let forced: bool = sqlx::query_scalar(
            "SELECT relrowsecurity AND relforcerowsecurity FROM pg_class WHERE relname = $1",
        )
        .bind(table)
        .fetch_one(&app.pool)
        .await
        .unwrap_or_else(|e| panic!("read {table}: {e}"));
        assert!(forced, "{table} must have RLS enabled and forced");
    }
}
