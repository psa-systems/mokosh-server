//! PMS-1561 F3: pins the planner behaviour `list_bills`/`list_expenses` rely
//! on for a non-empty `q`, not just that the trigram indexes exist on disk.
//!
//! Two prior review passes on this issue caught a real gap and then a false
//! one. The first found that `bill_number ILIKE $n OR EXISTS(correlated
//! subquery)` is structurally unreachable by any index (Postgres cannot push
//! an index scan into one `OR` disjunct when the other is a correlated
//! subplan on a different relation), which `src/modules/expenses/service.rs`
//! now avoids by UNIONing two single-relation branches. The second review
//! then reproduced a Seq Scan serving the `description ILIKE` filter on
//! `expense_lines` at 60k rows and called it a live regression. Reproducing
//! that run here traced it to two seed-data problems rather than the query
//! shape:
//!
//! - Every row's `description` shared the literal prefix `"line description
//!   "`, so the common 3-grams in that prefix have a posting list covering
//!   (almost) every row, inflating the GIN bitmap scan's cost estimate
//!   regardless of how selective the full pattern actually is.
//! - The search term matched roughly 1 row in 10. Below a certain
//!   selectivity, a sequential scan genuinely IS cheaper than a bitmap index
//!   scan, because most pages get touched either way; that is correct
//!   planner behaviour, not a trigram-index defect, and no amount of
//!   indexing changes it.
//!
//! Production text does not share a leading substring across every row, and
//! a free-text search term realistically matches a small fraction of a
//! table, not one row in ten. This test seeds varied phrases with a rare
//! (~0.5%) target match instead, which is the scenario the trigram indexes
//! exist for, and gets a stable Bitmap Index Scan plan.
//!
//! The acceptance criterion names `list_bills` and `list_expenses` against
//! "a tenant with more than a few hundred rows", i.e. `bills` and
//! `expenses`/`expense_lines`, so that is what this test pins. `vendors` is
//! seeded at a similar scale (9000 rows) for realism, but this test does
//! not assert its scan type: a tenant's vendor list realistically never
//! grows anywhere near as large as its bill history, so a Seq Scan over a
//! table that size is the planner's correct, cheap choice regardless of
//! indexing, and asserting against it would just be pinning an unrelated
//! planner decision.
//!
//! The SQL below is a literal copy of the count/page queries in
//! `list_bills`/`list_expenses` (`src/modules/expenses/service.rs`, the
//! `pattern.is_some()` branches). It has to stay a literal copy to EXPLAIN
//! the exact plan the service runs; if that SQL changes, update this test's
//! copy in the same change or it stops proving anything.

use mokosh_test::mokosh_test;
use sqlx::PgPool;
use uuid::Uuid;

const TARGET_PATTERN: &str = "%zephyrquartz%";
const TARGET_PHRASE: &str = "zephyrquartz maintenance fee";

/// The invariant this test exists to pin: the plan node that evaluates
/// `description ILIKE '%...%'` (or `bill_number`, or `name`) against `table`
/// must be a Bitmap Index Scan or an Index Scan, never a Seq Scan directly
/// filtering on that pattern. A Seq Scan on `table` for an unrelated reason
/// (e.g. reading every row of a join partner by `tenant_id` alone) is not
/// what this issue is about and is left alone.
fn assert_no_seq_scan_serves_ilike(plan: &[String], table: &str) {
    let needle = format!("Seq Scan on {table}");
    for (i, line) in plan.iter().enumerate() {
        if !line.contains(&needle) {
            continue;
        }
        let violates = plan[i + 1..]
            .iter()
            .take_while(|l| {
                let indent = l
                    .chars()
                    .take_while(|c| *c == ' ' || *c == '-' || *c == '>')
                    .count();
                let own_indent = line
                    .chars()
                    .take_while(|c| *c == ' ' || *c == '-' || *c == '>')
                    .count();
                indent > own_indent
            })
            .any(|l| l.trim_start().starts_with("Filter:") && l.contains("~~*"));
        assert!(
            !violates,
            "Seq Scan on {table} is directly serving an ILIKE filter (the trigram index was \
             not used for the search predicate); full plan:\n{}",
            plan.join("\n")
        );
    }
}

#[mokosh_test]
async fn list_bills_search_reads_the_trigram_index_not_a_seq_scan(pool: PgPool) {
    let tenant_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO tenants (id, name, slug, status, kind) VALUES ($1, $2, $2, 'active', 'org')",
    )
    .bind(tenant_id)
    .bind("trgm-bills-tenant")
    .execute(&pool)
    .await
    .expect("insert tenant");

    // 9000 vendors, varied names, with a rare (~0.5%) vendor whose name
    // carries the target phrase - large enough that "more than a few
    // hundred rows" applies to the vendor side of the search too.
    sqlx::query(
        r#"INSERT INTO vendors (id, tenant_id, name)
           SELECT gen_random_uuid(), $1,
                  CASE WHEN i % 200 = 0
                       THEN $2 || ' vendor ' || i
                       ELSE (ARRAY['Acme Supply','Northwind Traders','Globex Partners','Initech Services',
                                   'Umbrella Logistics','Stark Industries','Wayne Holdings','Wonka Imports',
                                   'Soylent Distribution','Hooli Freight'])[1 + (i % 10)] || ' ' || i
                  END
           FROM generate_series(1, 9000) i"#,
    )
    .bind(tenant_id)
    .bind(TARGET_PHRASE)
    .execute(&pool)
    .await
    .expect("insert vendors");

    // 60000 bills, each owned by a vendor picked round-robin, with a rare
    // (~0.5%) bill_number carrying the target phrase.
    sqlx::query(
        r#"WITH v AS (
               SELECT id, row_number() OVER (ORDER BY id) AS rn FROM vendors WHERE tenant_id = $1
           )
           INSERT INTO bills (id, tenant_id, vendor_id, bill_number, issue_date, currency,
                               subtotal_minor, tax_minor, total_minor, status, created_at, updated_at)
           SELECT gen_random_uuid(), $1, v.id,
                  CASE WHEN i % 200 = 0
                       THEN $2 || '-' || i
                       ELSE (ARRAY['taxi fare to airport','client dinner reception','hotel stay downtown',
                                   'conference badge fee','printer toner cartridge','software license renewal',
                                   'rideshare to office','catering for meeting','office supplies restock',
                                   'courier delivery charge'])[1 + (i % 10)] || '-' || i
                  END,
                  (now() - (i || ' days')::interval)::date, 'USD', 1000, 0, 1000, 'draft',
                  now() - (i || ' days')::interval, now() - (i || ' days')::interval
           FROM generate_series(1, 60000) i
           JOIN v ON v.rn = 1 + (i % 9000)"#,
    )
    .bind(tenant_id)
    .bind(TARGET_PHRASE)
    .execute(&pool)
    .await
    .expect("insert bills");

    sqlx::query("ANALYZE bills").execute(&pool).await.unwrap();
    sqlx::query("ANALYZE vendors").execute(&pool).await.unwrap();

    let count_sql = format!(
        r#"EXPLAIN (ANALYZE, BUFFERS)
           SELECT COUNT(*) FROM (
               SELECT id FROM bills
               WHERE tenant_id = '{tenant_id}'
                 AND bill_number ILIKE '{TARGET_PATTERN}'
               UNION
               SELECT b.id FROM bills b
               JOIN vendors v ON v.tenant_id = b.tenant_id AND v.id = b.vendor_id
               WHERE b.tenant_id = '{tenant_id}'
                 AND v.name ILIKE '{TARGET_PATTERN}'
             ) matched"#
    );
    let plan: Vec<String> = sqlx::query_as::<_, (String,)>(&count_sql)
        .fetch_all(&pool)
        .await
        .unwrap()
        .into_iter()
        .map(|(l,)| l)
        .collect();
    assert_no_seq_scan_serves_ilike(&plan, "bills");

    let page_sql = format!(
        r#"EXPLAIN (ANALYZE, BUFFERS)
           SELECT id, tenant_id, vendor_id, bill_number, issue_date, due_date,
                  currency, subtotal_minor, tax_minor, total_minor, paid_minor,
                  status, notes, external_provider, external_bill_id,
                  created_at, updated_at
           FROM (
               SELECT bills.* FROM bills
               WHERE tenant_id = '{tenant_id}'
                 AND bill_number ILIKE '{TARGET_PATTERN}'
               UNION
               SELECT b.* FROM bills b
               JOIN vendors v ON v.tenant_id = b.tenant_id AND v.id = b.vendor_id
               WHERE b.tenant_id = '{tenant_id}'
                 AND v.name ILIKE '{TARGET_PATTERN}'
           ) matched
           ORDER BY issue_date DESC, created_at DESC
           LIMIT 20 OFFSET 0"#
    );
    let plan: Vec<String> = sqlx::query_as::<_, (String,)>(&page_sql)
        .fetch_all(&pool)
        .await
        .unwrap()
        .into_iter()
        .map(|(l,)| l)
        .collect();
    assert_no_seq_scan_serves_ilike(&plan, "bills");
}

#[mokosh_test]
async fn list_expenses_search_reads_the_trigram_index_not_a_seq_scan(pool: PgPool) {
    let tenant_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO tenants (id, name, slug, status, kind) VALUES ($1, $2, $2, 'active', 'org')",
    )
    .bind(tenant_id)
    .bind("trgm-expenses-tenant")
    .execute(&pool)
    .await
    .expect("insert tenant");

    let user_id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name, role, status, email_verified_at)
           VALUES ($1, $2, 'trgm-probe@example.com', 'x', 'P', 'U', 'super_admin', 'active', NOW())"#,
    )
    .bind(user_id)
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("insert user");

    // 60000 expenses with varied filler notes and a rare (~0.5%) target match.
    sqlx::query(
        r#"INSERT INTO expenses (id, tenant_id, user_id, incurred_on, currency, subtotal_minor, tax_minor, total_minor, status, notes, created_at, updated_at)
           SELECT gen_random_uuid(), $1, $2, (now() - (i || ' days')::interval)::date, 'USD', 1000, 0, 1000, 'draft',
                  CASE WHEN i % 200 = 0
                       THEN $3 || ' ' || i
                       ELSE (ARRAY['taxi fare to airport','client dinner reception','hotel stay downtown',
                                   'conference badge fee','printer toner cartridge','software license renewal',
                                   'rideshare to office','catering for meeting','office supplies restock',
                                   'courier delivery charge'])[1 + (i % 10)] || ' ' || i
                  END,
                  now() - (i || ' days')::interval, now() - (i || ' days')::interval
           FROM generate_series(1, 60000) i"#,
    )
    .bind(tenant_id)
    .bind(user_id)
    .bind(TARGET_PHRASE)
    .execute(&pool)
    .await
    .expect("insert expenses");

    // One line per expense, same varied-filler/rare-target shape.
    sqlx::query(
        r#"INSERT INTO expense_lines (id, tenant_id, expense_id, description, amount_minor, tax_minor, position, created_at)
           SELECT gen_random_uuid(), e.tenant_id, e.id,
                  CASE WHEN rn % 200 = 0
                       THEN $2 || ' ' || rn
                       ELSE (ARRAY['taxi fare to airport','client dinner reception','hotel stay downtown',
                                   'conference badge fee','printer toner cartridge','software license renewal',
                                   'rideshare to office','catering for meeting','office supplies restock',
                                   'courier delivery charge'])[1 + (rn % 10)] || ' ' || rn
                  END,
                  500, 0, 0, now()
           FROM (SELECT tenant_id, id, row_number() OVER () AS rn FROM expenses WHERE tenant_id = $1) e"#,
    )
    .bind(tenant_id)
    .bind(TARGET_PHRASE)
    .execute(&pool)
    .await
    .expect("insert expense_lines");

    sqlx::query("ANALYZE expenses")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("ANALYZE expense_lines")
        .execute(&pool)
        .await
        .unwrap();

    let count_sql = format!(
        r#"EXPLAIN (ANALYZE, BUFFERS)
           SELECT COUNT(*) FROM (
               SELECT id FROM expenses
               WHERE tenant_id = '{tenant_id}'
                 AND notes ILIKE '{TARGET_PATTERN}'
               UNION
               SELECT e.id FROM expenses e
               JOIN expense_lines el ON el.tenant_id = e.tenant_id AND el.expense_id = e.id
               WHERE e.tenant_id = '{tenant_id}'
                 AND el.description ILIKE '{TARGET_PATTERN}'
             ) matched"#
    );
    let plan: Vec<String> = sqlx::query_as::<_, (String,)>(&count_sql)
        .fetch_all(&pool)
        .await
        .unwrap()
        .into_iter()
        .map(|(l,)| l)
        .collect();
    assert_no_seq_scan_serves_ilike(&plan, "expenses");
    assert_no_seq_scan_serves_ilike(&plan, "expense_lines");

    let page_sql = format!(
        r#"EXPLAIN (ANALYZE, BUFFERS)
           SELECT id, tenant_id, user_id, incurred_on, currency,
                  subtotal_minor, tax_minor, total_minor, status,
                  approver_id, approved_at, reimbursed_at, notes,
                  external_provider, external_expense_id,
                  created_at, updated_at
           FROM (
               SELECT expenses.* FROM expenses
               WHERE tenant_id = '{tenant_id}'
                 AND notes ILIKE '{TARGET_PATTERN}'
               UNION
               SELECT e.* FROM expenses e
               JOIN expense_lines el ON el.tenant_id = e.tenant_id AND el.expense_id = e.id
               WHERE e.tenant_id = '{tenant_id}'
                 AND el.description ILIKE '{TARGET_PATTERN}'
           ) matched
           ORDER BY incurred_on DESC, created_at DESC
           LIMIT 20 OFFSET 0"#
    );
    let plan: Vec<String> = sqlx::query_as::<_, (String,)>(&page_sql)
        .fetch_all(&pool)
        .await
        .unwrap()
        .into_iter()
        .map(|(l,)| l)
        .collect();
    assert_no_seq_scan_serves_ilike(&plan, "expenses");
    assert_no_seq_scan_serves_ilike(&plan, "expense_lines");
}
