//! PMS-979: per-customer invoice numbering.
//!
//! An invoice number used to come from one counter per tenant, so it read
//! `INV-000042`: it said nothing about whose invoice it was, and it told every
//! customer who received one how many invoices the MSP had issued. Both were
//! survivable while numbers were internal and stopped being so when the portal
//! started showing them.
//!
//! Under the new scheme a number is a short per-customer prefix, a dash, and a
//! per-customer sequence. These tests pin the four properties that make it
//! usable: the prefix is stable and not derived from the name, the sequence is
//! per customer, it is gap-free and unique under concurrency, and switching
//! scheme renumbers nothing.

mod common;

use mokosh_test::mokosh_test;
use serde_json::{json, Value};
use sqlx::PgPool;
use std::collections::HashSet;
use uuid::Uuid;

async fn use_company_prefixes(pool: &PgPool) {
    sqlx::query(
        "INSERT INTO tenant_settings (tenant_id, category, key, value) \
         VALUES ($1, 'billing_prefs', 'invoice_numbering', '\"company_prefix\"'::jsonb) \
         ON CONFLICT (tenant_id, category, key) DO UPDATE SET value = EXCLUDED.value",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .execute(pool)
    .await
    .expect("set the numbering scheme");
}

async fn create_invoice(app: &common::TestApp, token: &str, company_id: Uuid) -> Value {
    let resp = app
        .client
        .post(app.url("/api/v1/invoices"))
        .bearer_auth(token)
        .json(&json!({
            "company_id": company_id,
            "invoice_date": "2026-09-23",
            "due_date": "2026-10-23",
            "lines": [{
                "line_type": "service",
                "description": "Managed services",
                "quantity": "1",
                "unit_price": "100",
            }],
        }))
        .send()
        .await
        .expect("create invoice");
    assert!(
        resp.status().is_success(),
        "create should 2xx, got {}",
        resp.status()
    );
    resp.json().await.expect("invoice JSON")
}

async fn prefix_of(pool: &PgPool, company_id: Uuid) -> Option<String> {
    sqlx::query_scalar("SELECT invoice_prefix FROM companies WHERE id = $1")
        .bind(company_id)
        .fetch_one(pool)
        .await
        .expect("company row")
}

/// The case the issue was filed for: a customer's invoices carry their own
/// prefix and their own consecutive sequence, and another customer's numbering
/// is untouched by it.
#[mokosh_test]
async fn each_customer_gets_their_own_prefix_and_sequence(pool: PgPool) {
    let (_id, email, pw) = common::seed_admin(&pool).await;
    use_company_prefixes(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &pw).await;
    let acme = common::seed_company_named(&pool, "Acme Industries").await;
    let globex = common::seed_company_named(&pool, "Globex").await;

    let first = create_invoice(&app, &token, acme).await;
    let acme_prefix = prefix_of(&pool, acme).await.expect("a prefix was assigned");
    assert_eq!(
        first["invoice_number"].as_str(),
        Some(format!("{acme_prefix}-000001").as_str()),
        "{first}"
    );
    assert_eq!(first["number_scheme"].as_str(), Some("company_prefix"));

    // The same customer's next invoice continues their sequence.
    let second = create_invoice(&app, &token, acme).await;
    assert_eq!(
        second["invoice_number"].as_str(),
        Some(format!("{acme_prefix}-000002").as_str()),
    );

    // A different customer starts at one, under a prefix of their own.
    let other = create_invoice(&app, &token, globex).await;
    let globex_prefix = prefix_of(&pool, globex).await.expect("a prefix");
    assert_ne!(globex_prefix, acme_prefix, "one prefix per customer");
    assert_eq!(
        other["invoice_number"].as_str(),
        Some(format!("{globex_prefix}-000001").as_str()),
        "another customer's sequence is their own: {other}"
    );

    // And the prefix is stable: issuing more invoices never moves it.
    assert_eq!(
        prefix_of(&pool, acme).await.as_deref(),
        Some(acme_prefix.as_str())
    );
}

/// The prefix is drawn, not derived. Two companies with the same name get
/// different prefixes, and neither prefix contains the name, which is what
/// makes it survive a rename.
#[mokosh_test]
async fn the_prefix_is_not_derived_from_the_name(pool: PgPool) {
    let (_id, email, pw) = common::seed_admin(&pool).await;
    use_company_prefixes(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &pw).await;
    let one = common::seed_company_named(&pool, "Identical Name Ltd").await;
    let two = common::seed_company_named(&pool, "Identical Name Ltd 2").await;

    create_invoice(&app, &token, one).await;
    create_invoice(&app, &token, two).await;
    let a = prefix_of(&pool, one).await.expect("prefix");
    let b = prefix_of(&pool, two).await.expect("prefix");
    assert_ne!(a, b);
    for prefix in [&a, &b] {
        assert_eq!(prefix.len(), 4, "{prefix}");
        assert!(
            prefix
                .chars()
                .all(|c| "ABCDEFGHJKMNPQRSTUVWXYZ23456789".contains(c)),
            "no ambiguous characters: {prefix}"
        );
        assert!(
            !prefix.starts_with("ID"),
            "not taken from the name: {prefix}"
        );
    }

    // A rename does not touch it, which is the whole reason it is not derived.
    sqlx::query("UPDATE companies SET name = 'Renamed Entirely' WHERE id = $1")
        .bind(one)
        .execute(&pool)
        .await
        .expect("rename");
    let third = create_invoice(&app, &token, one).await;
    assert_eq!(
        third["invoice_number"].as_str(),
        Some(format!("{a}-000002").as_str()),
        "the customer's numbering survives the rename: {third}"
    );
}

/// Concurrent creates for one customer produce distinct, consecutive numbers.
/// The counter is a row rather than a Postgres sequence precisely so this
/// holds: the second create blocks on the first rather than reading a stale
/// value, and a rollback gives the number back instead of leaving a gap.
#[mokosh_test]
async fn concurrent_creates_are_unique_and_gap_free(pool: PgPool) {
    let (_id, email, pw) = common::seed_admin(&pool).await;
    use_company_prefixes(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &pw).await;
    let company = common::seed_company(&pool).await;

    let mut handles = Vec::new();
    for _ in 0..8 {
        let client = app.client.clone();
        let url = app.url("/api/v1/invoices");
        let token = token.clone();
        handles.push(tokio::spawn(async move {
            let resp = client
                .post(url)
                .bearer_auth(&token)
                .json(&json!({
                    "company_id": company,
                    "invoice_date": "2026-09-23",
                    "due_date": "2026-10-23",
                    "lines": [{
                        "line_type": "service",
                        "description": "Concurrent",
                        "quantity": "1",
                        "unit_price": "10",
                    }],
                }))
                .send()
                .await
                .expect("create");
            assert!(resp.status().is_success(), "{}", resp.status());
            let body: Value = resp.json().await.expect("invoice JSON");
            body["invoice_number"]
                .as_str()
                .expect("a number")
                .to_string()
        }));
    }
    let mut numbers = Vec::new();
    for handle in handles {
        numbers.push(handle.await.expect("join"));
    }

    let distinct: HashSet<&String> = numbers.iter().collect();
    assert_eq!(
        distinct.len(),
        numbers.len(),
        "every number is unique: {numbers:?}"
    );

    let prefix = prefix_of(&pool, company).await.expect("prefix");
    let mut sequences: Vec<i32> = numbers
        .iter()
        .map(|n| {
            let (head, tail) = n.split_once('-').expect("prefix-sequence");
            assert_eq!(head, prefix, "one prefix throughout: {n}");
            tail.parse().expect("a numeric sequence")
        })
        .collect();
    sequences.sort_unstable();
    assert_eq!(
        sequences,
        (1..=8).collect::<Vec<i32>>(),
        "consecutive from one, no gaps: {sequences:?}"
    );
}

/// The default is unchanged, so nothing moves for a tenant that does not opt
/// in, and switching schemes renumbers nothing that already exists.
#[mokosh_test]
async fn the_old_scheme_is_the_default_and_switching_renumbers_nothing(pool: PgPool) {
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &pw).await;
    let company = common::seed_company(&pool).await;

    // No setting: the tenant-wide counter, exactly as before.
    let legacy = create_invoice(&app, &token, company).await;
    let legacy_number = legacy["invoice_number"]
        .as_str()
        .expect("a number")
        .to_string();
    assert!(legacy_number.starts_with("INV-"), "{legacy_number}");
    assert_eq!(legacy["number_scheme"].as_str(), Some("tenant_sequence"));
    assert!(
        prefix_of(&pool, company).await.is_none(),
        "no prefix is assigned to a customer the tenant never opted in for"
    );

    // Switch, and the invoice already issued keeps its number.
    use_company_prefixes(&pool).await;
    let next = create_invoice(&app, &token, company).await;
    let prefix = prefix_of(&pool, company).await.expect("prefix");
    assert_eq!(
        next["invoice_number"].as_str(),
        Some(format!("{prefix}-000001").as_str()),
        "the new scheme starts this customer at one: {next}"
    );

    let unchanged: String = sqlx::query_scalar("SELECT invoice_number FROM invoices WHERE id = $1")
        .bind(Uuid::parse_str(legacy["id"].as_str().expect("id")).expect("uuid"))
        .fetch_one(&pool)
        .await
        .expect("the earlier invoice");
    assert_eq!(unchanged, legacy_number, "history is not renumbered");
    // And it still says which scheme issued it, so the two are tellable apart
    // without parsing the string.
    let scheme: Option<String> =
        sqlx::query_scalar("SELECT number_scheme FROM invoices WHERE id = $1")
            .bind(Uuid::parse_str(legacy["id"].as_str().expect("id")).expect("uuid"))
            .fetch_one(&pool)
            .await
            .expect("scheme");
    assert_eq!(scheme.as_deref(), Some("tenant_sequence"));
}

/// The setting is a closed set, refused at the write: a value outside it would
/// otherwise be read as the default and the tenant would think they had
/// switched when they had not.
#[mokosh_test]
async fn an_unknown_scheme_is_refused(pool: PgPool) {
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &pw).await;

    let resp = app
        .client
        .put(app.url("/api/v1/settings"))
        .bearer_auth(&token)
        .json(&json!({
            "category": "billing_prefs",
            "key": "invoice_numbering",
            "value": "per_year",
        }))
        .send()
        .await
        .expect("set setting");
    assert_eq!(resp.status(), reqwest::StatusCode::UNPROCESSABLE_ENTITY);

    for value in ["tenant_sequence", "company_prefix"] {
        let ok = app
            .client
            .put(app.url("/api/v1/settings"))
            .bearer_auth(&token)
            .json(&json!({
                "category": "billing_prefs",
                "key": "invoice_numbering",
                "value": value,
            }))
            .send()
            .await
            .expect("set setting");
        assert!(ok.status().is_success(), "{value}: {}", ok.status());
    }
}
