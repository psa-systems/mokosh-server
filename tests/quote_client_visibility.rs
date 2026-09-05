//! PMS-1060: a contact sees only the quotes that were issued to it.
//!
//! The dual-plane quote reads (`GET /api/v1/quotes`, `/quotes/{id}`,
//! `/quotes/{id}/pdf`, taking a contact bearer through
//! `RequireCallerContext`) scoped a contact to its company and nothing
//! else, so a `draft`, `submitted` or `approved` quote for the caller's own
//! company was in the list and a 200 by id: a customer saw the MSP's
//! pricing work in progress, including a quote the MSP decided not to
//! send. The retired portal router filtered to the issued statuses and
//! answered 404 for anything else, so the portal never confirmed an
//! internal quote existed. The contact arms now go through
//! `QuotesService::list_quotes_for_company` and `get_quote_for_company`,
//! which are those rules.
//!
//! Self-contained rather than on `tests/common`'s contact helper, because
//! that helper lands with the PMS-1031 port; the seed here writes the row
//! the way `grant_portal_access` leaves it.

mod common;

use reqwest::StatusCode;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

const CONTACT_PASSWORD: &str = "Kq7$mZ2n#PxR9wLf";

async fn seed_company(pool: &PgPool, name: &str) -> (Uuid, String) {
    let id = Uuid::new_v4();
    let slug = format!("co-{}", &id.simple().to_string()[..12]);
    sqlx::query("INSERT INTO companies (id, tenant_id, name, portal_slug) VALUES ($1, $2, $3, $4)")
        .bind(id)
        .bind(common::DEFAULT_TENANT_ID)
        .bind(name)
        .bind(&slug)
        .execute(pool)
        .await
        .expect("seed company");
    (id, slug)
}

/// A portal contact holding the Billing Contact role (`quotes:read`,
/// `quotes:accept`, migration 171), signed in on the contact plane.
async fn contact_token(
    app: &common::TestApp,
    pool: &PgPool,
    company_id: Uuid,
    slug: &str,
) -> String {
    let contact_id = Uuid::new_v4();
    let email = format!("{contact_id}@client.example");
    let hash = mokosh_server::utils::crypto::hash_password(CONTACT_PASSWORD).expect("hash");
    sqlx::query(
        "INSERT INTO contacts \
            (id, tenant_id, company_id, first_name, last_name, email, \
             is_portal_user, portal_password_hash) \
         VALUES ($1, $2, $3, 'Portal', 'Contact', $4, TRUE, $5)",
    )
    .bind(contact_id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company_id)
    .bind(&email)
    .bind(&hash)
    .execute(pool)
    .await
    .expect("seed contact");
    let role_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM portal_roles WHERE tenant_id = $1 AND name = 'Billing Contact'",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(pool)
    .await
    .expect("Billing Contact role");
    sqlx::query(
        "INSERT INTO contact_role_assignments (contact_id, role_id, tenant_id) VALUES ($1, $2, $3)",
    )
    .bind(contact_id)
    .bind(role_id)
    .bind(common::DEFAULT_TENANT_ID)
    .execute(pool)
    .await
    .expect("assign role");

    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/login"))
        .json(&serde_json::json!({ "slug": slug, "email": email, "password": CONTACT_PASSWORD }))
        .send()
        .await
        .expect("contact login");
    assert_eq!(resp.status(), StatusCode::OK, "contact login");
    let body: Value = resp.json().await.expect("login JSON");
    body["access_token"]
        .as_str()
        .expect("access_token")
        .to_string()
}

/// A quote in the given stored status, written directly so the fixture
/// does not depend on the approval walk.
async fn seed_quote(pool: &PgPool, company_id: Uuid, admin_id: Uuid, status: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO quotes (id, tenant_id, company_id, title, status, requested_by_id) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company_id)
    .bind(format!("Quote in {status}"))
    .bind(status)
    .bind(admin_id)
    .execute(pool)
    .await
    .expect("seed quote");
    id
}

/// The list carries the issued quotes and none of the working state; by
/// id, an un-issued quote is a 404 on the read, the document and the
/// decision alike, so the id is never confirmed.
#[sqlx::test]
async fn a_contact_sees_issued_quotes_and_nothing_else(pool: PgPool) {
    let (admin_id, admin_email, admin_pw) = common::seed_admin(&pool).await;
    let (company, slug) = seed_company(&pool, "Client A").await;
    let (other, _) = seed_company(&pool, "Client B").await;
    let mut issued = Vec::new();
    for status in ["sent", "accepted", "declined", "expired", "converted"] {
        issued.push(seed_quote(&pool, company, admin_id, status).await);
    }
    let mut hidden = Vec::new();
    for status in ["draft", "submitted", "approved", "rejected", "cancelled"] {
        hidden.push(seed_quote(&pool, company, admin_id, status).await);
    }
    let others_sent = seed_quote(&pool, other, admin_id, "sent").await;

    let app = common::boot(pool.clone()).await;
    let token = contact_token(&app, &pool, company, &slug).await;

    let listed: Value = app
        .client
        .get(app.url("/api/v1/quotes?per_page=50"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("contact list")
        .json()
        .await
        .expect("list JSON");
    let ids: Vec<Uuid> = listed["data"]
        .as_array()
        .expect("data")
        .iter()
        .filter_map(|q| q["id"].as_str().and_then(|s| Uuid::parse_str(s).ok()))
        .collect();
    assert_eq!(listed["meta"]["total"].as_u64(), Some(5), "{listed}");
    for id in &issued {
        assert!(ids.contains(id), "issued quote {id} missing: {listed}");
    }
    for id in &hidden {
        assert!(!ids.contains(id), "un-issued quote {id} leaked: {listed}");
    }
    assert!(
        !ids.contains(&others_sent),
        "another company's quote leaked"
    );

    for id in hidden.iter().chain(std::iter::once(&others_sent)) {
        for path in [
            format!("/api/v1/quotes/{id}"),
            format!("/api/v1/quotes/{id}/pdf"),
        ] {
            let resp = app
                .client
                .get(app.url(&path))
                .bearer_auth(&token)
                .send()
                .await
                .expect("contact get");
            assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{path}");
        }
        let decide = app
            .client
            .post(app.url(&format!("/api/v1/quotes/{id}/accept")))
            .bearer_auth(&token)
            .send()
            .await
            .expect("contact accept");
        assert_eq!(decide.status(), StatusCode::NOT_FOUND, "accept {id}");
    }

    // An issued quote reads, and staff still see everything.
    let read = app
        .client
        .get(app.url(&format!("/api/v1/quotes/{}", issued[0])))
        .bearer_auth(&token)
        .send()
        .await
        .expect("contact get issued");
    assert_eq!(read.status(), StatusCode::OK);
    let staff = common::login(&app, &admin_email, &admin_pw).await;
    let staff_list: Value = app
        .client
        .get(app.url(&format!("/api/v1/quotes?company_id={company}&per_page=50")))
        .bearer_auth(&staff)
        .send()
        .await
        .expect("staff list")
        .json()
        .await
        .expect("staff list JSON");
    assert_eq!(
        staff_list["meta"]["total"].as_u64(),
        Some(10),
        "{staff_list}"
    );
}
