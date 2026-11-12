//! PMS-800: the per-client documentation aggregate at
//! `GET /api/v1/companies/{company_id}/documentation` composes three
//! owning services (assets, credential vault, KB) into one response.
//! Each test here pins one of the three axes.

use crate::common;

use mokosh_test::mokosh_test;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_asset_type(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO asset_types (id, tenant_id, name, is_active) VALUES ($1, $2, $3, TRUE)",
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(format!("type-{}", id.simple()))
    .execute(pool)
    .await
    .expect("seed asset_type");
    id
}

async fn seed_asset(pool: &PgPool, company_id: Uuid, name: &str) -> Uuid {
    let type_id = seed_asset_type(pool).await;
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO assets (id, tenant_id, company_id, asset_type_id, name, status) \
         VALUES ($1, $2, $3, $4, $5, 'active')",
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company_id)
    .bind(type_id)
    .bind(name)
    .execute(pool)
    .await
    .expect("seed asset");
    id
}

async fn seed_credential(
    pool: &PgPool,
    company_id: Uuid,
    asset_id: Option<Uuid>,
    name: &str,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO credential_vault \
             (id, tenant_id, company_id, asset_id, name, credential_type, \
              username_encrypted, password_encrypted) \
         VALUES ($1, $2, $3, $4, $5, 'other', ''::bytea, ''::bytea)",
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company_id)
    .bind(asset_id)
    .bind(name)
    .execute(pool)
    .await
    .expect("seed credential");
    id
}

async fn seed_article(pool: &PgPool, author_id: Uuid, company_ids: &[Uuid], title: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO kb_articles \
             (id, tenant_id, author_id, title, slug, content, visibility, status, company_ids) \
         VALUES ($1, $2, $3, $4, $5, '', 'client_specific', 'published', $6)",
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(author_id)
    .bind(title)
    .bind(format!("slug-{}", id.simple()))
    .bind(company_ids)
    .execute(pool)
    .await
    .expect("seed article");
    id
}

#[mokosh_test]
async fn the_aggregate_returns_assets_credentials_and_articles_for_one_company(pool: PgPool) {
    let (admin, email, pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;

    let asset = seed_asset(&pool, company_id, "QB-SRV-01").await;
    seed_credential(&pool, company_id, Some(asset), "QB admin login").await;
    seed_credential(&pool, company_id, None, "Office WiFi").await;
    seed_article(&pool, admin, &[company_id], "How to upgrade QuickBooks").await;

    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &pw).await;

    let resp = app
        .client
        .get(app.url(&format!("/api/v1/companies/{company_id}/documentation")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("documentation GET");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: Value = resp.json().await.expect("body");

    let assets = body["assets"].as_array().expect("assets[]");
    assert_eq!(assets.len(), 1);
    assert_eq!(assets[0]["name"].as_str(), Some("QB-SRV-01"));

    let creds = body["credentials"].as_array().expect("credentials[]");
    assert_eq!(
        creds.len(),
        2,
        "aggregate returns asset-scoped + company-scoped credentials"
    );

    let articles = body["articles"].as_array().expect("articles[]");
    assert_eq!(articles.len(), 1);
    assert_eq!(
        articles[0]["title"].as_str(),
        Some("How to upgrade QuickBooks")
    );
}

#[mokosh_test]
async fn the_aggregate_omits_secret_material(pool: PgPool) {
    let (_admin, email, pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    seed_credential(&pool, company_id, None, "Vendor portal login").await;

    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &pw).await;
    let resp = app
        .client
        .get(app.url(&format!("/api/v1/companies/{company_id}/documentation")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("documentation GET");
    let body: Value = resp.json().await.expect("body");
    let cred = &body["credentials"][0];
    // CredentialSummary deliberately omits every encrypted field; the
    // audited reveal path is the one way to get a password.
    assert!(cred.get("password_encrypted").is_none());
    assert!(cred.get("password").is_none());
    assert!(cred.get("username").is_none());
    assert!(cred.get("notes_encrypted").is_none());
    assert!(cred.get("secret_data").is_none());
}

#[mokosh_test]
async fn the_aggregate_scopes_to_one_company(pool: PgPool) {
    let (admin, email, pw) = common::seed_admin(&pool).await;
    let company_one = common::seed_company_named(&pool, "Acme One").await;
    let company_two = common::seed_company_named(&pool, "Acme Two").await;

    seed_asset(&pool, company_one, "one-01").await;
    seed_asset(&pool, company_two, "two-01").await;
    seed_credential(&pool, company_one, None, "one-cred").await;
    seed_credential(&pool, company_two, None, "two-cred").await;
    seed_article(&pool, admin, &[company_one], "One article").await;
    seed_article(&pool, admin, &[company_two], "Two article").await;

    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &pw).await;

    // Reading company_one returns ONLY company_one's rows.
    let resp = app
        .client
        .get(app.url(&format!("/api/v1/companies/{company_one}/documentation")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("GET");
    let body: Value = resp.json().await.expect("body");
    let assets = body["assets"].as_array().expect("assets[]");
    assert_eq!(assets.len(), 1);
    assert_eq!(assets[0]["name"].as_str(), Some("one-01"));
    let articles = body["articles"].as_array().expect("articles[]");
    assert_eq!(articles.len(), 1);
    assert_eq!(articles[0]["title"].as_str(), Some("One article"));
    let creds = body["credentials"].as_array().expect("credentials[]");
    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0]["name"].as_str(), Some("one-cred"));
}
