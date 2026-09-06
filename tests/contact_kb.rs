//! PMS-1082: a contact with `kb:read` reads the knowledge base through
//! the same `/api/v1/kb` routes the staff SPA calls, and sees only the
//! published, Company-visible slice: `public` articles, plus
//! `client_specific` ones naming its Company. Internal, draft, foreign
//! and unknown articles 404 alike; a contact without the capability is
//! 403; the staff arm is unchanged and still behind the module gate.

mod common;

use reqwest::StatusCode;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

struct Fixture {
    author_id: Uuid,
    staff_email: String,
    staff_password: String,
    company_a: Uuid,
    company_b: Uuid,
    pub_art: Uuid,
    a_art: Uuid,
    b_art: Uuid,
    internal_art: Uuid,
    draft_art: Uuid,
    public_cat: Uuid,
    internal_cat: Uuid,
}

async fn seed_company(pool: &PgPool, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(common::DEFAULT_TENANT_ID)
        .bind(name)
        .execute(pool)
        .await
        .expect("seed company");
    id
}

async fn seed_article(
    pool: &PgPool,
    author_id: Uuid,
    slug: &str,
    visibility: &str,
    status: &str,
    company_ids: &[Uuid],
    category_id: Option<Uuid>,
) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO kb_articles \
         (tenant_id, title, slug, content, visibility, status, author_id, company_ids, \
          category_id, published_at) \
         VALUES ($1, $2, $2, 'body', $3, $4, $5, $6, $7, \
                 CASE WHEN $4 = 'published' THEN NOW() ELSE NULL END) \
         RETURNING id",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(slug)
    .bind(visibility)
    .bind(status)
    .bind(author_id)
    .bind(company_ids.to_vec())
    .bind(category_id)
    .fetch_one(pool)
    .await
    .expect("seed article")
}

async fn seed_category(pool: &PgPool, slug: &str, visibility: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO kb_categories (tenant_id, name, slug, visibility) \
         VALUES ($1, $2, $2, $3) RETURNING id",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(slug)
    .bind(visibility)
    .fetch_one(pool)
    .await
    .expect("seed category")
}

async fn seed(pool: &PgPool) -> Fixture {
    let (author_id, staff_email, staff_password) = common::seed_admin(pool).await;
    let company_a = seed_company(pool, "Company A").await;
    let company_b = seed_company(pool, "Company B").await;
    let public_cat = seed_category(pool, "how-to", "public").await;
    let internal_cat = seed_category(pool, "runbooks", "internal").await;
    let pub_art = seed_article(
        pool,
        author_id,
        "pub-art",
        "public",
        "published",
        &[],
        Some(public_cat),
    )
    .await;
    let a_art = seed_article(
        pool,
        author_id,
        "a-art",
        "client_specific",
        "published",
        &[company_a],
        None,
    )
    .await;
    let b_art = seed_article(
        pool,
        author_id,
        "b-art",
        "client_specific",
        "published",
        &[company_b],
        None,
    )
    .await;
    let internal_art = seed_article(
        pool,
        author_id,
        "internal-art",
        "internal",
        "published",
        &[],
        Some(internal_cat),
    )
    .await;
    let draft_art = seed_article(pool, author_id, "draft-art", "public", "draft", &[], None).await;
    Fixture {
        author_id,
        staff_email,
        staff_password,
        company_a,
        company_b,
        pub_art,
        a_art,
        b_art,
        internal_art,
        draft_art,
        public_cat,
        internal_cat,
    }
}

async fn get(app: &common::TestApp, token: &str, path: &str) -> reqwest::Response {
    app.client
        .get(app.url(path))
        .bearer_auth(token)
        .send()
        .await
        .expect("send")
}

async fn get_json(app: &common::TestApp, token: &str, path: &str) -> Value {
    let resp = get(app, token, path).await;
    let status = resp.status();
    let text = resp.text().await.expect("body");
    assert_eq!(status, StatusCode::OK, "GET {path}: {text}");
    serde_json::from_str(&text).expect("JSON")
}

fn slugs(body: &Value) -> Vec<String> {
    let mut v: Vec<String> = body["data"]
        .as_array()
        .expect("data array")
        .iter()
        .map(|a| a["slug"].as_str().expect("slug").to_string())
        .collect();
    v.sort();
    v
}

// A contact with `kb:read` lists exactly the published, Company-visible
// articles, in the customer's projection, and cannot widen the slice
// with the staff filters.
#[sqlx::test]
async fn a_contact_lists_the_published_company_visible_slice(pool: PgPool) {
    let f = seed(&pool).await;
    let contact =
        common::seed_portal_contact(&pool, f.company_a, "a@example.com", &["Support Contact"])
            .await;
    let app = common::boot(pool.clone()).await;
    let token = common::contact_token(&app, &contact).await;

    let body = get_json(&app, &token, "/api/v1/kb/articles?per_page=50").await;
    assert_eq!(slugs(&body), vec!["a-art", "pub-art"]);
    assert_eq!(body["meta"]["total"].as_u64(), Some(2));

    // PMS-1061: the customer's projection, not the staff type.
    let row = &body["data"][0];
    for staff_only in [
        "author_id",
        "view_count",
        "helpful_count",
        "not_helpful_count",
        "company_ids",
        "visibility",
        "status",
        "created_at",
    ] {
        assert!(row.get(staff_only).is_none(), "{staff_only} leaked: {row}");
    }
    for kept in [
        "id",
        "title",
        "slug",
        "content",
        "published_at",
        "tags",
        "updated_at",
    ] {
        assert!(row.get(kept).is_some(), "{kept} missing: {row}");
    }

    // The staff filters cannot widen the slice: asking for drafts or
    // internal articles answers the same two rows, not a different set.
    let widened = get_json(
        &app,
        &token,
        "/api/v1/kb/articles?status=draft&visibility=internal&per_page=50",
    )
    .await;
    assert_eq!(slugs(&widened), vec!["a-art", "pub-art"]);

    // The category and search filters still narrow it.
    let by_cat = get_json(
        &app,
        &token,
        &format!("/api/v1/kb/articles?category_id={}", f.public_cat),
    )
    .await;
    assert_eq!(slugs(&by_cat), vec!["pub-art"]);
    let by_q = get_json(&app, &token, "/api/v1/kb/articles?q=a-art").await;
    assert!(slugs(&by_q).contains(&"a-art".to_string()));
    assert!(!slugs(&by_q).contains(&"b-art".to_string()));
}

// The detail read answers the visible article trimmed, and 404s
// identically for an internal, a draft, another Company's and an
// unknown article.
#[sqlx::test]
async fn a_hidden_article_404s_exactly_like_an_unknown_one(pool: PgPool) {
    let f = seed(&pool).await;
    let contact =
        common::seed_portal_contact(&pool, f.company_a, "a@example.com", &["Read-Only"]).await;
    let app = common::boot(pool.clone()).await;
    let token = common::contact_token(&app, &contact).await;

    let a = get_json(&app, &token, &format!("/api/v1/kb/articles/{}", f.a_art)).await;
    assert_eq!(a["slug"], "a-art");
    assert!(a.get("author_id").is_none());
    let p = get_json(&app, &token, &format!("/api/v1/kb/articles/{}", f.pub_art)).await;
    assert_eq!(p["slug"], "pub-art");

    let unknown = get(
        &app,
        &token,
        &format!("/api/v1/kb/articles/{}", Uuid::new_v4()),
    )
    .await;
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND);
    let unknown_body = unknown.text().await.unwrap();
    for (name, id) in [
        ("internal", f.internal_art),
        ("draft", f.draft_art),
        ("foreign", f.b_art),
    ] {
        let resp = get(&app, &token, &format!("/api/v1/kb/articles/{id}")).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{name} article");
        assert_eq!(
            resp.text().await.unwrap(),
            unknown_body,
            "{name} article must be indistinguishable from an unknown id"
        );
    }

    // A customer's read does not count as a staff view.
    let views: i32 = sqlx::query_scalar("SELECT view_count FROM kb_articles WHERE id = $1")
        .bind(f.a_art)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(views, 0);
}

// Categories: the internal one stays with the staff. (Migration 023
// seeds public categories on the default tenant, so the check is on
// membership rather than the exact set.)
#[sqlx::test]
async fn a_contact_sees_only_non_internal_categories(pool: PgPool) {
    let f = seed(&pool).await;
    let contact =
        common::seed_portal_contact(&pool, f.company_a, "a@example.com", &["Support Contact"])
            .await;
    let app = common::boot(pool.clone()).await;
    let token = common::contact_token(&app, &contact).await;

    let body = get_json(&app, &token, "/api/v1/kb/categories?per_page=50").await;
    let seen = slugs(&body);
    assert!(seen.contains(&"how-to".to_string()), "{seen:?}");
    assert!(!seen.contains(&"runbooks".to_string()), "{seen:?}");
    let rows = body["data"].as_array().unwrap();
    assert_eq!(body["meta"]["total"].as_u64(), Some(rows.len() as u64));
    assert!(
        rows.iter().all(|c| c["visibility"] != "internal"),
        "{seen:?}"
    );
    assert!(rows.iter().all(|c| c["id"] != f.internal_cat.to_string()));
}

// Without `kb:read` (the Billing Contact role has no KB capability),
// every read is 403; with no bearer at all it is 401; and the
// staff-only routes stay closed to a contact bearer.
#[sqlx::test]
async fn without_kb_read_the_reads_are_403(pool: PgPool) {
    let f = seed(&pool).await;
    let billing =
        common::seed_portal_contact(&pool, f.company_a, "b@example.com", &["Billing Contact"])
            .await;
    let reader =
        common::seed_portal_contact(&pool, f.company_a, "r@example.com", &["Read-Only"]).await;
    let app = common::boot(pool.clone()).await;
    let billing_token = common::contact_token(&app, &billing).await;
    let reader_token = common::contact_token(&app, &reader).await;

    for path in [
        "/api/v1/kb/categories".to_string(),
        "/api/v1/kb/articles".to_string(),
        format!("/api/v1/kb/articles/{}", f.pub_art),
    ] {
        let resp = get(&app, &billing_token, &path).await;
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "{path} without kb:read"
        );
        let anon = app.client.get(app.url(&path)).send().await.unwrap();
        assert_eq!(anon.status(), StatusCode::UNAUTHORIZED, "{path} anonymous");
    }

    // The rest of the tree never opened to a contact: versions, the
    // draft, the vote and the write routes all refuse the bearer.
    for path in [
        format!("/api/v1/kb/articles/{}/versions", f.pub_art),
        format!("/api/v1/kb/articles/{}/draft", f.pub_art),
        format!("/api/v1/kb/articles/{}/vote", f.pub_art),
    ] {
        let resp = get(&app, &reader_token, &path).await;
        assert!(
            resp.status() == StatusCode::UNAUTHORIZED || resp.status() == StatusCode::NOT_FOUND,
            "{path} must stay closed to a contact, got {}",
            resp.status()
        );
    }
    let write = app
        .client
        .post(app.url("/api/v1/kb/articles"))
        .bearer_auth(&reader_token)
        .json(&serde_json::json!({ "title": "x", "slug": "x", "content": "x" }))
        .send()
        .await
        .unwrap();
    assert_ne!(write.status(), StatusCode::OK, "a contact cannot author");
    assert_ne!(write.status(), StatusCode::CREATED);
}

// The staff arm is what it was: the whole catalogue with the staff
// type, behind the knowledge_base module gate, which the contact arm
// does not consult.
#[sqlx::test]
async fn the_staff_arm_is_unchanged_and_keeps_its_module_gate(pool: PgPool) {
    let f = seed(&pool).await;
    let contact =
        common::seed_portal_contact(&pool, f.company_b, "b@example.com", &["Support Contact"])
            .await;
    let app = common::boot(pool.clone()).await;
    let staff = common::login(&app, &f.staff_email, &f.staff_password).await;
    let contact_token = common::contact_token(&app, &contact).await;

    let body = get_json(&app, &staff, "/api/v1/kb/articles?per_page=50").await;
    assert_eq!(
        slugs(&body),
        vec!["a-art", "b-art", "draft-art", "internal-art", "pub-art"]
    );
    assert_eq!(
        body["data"][0]["author_id"],
        Value::from(f.author_id.to_string())
    );
    let cats = get_json(&app, &staff, "/api/v1/kb/categories?per_page=50").await;
    let cat_slugs = slugs(&cats);
    assert!(cat_slugs.contains(&"how-to".to_string()), "{cat_slugs:?}");
    assert!(cat_slugs.contains(&"runbooks".to_string()), "{cat_slugs:?}");
    let detail = get_json(
        &app,
        &staff,
        &format!("/api/v1/kb/articles/{}", f.internal_art),
    )
    .await;
    assert_eq!(detail["visibility"], "internal");

    // Company B's contact sees its own slice, not A's.
    let b = get_json(&app, &contact_token, "/api/v1/kb/articles").await;
    assert_eq!(slugs(&b), vec!["b-art", "pub-art"]);

    // Module off: staff 404 on all three reads, the contact still reads.
    let flipped = sqlx::query(
        "UPDATE module_config SET is_enabled = FALSE \
         WHERE tenant_id = $1 AND module_name = 'knowledge_base'",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .execute(&pool)
    .await
    .unwrap()
    .rows_affected();
    assert_eq!(
        flipped, 1,
        "the default tenant carries a knowledge_base row"
    );
    for path in [
        "/api/v1/kb/categories".to_string(),
        "/api/v1/kb/articles".to_string(),
        format!("/api/v1/kb/articles/{}", f.pub_art),
    ] {
        let resp = get(&app, &staff, &path).await;
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "{path} staff, module off"
        );
        let resp = get(&app, &contact_token, &path).await;
        assert_eq!(resp.status(), StatusCode::OK, "{path} contact, module off");
    }
}
