//! Integration test: PMS-730 client request forms (MACD) by magic link.
//!
//! Covers the acceptance criteria end to end: an agent sends a client a link,
//! the link resolves to a server-defined form, an invalid submission is
//! rejected per field, a valid one creates a ticket attributed to the right
//! tenant and company and linked to the KB article for that request type, and
//! the link is single-use and expiring.
//!
//! The token is deliberately never returned by the API, so these tests
//! recover it the way the client does: out of the queued email body. That
//! makes the first acceptance criterion ("an MSP user can send a client a
//! request-form link by email") part of every test here rather than something
//! asserted once and then bypassed.

mod common;

use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

/// A minimal new-starter form with a KB article attached, so the created
/// ticket has a procedure to carry.
async fn seed_form_with_article(
    app: &common::TestApp,
    token: &str,
    pool: &PgPool,
    author_id: Uuid,
) -> (String, Uuid) {
    let article_id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO kb_articles
           (id, tenant_id, title, slug, content, visibility, status, author_id)
           VALUES ($1, $2, 'Onboard a new starter', 'onboard-a-new-starter',
                   'Create the account, assign the laptop.', 'internal', 'published', $3)"#,
    )
    .bind(article_id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(author_id)
    .execute(pool)
    .await
    .expect("seed kb article");

    let resp = app
        .client
        .post(app.url("/api/v1/forms"))
        .bearer_auth(token)
        .json(&json!({
            "name": "New starter",
            "slug": "new-starter",
            "kb_article_id": article_id,
            "fields": [
                {
                    "name": "first_name",
                    "label": "First name",
                    "field_type": "text",
                    "is_required": true,
                    "sort_order": 1
                },
                {
                    "name": "start_date",
                    "label": "Start date",
                    "field_type": "date",
                    "is_required": true,
                    "date_not_in_past": true,
                    "sort_order": 2
                },
                {
                    "name": "laptop",
                    "label": "Laptop",
                    "field_type": "select",
                    "is_required": true,
                    "options": ["new", "reuse existing", "none"],
                    "sort_order": 3
                }
            ]
        }))
        .send()
        .await
        .expect("send create form");
    assert!(resp.status().is_success(), "create form should 2xx");
    let body: serde_json::Value = resp.json().await.expect("create form JSON");
    (
        body["id"].as_str().expect("form id").to_string(),
        article_id,
    )
}

/// Issue a link and recover the token from the queued email, the way the
/// recipient would. Returns `(token, link_row_id)`.
async fn issue_link(
    app: &common::TestApp,
    token: &str,
    pool: &PgPool,
    form_id: &str,
    company_id: Uuid,
) -> (String, Uuid) {
    let resp = app
        .client
        .post(app.url("/api/v1/form-request-links"))
        .bearer_auth(token)
        .json(&json!({
            "form_definition_id": form_id,
            "company_id": company_id,
            "recipient_email": "client@example.com"
        }))
        .send()
        .await
        .expect("send issue link");
    let status = resp.status();
    let text = resp.text().await.expect("issue link body");
    assert!(
        status.is_success(),
        "issue link should 2xx, got {status} body={text}"
    );
    let body: serde_json::Value = serde_json::from_str(&text).expect("issue link JSON");

    assert_eq!(body["recipient_email"].as_str(), Some("client@example.com"));
    assert!(body["used_at"].is_null(), "a freshly issued link is unused");
    assert!(
        !text.contains('.') || body.get("token").is_none(),
        "the response must never carry the token itself"
    );
    let link_id = Uuid::parse_str(body["id"].as_str().expect("link id")).expect("link uuid");

    // The token only ever exists in the queued message, which is the whole
    // point: it is a credential for the recipient, not a value the API hands
    // back to its own caller.
    // `notifications.body` is the rendered queue row; `body_text` is the
    // template column it was rendered FROM.
    let body_text: String = sqlx::query_scalar(
        "SELECT body FROM notifications WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 1",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(pool)
    .await
    .expect("a request-link email was queued");

    let token = body_text
        .split("/request-forms/")
        .nth(1)
        .expect("the queued email carries the link")
        .split_whitespace()
        .next()
        .expect("the link has a token")
        .to_string();
    (token, link_id)
}

fn field_codes(body: &serde_json::Value) -> Vec<(String, String)> {
    let mut pairs: Vec<(String, String)> = body["error"]["errors"]
        .as_array()
        .expect("a 422 body carries error.errors[]")
        .iter()
        .map(|e| {
            (
                e["field"].as_str().unwrap_or_default().to_string(),
                e["code"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect();
    pairs.sort();
    pairs
}

/// MAPPS-425: the client received a link to the apex and a subject reading
/// `... request form from {{tenant_name}}`.
///
/// The link host is the whole defect: `/request-forms/:token` exists only in
/// mokosh-apps, and on every deployed environment `CLIENT_ORIGIN` is the apex
/// (bunyip-web hosts login and the OAuth popup there), so a link built from it
/// landed on bunyip's 404. The test harness sets `spa_base_url` to a host that
/// differs from `client_origin` precisely so this cannot pass by coincidence.
#[sqlx::test]
async fn the_emailed_link_points_at_the_spa_and_names_the_tenant(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let app = common::boot(pool.clone()).await;
    let agent_token = common::login(&app, &email, &password).await;
    let (form_id, _article_id) = seed_form_with_article(&app, &agent_token, &pool, admin_id).await;
    let _ = issue_link(&app, &agent_token, &pool, &form_id, company_id).await;

    let (subject, body): (String, String) = sqlx::query_as(
        "SELECT subject, body FROM notifications WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 1",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(&pool)
    .await
    .expect("a request-link email was queued");

    assert!(
        body.contains("http://spa.localhost/request-forms/"),
        "the link must be built from the SPA origin, not the login origin; got body={body}"
    );
    assert!(
        !body.contains("http://localhost/request-forms/"),
        "a link on the login origin is the MAPPS-425 404; got body={body}"
    );

    let tenant_name: String = sqlx::query_scalar("SELECT name FROM tenants WHERE id = $1")
        .bind(common::DEFAULT_TENANT_ID)
        .fetch_one(&pool)
        .await
        .expect("the seeded tenant has a name");
    assert!(
        subject.contains(&tenant_name),
        "the subject must name the MSP; got subject={subject}"
    );
    assert!(
        !subject.contains("{{") && !body.contains("{{"),
        "an unresolved placeholder must never reach a client; subject={subject} body={body}"
    );
}

/// PMS-748: the email has to say who sent it, who it was meant for, how to ask
/// a question, and how to complain. Before this it said none of the four: a
/// client received a request for personal details from an organisation name
/// alone, closing with "if you were not expecting this, you can ignore this
/// message".
///
/// Also the end-to-end check on migration 102, which rewrites the template
/// seeded by 101. The suite applies both, so a mismatch between the copy and
/// the keys the sender supplies fails here as an unresolved placeholder.
#[sqlx::test]
async fn the_email_names_the_sender_the_client_and_how_to_get_help(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let app = common::boot(pool.clone()).await;
    let agent_token = common::login(&app, &email, &password).await;
    let (form_id, _article_id) = seed_form_with_article(&app, &agent_token, &pool, admin_id).await;

    // Give the definition contact details, the optional half of the footer.
    let resp = app
        .client
        .patch(app.url(&format!("/api/v1/forms/{form_id}")))
        .bearer_auth(&agent_token)
        .json(&json!({ "contact_info": "the service desk on 555-0100" }))
        .send()
        .await
        .expect("patch contact_info");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    let _ = issue_link(&app, &agent_token, &pool, &form_id, company_id).await;

    let (subject, body): (String, String) = sqlx::query_as(
        "SELECT subject, body FROM notifications WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 1",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(&pool)
    .await
    .expect("a request-link email was queued");

    assert!(
        body.contains("Test Admin"),
        "the client must be told which PERSON is asking; got body={body}"
    );
    assert!(
        body.contains("Acme Co"),
        "the closing line must say who the message was intended for; got body={body}"
    );
    assert!(
        body.contains("the service desk on 555-0100"),
        "a definition carrying contact details must offer them; got body={body}"
    );
    assert!(
        body.contains("abuse@test.invalid"),
        "the harness configures an abuse address, so the notice must appear; got body={body}"
    );
    assert!(
        !body.contains("you can ignore this message"),
        "the replaced line gave a recipient nothing to check; got body={body}"
    );
    assert!(
        !subject.contains("{{") && !body.contains("{{"),
        "an unresolved placeholder must never reach a client; subject={subject} body={body}"
    );
}

/// The form page is reached from an email by someone with no account here, so
/// it carries its own attribution rather than relying on the message that
/// linked to it still being open.
#[sqlx::test]
async fn the_public_form_names_the_msp(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let app = common::boot(pool.clone()).await;
    let agent_token = common::login(&app, &email, &password).await;
    let (form_id, _article_id) = seed_form_with_article(&app, &agent_token, &pool, admin_id).await;
    let (token, _link_id) = issue_link(&app, &agent_token, &pool, &form_id, company_id).await;

    let form: serde_json::Value = app
        .client
        .get(app.url(&format!("/api/v1/public/request-forms/{token}")))
        .send()
        .await
        .expect("send public get")
        .json()
        .await
        .expect("public form JSON");

    let tenant_name: String = sqlx::query_scalar("SELECT name FROM tenants WHERE id = $1")
        .bind(common::DEFAULT_TENANT_ID)
        .fetch_one(&pool)
        .await
        .expect("the seeded tenant has a name");
    assert_eq!(
        form["tenant_name"].as_str(),
        Some(tenant_name.as_str()),
        "a client must be able to see who is asking without going back to the email"
    );
    assert!(
        form["contact_info"].is_null(),
        "this definition carries no contact details, and none must be invented"
    );
}

#[sqlx::test]
async fn a_link_resolves_to_the_form_without_leaking_internals(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let app = common::boot(pool.clone()).await;
    let agent_token = common::login(&app, &email, &password).await;
    let (form_id, _article_id) = seed_form_with_article(&app, &agent_token, &pool, admin_id).await;
    let (token, _link_id) = issue_link(&app, &agent_token, &pool, &form_id, company_id).await;

    // No auth header: this is the client, who has no session at all.
    let resp = app
        .client
        .get(app.url(&format!("/api/v1/public/request-forms/{token}")))
        .send()
        .await
        .expect("send public get");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let form: serde_json::Value = resp.json().await.expect("public form JSON");

    assert_eq!(form["name"].as_str(), Some("New starter"));
    let fields = form["fields"].as_array().expect("fields[]");
    assert_eq!(fields.len(), 3);
    assert_eq!(fields[0]["name"].as_str(), Some("first_name"));
    assert_eq!(
        fields[2]["options"].as_array().map(|o| o.len()),
        Some(3),
        "the client needs the option set to render the select"
    );

    // The client view carries what is needed to render and validate, and
    // nothing about the tenant's internals. The KB article in particular is an
    // internal procedure for whoever works the ticket.
    assert!(form.get("kb_article_id").is_none());
    assert!(form.get("id").is_none());
    assert!(form.get("created_by_id").is_none());
    assert!(fields[0].get("id").is_none());
}

#[sqlx::test]
async fn an_invalid_submission_is_rejected_per_field_and_leaves_the_link_live(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let app = common::boot(pool.clone()).await;
    let agent_token = common::login(&app, &email, &password).await;
    let (form_id, _) = seed_form_with_article(&app, &agent_token, &pool, admin_id).await;
    let (token, link_id) = issue_link(&app, &agent_token, &pool, &form_id, company_id).await;

    let resp = app
        .client
        .post(app.url(&format!("/api/v1/public/request-forms/{token}")))
        .json(&json!({"payload": {"laptop": "gaming rig"}}))
        .send()
        .await
        .expect("send bad submission");
    assert_eq!(resp.status(), reqwest::StatusCode::UNPROCESSABLE_ENTITY);
    let body: serde_json::Value = resp.json().await.expect("error JSON");
    assert_eq!(
        field_codes(&body),
        vec![
            ("first_name".to_string(), "required".to_string()),
            ("laptop".to_string(), "option".to_string()),
            ("start_date".to_string(), "required".to_string()),
        ]
    );

    // A rejected submission must not burn the link, or a client who mistypes
    // a date would need a new one emailed to them.
    let used_at: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT used_at FROM form_request_tokens WHERE id = $1")
            .bind(link_id)
            .fetch_one(&pool)
            .await
            .expect("link row");
    assert!(
        used_at.is_none(),
        "a rejected submission must leave the link usable"
    );

    let tickets: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tickets WHERE tenant_id = $1")
        .bind(common::DEFAULT_TENANT_ID)
        .fetch_one(&pool)
        .await
        .expect("count tickets");
    assert_eq!(tickets, 0, "a rejected submission must not create a ticket");
}

#[sqlx::test]
async fn a_valid_submission_creates_a_ticket_carrying_the_data_and_the_article(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let app = common::boot(pool.clone()).await;
    let agent_token = common::login(&app, &email, &password).await;
    let (form_id, article_id) = seed_form_with_article(&app, &agent_token, &pool, admin_id).await;
    let (token, link_id) = issue_link(&app, &agent_token, &pool, &form_id, company_id).await;

    let resp = app
        .client
        .post(app.url(&format!("/api/v1/public/request-forms/{token}")))
        .json(&json!({"payload": {
            "first_name": "  Dana  ",
            "start_date": "2099-06-01",
            "laptop": "new"
        }}))
        .send()
        .await
        .expect("send good submission");
    let status = resp.status();
    let text = resp.text().await.expect("submission body");
    assert_eq!(
        status,
        reqwest::StatusCode::CREATED,
        "valid submission should 201, got {status} body={text}"
    );
    let receipt: serde_json::Value = serde_json::from_str(&text).expect("receipt JSON");
    let ticket_number = receipt["ticket_number"]
        .as_str()
        .expect("the client gets a ticket number to quote")
        .to_string();
    assert_eq!(
        receipt.as_object().map(|o| o.len()),
        Some(1),
        "the receipt carries the ticket number and nothing else about the tenant"
    );

    let (
        db_tenant,
        db_company,
        db_article,
        db_title,
        db_description,
        db_source,
        db_created_by,
    ): (
        Uuid,
        Uuid,
        Option<Uuid>,
        String,
        Option<String>,
        String,
        Uuid,
    ) = sqlx::query_as(
        "SELECT tenant_id, company_id, procedure_kb_article_id, title, description, source, created_by_id \
         FROM tickets WHERE ticket_number = $1",
    )
    .bind(&ticket_number)
    .fetch_one(&pool)
    .await
    .expect("the submission created a ticket");

    assert_eq!(db_tenant, common::DEFAULT_TENANT_ID);
    assert_eq!(
        db_company, company_id,
        "the company comes from the link, never from the payload"
    );
    assert_eq!(
        db_article,
        Some(article_id),
        "the ticket carries the KB article for this request type"
    );
    assert_eq!(db_source, "portal");
    assert_eq!(
        db_created_by, admin_id,
        "the acting user is the agent who issued the link; the submitter has no users row"
    );
    assert!(db_title.starts_with("New starter"), "got title {db_title}");

    // The description renders the answers under the form's own labels, in the
    // form's order, so whoever works the ticket reads what the client saw.
    // PMS-747: as a Markdown list. The SPA renders this field as Markdown,
    // where the plain newlines this used to emit are not line breaks, so every
    // answer collapsed into one run-on paragraph.
    let description = db_description.expect("description");
    assert!(
        description.contains("- **First name:** Dana"),
        "got {description}"
    );
    assert!(
        description.contains("- **Start date:** 2099-06-01"),
        "got {description}"
    );
    assert!(
        description.contains("- **Laptop:** new"),
        "got {description}"
    );

    // The chain link -> submission -> ticket is traceable in both directions.
    let (used_at, submission_id): (Option<chrono::DateTime<chrono::Utc>>, Option<Uuid>) =
        sqlx::query_as("SELECT used_at, submission_id FROM form_request_tokens WHERE id = $1")
            .bind(link_id)
            .fetch_one(&pool)
            .await
            .expect("link row");
    assert!(used_at.is_some(), "a redeemed link is burned");
    let submission_id = submission_id.expect("the link records its submission");

    let (payload, ticket_id): (serde_json::Value, Option<Uuid>) =
        sqlx::query_as("SELECT payload, ticket_id FROM form_submissions WHERE id = $1")
            .bind(submission_id)
            .fetch_one(&pool)
            .await
            .expect("submission row");
    assert_eq!(
        payload["first_name"].as_str(),
        Some("Dana"),
        "answers are trimmed before storage"
    );
    assert!(ticket_id.is_some(), "the submission records its ticket");
}

#[sqlx::test]
async fn a_link_is_single_use(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let app = common::boot(pool.clone()).await;
    let agent_token = common::login(&app, &email, &password).await;
    let (form_id, _) = seed_form_with_article(&app, &agent_token, &pool, admin_id).await;
    let (token, _) = issue_link(&app, &agent_token, &pool, &form_id, company_id).await;

    let payload = json!({"payload": {
        "first_name": "Dana",
        "start_date": "2099-06-01",
        "laptop": "new"
    }});

    let first = app
        .client
        .post(app.url(&format!("/api/v1/public/request-forms/{token}")))
        .json(&payload)
        .send()
        .await
        .expect("send first submission");
    assert_eq!(first.status(), reqwest::StatusCode::CREATED);

    let second = app
        .client
        .post(app.url(&format!("/api/v1/public/request-forms/{token}")))
        .json(&payload)
        .send()
        .await
        .expect("send second submission");
    assert_eq!(
        second.status(),
        reqwest::StatusCode::GONE,
        "a used link must not create a second ticket"
    );

    // Reading the form through a used link is refused too, so the client sees
    // the terminal state rather than a form that will fail on submit.
    let reread = app
        .client
        .get(app.url(&format!("/api/v1/public/request-forms/{token}")))
        .send()
        .await
        .expect("send re-read");
    assert_eq!(reread.status(), reqwest::StatusCode::GONE);

    let tickets: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tickets WHERE tenant_id = $1")
        .bind(common::DEFAULT_TENANT_ID)
        .fetch_one(&pool)
        .await
        .expect("count tickets");
    assert_eq!(tickets, 1, "exactly one ticket for one link");
}

#[sqlx::test]
async fn an_expired_or_guessed_link_is_refused_identically(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let app = common::boot(pool.clone()).await;
    let agent_token = common::login(&app, &email, &password).await;
    let (form_id, _) = seed_form_with_article(&app, &agent_token, &pool, admin_id).await;
    let (token, link_id) = issue_link(&app, &agent_token, &pool, &form_id, company_id).await;

    sqlx::query(
        "UPDATE form_request_tokens SET expires_at = NOW() - INTERVAL '1 hour' WHERE id = $1",
    )
    .bind(link_id)
    .execute(&pool)
    .await
    .expect("expire the link");

    let expired = app
        .client
        .get(app.url(&format!("/api/v1/public/request-forms/{token}")))
        .send()
        .await
        .expect("send expired");
    assert_eq!(expired.status(), reqwest::StatusCode::BAD_REQUEST);
    let expired_body: serde_json::Value = expired.json().await.expect("expired JSON");

    // A guessed token, a token for a row that does not exist, and a malformed
    // one must all be indistinguishable from an expired one, or the response
    // becomes an oracle for which token ids are real.
    for candidate in [
        format!("{}.{}", Uuid::new_v4(), "x".repeat(64)),
        "not-a-uuid.secret".to_string(),
        "no-separator".to_string(),
    ] {
        let resp = app
            .client
            .get(app.url(&format!("/api/v1/public/request-forms/{candidate}")))
            .send()
            .await
            .expect("send guessed");
        assert_eq!(
            resp.status(),
            reqwest::StatusCode::BAD_REQUEST,
            "candidate {candidate} should look exactly like an expired link"
        );
        let body: serde_json::Value = resp.json().await.expect("guessed JSON");
        assert_eq!(
            body["error"]["message"], expired_body["error"]["message"],
            "candidate {candidate} must not be distinguishable from an expired link"
        );
    }

    // A token whose id is real but whose secret is wrong must be refused too.
    let (real_id, _) = (link_id, ());
    let wrong_secret = format!("{}.{}", real_id, "x".repeat(64));
    let resp = app
        .client
        .get(app.url(&format!("/api/v1/public/request-forms/{wrong_secret}")))
        .send()
        .await
        .expect("send wrong secret");
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
}
