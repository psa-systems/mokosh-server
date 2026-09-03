//! PMS-931: editing a ticket note.
//!
//! `/api/v1/tickets/{id}/notes` served GET and POST and nothing else, so a note
//! was append-only for everyone at every role, its author included. Reported as
//! MAPPS-593 ("the MSP owner cannot edit internal notes"), which framed it as a
//! permission problem; there was no update path being denied to admins, there
//! was no update path.
//!
//! Two gates answer differently and both are pinned here. WHO may edit is a
//! permission, so the wrong caller gets 403. WHETHER this row may be edited at
//! all is the row's state rather than the caller's rights, so it gets 409.

mod common;

use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_note(
    pool: &PgPool,
    ticket_id: Uuid,
    author: Uuid,
    note_type: &str,
    emailed: bool,
    contact: Option<Uuid>,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO ticket_notes
           (id, tenant_id, ticket_id, content, note_type, created_by_id,
            is_email_sent, created_by_contact_id)
           VALUES ($1, $2, $3, 'the original text', $4, $5, $6, $7)"#,
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(ticket_id)
    .bind(note_type)
    .bind(author)
    .bind(emailed)
    .bind(contact)
    .execute(pool)
    .await
    .expect("seed note");
    id
}

async fn seed_contact(pool: &PgPool, company_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO contacts (id, tenant_id, company_id, first_name, last_name, email) \
         VALUES ($1, $2, $3, 'Portal', 'Person', $4)",
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company_id)
    .bind(format!("portal-{}@example.com", &id.to_string()[..8]))
    .execute(pool)
    .await
    .expect("seed contact");
    id
}

async fn edit(
    app: &common::TestApp,
    token: &str,
    ticket_id: Uuid,
    note_id: Uuid,
    content: &str,
) -> reqwest::Response {
    app.client
        .put(app.url(&format!("/api/v1/tickets/{ticket_id}/notes/{note_id}")))
        .bearer_auth(token)
        .json(&serde_json::json!({ "content": content }))
        .send()
        .await
        .expect("send note edit")
}

#[sqlx::test(migrations = "./migrations")]
async fn the_author_can_correct_their_own_note(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let (ticket_id, _) = common::seed_ticket_and_note(&pool, admin_id, company_id).await;
    let note_id = seed_note(&pool, ticket_id, admin_id, "internal", false, None).await;

    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let resp = edit(&app, &token, ticket_id, note_id, "the corrected text").await;
    assert_eq!(resp.status(), 200, "{:?}", resp.text().await);
    let body: Value = resp.json().await.expect("JSON body");
    assert_eq!(body["content"], "the corrected text");

    let stored: String = sqlx::query_scalar("SELECT content FROM ticket_notes WHERE id = $1")
        .bind(note_id)
        .fetch_one(&pool)
        .await
        .expect("read back");
    assert_eq!(stored, "the corrected text");

    // `ticket_notes` carries no `updated_at` trigger, so the UPDATE has to set
    // it. Without this the client cannot mark the note as edited and an edit is
    // silent, which is worse than not editing.
    let (created, updated): (chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>) =
        sqlx::query_as("SELECT created_at, updated_at FROM ticket_notes WHERE id = $1")
            .bind(note_id)
            .fetch_one(&pool)
            .await
            .expect("read timestamps");
    assert!(
        updated > created,
        "updated_at moved: {updated} vs {created}"
    );
    assert!(
        body["updated_at"].as_str().is_some(),
        "and the response carries it: {body}"
    );
}

/// What makes editing acceptable at all: the original text survives it. An
/// audit row with only the new value would let an edit quietly rewrite history.
#[sqlx::test(migrations = "./migrations")]
async fn the_audit_row_keeps_the_text_that_was_replaced(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let (ticket_id, _) = common::seed_ticket_and_note(&pool, admin_id, company_id).await;
    let note_id = seed_note(&pool, ticket_id, admin_id, "internal", false, None).await;

    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let resp = edit(&app, &token, ticket_id, note_id, "the corrected text").await;
    assert_eq!(resp.status(), 200);

    let (old, new): (Option<Value>, Option<Value>) = sqlx::query_as(
        "SELECT old_values, new_values FROM audit_log \
         WHERE entity_type = 'ticket_notes' AND entity_id = $1 AND action = 'update'",
    )
    .bind(note_id)
    .fetch_one(&pool)
    .await
    .expect("an update audit row exists");

    assert_eq!(
        old.expect("before image")["content"],
        "the original text",
        "the replaced text is recoverable"
    );
    assert_eq!(new.expect("after image")["content"], "the corrected text");
}

#[sqlx::test(migrations = "./migrations")]
async fn an_admin_can_correct_somebody_elses_note(pool: PgPool) {
    let (admin_id, admin_email, admin_password) = common::seed_admin(&pool).await;
    let (tech_id, _, _) = common::seed_user(
        &pool,
        common::DEFAULT_TENANT_ID,
        "tech@example.com",
        "technician",
    )
    .await;
    let company_id = common::seed_company(&pool).await;
    let (ticket_id, _) = common::seed_ticket_and_note(&pool, admin_id, company_id).await;
    let note_id = seed_note(&pool, ticket_id, tech_id, "internal", false, None).await;

    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &admin_email, &admin_password).await;

    let resp = edit(&app, &token, ticket_id, note_id, "corrected by the owner").await;
    assert_eq!(resp.status(), 200, "{:?}", resp.text().await);
}

/// The half the report actually asked about, from the other side: everyone
/// else corrects their own and nobody else's.
#[sqlx::test(migrations = "./migrations")]
async fn a_technician_cannot_edit_a_note_they_did_not_write(pool: PgPool) {
    let (admin_id, _, _) = common::seed_admin(&pool).await;
    let (_, tech_email, tech_password) = common::seed_user(
        &pool,
        common::DEFAULT_TENANT_ID,
        "tech@example.com",
        "technician",
    )
    .await;
    let company_id = common::seed_company(&pool).await;
    let (ticket_id, _) = common::seed_ticket_and_note(&pool, admin_id, company_id).await;
    let note_id = seed_note(&pool, ticket_id, admin_id, "internal", false, None).await;

    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &tech_email, &tech_password).await;

    let resp = edit(&app, &token, ticket_id, note_id, "not mine to touch").await;
    assert_eq!(resp.status(), 403);

    let stored: String = sqlx::query_scalar("SELECT content FROM ticket_notes WHERE id = $1")
        .bind(note_id)
        .fetch_one(&pool)
        .await
        .expect("read back");
    assert_eq!(
        stored, "the original text",
        "a refused edit changes nothing"
    );
}

/// A row whose state forbids the edit answers 409, not 403: the caller has the
/// right to edit notes and this particular row is what refuses. Each reason
/// arrives as a sentence, because "Conflict" alone does not tell an agent
/// which of the rules they hit.
#[sqlx::test(migrations = "./migrations")]
async fn a_frozen_note_refuses_with_a_reason(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let (ticket_id, _) = common::seed_ticket_and_note(&pool, admin_id, company_id).await;
    let contact_id = seed_contact(&pool, company_id).await;

    let emailed = seed_note(&pool, ticket_id, admin_id, "public", true, None).await;
    let from_portal = seed_note(
        &pool,
        ticket_id,
        admin_id,
        "public",
        false,
        Some(contact_id),
    )
    .await;
    let from_time = seed_note(&pool, ticket_id, admin_id, "time_entry", false, None).await;

    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    for (note_id, expect) in [
        (emailed, "emailed"),
        (from_portal, "customer"),
        (from_time, "time entry"),
    ] {
        let resp = edit(&app, &token, ticket_id, note_id, "rewritten").await;
        assert_eq!(resp.status(), 409, "note {note_id} should refuse");
        let body: Value = resp.json().await.expect("JSON body");
        let text = body.to_string();
        assert!(
            text.contains(expect),
            "the refusal names the reason ({expect}): {text}"
        );

        let stored: String = sqlx::query_scalar("SELECT content FROM ticket_notes WHERE id = $1")
            .bind(note_id)
            .fetch_one(&pool)
            .await
            .expect("read back");
        assert_eq!(stored, "the original text");
    }
}

/// A public note nobody emailed is still editable. The customer may have read
/// it in the portal, but there is no copy outside the system to disagree with,
/// so freezing it would cost the agent a correction for nothing.
#[sqlx::test(migrations = "./migrations")]
async fn a_public_note_that_was_never_emailed_is_editable(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let (ticket_id, _) = common::seed_ticket_and_note(&pool, admin_id, company_id).await;
    let note_id = seed_note(&pool, ticket_id, admin_id, "public", false, None).await;

    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let resp = edit(&app, &token, ticket_id, note_id, "corrected").await;
    assert_eq!(resp.status(), 200, "{:?}", resp.text().await);
}

/// A note id under the wrong ticket is a 404, the same answer an id that does
/// not exist gets, so the path is not an existence oracle for other tickets'
/// notes.
#[sqlx::test(migrations = "./migrations")]
async fn a_note_from_another_ticket_is_not_found(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let (ticket_a, _) = common::seed_ticket_and_note(&pool, admin_id, company_id).await;
    let (ticket_b, _) = common::seed_ticket_and_note(&pool, admin_id, company_id).await;
    let note_on_b = seed_note(&pool, ticket_b, admin_id, "internal", false, None).await;

    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let resp = edit(&app, &token, ticket_a, note_on_b, "wrong ticket").await;
    assert_eq!(resp.status(), 404);

    let unknown = edit(&app, &token, ticket_a, Uuid::new_v4(), "no such note").await;
    assert_eq!(
        unknown.status(),
        404,
        "and an id that exists nowhere answers identically"
    );
}

/// The same rule `CreateNoteRequest` applies. An edit that blanks a note is a
/// delete wearing an edit's clothes, and deleting is not what this endpoint is.
#[sqlx::test(migrations = "./migrations")]
async fn an_edit_cannot_blank_a_note(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let (ticket_id, _) = common::seed_ticket_and_note(&pool, admin_id, company_id).await;
    let note_id = seed_note(&pool, ticket_id, admin_id, "internal", false, None).await;

    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let resp = edit(&app, &token, ticket_id, note_id, "").await;
    assert_eq!(resp.status(), 422, "{:?}", resp.text().await);
}

/// The edit changes the text and nothing else. `note_type` in the body is not a
/// field the request carries, so an internal note cannot be published by
/// editing it, and a public one cannot be retracted.
#[sqlx::test(migrations = "./migrations")]
async fn an_edit_cannot_change_what_kind_of_note_it_is(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let (ticket_id, _) = common::seed_ticket_and_note(&pool, admin_id, company_id).await;
    let note_id = seed_note(&pool, ticket_id, admin_id, "internal", false, None).await;

    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let resp = app
        .client
        .put(app.url(&format!("/api/v1/tickets/{ticket_id}/notes/{note_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "content": "still internal", "note_type": "public" }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);

    let kind: String = sqlx::query_scalar("SELECT note_type FROM ticket_notes WHERE id = $1")
        .bind(note_id)
        .fetch_one(&pool)
        .await
        .expect("read back");
    assert_eq!(kind, "internal", "the extra field is ignored, not applied");
}
