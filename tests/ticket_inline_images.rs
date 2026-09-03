//! PMS-941: an image embedded in a ticket description or note, and the public
//! URL an `<img>` can actually fetch.
//!
//! The read is unauthenticated by necessity, exactly as PMS-923's KB image is:
//! a browser fetches an embedded image as `<img src="...">`, which carries no
//! `Authorization` header, and the SPA holds a bearer rather than a cookie.
//!
//! The difference from the KB case, and what most of this file pins, is that
//! `ticket_attachments` is a SHARED table. It already held portal uploads and
//! inbound-email attachments (PMS-450) when this route was added, all stored
//! under an authenticated-only contract, and it has no MIME allowlist. So the
//! public read answers for rows carrying `is_inline` and nothing else, and the
//! tests below check the negative case as hard as the positive one.

mod common;

use reqwest::multipart::{Form, Part};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

/// Point the upload root somewhere writable, and hold the whole binary to a
/// 1 KiB cap. Set before `common::boot`, because `AttachmentConfig::from_env`
/// is read when the router is built.
///
/// The same values for every case in this file on purpose: env is
/// process-global and `#[sqlx::test]` cases in one binary run concurrently, so
/// a case that changed the cap for itself would change it under its neighbours.
/// 1 KiB is also what proves the inline cap is a floor rather than a fixed
/// 5 MiB: the oversize case below is refused at 4 KiB, well under 5 MiB,
/// because lowering `ATTACHMENT_MAX_BYTES` lowers the inline cap with it.
fn install_test_attachment_env() {
    common::storage_root();
    std::env::set_var("ATTACHMENT_MAX_BYTES", "1024");
}

/// A one-pixel PNG, so the fixture is a real image of an allowed type.
const PNG: &[u8] = &[
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4,
    0x89, 0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0x00, 0x01, 0x00, 0x00,
    0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE,
    0x42, 0x60, 0x82,
];

async fn upload_inline(
    app: &common::TestApp,
    token: &str,
    ticket: Uuid,
    name: &str,
    mime: &str,
    bytes: Vec<u8>,
) -> (u16, Value) {
    let part = Part::bytes(bytes)
        .file_name(name.to_string())
        .mime_str(mime)
        .expect("mime");
    let resp = app
        .client
        .post(app.url(&format!("/api/v1/tickets/{ticket}/attachments/inline")))
        .bearer_auth(token)
        .multipart(Form::new().part("file", part))
        .send()
        .await
        .expect("inline upload");
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(Value::Null))
}

/// The whole point: upload an image against a ticket, then fetch it with no
/// session at all, which is what a browser rendering `<img>` does.
#[sqlx::test]
async fn an_inline_image_is_fetchable_without_a_session(pool: PgPool) {
    install_test_attachment_env();
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let (ticket_id, _note_id) = common::seed_ticket_and_note(&pool, admin_id, company_id).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let (status, body) = upload_inline(
        &app,
        &token,
        ticket_id,
        "shot.png",
        "image/png",
        PNG.to_vec(),
    )
    .await;
    assert_eq!(status, 200, "upload: {body}");
    assert_eq!(
        body["note_id"],
        Value::Null,
        "an inline image is embedded while the text is still being written, so \
         there is no note to hang it from yet"
    );
    assert_eq!(body["is_inline"], Value::Bool(true));

    let url = body["url"].as_str().expect("a url").to_string();
    assert!(
        url.starts_with("/api/v1/public/tickets/attachments/"),
        "relative, so the SPA joins its own API base: {url}"
    );

    // No bearer. This is the request an `<img>` makes.
    let resp = app.client.get(app.url(&url)).send().await.expect("fetch");
    assert_eq!(resp.status().as_u16(), 200, "an <img> carries no header");
    let headers = resp.headers().clone();
    assert_eq!(
        headers.get("content-type").and_then(|v| v.to_str().ok()),
        Some("image/png")
    );
    assert_eq!(
        headers
            .get("x-content-type-options")
            .and_then(|v| v.to_str().ok()),
        Some("nosniff"),
        "the bytes are user-supplied, so a browser must not sniff its way to \
         something scriptable"
    );
    assert!(
        headers.get("content-disposition").is_none(),
        "a download disposition would make the browser save the file instead \
         of rendering it, which defeats the point of the route"
    );
    assert_eq!(
        headers.get("cache-control").and_then(|v| v.to_str().ok()),
        Some("public, max-age=31536000, immutable"),
        "there is no session here, so a shared cache may keep a copy"
    );
    assert_eq!(resp.bytes().await.expect("bytes").as_ref(), PNG);
}

/// The security case. A note attachment is a real row in the same table, under
/// a real id, and it must answer the public route exactly as an id that never
/// existed does. This is the regression that would turn an invoice or a log
/// bundle into a world-readable file.
#[sqlx::test]
async fn an_ordinary_attachment_is_not_readable_on_the_public_route(pool: PgPool) {
    install_test_attachment_env();
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let (ticket_id, note_id) = common::seed_ticket_and_note(&pool, admin_id, company_id).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    // The existing, authenticated note-attachment path. Nothing about it
    // changes; it just must not become public.
    let part = Part::bytes(b"invoice,total\nacme,1000\n".to_vec())
        .file_name("invoice.csv".to_string())
        .mime_str("text/csv")
        .expect("mime");
    let resp = app
        .client
        .post(app.url(&format!(
            "/api/v1/tickets/{ticket_id}/notes/{note_id}/attachments"
        )))
        .bearer_auth(&token)
        .multipart(Form::new().part("file", part))
        .send()
        .await
        .expect("note upload");
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = resp.json().await.expect("json");
    let id = body["id"].as_str().expect("an id").to_string();
    assert_eq!(body["is_inline"], Value::Bool(false));
    assert_eq!(
        body["url"],
        Value::Null,
        "there is no public URL for this file, so none may be advertised"
    );

    let real_but_private = app
        .client
        .get(app.url(&format!("/api/v1/public/tickets/attachments/{id}")))
        .send()
        .await
        .expect("public fetch");
    let never_existed = app
        .client
        .get(app.url(&format!(
            "/api/v1/public/tickets/attachments/{}",
            Uuid::new_v4()
        )))
        .send()
        .await
        .expect("public fetch");
    assert_eq!(real_but_private.status().as_u16(), 404);
    assert_eq!(
        never_existed.status().as_u16(),
        real_but_private.status().as_u16(),
        "an attachment that exists but was never flagged must be \
         indistinguishable from an id that never existed"
    );
}

/// SVG is a script-capable document and this route serves from the API origin
/// to unauthenticated clients, so it is refused at upload rather than sanitised
/// at render. Non-images are refused for the same reason: the public route only
/// ever hands back what this endpoint stored.
#[sqlx::test]
async fn only_renderable_image_types_can_be_stored_inline(pool: PgPool) {
    install_test_attachment_env();
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let (ticket_id, _note_id) = common::seed_ticket_and_note(&pool, admin_id, company_id).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let svg = br#"<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>"#;
    let (status, body) = upload_inline(
        &app,
        &token,
        ticket_id,
        "x.svg",
        "image/svg+xml",
        svg.to_vec(),
    )
    .await;
    assert_eq!(status, 400, "an SVG must not be storable inline: {body}");

    let (status, body) = upload_inline(
        &app,
        &token,
        ticket_id,
        "notes.pdf",
        "application/pdf",
        b"%PDF-1.4".to_vec(),
    )
    .await;
    assert_eq!(status, 400, "a PDF is not an inline image: {body}");

    // A browser sends parameters and arbitrary case; that must still be taken.
    let (status, body) = upload_inline(
        &app,
        &token,
        ticket_id,
        "shot.png",
        "IMAGE/PNG; charset=binary",
        PNG.to_vec(),
    )
    .await;
    assert_eq!(
        status, 200,
        "a browser-shaped header must be accepted: {body}"
    );
    assert_eq!(
        body["mime_type"], "image/png",
        "the stored type is the canonical one, not whatever casing arrived"
    );
}

/// The WRITE is authenticated and tenant-scoped even though the read is not,
/// and a ticket in another tenant is not addressable.
#[sqlx::test]
async fn the_upload_still_needs_a_session_and_the_right_tenant(pool: PgPool) {
    install_test_attachment_env();
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let (ticket_id, _note_id) = common::seed_ticket_and_note(&pool, admin_id, company_id).await;
    let app = common::boot(pool).await;

    let part = Part::bytes(PNG.to_vec())
        .file_name("a.png".to_string())
        .mime_str("image/png")
        .expect("mime");
    let anon = app
        .client
        .post(app.url(&format!("/api/v1/tickets/{ticket_id}/attachments/inline")))
        .multipart(Form::new().part("file", part))
        .send()
        .await
        .expect("anon upload");
    assert_eq!(anon.status().as_u16(), 401, "the WRITE needs a session");

    let token = common::login(&app, &email, &password).await;
    let (status, _) = upload_inline(
        &app,
        &token,
        Uuid::new_v4(),
        "a.png",
        "image/png",
        PNG.to_vec(),
    )
    .await;
    assert_eq!(
        status, 404,
        "a ticket id outside the caller's tenant does not resolve"
    );
}

/// The public read revalidates like the private download does, so a browser
/// rendering the same ticket twice does not re-fetch the bytes.
#[sqlx::test]
async fn a_cached_inline_image_revalidates_to_304(pool: PgPool) {
    install_test_attachment_env();
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let (ticket_id, _note_id) = common::seed_ticket_and_note(&pool, admin_id, company_id).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let (_, body) = upload_inline(
        &app,
        &token,
        ticket_id,
        "shot.png",
        "image/png",
        PNG.to_vec(),
    )
    .await;
    let url = body["url"].as_str().expect("a url").to_string();

    let first = app.client.get(app.url(&url)).send().await.expect("fetch");
    let etag = first
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .expect("an etag")
        .to_string();

    let second = app
        .client
        .get(app.url(&url))
        .header("if-none-match", &etag)
        .send()
        .await
        .expect("conditional fetch");
    assert_eq!(second.status().as_u16(), 304);
    assert!(
        second.bytes().await.expect("body").is_empty(),
        "a 304 carries no body"
    );
}

/// An inline image is capped, and the cap follows `ATTACHMENT_MAX_BYTES` down.
/// The default is 5 MiB rather than the 25 MiB an attachment gets: 25 MiB is a
/// size for a file somebody chose to download, whereas this one is fetched by
/// every browser that renders the ticket, without a session.
#[sqlx::test]
async fn an_oversized_inline_image_is_refused(pool: PgPool) {
    install_test_attachment_env();
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let (ticket_id, _note_id) = common::seed_ticket_and_note(&pool, admin_id, company_id).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let (status, body) = upload_inline(
        &app,
        &token,
        ticket_id,
        "big.png",
        "image/png",
        vec![0u8; 4096],
    )
    .await;
    assert_eq!(status, 413, "oversize inline upload: {body}");
}
