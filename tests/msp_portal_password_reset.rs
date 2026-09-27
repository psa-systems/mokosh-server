//! PMS-1343: the MSP owns the portal password reset, and the portal user's
//! access, for the whole life of the client relationship.
//!
//! David set the boundary and repeated it: an end user does not reset their own
//! portal password, they contact their MSP, who performs the reset; the MSP can
//! also end the relationship by marking the account inactive. The team provides
//! the platform and the MSP owns everything about the client.
//!
//! The self-service half is gone (`tests/portal_password_reset.rs` pins its
//! absence). What this file pins is the half that has to work in its place, and
//! which nothing covered before: the two MSP-side controls existed but had no
//! test between them.
//!
//! * `POST /contacts/{id}/resend-portal-invite` is the reset. It mints a fresh
//!   link, mails it to the contact, and supersedes any outstanding one.
//! * `POST /contacts/{id}/revoke-portal-access` is the deactivation. It stops
//!   the sign-in without deleting anything.

mod common;

use mokosh_test::mokosh_test;
use reqwest::StatusCode;
use sqlx::PgPool;
use uuid::Uuid;

const STRONG: &str = "Xy9#pQ4v!Lm2wRt7";

async fn seed_company(pool: &PgPool) -> Uuid {
    let company = Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, 'Acme Co')")
        .bind(company)
        .bind(common::DEFAULT_TENANT_ID)
        .execute(pool)
        .await
        .expect("seed company");
    company
}

/// The MSP-side reset, as an agent performs it.
async fn resend_invite(app: &common::TestApp, token: &str, contact_id: Uuid) -> reqwest::Response {
    app.client
        .post(app.url(&format!(
            // The nest adds its own `/contacts`, and the routes inside carry one
            // too, so the live path doubles the segment. Pre-existing, and
            // `tests/company_scoped_portal_roles.rs` addresses it the same way.
            "/api/v1/contacts/contacts/{contact_id}/resend-portal-invite"
        )))
        .bearer_auth(token)
        .send()
        .await
        .expect("resend the portal invite")
}

async fn revoke_access(app: &common::TestApp, token: &str, contact_id: Uuid) -> reqwest::Response {
    app.client
        .post(app.url(&format!(
            "/api/v1/contacts/contacts/{contact_id}/revoke-portal-access"
        )))
        .bearer_auth(token)
        .send()
        .await
        .expect("revoke portal access")
}

async fn contact_login(
    app: &common::TestApp,
    slug: &str,
    email: &str,
    password: &str,
) -> StatusCode {
    app.client
        .post(app.url("/api/v1/contact/auth/login"))
        .json(&serde_json::json!({ "slug": slug, "email": email, "password": password }))
        .send()
        .await
        .expect("contact login")
        .status()
}

/// The live, unredeemed link for `contact_id`, as the mail would carry it.
///
/// Read out of the table rather than out of the mail because only the Argon2
/// hash is stored and the plaintext leaves the service inside the message; what
/// the test needs is to know WHICH row is live, which is what supersession is
/// about.
async fn live_token_ids(pool: &PgPool, contact_id: Uuid) -> Vec<Uuid> {
    sqlx::query_scalar(
        "SELECT id FROM portal_setup_tokens \
         WHERE contact_id = $1 AND used_at IS NULL ORDER BY created_at",
    )
    .bind(contact_id)
    .fetch_all(pool)
    .await
    .expect("read the live setup tokens")
}

async fn latest_mail(pool: &PgPool) -> (String, String) {
    let (subject, body): (Option<String>, String) = sqlx::query_as(
        "SELECT subject, body FROM notifications \
         WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 1",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(pool)
    .await
    .expect("a notification was queued");
    (subject.unwrap_or_default(), body)
}

/// AC: an MSP user triggers a reset and the contact receives a set-password
/// link.
///
/// The link is the whole deliverable. An agent who clicks this and sees a 204
/// has told their customer a mail is coming, so a reset that mints a token and
/// fails to send is worse than one that refuses.
#[mokosh_test]
async fn the_msp_can_reset_a_portal_password_and_the_contact_gets_a_link(pool: PgPool) {
    let (_admin, email, password) = common::seed_admin(&pool).await;
    let company = seed_company(&pool).await;
    let contact = common::seed_portal_contact(&pool, company, "customer@acme.example", &[]).await;
    let app = common::boot(pool.clone()).await;
    let staff = common::login(&app, &email, &password).await;

    let response = resend_invite(&app, &staff, contact.id).await;
    assert!(
        response.status().is_success(),
        "the MSP-side reset answered {}",
        response.status()
    );

    assert_eq!(
        live_token_ids(&pool, contact.id).await.len(),
        1,
        "the reset mints exactly one live link"
    );

    let (subject, body) = latest_mail(&pool).await;
    assert!(
        body.contains("/set-password?token="),
        "the customer is sent a link they can redeem: {body}"
    );
    assert!(
        body.contains(&contact.slug),
        "and it is scoped to their own portal: {body}"
    );
    // PMS-1140: a mail a customer receives names the MSP, never the product.
    // `Mokosh` is the default app name, so its absence is what says this is
    // the customer-facing template rather than a staff one wearing a new
    // event name. The self-service reset mail used to carry this assertion.
    for product in ["Mokosh", "mokosh"] {
        assert!(
            !subject.contains(product) && !body.contains(product),
            "the product name reached a customer: {subject} / {body}"
        );
    }
}

/// A reissued link supersedes the one before it.
///
/// This is PMS-1297 on the path that still exists. It matters more here than it
/// did for self-service: an agent who resends because the customer says the
/// first link did not arrive must not leave two live links on the account, and
/// the customer who then finds the first one in a spam folder must not be able
/// to use it.
#[mokosh_test]
async fn a_reissued_link_supersedes_the_one_before_it(pool: PgPool) {
    let (_admin, email, password) = common::seed_admin(&pool).await;
    let company = seed_company(&pool).await;
    let contact = common::seed_portal_contact(&pool, company, "resend@acme.example", &[]).await;
    let app = common::boot(pool.clone()).await;
    let staff = common::login(&app, &email, &password).await;

    assert!(resend_invite(&app, &staff, contact.id)
        .await
        .status()
        .is_success());
    let first = live_token_ids(&pool, contact.id).await;
    assert_eq!(first.len(), 1);

    assert!(resend_invite(&app, &staff, contact.id)
        .await
        .status()
        .is_success());
    let second = live_token_ids(&pool, contact.id).await;
    assert_eq!(second.len(), 1, "only one link is ever live");
    assert_ne!(
        first[0], second[0],
        "the second resend issued a new link rather than remailing the first"
    );
}

/// AC: an MSP user deactivates a portal contact and that contact can no longer
/// sign in. AC: the record and its history are preserved.
///
/// Both halves in one case on purpose. "Cannot sign in" is easy to achieve by
/// deleting the contact, and that is precisely what must not happen: the
/// company keeps its tickets, its invoices and the person who raised them.
#[mokosh_test]
async fn deactivating_a_contact_stops_the_sign_in_and_keeps_the_record(pool: PgPool) {
    let (_admin, email, password) = common::seed_admin(&pool).await;
    let company = seed_company(&pool).await;
    let contact = common::seed_portal_contact(&pool, company, "leaver@acme.example", &[]).await;
    let app = common::boot(pool.clone()).await;
    let staff = common::login(&app, &email, &password).await;

    assert_eq!(
        contact_login(
            &app,
            &contact.slug,
            &contact.email,
            common::CONTACT_PASSWORD
        )
        .await,
        StatusCode::OK,
        "the contact could sign in before the MSP revoked access"
    );

    let response = revoke_access(&app, &staff, contact.id).await;
    assert!(
        response.status().is_success(),
        "revoke answered {}",
        response.status()
    );

    assert_eq!(
        contact_login(
            &app,
            &contact.slug,
            &contact.email,
            common::CONTACT_PASSWORD
        )
        .await,
        StatusCode::UNAUTHORIZED,
        "a deactivated contact must not be able to sign in"
    );

    // The record survives, which is the other half of the requirement.
    let (exists, is_portal_user): (bool, bool) = sqlx::query_as(
        "SELECT TRUE, is_portal_user FROM contacts WHERE id = $1 AND tenant_id = $2",
    )
    .bind(contact.id)
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(&pool)
    .await
    .expect("the contact row is still there");
    assert!(exists);
    assert!(
        !is_portal_user,
        "revoking clears the portal flag rather than the row"
    );

    // And no unredeemed link is left behind for the person who just left.
    assert!(
        live_token_ids(&pool, contact.id).await.is_empty(),
        "revoking portal access must not leave a live set-password link"
    );
}

/// A reset is refused for a contact the MSP has not granted portal access to.
///
/// The refusal is what keeps the two controls honest as a pair: if a reset
/// silently re-granted access, revoking would be undone by the next support
/// call.
#[mokosh_test]
async fn a_reset_is_refused_once_access_has_been_revoked(pool: PgPool) {
    let (_admin, email, password) = common::seed_admin(&pool).await;
    let company = seed_company(&pool).await;
    let contact = common::seed_portal_contact(&pool, company, "revoked@acme.example", &[]).await;
    let app = common::boot(pool.clone()).await;
    let staff = common::login(&app, &email, &password).await;

    assert!(revoke_access(&app, &staff, contact.id)
        .await
        .status()
        .is_success());

    let response = resend_invite(&app, &staff, contact.id).await;
    assert_eq!(
        response.status(),
        StatusCode::CONFLICT,
        "resending to a revoked contact must refuse rather than re-grant"
    );
    assert!(
        live_token_ids(&pool, contact.id).await.is_empty(),
        "and it must not have minted a link on the way to refusing"
    );
    let _ = STRONG;
}
