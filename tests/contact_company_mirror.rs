//! PMS-1069: editing a contact never drops its company.
//!
//! `contacts.company_id` is a mirror of the primary `contact_companies` row
//! (PMS-806) and `update_contact` re-derives it from that table on every edit,
//! so a contact written with the mirror alone lost its company on the first edit
//! of any field: no error, no audit entry naming a removed link, and for a
//! portal contact a setup token minted with no email to carry it.
//!
//! Two writers outside `modules/contacts` produced exactly that row on every
//! run, so both are driven here as they run in production rather than restated
//! as a fixture INSERT: the email-intake auto-created sender, and the tenant's
//! provisioned portal admin contact.

mod common;

use mokosh_server::modules::tenants::TenantService;
use mokosh_server::Database;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    let out = h.finalize();
    let mut s = String::with_capacity(64);
    for b in out {
        use std::fmt::Write;
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

async fn seed_intake_token(pool: &PgPool, bearer: &str) {
    sqlx::query(
        r#"INSERT INTO tenant_intake_tokens (tenant_id, kind, token_hash, label)
           VALUES ($1, 'email_intake', $2, 'PMS-1069 test gateway')"#,
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(sha256_hex(bearer.as_bytes()))
    .execute(pool)
    .await
    .expect("seed intake token");
}

async fn company_of(pool: &PgPool, contact_id: Uuid) -> Option<Uuid> {
    sqlx::query_scalar("SELECT company_id FROM contacts WHERE id = $1")
        .bind(contact_id)
        .fetch_one(pool)
        .await
        .expect("read contact company_id")
}

async fn primary_link_of(pool: &PgPool, contact_id: Uuid) -> Option<Uuid> {
    sqlx::query_scalar(
        "SELECT company_id FROM contact_companies WHERE contact_id = $1 AND is_primary",
    )
    .bind(contact_id)
    .fetch_optional(pool)
    .await
    .expect("read primary contact_companies link")
}

/// An email-intake contact keeps the company its tickets hang off when an agent
/// edits any field of it.
///
/// The company association is the whole value of an auto-created contact: it is
/// what ties the sender's tickets to a customer. Losing it is silent from the
/// row's point of view, because nothing was removed.
#[sqlx::test]
async fn an_email_intake_contact_keeps_its_company_when_edited(pool: PgPool) {
    let (_admin_id, admin_email, admin_password) = common::seed_admin(&pool).await;
    let fallback_company = common::seed_company(&pool).await;
    let bearer = "pms1069-intake-token";
    seed_intake_token(&pool, bearer).await;
    sqlx::query(
        r#"INSERT INTO tenant_settings (tenant_id, category, key, value)
           VALUES ($1, 'email_intake', 'default_company_id', to_jsonb($2::text))"#,
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(fallback_company.to_string())
    .execute(&pool)
    .await
    .expect("seed fallback company setting");

    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &admin_email, &admin_password).await;

    let intake = app
        .client
        .post(app.url("/api/v1/email-intake"))
        .bearer_auth(bearer)
        .json(&serde_json::json!({
            "message_id": "<pms1069-intake@example.com>",
            "from_email": "sender@example.com",
            "from_name": "Sen Der",
            "subject": "Printer is on fire",
            "body_text": "again",
        }))
        .send()
        .await
        .expect("email intake POST");
    assert!(
        intake.status().is_success(),
        "intake returned {}",
        intake.status()
    );

    let contact_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM contacts WHERE tenant_id = $1 AND lower(email) = 'sender@example.com'",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(&pool)
    .await
    .expect("auto-created contact row");

    // The writer half: the mirror never lands without its link.
    assert_eq!(
        company_of(&pool, contact_id).await,
        Some(fallback_company),
        "intake must file the sender under the fallback company"
    );
    assert_eq!(
        primary_link_of(&pool, contact_id).await,
        Some(fallback_company),
        "the auto-created contact must carry the primary contact_companies row \
         its company_id mirrors"
    );

    // The edit half: a field this request does not mention cannot change.
    let edit = app
        .client
        .put(app.url(&format!("/api/v1/contacts/contacts/{contact_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "first_name": "Edited" }))
        .send()
        .await
        .expect("update contact");
    assert!(
        edit.status().is_success(),
        "update returned {}",
        edit.status()
    );

    assert_eq!(
        company_of(&pool, contact_id).await,
        Some(fallback_company),
        "editing an unrelated field must not unlink the contact from its company"
    );
    assert_eq!(
        primary_link_of(&pool, contact_id).await,
        Some(fallback_company),
        "the primary link must survive the edit too"
    );
}

/// The tenant's provisioned portal admin contact survives an edit and still
/// gets a deliverable portal grant email afterwards.
///
/// Driven through `TenantService::insert_portal_admin_contact`, the writer that
/// provisioning uses, rather than a fixture copy of its INSERT. Two details of
/// the shape are worth knowing before reading the steps:
///
/// - that contact is created `is_portal_user = TRUE`, so the grant that mails a
///   setup link is the false -> true flip on `PUT /contacts/contacts/{id}`,
///   which is the path `send_setup_email` serves;
/// - it sits on the tenant's `own_company`, which `grant_portal_access` refuses
///   by design (an internal bookkeeping company is never a real customer), so
///   the update path is also the only grant this contact can get.
///
/// Without the fix the first edit nulls `company_id`, and the grant then mints a
/// token, commits it, and drops the email with a WARN: a redeemable link nobody
/// was sent.
#[sqlx::test]
async fn a_provisioned_portal_admin_contact_is_still_mailable_after_an_edit(pool: PgPool) {
    let (_admin_id, admin_email, admin_password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &admin_email, &admin_password).await;

    let tenants = TenantService::new(Database::from_pool(pool.clone()));
    tenants
        .ensure_own_company(common::DEFAULT_TENANT_ID)
        .await
        .expect("tenant own company");
    let contact_id = tenants
        .insert_portal_admin_contact(
            common::DEFAULT_TENANT_ID,
            "portal.admin@mcl.example",
            "Portal",
            "Admin",
        )
        .await
        .expect("provision portal admin contact");
    let own_company = company_of(&pool, contact_id)
        .await
        .expect("the provisioned contact carries a company_id");
    assert_eq!(
        primary_link_of(&pool, contact_id).await,
        Some(own_company),
        "provisioning must write the primary contact_companies row its \
         company_id mirrors"
    );

    // The edit. `is_portal_user: false` rides along so the grant below is a real
    // false -> true transition; the renamed field is the part that used to be
    // enough on its own to drop the company.
    let edit = app
        .client
        .put(app.url(&format!("/api/v1/contacts/contacts/{contact_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "first_name": "Edited", "is_portal_user": false }))
        .send()
        .await
        .expect("update contact");
    assert!(
        edit.status().is_success(),
        "update returned {}",
        edit.status()
    );
    assert_eq!(
        company_of(&pool, contact_id).await,
        Some(own_company),
        "editing the provisioned portal admin must not unlink it from its company"
    );

    // The grant.
    let grant = app
        .client
        .put(app.url(&format!("/api/v1/contacts/contacts/{contact_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "is_portal_user": true }))
        .send()
        .await
        .expect("grant portal access");
    assert!(
        grant.status().is_success(),
        "grant returned {}",
        grant.status()
    );

    let body: String = sqlx::query_scalar(
        "SELECT body FROM notifications \
         WHERE tenant_id = $1 AND recipient = $2 AND channel_type = 'email'",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind("portal.admin@mcl.example")
    .fetch_one(&pool)
    .await
    .expect("the grant email was queued");

    let slug: String =
        sqlx::query_scalar("SELECT portal_slug FROM companies WHERE id = $1 AND tenant_id = $2")
            .bind(own_company)
            .bind(common::DEFAULT_TENANT_ID)
            .fetch_one(&pool)
            .await
            .expect("read portal_slug");
    let expected_prefix = format!("/portal/{slug}/set-password?token=");
    assert!(
        body.contains(&expected_prefix),
        "the grant email must carry the /portal/{{slug}}/set-password URL, got: {body}"
    );
}

/// The mirror is still derived, not sticky: an explicit empty `companies` list
/// unlinks the contact.
///
/// The repair in `update_contact` adopts `contacts.company_id` as the primary
/// link only when the contact has NO links at all, so it can never contradict a
/// list the caller actually sent. Without this pin, widening it to "never null a
/// non-null company_id" would look equally correct and would make unlinking
/// impossible.
#[sqlx::test]
async fn an_explicit_empty_company_list_still_unlinks_the_contact(pool: PgPool) {
    let (_admin_id, admin_email, admin_password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &admin_email, &admin_password).await;

    let created: serde_json::Value = app
        .client
        .post(app.url("/api/v1/contacts/contacts"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "company_id": company_id,
            "first_name": "Linked",
            "last_name": "Contact",
            "email": "linked@mcl.example",
            "contact_type": "primary",
        }))
        .send()
        .await
        .expect("create contact")
        .json()
        .await
        .expect("created contact JSON");
    let contact_id: Uuid = created["id"]
        .as_str()
        .expect("created contact id")
        .parse()
        .expect("uuid");
    assert_eq!(company_of(&pool, contact_id).await, Some(company_id));

    let unlink = app
        .client
        .put(app.url(&format!("/api/v1/contacts/contacts/{contact_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "companies": [] }))
        .send()
        .await
        .expect("unlink contact");
    assert!(
        unlink.status().is_success(),
        "unlink returned {}",
        unlink.status()
    );

    assert_eq!(
        company_of(&pool, contact_id).await,
        None,
        "an explicit empty companies list must still clear the mirror"
    );
    assert_eq!(primary_link_of(&pool, contact_id).await, None);
}
