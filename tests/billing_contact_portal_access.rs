//! PMS-1186: being made the billing contact lets you see the invoice you were
//! sent.
//!
//! Two unrelated things were both called "the billing contact" and nothing
//! kept them in step. `companies.default_billing_contact_id` decides who
//! RECEIVES the invoice mail with its pay link; a portal role holding
//! `invoices:read` decides who can SEE an invoice after signing in. So the MSP
//! designates Jane, sends her an invoice, and Jane signs in to a portal that
//! shows her nothing - and nothing on the MSP's side says so.

mod common;

use sqlx::PgPool;
use uuid::Uuid;

async fn role_id(pool: &PgPool, name: &str) -> Uuid {
    sqlx::query_scalar("SELECT id FROM portal_roles WHERE tenant_id = $1 AND name = $2")
        .bind(common::DEFAULT_TENANT_ID)
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap_or_else(|e| panic!("read portal_role {name}: {e}"))
}

/// The union `load_contact_capabilities` computes, asked of the database
/// directly so the assertion is about what is stored rather than what a
/// handler chose to answer.
async fn capabilities(pool: &PgPool, contact_id: Uuid) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT DISTINCT cap FROM contact_role_assignments cra \
         INNER JOIN portal_roles pr ON pr.id = cra.role_id, \
         LATERAL unnest(pr.capabilities) AS cap \
         WHERE cra.tenant_id = $1 AND cra.contact_id = $2 ORDER BY cap",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(contact_id)
    .fetch_all(pool)
    .await
    .expect("read capabilities")
}

async fn seed_company(pool: &PgPool, label: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(common::DEFAULT_TENANT_ID)
        .bind(format!("BCPA {label} {}", &id.simple().to_string()[..6]))
        .execute(pool)
        .await
        .expect("seed company");
    id
}

/// A contact of `company_id`, a portal user or not, holding `roles`.
async fn seed_contact(
    pool: &PgPool,
    company_id: Uuid,
    label: &str,
    is_portal_user: bool,
    roles: &[&str],
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO contacts (id, tenant_id, company_id, first_name, last_name, email, is_portal_user) \
         VALUES ($1, $2, $3, 'Bill', 'Payer', $4, $5)",
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company_id)
    .bind(format!("{label}-{}@bcpa.example", &id.simple().to_string()[..6]))
    .bind(is_portal_user)
    .execute(pool)
    .await
    .expect("seed contact");
    for role in roles {
        let role_id = role_id(pool, role).await;
        sqlx::query(
            "INSERT INTO contact_role_assignments (contact_id, role_id, tenant_id) \
             VALUES ($1, $2, $3)",
        )
        .bind(id)
        .bind(role_id)
        .bind(common::DEFAULT_TENANT_ID)
        .execute(pool)
        .await
        .expect("assign role");
    }
    id
}

/// What the MSP does in the UI: set the company's default billing contact.
async fn set_billing_contact(
    app: &common::TestApp,
    token: &str,
    company_id: Uuid,
    contact_id: Uuid,
) -> reqwest::StatusCode {
    app.client
        .put(app.url(&format!("/api/v1/contacts/companies/{company_id}")))
        .bearer_auth(token)
        .json(&serde_json::json!({ "default_billing_contact_id": contact_id }))
        .send()
        .await
        .expect("update company")
        .status()
}

/// The case that shipped: a portal contact whose access was granted for
/// tickets is made the billing contact, and could then be mailed an invoice
/// they could not open.
#[sqlx::test]
async fn designating_a_billing_contact_lets_them_read_invoices(pool: PgPool) {
    let (_admin, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let company = seed_company(&pool, "grant").await;
    let contact = seed_contact(&pool, company, "support", true, &["Support Contact"]).await;
    assert!(
        !capabilities(&pool, contact)
            .await
            .contains(&"invoices:read".to_string()),
        "the fixture has to start unable to read invoices, or this proves nothing"
    );

    assert_eq!(
        set_billing_contact(&app, &token, company, contact).await,
        reqwest::StatusCode::OK
    );

    let caps = capabilities(&pool, contact).await;
    assert!(
        caps.contains(&"invoices:read".to_string()),
        "the billing contact must be able to read invoices: {caps:?}"
    );
    assert!(
        caps.contains(&"tickets:read".to_string()),
        "and must keep the access they already had: {caps:?}"
    );
}

/// The grant is recorded, so an MSP can see the application did it and undo it.
#[sqlx::test]
async fn the_grant_is_audited_against_the_contact(pool: PgPool) {
    let (_admin, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let company = seed_company(&pool, "audit").await;
    let contact = seed_contact(&pool, company, "audited", true, &["Support Contact"]).await;
    set_billing_contact(&app, &token, company, contact).await;

    let granted: Option<String> = sqlx::query_scalar(
        "SELECT new_values ->> 'portal_role_granted' FROM audit_log \
         WHERE tenant_id = $1 AND entity_type = 'contacts' AND entity_id = $2 \
           AND new_values ? 'portal_role_granted'",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(contact)
    .fetch_optional(&pool)
    .await
    .expect("read audit");
    assert_eq!(granted.as_deref(), Some("Billing Contact"));
}

/// A contact who cannot sign in is left alone. Granting a role to somebody
/// with no portal access changes nothing, and flipping `is_portal_user` here
/// would invite a person to a portal without anyone deciding to.
#[sqlx::test]
async fn a_contact_who_is_not_a_portal_user_is_left_alone(pool: PgPool) {
    let (_admin, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let company = seed_company(&pool, "offline").await;
    let contact = seed_contact(&pool, company, "offline", false, &[]).await;
    set_billing_contact(&app, &token, company, contact).await;

    assert!(
        capabilities(&pool, contact).await.is_empty(),
        "no portal access means no role to grant"
    );
    let is_portal_user: bool =
        sqlx::query_scalar("SELECT is_portal_user FROM contacts WHERE id = $1")
            .bind(contact)
            .fetch_one(&pool)
            .await
            .expect("read contact");
    assert!(
        !is_portal_user,
        "this must never invite somebody to the portal on its own"
    );
}

/// Somebody who can already read invoices gains no second role, whichever role
/// gave them the capability.
#[sqlx::test]
async fn a_contact_who_can_already_read_invoices_gains_nothing(pool: PgPool) {
    let (_admin, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let company = seed_company(&pool, "readonly").await;
    // Read-Only holds invoices:read and is not the Billing Contact role.
    let contact = seed_contact(&pool, company, "readonly", true, &["Read-Only"]).await;
    set_billing_contact(&app, &token, company, contact).await;

    let assignments: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM contact_role_assignments WHERE tenant_id = $1 AND contact_id = $2",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(contact)
    .fetch_one(&pool)
    .await
    .expect("count assignments");
    assert_eq!(
        assignments, 1,
        "they could already read invoices, so nothing needed granting"
    );
}

/// Re-running the same designation changes nothing.
#[sqlx::test]
async fn designating_the_same_contact_twice_is_a_no_op(pool: PgPool) {
    let (_admin, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let company = seed_company(&pool, "twice").await;
    let contact = seed_contact(&pool, company, "twice", true, &["Support Contact"]).await;
    set_billing_contact(&app, &token, company, contact).await;
    set_billing_contact(&app, &token, company, contact).await;

    let assignments: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM contact_role_assignments WHERE tenant_id = $1 AND contact_id = $2",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(contact)
    .fetch_one(&pool)
    .await
    .expect("count assignments");
    assert_eq!(assignments, 2, "Support Contact plus Billing Contact, once");
}
