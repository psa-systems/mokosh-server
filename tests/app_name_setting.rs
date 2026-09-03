//! PMS-789: the deployment's product name as a system setting.
//!
//! The value moved from compile-time literals to a `tenant_settings` row on the
//! system tenant. What these tests pin is the migration path, because that is
//! where this kind of move goes wrong:
//!
//! - A deployment that upgrades and sets nothing must render exactly what it
//!   rendered before. There is no `APP_NAME` environment variable in this repo
//!   to seed from (verified across `src/`, `.env.example`, `compose.dev.yml`
//!   and both deployed compose files), so the default constant carries that
//!   guarantee alone and every test below that asserts "Mokosh" is asserting
//!   the unchanged-on-upgrade contract, not a cosmetic default.
//! - The value must reach outbound mail after an admin changes it, with no
//!   restart, which is the difference between this and the env var it replaces.
//! - A blank name must be unreachable. It is the one outcome worse than the
//!   name never having been configurable.
//!
//! The cache is process-global (see `utils::app_name` for why it cannot be a
//! per-read query), so these tests serialize on [`GUARD`] rather than racing
//! each other inside the one test binary.

mod common;

use sqlx::PgPool;
use uuid::Uuid;

use mokosh_server::modules::audit::AuditCtx;
use mokosh_server::modules::auth::AuthService;
use mokosh_server::modules::auth::TenantId;
use mokosh_server::modules::invitations::{CreateInvitationRequest, InvitationsService};
use mokosh_server::modules::notifications::NotificationsService;
use mokosh_server::modules::settings::app_name::{
    get_app_name_settings, put_app_name_settings, resolve_and_cache, AppNameInput,
};
use mokosh_server::utils::app_name::{app_name, set_app_name, DEFAULT_APP_NAME};
use mokosh_server::utils::deployment::DeploymentMode;
use mokosh_server::Database;

/// Serializes the process-global cache across the tests in this binary, and
/// resets it so each test starts from "nothing configured" no matter which ran
/// first.
///
/// `tokio::sync::Mutex` rather than the std one because the guard is held for
/// the whole test, across its awaits.
static GUARD: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn isolated() -> tokio::sync::MutexGuard<'static, ()> {
    let g = GUARD.lock().await;
    set_app_name(None);
    g
}

fn invites(pool: &PgPool) -> InvitationsService {
    InvitationsService::new(Database::from_pool(pool.clone()))
        .with_app_url("https://app.example.test".to_string())
}

/// One admin per test. `seed_admin` uses a fixed address, so calling it twice
/// in the same database trips the `(tenant_id, email)` unique constraint.
async fn seed_one_admin(pool: &PgPool) -> Uuid {
    common::seed_admin(pool).await.0
}

/// Seed a local-credential user, ask for a password reset, and return the
/// (subject, body) the recipient would get. The dispatcher renders the seeded
/// `auth.password_reset` template and queues the row; the worker drains it
/// later, so nothing else has to run.
async fn reset_mail(pool: &PgPool, email: &str) -> (String, String) {
    let hash = mokosh_server::utils::crypto::hash_password("local-password-123")
        .expect("hash test password");
    sqlx::query(
        "INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name, role, status)
         VALUES ($1, $2, $3, $4, 'Local', 'User', 'admin', 'active')",
    )
    .bind(Uuid::new_v4())
    .bind(common::DEFAULT_TENANT_ID)
    .bind(email)
    .bind(&hash)
    .execute(pool)
    .await
    .expect("seed user");

    let db = Database::from_pool(pool.clone());
    AuthService::with_dispatcher(
        db.clone(),
        "test-jwt-secret-please-change".to_string(),
        std::sync::Arc::new(mokosh_server::utils::email::LogMailer),
        "http://localhost:4301".to_string(),
        NotificationsService::with_encryption_key(db, [0u8; 32]),
    )
    // Self-hosted: a SaaS deployment refuses the reset outright (PMS-905), so
    // the mail this asserts on would never be queued in that mode.
    .with_deployment_mode(DeploymentMode::SelfHosted)
    .request_password_reset(Some(common::DEFAULT_TENANT_ID), email)
    .await
    .expect("reset queues mail");

    sqlx::query_as("SELECT subject, body FROM notifications WHERE recipient = $1")
        .bind(email)
        .fetch_one(pool)
        .await
        .expect("the reset queued an email row")
}

fn actx() -> AuditCtx {
    AuditCtx {
        tenant_id: Some(common::DEFAULT_TENANT_ID),
        user_id: None,
        ip: None,
        user_agent: None,
    }
}

/// Send one invitation and return the subject the recipient would see. The
/// dispatcher worker drains `notifications` later; the row it drains is what
/// this reads, so no worker has to run.
async fn invite_subject(pool: &PgPool, admin_id: Uuid, email: &str) -> String {
    invites(pool)
        .create(
            TenantId::from_trusted(common::DEFAULT_TENANT_ID),
            admin_id,
            &CreateInvitationRequest {
                email: email.to_string(),
                role: "technician".to_string(),
            },
            &actx(),
        )
        .await
        .expect("create invitation");

    sqlx::query_scalar("SELECT subject FROM notifications WHERE recipient = $1")
        .bind(email)
        .fetch_one(pool)
        .await
        .expect("the invitation queued an email row")
}

/// Write a value straight into the store, bypassing the admin API's validation.
/// Used to stand in for a row that predates a rule or was edited by hand.
async fn store_raw(pool: &PgPool, value: &str) {
    sqlx::query(
        "INSERT INTO tenant_settings (tenant_id, category, key, value)
         VALUES ($1, 'system', 'app_name', $2)
         ON CONFLICT (tenant_id, category, key) DO UPDATE SET value = EXCLUDED.value",
    )
    .bind(Uuid::from_u128(1))
    .bind(serde_json::Value::String(value.to_string()))
    .execute(pool)
    .await
    .expect("seed the stored app name");
}

/// The upgrade case, and the reason the default is a hard requirement rather
/// than a nicety: an existing deployment has no setting row, and must read
/// exactly as it did before the move.
#[sqlx::test]
async fn a_deployment_with_no_setting_row_renders_the_unchanged_default(pool: PgPool) {
    let _g = isolated().await;
    let admin = seed_one_admin(&pool).await;
    let db = Database::from_pool(pool.clone());

    resolve_and_cache(&db).await.expect("boot-time load");

    assert_eq!(
        &*app_name(),
        "Mokosh",
        "an upgraded deployment that sets nothing must render what it rendered before"
    );
    let view = get_app_name_settings(&db).await.expect("read settings");
    assert_eq!(view.app_name, None, "nothing is configured");
    assert_eq!(
        view.effective, "Mokosh",
        "and the admin screen still reports a name, never a blank"
    );

    assert_eq!(
        invite_subject(&pool, admin, "unchanged@example.test").await,
        "You have been invited to Default on Mokosh",
        "the outbound copy is byte-identical to the pre-PMS-789 literal"
    );
}

/// AC5, and the whole point of the move: an admin changes the name and the next
/// mail carries it, in the same process, with nothing restarted and no second
/// boot-time load.
#[sqlx::test]
async fn an_admin_change_reaches_outbound_mail_with_no_restart(pool: PgPool) {
    let _g = isolated().await;
    let admin = seed_one_admin(&pool).await;
    let db = Database::from_pool(pool.clone());
    resolve_and_cache(&db).await.expect("boot-time load");

    put_app_name_settings(
        &db,
        AppNameInput {
            app_name: "PSA Systems".to_string(),
        },
    )
    .await
    .expect("admin sets the name");

    assert_eq!(
        invite_subject(&pool, admin, "first@example.test").await,
        "You have been invited to Default on PSA Systems",
    );

    // Changed a second time, because a cache that is only ever populated once
    // would pass the assertion above and still be broken.
    put_app_name_settings(
        &db,
        AppNameInput {
            app_name: "PSA Staging".to_string(),
        },
    )
    .await
    .expect("admin changes the name again");

    assert_eq!(
        invite_subject(&pool, admin, "second@example.test").await,
        "You have been invited to Default on PSA Staging",
        "the second change took effect too, so the value is read per send"
    );
}

/// The other half of "no restart": a name set in a previous process is picked
/// up by the next boot, which is what makes the setting durable rather than
/// only live in the process that wrote it.
#[sqlx::test]
async fn a_stored_name_is_picked_up_by_the_next_boot(pool: PgPool) {
    let _g = isolated().await;
    let admin = seed_one_admin(&pool).await;
    let db = Database::from_pool(pool.clone());

    store_raw(&pool, "PSA Systems").await;
    // The cache is cold, exactly as it is in a process that has just started.
    assert_eq!(
        &*app_name(),
        DEFAULT_APP_NAME,
        "cold cache reads the default"
    );

    resolve_and_cache(&db).await.expect("boot-time load");

    assert_eq!(&*app_name(), "PSA Systems");
    assert_eq!(
        invite_subject(&pool, admin, "afterboot@example.test").await,
        "You have been invited to Default on PSA Systems",
    );
}

/// Clearing the override is a supported action, and it must land on the default
/// rather than on an empty string - the same outcome as never having set one.
#[sqlx::test]
async fn clearing_the_name_restores_the_default_rather_than_a_blank(pool: PgPool) {
    let _g = isolated().await;
    let admin = seed_one_admin(&pool).await;
    let db = Database::from_pool(pool.clone());

    put_app_name_settings(
        &db,
        AppNameInput {
            app_name: "PSA Systems".to_string(),
        },
    )
    .await
    .expect("set");
    assert_eq!(&*app_name(), "PSA Systems");

    let view = put_app_name_settings(
        &db,
        AppNameInput {
            app_name: "   ".to_string(),
        },
    )
    .await
    .expect("an empty write clears the override");

    assert_eq!(view.app_name, None);
    assert_eq!(view.effective, DEFAULT_APP_NAME);
    assert_eq!(&*app_name(), DEFAULT_APP_NAME);
    assert_eq!(
        invite_subject(&pool, admin, "cleared@example.test").await,
        "You have been invited to Default on Mokosh",
        "a cleared name renders the default, never an empty gap in the sentence"
    );
    // The row is gone, so the next boot resolves to the default too rather than
    // reloading an empty string.
    resolve_and_cache(&db).await.expect("reload");
    assert_eq!(&*app_name(), DEFAULT_APP_NAME);
}

/// A row that the admin API would refuse today (written before a rule existed,
/// or edited straight in the database) must not reach an email `Subject`
/// header. Boot drops it and falls back, rather than rendering it.
#[sqlx::test]
async fn an_unusable_stored_name_is_dropped_at_boot(pool: PgPool) {
    let _g = isolated().await;
    let admin = seed_one_admin(&pool).await;
    let db = Database::from_pool(pool.clone());

    store_raw(&pool, "PSA\r\nBcc: attacker@example.test").await;
    resolve_and_cache(&db).await.expect("boot-time load");

    assert_eq!(
        &*app_name(),
        DEFAULT_APP_NAME,
        "a control character in the stored name is header injection, so it is not rendered"
    );
    let subject = invite_subject(&pool, admin, "injected@example.test").await;
    assert!(
        !subject.contains('\r') && !subject.contains('\n'),
        "no newline reached the subject header: {subject:?}"
    );
}

/// The admin write path refuses the same value at the door, so the fallback
/// above is a backstop and not the only defence.
#[sqlx::test]
async fn the_admin_api_refuses_a_name_that_would_inject_a_header(pool: PgPool) {
    let _g = isolated().await;
    let db = Database::from_pool(pool.clone());

    let refused = put_app_name_settings(
        &db,
        AppNameInput {
            app_name: "PSA\r\nBcc: attacker@example.test".to_string(),
        },
    )
    .await;
    assert!(refused.is_err(), "got {refused:?}");

    assert_eq!(
        &*app_name(),
        DEFAULT_APP_NAME,
        "a refused write leaves the live value alone"
    );
    assert_eq!(
        get_app_name_settings(&db)
            .await
            .expect("read settings")
            .app_name,
        None,
        "and persists nothing"
    );
}

/// The consumer that cannot make a query: the catch-all 404 page takes no
/// `State` and has to render when the database is unreachable. It reads the
/// same cache, which is why the value is cached rather than fetched per read.
#[sqlx::test]
async fn the_api_landing_page_names_the_deployment_without_touching_the_database(pool: PgPool) {
    let _g = isolated().await;
    let db = Database::from_pool(pool.clone());
    put_app_name_settings(
        &db,
        AppNameInput {
            app_name: "PSA Systems".to_string(),
        },
    )
    .await
    .expect("set the name");

    let app = common::boot(pool.clone()).await;
    let body = app
        .client
        .get(format!("{}/no-such-page", app.base))
        .send()
        .await
        .expect("request the fallback")
        .text()
        .await
        .expect("read body");

    assert!(
        body.contains("PSA Systems backend API"),
        "the landing page names the deployment: {body}"
    );
    assert!(
        !body.contains("Mokosh"),
        "and no longer names the product literally: {body}"
    );
}

/// A name with HTML in it is escaped on the page rather than injected into it.
/// `sanitize` bars control characters, not markup, so the escaping is the
/// defence and it belongs at the render site.
#[sqlx::test]
async fn a_name_containing_markup_is_escaped_on_the_landing_page(pool: PgPool) {
    let _g = isolated().await;
    let db = Database::from_pool(pool.clone());
    put_app_name_settings(
        &db,
        AppNameInput {
            app_name: "<script>alert(1)</script>".to_string(),
        },
    )
    .await
    .expect("set the name");

    let app = common::boot(pool.clone()).await;
    let body = app
        .client
        .get(format!("{}/no-such-page", app.base))
        .send()
        .await
        .expect("request the fallback")
        .text()
        .await
        .expect("read body");

    assert!(
        !body.contains("<script>"),
        "the name was injected as markup: {body}"
    );
    assert!(body.contains("&lt;script&gt;"), "escaped instead: {body}");
}

/// The seeded transactional templates are the highest-volume mail this server
/// sends, and migration 116 rewrote their product name to `{{app_name}}`.
/// Fixing the Rust call sites and leaving these would ship the exact mismatch
/// the issue exists to remove: an admin sets "PSA Systems" and the reset mail
/// still says Mokosh.
#[sqlx::test]
async fn the_seeded_password_reset_mail_renders_the_configured_name(pool: PgPool) {
    let _g = isolated().await;
    let db = Database::from_pool(pool.clone());
    put_app_name_settings(
        &db,
        AppNameInput {
            app_name: "PSA Systems".to_string(),
        },
    )
    .await
    .expect("admin sets the name");

    let (subject, body) = reset_mail(&pool, "reset@example.test").await;
    assert_eq!(subject, "Reset your PSA Systems password");
    assert!(
        body.contains("reset your PSA Systems password"),
        "body still names the product literally: {body}"
    );
    assert!(
        !subject.contains("Mokosh") && !body.contains("Mokosh"),
        "the literal survived somewhere: {subject} / {body}"
    );
    assert!(
        !body.contains("{{app_name}}"),
        "the placeholder rendered as literal braces, so the context did not carry it: {body}"
    );
}

/// The upgrade case for the same mail: a deployment that sets nothing gets the
/// wording it had before PMS-789, character for character.
#[sqlx::test]
async fn the_seeded_password_reset_mail_is_unchanged_when_nothing_is_configured(pool: PgPool) {
    let _g = isolated().await;
    let db = Database::from_pool(pool.clone());
    resolve_and_cache(&db).await.expect("boot-time load");

    let (subject, body) = reset_mail(&pool, "unchanged-reset@example.test").await;
    assert_eq!(subject, "Reset your Mokosh password");
    assert!(
        body.starts_with("We received a request to reset your Mokosh password."),
        "pre-789 wording not preserved: {body}"
    );
}

/// Migration 116 has to have actually rewritten the seeded rows, not just the
/// seed files. A fresh database is what an upgraded one becomes, so if any
/// template still holds the literal here, it holds it in production too.
#[sqlx::test]
async fn no_seeded_template_still_names_the_product_literally(pool: PgPool) {
    let stragglers: Vec<(String, String)> = sqlx::query_as(
        "SELECT event_type, channel_type FROM notification_templates
         WHERE subject LIKE '%Mokosh%' OR body_text LIKE '%Mokosh%' OR body_html LIKE '%Mokosh%'",
    )
    .fetch_all(&pool)
    .await
    .expect("scan templates");
    assert!(
        stragglers.is_empty(),
        "templates still naming the product literally: {stragglers:?}"
    );

    let templated: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM notification_templates WHERE body_text LIKE '%{{app_name}}%'",
    )
    .fetch_one(&pool)
    .await
    .expect("count templated");
    assert_eq!(
        templated, 2,
        "expected the two transactional templates to carry the placeholder"
    );
}

/// The migration must not reword a tenant's own copy. Its WHERE clauses match
/// the seeded text verbatim, so re-running it against a customised row is a
/// no-op - which is exactly what an upgrade does to an operator who edited
/// their template through the notification CRUD API.
#[sqlx::test]
async fn re_running_the_migration_leaves_a_customised_template_alone(pool: PgPool) {
    let mine = "Our own words about Mokosh, thanks.";
    sqlx::query(
        "UPDATE notification_templates SET body_text = $1
         WHERE event_type = 'auth.welcome' AND channel_type = 'email'",
    )
    .bind(mine)
    .execute(&pool)
    .await
    .expect("customise the template");

    let sql = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/migrations/116_app_name_in_transactional_copy.sql"
    ))
    .expect("read migration 116");
    sqlx::raw_sql(&sql)
        .execute(&pool)
        .await
        .expect("re-run migration 116");

    let after: String = sqlx::query_scalar(
        "SELECT body_text FROM notification_templates
         WHERE event_type = 'auth.welcome' AND channel_type = 'email'",
    )
    .fetch_one(&pool)
    .await
    .expect("read back");
    assert_eq!(
        after, mine,
        "the migration overwrote a template the operator had customised"
    );
}
