//! PMS-1471: `DELETE /api/v1/contacts/contacts/{id}` for an id that never
//! existed (or was already deleted) must return 404 and must not write a
//! `contacts` audit row for that id, since there was never a row to snapshot.

mod common;

use mokosh_test::mokosh_test;
use reqwest::StatusCode;
use sqlx::PgPool;
use uuid::Uuid;

#[mokosh_test]
async fn deleting_an_unknown_contact_returns_404_and_writes_no_audit_row(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let unknown_id = Uuid::new_v4();
    let resp = app
        .client
        .delete(app.url(&format!("/api/v1/contacts/contacts/{unknown_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send delete contact");
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let audit_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_log WHERE entity_type = 'contacts' AND entity_id = $1",
    )
    .bind(unknown_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        audit_count, 0,
        "no audit row for an id that was never deleted"
    );
}
