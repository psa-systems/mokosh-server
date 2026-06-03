//! Integration test: contacts CRUD happy path.
//!
//! Covers PMS-124 F10 acceptance for the contacts route group: a logged-in
//! admin can create a company, list it back, fetch it by id, then delete it.

mod common;

use sqlx::PgPool;

#[sqlx::test]
async fn company_crud_happy_path(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    common::login(&app, &email, &password).await;

    // CREATE
    let create_body = serde_json::json!({ "name": "Acme Co" });
    let create_resp = app
        .client
        .post(app.url("/api/v1/contacts/companies"))
        .json(&create_body)
        .send()
        .await
        .expect("send create company");
    assert!(
        create_resp.status().is_success(),
        "create company should 2xx, got {}",
        create_resp.status()
    );
    let created: serde_json::Value = create_resp.json().await.expect("create response JSON");
    let company_id = created["id"]
        .as_str()
        .expect("created company has an id")
        .to_string();

    // LIST
    let list_resp = app
        .client
        .get(app.url("/api/v1/contacts/companies"))
        .send()
        .await
        .expect("send list companies");
    assert_eq!(list_resp.status(), reqwest::StatusCode::OK);
    let list: serde_json::Value = list_resp.json().await.expect("list response JSON");
    let items = list["data"].as_array().expect("list has data array");
    assert!(
        items.iter().any(|c| c["id"].as_str() == Some(&company_id)),
        "list should contain the company we just created"
    );

    // GET by id
    let get_resp = app
        .client
        .get(app.url(&format!("/api/v1/contacts/companies/{company_id}")))
        .send()
        .await
        .expect("send get company");
    assert_eq!(get_resp.status(), reqwest::StatusCode::OK);
    let got: serde_json::Value = get_resp.json().await.expect("get response JSON");
    assert_eq!(got["name"].as_str(), Some("Acme Co"));

    // DELETE
    let delete_resp = app
        .client
        .delete(app.url(&format!("/api/v1/contacts/companies/{company_id}")))
        .send()
        .await
        .expect("send delete company");
    assert!(
        delete_resp.status().is_success(),
        "delete company should 2xx, got {}",
        delete_resp.status()
    );
}
