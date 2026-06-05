//! Integration tests for the `settings` module + the cross-cutting
//! module-gating behaviour from PMS-113.
//!
//! Covers:
//! - PMS-113 AC1: tenant_settings round-trip via /api/v1/settings/:category/:key;
//!   per-(category, key) value validation; unknown pairs accepted as-is.
//! - PMS-113 AC2: module-config round-trip on both surfaces and proof that
//!   the tenants-API surface delegates to the same row as the settings-API.
//! - PMS-113 AC3: a disabled module returns 404 from its own routes; flipping
//!   it back enables them again.
//! - PMS-113 AC4: missing module-config row returns a soft default.

mod common;

use sqlx::PgPool;

// --- AC1: tenant_settings round-trip + validation -----------------------------

#[sqlx::test]
async fn tenant_setting_round_trip_persists(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let put = app
        .client
        .put(app.url("/api/v1/settings/notifications/channel_email_enabled"))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "value": true }))
        .send()
        .await
        .expect("send put setting");
    assert!(
        put.status().is_success(),
        "PUT expected 2xx, got {}",
        put.status()
    );

    let get = app
        .client
        .get(app.url("/api/v1/settings/notifications/channel_email_enabled"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send get setting");
    assert_eq!(get.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = get.json().await.expect("get JSON");
    assert_eq!(body["category"].as_str(), Some("notifications"));
    assert_eq!(body["key"].as_str(), Some("channel_email_enabled"));
    assert_eq!(body["value"].as_bool(), Some(true));
}

#[sqlx::test]
async fn tenant_setting_value_validation_rejects_bad_shape(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let bad = app
        .client
        .put(app.url("/api/v1/settings/branding/primary_color"))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "value": "not-a-hex" }))
        .send()
        .await
        .expect("send bad-value put");
    assert_eq!(
        bad.status(),
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "non-hex primary_color must 422"
    );

    let good = app
        .client
        .put(app.url("/api/v1/settings/branding/primary_color"))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "value": "#0066cc" }))
        .send()
        .await
        .expect("send good put");
    assert!(
        good.status().is_success(),
        "valid hex must 2xx, got {}",
        good.status()
    );
}

#[sqlx::test]
async fn tenant_setting_unknown_category_accepted_with_warn(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let resp = app
        .client
        .put(app.url("/api/v1/settings/experimental_feature_x/knob_y"))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "value": 42 }))
        .send()
        .await
        .expect("send unknown-category put");
    assert!(
        resp.status().is_success(),
        "unknown (category, key) must be accepted, got {}",
        resp.status()
    );
}

#[sqlx::test]
async fn get_settings_by_category_lists_only_that_category(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    for (path, body) in [
        (
            "/api/v1/settings/notifications/channel_email_enabled",
            serde_json::json!({ "value": true }),
        ),
        (
            "/api/v1/settings/notifications/channel_in_app_enabled",
            serde_json::json!({ "value": false }),
        ),
        (
            "/api/v1/settings/branding/primary_color",
            serde_json::json!({ "value": "#abcdef" }),
        ),
    ] {
        let r = app
            .client
            .put(app.url(path))
            .bearer_auth(&token)
            .json(&body)
            .send()
            .await
            .expect("seed setting");
        assert!(r.status().is_success(), "seed {path} failed {}", r.status());
    }

    let notif: serde_json::Value = app
        .client
        .get(app.url("/api/v1/settings/notifications"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send notif")
        .json()
        .await
        .expect("notif JSON");
    let notif_arr = notif.as_array().expect("notifications list is an array");
    assert_eq!(
        notif_arr.len(),
        2,
        "notifications category should hold 2 rows"
    );

    let brand: serde_json::Value = app
        .client
        .get(app.url("/api/v1/settings/branding"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send branding")
        .json()
        .await
        .expect("branding JSON");
    let brand_arr = brand.as_array().expect("branding list is an array");
    assert_eq!(brand_arr.len(), 1);
}

#[sqlx::test]
async fn tenant_setting_delete_then_get_returns_404(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let put = app
        .client
        .put(app.url("/api/v1/settings/branding/primary_color"))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "value": "#123456" }))
        .send()
        .await
        .expect("seed setting");
    assert!(put.status().is_success());

    let del = app
        .client
        .delete(app.url("/api/v1/settings/branding/primary_color"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send delete");
    assert!(
        del.status().is_success(),
        "delete must 2xx, got {}",
        del.status()
    );

    let get = app
        .client
        .get(app.url("/api/v1/settings/branding/primary_color"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send get after delete");
    assert_eq!(
        get.status(),
        reqwest::StatusCode::NOT_FOUND,
        "after delete GET must 404"
    );
}

// --- AC2: module-config round-trip on both surfaces ---------------------------

#[sqlx::test]
async fn module_config_settings_surface_round_trip(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let put = app
        .client
        .put(app.url("/api/v1/settings/modules/test_module_settings"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "is_enabled": true,
            "config": { "foo": "bar" }
        }))
        .send()
        .await
        .expect("send put");
    assert!(
        put.status().is_success(),
        "PUT must 2xx, got {}",
        put.status()
    );

    let get = app
        .client
        .get(app.url("/api/v1/settings/modules/test_module_settings"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send get");
    assert_eq!(get.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = get.json().await.expect("get JSON");
    assert_eq!(body["module_name"].as_str(), Some("test_module_settings"));
    assert_eq!(body["is_enabled"].as_bool(), Some(true));
    assert_eq!(body["config"]["foo"].as_str(), Some("bar"));
}

/// PUT on the tenants-API surface, GET on the settings-API surface.
/// Both hit the same row in `module_config` because the tenants
/// handlers delegate to SettingsService (PMS-113 AC2).
#[sqlx::test]
async fn module_config_tenants_surface_delegates_to_settings(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let put = app
        .client
        .put(app.url(&format!(
            "/api/v1/tenants/{}/modules/test_module_tenants",
            common::DEFAULT_TENANT_ID
        )))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "is_enabled": true,
            "config": { "x": 1 }
        }))
        .send()
        .await
        .expect("send tenants put");
    assert!(
        put.status().is_success(),
        "tenants PUT must 2xx, got {}",
        put.status()
    );

    let get = app
        .client
        .get(app.url("/api/v1/settings/modules/test_module_tenants"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send settings get");
    assert_eq!(get.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = get.json().await.expect("get JSON");
    assert_eq!(body["module_name"].as_str(), Some("test_module_tenants"));
    assert_eq!(body["is_enabled"].as_bool(), Some(true));
    assert_eq!(body["config"]["x"].as_i64(), Some(1));
}

// --- AC4: soft default on missing module-config row --------------------------

#[sqlx::test]
async fn module_config_get_missing_returns_soft_default(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let get = app
        .client
        .get(app.url("/api/v1/settings/modules/never_seen_module"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send get missing");
    assert_eq!(
        get.status(),
        reqwest::StatusCode::OK,
        "missing module must soft-default, not 404"
    );
    let body: serde_json::Value = get.json().await.expect("get JSON");
    assert_eq!(body["module_name"].as_str(), Some("never_seen_module"));
    assert_eq!(body["is_enabled"].as_bool(), Some(false));
    assert!(
        body["config"].is_object() && body["config"].as_object().unwrap().is_empty(),
        "config must be an empty object, got {:?}",
        body["config"]
    );
}

// --- AC3: runtime feature gating (the keystone) ------------------------------

/// Disable the billing module via PUT; a subsequent GET on a billing
/// route returns 404; flipping it back lets traffic through again.
/// Pins the `RequireModuleEnabled` extractor and the entire PMS-113
/// AC3 wiring (extractor + Extension layer + sweep).
#[sqlx::test]
async fn disabled_module_returns_404_on_route_access(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    // Sanity: billing is enabled by default (migration 023 seeds it
    // with is_enabled=TRUE for the default tenant).
    let before = app
        .client
        .get(app.url("/api/v1/billing/invoices?per_page=5"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("baseline billing GET");
    assert_eq!(
        before.status(),
        reqwest::StatusCode::OK,
        "billing must be enabled at start, got {}",
        before.status()
    );

    // Disable.
    let disable = app
        .client
        .put(app.url("/api/v1/settings/modules/billing"))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "is_enabled": false }))
        .send()
        .await
        .expect("disable billing");
    assert!(disable.status().is_success());

    // The gated route now 404s.
    let gated = app
        .client
        .get(app.url("/api/v1/billing/invoices?per_page=5"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("gated billing GET");
    assert_eq!(
        gated.status(),
        reqwest::StatusCode::NOT_FOUND,
        "disabled billing module must 404 (got {})",
        gated.status()
    );

    // Re-enable.
    let enable = app
        .client
        .put(app.url("/api/v1/settings/modules/billing"))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "is_enabled": true }))
        .send()
        .await
        .expect("re-enable billing");
    assert!(enable.status().is_success());

    let after = app
        .client
        .get(app.url("/api/v1/billing/invoices?per_page=5"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("post-enable billing GET");
    assert_eq!(
        after.status(),
        reqwest::StatusCode::OK,
        "re-enabled billing module must serve again, got {}",
        after.status()
    );
}

#[sqlx::test]
async fn enabled_module_response_unchanged(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    // Default billing is enabled; the extractor should pass through.
    let resp = app
        .client
        .get(app.url("/api/v1/billing/invoices?per_page=5"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send billing list");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "enabled billing module must serve cleanly, got {}",
        resp.status()
    );
    let body: serde_json::Value = resp.json().await.expect("list JSON");
    // Just shape sanity - empty data + meta envelope.
    assert!(body["data"].is_array());
    assert!(body["meta"].is_object());
}
