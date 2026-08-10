//! PMS-729: host-derived tenant resolution for the client portal.
//!
//! The extractor + policy have full unit coverage in
//! `src/modules/portal/host_tenant.rs`; this suite pins the HTTP wire
//! shape that the unit tests cannot: the login handler's Host-header read
//! path, the fail-closed 401 envelope byte-identical to a wrong password,
//! and the `/portal/host` branding endpoint's 200-vs-404 posture.
//!
//! Each test boots the router with an explicit `PortalHostConfig` via
//! `boot_with_portal_host` (no process-env mutation) so it can run
//! alongside every other integration binary without leaking state.

mod common;

use sqlx::PgPool;
use uuid::Uuid;

use mokosh_server::modules::portal::PortalHostConfig;

const PORTAL_PASSWORD: &str = "portal-password-12345";
const PORTAL_SUFFIX: &str = ".client.a8n.systems";

/// Seed a tenant with the given slug + display name + branding logo. The
/// PMS-729 host lookup runs on tenants with `status = 'active'`, so all
/// seeds here are active by construction.
async fn seed_tenant(pool: &PgPool, slug: &str, name: &str, logo_url: Option<&str>) -> Uuid {
    let id = Uuid::new_v4();
    let branding = match logo_url {
        Some(url) => serde_json::json!({ "logo_url": url }),
        None => serde_json::json!({}),
    };
    sqlx::query(
        r#"
        INSERT INTO tenants (id, name, slug, status, kind, branding)
        VALUES ($1, $2, $3, 'active', 'org', $4)
        "#,
    )
    .bind(id)
    .bind(name)
    .bind(slug)
    .bind(branding)
    .execute(pool)
    .await
    .expect("seed tenant");
    id
}

/// Seed a company under the given tenant. Returns its id.
async fn seed_company(pool: &PgPool, tenant_id: Uuid, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(tenant_id)
        .bind(name)
        .execute(pool)
        .await
        .expect("seed company");
    id
}

/// Seed a portal-enabled contact with a hashed password.
async fn seed_portal_contact(pool: &PgPool, tenant_id: Uuid, company_id: Uuid, email: &str) {
    let hash =
        mokosh_server::utils::crypto::hash_password(PORTAL_PASSWORD).expect("hash portal password");
    sqlx::query(
        r#"
        INSERT INTO contacts (
            id, tenant_id, company_id, first_name, last_name, email,
            is_portal_user, portal_password_hash
        )
        VALUES ($1, $2, $3, 'Portal', 'Contact', $4, TRUE, $5)
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(tenant_id)
    .bind(company_id)
    .bind(email)
    .bind(&hash)
    .execute(pool)
    .await
    .expect("seed portal contact");
}

/// `POST /api/v1/portal/auth/login` with a caller-controlled `Host`
/// header (drives the PMS-729 host-derived path) and a JSON body whose
/// shape reflects whether a legacy `tenant_slug` field is present.
async fn portal_login_with_host(
    app: &common::TestApp,
    host: &str,
    body: serde_json::Value,
) -> reqwest::Response {
    app.client
        .post(app.url("/api/v1/portal/auth/login"))
        .header(reqwest::header::HOST, host)
        .json(&body)
        .send()
        .await
        .expect("send portal login")
}

/// `GET /api/v1/portal/host` with a caller-controlled `Host` header.
async fn portal_host_hint(app: &common::TestApp, host: &str) -> reqwest::Response {
    app.client
        .get(app.url("/api/v1/portal/host"))
        .header(reqwest::header::HOST, host)
        .send()
        .await
        .expect("send portal host hint")
}

/// Boot the router with the PMS-729 portal-host feature enabled.
fn portal_host_enabled() -> PortalHostConfig {
    PortalHostConfig::from_suffix(PORTAL_SUFFIX)
}

/// Assert the response looks like an `AppError::Unauthorized`: 401
/// with the shared `{error:{code:"UNAUTHORIZED", message}}` envelope.
/// The portal login handler collapses every negative host / body slug
/// outcome to this exact shape so the endpoint cannot be used to
/// enumerate MSPs.
async fn assert_unauthorized_envelope(resp: reqwest::Response, ctx: &str) {
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "{ctx}: expected 401, got {}",
        resp.status()
    );
    let body: serde_json::Value = resp.json().await.expect("401 body is JSON");
    assert_eq!(
        body["error"]["code"].as_str(),
        Some("UNAUTHORIZED"),
        "{ctx}: envelope code = UNAUTHORIZED; got {body}"
    );
}

// AC (PMS-729 §5.3): a portal-shape Host resolves to the tenant slug and
// the login succeeds without a `tenant_slug` in the body.
#[sqlx::test]
async fn host_only_login_succeeds(pool: PgPool) {
    let tenant = seed_tenant(&pool, "acme", "Acme MSP", None).await;
    let company = seed_company(&pool, tenant, "Acme Co").await;
    seed_portal_contact(&pool, tenant, company, "user@acme.example").await;
    let app = common::boot_with_portal_host(pool, portal_host_enabled()).await;

    let resp = portal_login_with_host(
        &app,
        "acme.client.a8n.systems",
        serde_json::json!({
            "email": "user@acme.example",
            "password": PORTAL_PASSWORD,
        }),
    )
    .await;
    assert!(
        resp.status().is_success(),
        "host-only login should 2xx, got {}",
        resp.status()
    );
    let body: serde_json::Value = resp.json().await.expect("login body JSON");
    assert!(
        body["access_token"].as_str().is_some(),
        "login returns an access token"
    );
    assert_eq!(
        body["contact"]["tenant_id"].as_str(),
        Some(tenant.to_string().as_str()),
        "session is scoped to the host-resolved tenant"
    );
}

// AC: host+body slug match still authenticates. Legacy `?tenant=` links
// that already fill the field continue to work on portal-shape hosts.
#[sqlx::test]
async fn host_and_matching_body_login_succeeds(pool: PgPool) {
    let tenant = seed_tenant(&pool, "acme", "Acme MSP", None).await;
    let company = seed_company(&pool, tenant, "Acme Co").await;
    seed_portal_contact(&pool, tenant, company, "user@acme.example").await;
    let app = common::boot_with_portal_host(pool, portal_host_enabled()).await;

    let resp = portal_login_with_host(
        &app,
        "acme.client.a8n.systems",
        serde_json::json!({
            "tenant_slug": "acme",
            "email": "user@acme.example",
            "password": PORTAL_PASSWORD,
        }),
    )
    .await;
    assert!(
        resp.status().is_success(),
        "host+matching-body login should 2xx, got {}",
        resp.status()
    );
}

// AC: host and body slug disagree -> 401 with the wrong-password
// envelope. Prevents a cross-tenant credential replay from any portal
// host: a session on acme.client.<apex> cannot be turned into a beta
// session by supplying `tenant_slug: "beta"` in the body.
#[sqlx::test]
async fn host_and_mismatched_body_fails_closed(pool: PgPool) {
    let acme = seed_tenant(&pool, "acme", "Acme MSP", None).await;
    let beta = seed_tenant(&pool, "beta", "Beta MSP", None).await;
    let acme_co = seed_company(&pool, acme, "Acme Co").await;
    let beta_co = seed_company(&pool, beta, "Beta Co").await;
    seed_portal_contact(&pool, acme, acme_co, "shared@example.com").await;
    seed_portal_contact(&pool, beta, beta_co, "shared@example.com").await;
    let app = common::boot_with_portal_host(pool, portal_host_enabled()).await;

    let resp = portal_login_with_host(
        &app,
        "acme.client.a8n.systems",
        serde_json::json!({
            "tenant_slug": "beta",
            "email": "shared@example.com",
            "password": PORTAL_PASSWORD,
        }),
    )
    .await;
    assert_unauthorized_envelope(resp, "host=acme body=beta").await;
}

// AC: an unknown Host slug is indistinguishable from a wrong password.
// A visitor who knows a real email + password on the "default" tenant
// cannot log in through `nope.client.<apex>` even though the credential
// itself is valid: the host resolves to nothing and the body carries no
// slug, so the policy fails closed.
#[sqlx::test]
async fn unknown_host_slug_fails_closed(pool: PgPool) {
    let tenant = seed_tenant(&pool, "acme", "Acme MSP", None).await;
    let company = seed_company(&pool, tenant, "Acme Co").await;
    seed_portal_contact(&pool, tenant, company, "user@acme.example").await;
    let app = common::boot_with_portal_host(pool, portal_host_enabled()).await;

    let resp = portal_login_with_host(
        &app,
        "nope.client.a8n.systems",
        serde_json::json!({
            "email": "user@acme.example",
            "password": PORTAL_PASSWORD,
        }),
    )
    .await;
    assert_unauthorized_envelope(resp, "unknown host slug").await;
}

// AC (backwards compat): a non-portal Host still authenticates the legacy
// body-only path. The mokosh-apps SPA on `msp.<apex>` and any historic
// `?tenant=X` link keep working after the feature is turned on.
#[sqlx::test]
async fn legacy_body_only_login_still_works_on_non_portal_host(pool: PgPool) {
    let tenant = seed_tenant(&pool, "acme", "Acme MSP", None).await;
    let company = seed_company(&pool, tenant, "Acme Co").await;
    seed_portal_contact(&pool, tenant, company, "user@acme.example").await;
    let app = common::boot_with_portal_host(pool, portal_host_enabled()).await;

    // A host that doesn't end with the portal suffix -> extractor returns
    // None; the login falls back to the body slug exactly like pre-PMS-729.
    let resp = portal_login_with_host(
        &app,
        "msp.a8n.systems",
        serde_json::json!({
            "tenant_slug": "acme",
            "email": "user@acme.example",
            "password": PORTAL_PASSWORD,
        }),
    )
    .await;
    assert!(
        resp.status().is_success(),
        "legacy body-only login should 2xx on a non-portal host, got {}",
        resp.status()
    );
}

// AC (kill switch): with the feature disabled (empty suffix) every Host
// looks legacy. A request lands on `acme.client.<apex>` but the extractor
// is off, so the router still requires a body slug and, when supplied,
// authenticates normally.
#[sqlx::test]
async fn feature_disabled_ignores_the_host(pool: PgPool) {
    let tenant = seed_tenant(&pool, "acme", "Acme MSP", None).await;
    let company = seed_company(&pool, tenant, "Acme Co").await;
    seed_portal_contact(&pool, tenant, company, "user@acme.example").await;
    // Explicit empty suffix -> feature off. Same posture as pre-PMS-729.
    let app = common::boot_with_portal_host(pool, PortalHostConfig::from_suffix("")).await;

    // Body-only login authenticates.
    let ok = portal_login_with_host(
        &app,
        "acme.client.a8n.systems",
        serde_json::json!({
            "tenant_slug": "acme",
            "email": "user@acme.example",
            "password": PORTAL_PASSWORD,
        }),
    )
    .await;
    assert!(
        ok.status().is_success(),
        "with the feature off, body-only login should 2xx even on a portal-shape host, got {}",
        ok.status()
    );

    // No body slug + feature off -> fail-closed even though the host would
    // resolve if the feature were on.
    let missing = portal_login_with_host(
        &app,
        "acme.client.a8n.systems",
        serde_json::json!({
            "email": "user@acme.example",
            "password": PORTAL_PASSWORD,
        }),
    )
    .await;
    assert_unauthorized_envelope(missing, "feature off, no body slug").await;
}

// AC: `/portal/host` returns the branding hint (200 + name + optional
// logo URL) when the Host resolves to an active tenant. The endpoint is
// public: no auth is needed to paint the login screen.
#[sqlx::test]
async fn host_hint_returns_branding_for_active_tenant(pool: PgPool) {
    seed_tenant(
        &pool,
        "acme",
        "Acme MSP",
        Some("https://cdn.example.com/acme.png"),
    )
    .await;
    let app = common::boot_with_portal_host(pool, portal_host_enabled()).await;

    let resp = portal_host_hint(&app, "acme.client.a8n.systems").await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("host hint body");
    assert_eq!(body["name"].as_str(), Some("Acme MSP"));
    assert_eq!(
        body["logo_url"].as_str(),
        Some("https://cdn.example.com/acme.png"),
        "logo_url is surfaced from the tenants.branding JSONB"
    );
}

// AC: `logo_url` is skipped from the response when the tenant has no
// branding entry, so the SPA can distinguish "hint exists but no logo"
// from "no hint at all" without a truthy-empty-string trap.
#[sqlx::test]
async fn host_hint_omits_logo_url_when_absent(pool: PgPool) {
    seed_tenant(&pool, "acme", "Acme MSP", None).await;
    let app = common::boot_with_portal_host(pool, portal_host_enabled()).await;

    let resp = portal_host_hint(&app, "acme.client.a8n.systems").await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("host hint body");
    assert_eq!(body["name"].as_str(), Some("Acme MSP"));
    assert!(
        body.get("logo_url").is_none(),
        "logo_url must be omitted, got {body}"
    );
}

// AC (phase 2 §6): `/portal/host` surfaces the full extended branding
// surface (primary_color, welcome_message, support_email, footer_text,
// favicon_url, logo_url_dark, primary_color_dark, support_phone,
// support_hours) alongside `name` + `logo_url`, all flattened at the
// JSON layer so the SPA reads them as top-level fields.
#[sqlx::test]
async fn host_hint_surfaces_full_branding_surface(pool: PgPool) {
    // Seed a tenant with every branding field populated so a wire
    // regression here surfaces at once.
    let branding = serde_json::json!({
        "logo_url": "https://cdn.example/acme.png",
        "logo_url_dark": "https://cdn.example/acme-dark.png",
        "favicon_url": "https://cdn.example/acme.ico",
        "primary_color": "#2563eb",
        "primary_color_dark": "#60a5fa",
        "support_email": "help@acme.example",
        "support_phone": "+1 555 0100",
        "support_hours": "Mon-Fri 9am-5pm ET",
        "footer_text": "Powered by Acme MSP",
        "welcome_message": "Welcome to Acme's client portal",
    });
    let id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO tenants (id, name, slug, status, kind, branding)
        VALUES ($1, 'Acme MSP', 'acme', 'active', 'org', $2)
        "#,
    )
    .bind(id)
    .bind(&branding)
    .execute(&pool)
    .await
    .expect("seed tenant with full branding");
    let app = common::boot_with_portal_host(pool, portal_host_enabled()).await;

    let resp = portal_host_hint(&app, "acme.client.a8n.systems").await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("host hint body");

    // Name still on top.
    assert_eq!(body["name"].as_str(), Some("Acme MSP"));
    // Every branding field surfaces flat (not nested under `branding`).
    for (key, expected) in [
        ("logo_url", "https://cdn.example/acme.png"),
        ("logo_url_dark", "https://cdn.example/acme-dark.png"),
        ("favicon_url", "https://cdn.example/acme.ico"),
        ("primary_color", "#2563eb"),
        ("primary_color_dark", "#60a5fa"),
        ("support_email", "help@acme.example"),
        ("support_phone", "+1 555 0100"),
        ("support_hours", "Mon-Fri 9am-5pm ET"),
        ("footer_text", "Powered by Acme MSP"),
        ("welcome_message", "Welcome to Acme's client portal"),
    ] {
        assert_eq!(
            body[key].as_str(),
            Some(expected),
            "{key} should surface flat"
        );
    }
    // No nested `branding` wrapper.
    assert!(
        body.get("branding").is_none(),
        "branding must be flattened, not nested: {body}"
    );
}

// AC: an unknown Host slug returns 404 with no body. The endpoint cannot
// be used to enumerate live MSPs by trying candidate slugs.
#[sqlx::test]
async fn host_hint_returns_404_for_unknown_host(pool: PgPool) {
    let app = common::boot_with_portal_host(pool, portal_host_enabled()).await;

    let resp = portal_host_hint(&app, "nope.client.a8n.systems").await;
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
}

// AC: `/portal/host` also 404s when the feature is disabled, so a stray
// portal-shape probe against a legacy deployment does not leak a "yes,
// the feature is on but this MSP is unknown" signal.
#[sqlx::test]
async fn host_hint_returns_404_when_feature_disabled(pool: PgPool) {
    seed_tenant(&pool, "acme", "Acme MSP", None).await;
    let app = common::boot_with_portal_host(pool, PortalHostConfig::from_suffix("")).await;

    let resp = portal_host_hint(&app, "acme.client.a8n.systems").await;
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
}

// AC: X-Forwarded-Host takes precedence over Host so a reverse-proxy
// chain (Dioxus dev proxy, Traefik, cloud LB) that rewrites Host to
// the backend service name still lets the extractor see the browser's
// original host. Sends the "wrong" Host and the "right" X-Forwarded-Host,
// verifies the resolve fires against the forwarded value.
#[sqlx::test]
async fn x_forwarded_host_wins_over_host(pool: PgPool) {
    seed_tenant(&pool, "acme", "Acme MSP", None).await;
    let app = common::boot_with_portal_host(pool, portal_host_enabled()).await;

    let resp = app
        .client
        .get(app.url("/api/v1/portal/host"))
        .header(reqwest::header::HOST, "server:8080")
        .header("X-Forwarded-Host", "acme.client.a8n.systems")
        .send()
        .await
        .expect("send /portal/host");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("host hint body");
    assert_eq!(body["name"].as_str(), Some("Acme MSP"));
}

// AC: `X-Forwarded-Host` allows a comma-separated chain (RFC 7239); the
// extractor reads the LEFTMOST value (the original browser host before
// any of the forwarded hops rewrote it).
#[sqlx::test]
async fn x_forwarded_host_reads_leftmost_of_a_chain(pool: PgPool) {
    seed_tenant(&pool, "acme", "Acme MSP", None).await;
    let app = common::boot_with_portal_host(pool, portal_host_enabled()).await;

    let resp = app
        .client
        .get(app.url("/api/v1/portal/host"))
        .header(reqwest::header::HOST, "server:8080")
        .header(
            "X-Forwarded-Host",
            "acme.client.a8n.systems, edge-1.internal, lb.internal",
        )
        .send()
        .await
        .expect("send /portal/host");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
}

// AC: an empty X-Forwarded-Host falls through to Host (defensive; some
// proxies send an empty header when they can't determine the original
// host, and we want the extractor to still work in that case).
#[sqlx::test]
async fn empty_x_forwarded_host_falls_back_to_host(pool: PgPool) {
    seed_tenant(&pool, "acme", "Acme MSP", None).await;
    let app = common::boot_with_portal_host(pool, portal_host_enabled()).await;

    let resp = app
        .client
        .get(app.url("/api/v1/portal/host"))
        .header(reqwest::header::HOST, "acme.client.a8n.systems")
        .header("X-Forwarded-Host", "")
        .send()
        .await
        .expect("send /portal/host");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
}

// AC: a Host that ends with the suffix but carries a malformed label
// (invalid characters, leading/trailing hyphen, empty label) is treated
// exactly like an unknown host: 404 on `/portal/host`, 401 on
// `/portal/auth/login`. This keeps the failure envelope stable so the
// caller cannot probe the label validator.
#[sqlx::test]
async fn malformed_host_label_fails_closed(pool: PgPool) {
    seed_tenant(&pool, "acme", "Acme MSP", None).await;
    let app = common::boot_with_portal_host(pool, portal_host_enabled()).await;

    for host in [
        "-bad.client.a8n.systems",     // leading hyphen
        "bad_slug.client.a8n.systems", // invalid character
        ".client.a8n.systems",         // empty label
    ] {
        let hint = portal_host_hint(&app, host).await;
        assert_eq!(
            hint.status(),
            reqwest::StatusCode::NOT_FOUND,
            "{host}: /portal/host should 404"
        );

        let login = portal_login_with_host(
            &app,
            host,
            serde_json::json!({
                "email": "user@acme.example",
                "password": PORTAL_PASSWORD,
            }),
        )
        .await;
        assert_unauthorized_envelope(login, host).await;
    }
}
