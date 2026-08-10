//! PMS-729 phase 2 §5 H9: portal-response CSP audit.
//!
//! The plan doc's H9 asked for "portal-specific CSP" work; the actual
//! finding after inspecting `src/utils/security_headers.rs` is that the
//! existing global CSP (`default-src 'none'; style-src 'unsafe-inline';
//! frame-ancestors 'none'; base-uri 'none'; form-action 'none'`) is
//! ALREADY correct for the portal API surface:
//!
//! - Portal routes return JSON only. There is no page that needs to
//!   load scripts, images, fonts, or fetch cross-origin resources
//!   from within the response body.
//! - The mokosh-apps SPA (Caddyfile-served, separate process) sets its
//!   own SPA-appropriate CSP that permits WASM + inline styles + the
//!   API origin's `connect-src`. That is where the SPA's CSP lives;
//!   the server-side `security_headers` middleware just protects the
//!   API surface.
//!
//! So H9 does NOT introduce a new portal-specific CSP. It DOES add
//! this regression test: pin the CSP that every portal response
//! carries so a future middleware edit cannot silently loosen it.
//!
//! If the portal ever gains an HTML-returning endpoint (a
//! server-rendered receipt or invoice PDF viewer, say), that specific
//! handler will need its own `csp_with_...` helper (mirroring
//! `csp_with_script_nonce`) and this test's expectation set will fork.

mod common;

use sqlx::PgPool;

const EXPECTED_CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; \
     frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

/// Every portal response - authenticated or not, success or error -
/// must carry the strict CSP so a browser sandboxes any embedded
/// content (there is none, by design) and blocks base/form injection.
#[sqlx::test]
async fn portal_health_response_ships_strict_csp(pool: PgPool) {
    let app = common::boot(pool).await;

    let resp = app
        .client
        .get(app.url("/api/v1/portal/health"))
        .send()
        .await
        .expect("send /portal/health");
    assert!(resp.status().is_success());
    let csp = resp
        .headers()
        .get("content-security-policy")
        .expect("CSP header present on /portal/health")
        .to_str()
        .expect("CSP header is ASCII");
    // Collapse repeated whitespace so the literal above (which line-
    // wraps for readability) compares to the wire value (which does
    // not).
    let normalise = |s: &str| s.split_whitespace().collect::<Vec<_>>().join(" ");
    assert_eq!(normalise(csp), normalise(EXPECTED_CSP), "CSP drift: {csp}");
}

/// A 401 from the auth middleware also carries the CSP (fail-closed
/// paths must not skip the middleware).
#[sqlx::test]
async fn portal_401_response_still_ships_strict_csp(pool: PgPool) {
    let app = common::boot(pool).await;

    let resp = app
        .client
        .get(app.url("/api/v1/portal/auth/me"))
        .send()
        .await
        .expect("send /portal/auth/me without a bearer");
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
    let csp = resp
        .headers()
        .get("content-security-policy")
        .expect("CSP header present on 401")
        .to_str()
        .unwrap();
    let normalise = |s: &str| s.split_whitespace().collect::<Vec<_>>().join(" ");
    assert_eq!(
        normalise(csp),
        normalise(EXPECTED_CSP),
        "CSP drift on 401: {csp}"
    );
}

/// The full companion set of security headers: HSTS, nosniff,
/// x-frame-options, referrer-policy, permissions-policy. Pinning all
/// of them at once prevents a partial removal (e.g. someone drops
/// HSTS while leaving CSP intact and thinks security is unchanged).
#[sqlx::test]
async fn portal_response_ships_full_security_header_set(pool: PgPool) {
    let app = common::boot(pool).await;

    let resp = app
        .client
        .get(app.url("/api/v1/portal/health"))
        .send()
        .await
        .expect("send /portal/health");
    let headers = resp.headers();

    assert_eq!(
        headers
            .get("strict-transport-security")
            .and_then(|v| v.to_str().ok()),
        Some("max-age=31536000; includeSubDomains; preload")
    );
    assert_eq!(
        headers
            .get("x-content-type-options")
            .and_then(|v| v.to_str().ok()),
        Some("nosniff")
    );
    assert_eq!(
        headers.get("x-frame-options").and_then(|v| v.to_str().ok()),
        Some("DENY")
    );
    assert_eq!(
        headers.get("referrer-policy").and_then(|v| v.to_str().ok()),
        Some("no-referrer")
    );
    // Permissions-Policy: check for a couple of the denials rather
    // than the exact whitespace-normalised full string.
    let pp = headers
        .get("permissions-policy")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    for denial in ["geolocation=()", "camera=()", "microphone=()"] {
        assert!(
            pp.contains(denial),
            "permissions-policy missing {denial}: {pp}"
        );
    }
}
