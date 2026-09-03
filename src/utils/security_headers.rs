//! Security response headers (PMS-388).
//!
//! Three of the four browser-facing surfaces (the mokosh-server API, the
//! mokosh-apps SPA, and the bunyip-web identity UI) shipped with no security
//! response headers; only bunyip-api set a full set via its
//! `.wrap(SecurityHeaders)` layer. The 2026-06-17 standup rejected fixing this
//! in the shared Traefik layer (broad blast radius: a `headers-security@docker`
//! middleware attempt broke Mokosh and knocked out Bunyip until manual
//! recovery) and moved the fix to the application layer instead.
//!
//! This middleware is the mokosh-server half of that decision: parity with
//! bunyip-api's `SecurityHeaders`. It attaches HSTS, nosniff, frame-deny, a
//! restrictive Referrer-Policy / Permissions-Policy, and a CSP tuned for this
//! surface (a JSON API whose only browser-rendered page is the
//! `not_a_frontend` fallback) to every response.
//!
//! A header the handler already set wins: the middleware only fills in the
//! ones that are absent. PMS-691's `csp_with_script_nonce` helper went away
//! with the Google OAuth popup in PMS-837 (its only caller); the `or_insert`
//! contract stays because it is what lets any future handler own its own CSP.

use axum::http::{header::HeaderName, HeaderValue};

/// Static (name, value) header pairs applied to every response. Kept as raw
/// string literals so the whole set is auditable in one place; all are valid
/// `HeaderValue`s and are parsed once per response with `from_static`.
const SECURITY_HEADERS: &[(&str, &str)] = &[
    // One year, include subdomains, preload-eligible. Ignored by browsers over
    // plain HTTP, so safe to send unconditionally behind the TLS proxy.
    (
        "strict-transport-security",
        "max-age=31536000; includeSubDomains; preload",
    ),
    // Stop MIME sniffing.
    ("x-content-type-options", "nosniff"),
    // Disallow framing entirely (clickjacking). Redundant with the CSP
    // `frame-ancestors 'none'` below, kept for older browsers.
    ("x-frame-options", "DENY"),
    // Do not leak the API URL (which can carry ids) in the Referer header.
    ("referrer-policy", "no-referrer"),
    // Deny every powerful browser feature by default; this surface needs none.
    (
        "permissions-policy",
        "accelerometer=(), autoplay=(), camera=(), display-capture=(), \
         encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), \
         magnetometer=(), microphone=(), midi=(), payment=(), usb=()",
    ),
    // API surface: nothing should load sub-resources. `style-src 'unsafe-inline'`
    // is the single allowance so the inline-styled `not_a_frontend` fallback
    // page still renders; `frame-ancestors 'none'` blocks clickjacking and
    // `base-uri 'none'` blocks base-tag injection.
    (
        "content-security-policy",
        "default-src 'none'; style-src 'unsafe-inline'; \
         frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    ),
];

/// Axum middleware that adds the [`SECURITY_HEADERS`] set to every response.
/// Mounted as a global layer on the outermost router so it covers the API, the
/// portal API, and the `not_a_frontend` fallback uniformly.
pub async fn security_headers(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    for (name, value) in SECURITY_HEADERS {
        // `or_insert`, not `insert`: the middleware runs after the handler, so
        // `insert` would clobber a handler-set header (the OAuth callback's
        // nonce CSP) with the global default.
        headers
            .entry(HeaderName::from_static(name))
            .or_insert(HeaderValue::from_static(value));
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::IntoResponse;
    use axum::{body::Body, http::Request, routing::get, Router};
    use tower::ServiceExt;

    fn app() -> Router {
        Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn(security_headers))
    }

    #[tokio::test]
    async fn every_security_header_is_present() {
        let response = app()
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let headers = response.headers();
        for (name, value) in SECURITY_HEADERS {
            let got = headers
                .get(*name)
                .unwrap_or_else(|| panic!("missing security header {name}"));
            assert_eq!(got, *value, "wrong value for {name}");
        }
    }

    #[tokio::test]
    async fn hsts_and_frame_deny_have_expected_values() {
        let response = app()
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            response.headers().get("strict-transport-security").unwrap(),
            "max-age=31536000; includeSubDomains; preload"
        );
        assert_eq!(response.headers().get("x-frame-options").unwrap(), "DENY");
        assert_eq!(
            response.headers().get("x-content-type-options").unwrap(),
            "nosniff"
        );
    }

    /// PMS-691 / PMS-837: no response relaxes `script-src` any more. Every
    /// response keeps `default-src 'none'` with no `script-src` at all, so an
    /// injected inline script has nothing to run under.
    #[tokio::test]
    async fn global_csp_has_no_script_src_relaxation() {
        let response = app()
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let csp = response
            .headers()
            .get("content-security-policy")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(csp.contains("default-src 'none'"), "global CSP: {csp}");
        assert!(!csp.contains("script-src"), "global CSP: {csp}");
        assert!(!csp.contains("nonce-"), "global CSP: {csp}");
    }

    /// The middleware runs after the handler, so it must not overwrite a CSP the
    /// handler set for itself (PMS-691).
    #[tokio::test]
    async fn handler_set_csp_survives_the_middleware() {
        let handler_csp = "default-src 'none'; img-src 'self'".to_string();
        let expected = handler_csp.clone();
        let app = Router::new()
            .route(
                "/popup",
                get(move || {
                    let value = handler_csp.clone();
                    async move {
                        let mut response = "<html></html>".into_response();
                        response.headers_mut().insert(
                            HeaderName::from_static("content-security-policy"),
                            HeaderValue::from_str(&value).unwrap(),
                        );
                        response
                    }
                }),
            )
            .layer(axum::middleware::from_fn(security_headers));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/popup")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.headers().get("content-security-policy").unwrap(),
            expected.as_str()
        );
        // The rest of the set is still filled in.
        assert_eq!(response.headers().get("x-frame-options").unwrap(), "DENY");
    }
}
