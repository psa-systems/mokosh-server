//! Mokosh-side glue for the Google OAuth flow.
//!
//! All of the OAuth/HTTPS work lives in the `google-oauth-flow`
//! workspace crate; this module owns only the mokosh-specific
//! concerns: signing a short-lived state cookie with the existing
//! `JWT_SECRET`, and rendering the HTML that closes the OAuth popup
//! and `postMessage`s tokens back to the SPA opener.

use axum::response::Html;
use chrono::{Duration, Utc};
use cookie::time::Duration as CookieDuration;
use cookie::{Cookie, SameSite};
use google_oauth_flow::AuthorizationState;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use thiserror::Error;

/// Cookie name used to carry the signed `AuthorizationState` between the
/// authorize redirect and the callback.
pub const STATE_COOKIE_NAME: &str = "mokosh_google_oauth_state";
const STATE_COOKIE_PATH: &str = "/api/v1/auth/google/callback";
const STATE_COOKIE_TTL_SECS: i64 = 10 * 60;

#[derive(Debug, Serialize, Deserialize)]
struct StateClaims {
    csrf: String,
    pkce: String,
    exp: i64,
}

#[derive(Debug, Error)]
pub enum StateCookieError {
    #[error("missing state cookie")]
    Missing,
    #[error("invalid state cookie: {0}")]
    Invalid(String),
}

/// Encode the OAuth state values into a `Set-Cookie` header value.
///
/// The cookie is HMAC-signed with the application's `JWT_SECRET`,
/// `HttpOnly`, `SameSite=Lax` (Strict would block Google's redirect
/// back), and scoped to the callback path. `secure` should be `true`
/// outside development - browsers drop `Secure` cookies on plain HTTP
/// localhost.
pub fn encode_state_cookie(
    state: &AuthorizationState,
    jwt_secret: &[u8],
    secure: bool,
) -> Result<String, StateCookieError> {
    let exp = (Utc::now() + Duration::seconds(STATE_COOKIE_TTL_SECS)).timestamp();
    let claims = StateClaims {
        csrf: state.csrf_token.clone(),
        pkce: state.pkce_verifier.clone(),
        exp,
    };
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_secret),
    )
    .map_err(|e| StateCookieError::Invalid(e.to_string()))?;

    let mut cookie = Cookie::new(STATE_COOKIE_NAME, token);
    cookie.set_path(STATE_COOKIE_PATH);
    cookie.set_http_only(true);
    cookie.set_same_site(SameSite::Lax);
    cookie.set_secure(secure);
    cookie.set_max_age(CookieDuration::seconds(STATE_COOKIE_TTL_SECS));
    Ok(cookie.to_string())
}

/// Decode the OAuth state cookie. Returns the original
/// `AuthorizationState` for the caller to compare against the `state`
/// query param.
pub fn decode_state_cookie(
    cookie_value: &str,
    jwt_secret: &[u8],
) -> Result<AuthorizationState, StateCookieError> {
    let data = decode::<StateClaims>(
        cookie_value,
        &DecodingKey::from_secret(jwt_secret),
        &Validation::default(),
    )
    .map_err(|e| StateCookieError::Invalid(e.to_string()))?;
    Ok(AuthorizationState {
        csrf_token: data.claims.csrf,
        pkce_verifier: data.claims.pkce,
    })
}

/// `Set-Cookie` header value that clears the state cookie after the
/// callback has consumed it.
pub fn clear_state_cookie() -> String {
    let mut cookie = Cookie::new(STATE_COOKIE_NAME, "");
    cookie.set_path(STATE_COOKIE_PATH);
    cookie.set_http_only(true);
    cookie.set_same_site(SameSite::Lax);
    cookie.set_max_age(CookieDuration::seconds(0));
    cookie.to_string()
}

/// Read the state cookie value out of a raw `Cookie:` request header.
pub fn read_state_cookie(cookie_header: &str) -> Option<String> {
    Cookie::split_parse(cookie_header)
        .filter_map(Result::ok)
        .find(|c| c.name() == STATE_COOKIE_NAME)
        .map(|c| c.value().to_string())
}

/// Render the popup-closing HTML page that `postMessage`s the payload
/// back to the SPA opener and closes the popup window.
///
/// Critical: `client_origin` is passed as the second argument to
/// `postMessage` so the browser only delivers the payload to the
/// configured SPA origin - never `*`.
pub fn callback_html(payload: &JsonValue, client_origin: &str) -> Html<String> {
    // `serde_json::to_string` HTML-escapes `<`, `>`, and `&`, so this
    // is safe to embed inline in a <script> tag.
    let payload_json = serde_json::to_string(payload).unwrap_or_else(|_| "{}".to_string());
    let origin_json =
        serde_json::to_string(client_origin).unwrap_or_else(|_| "\"\"".to_string());

    let body = format!(
        r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Signing in...</title></head>
<body>
<p>You can close this window.</p>
<script>
(function () {{
  var payload = {payload_json};
  var targetOrigin = {origin_json};
  if (window.opener) {{
    window.opener.postMessage({{ type: "mokosh-google-auth", payload: payload }}, targetOrigin);
  }}
  window.close();
}})();
</script>
</body></html>
"#
    );
    Html(body)
}
