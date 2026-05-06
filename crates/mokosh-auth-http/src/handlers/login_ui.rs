//! Minimal login UI served by the OP itself.
//!
//! `GET /login` renders an HTML form (no JS required). `POST /login`
//! accepts the form-encoded body, drives `LocalAuth`, sets the OP
//! session cookie, and 302s to `/oauth2/authorize?<return_to>` so the
//! interrupted code flow resumes.
//!
//! The page is deliberately a single inline HTML string with no
//! templating engine: it's part of the trust boundary, has zero data
//! attack surface, and stays trivially auditable.

use axum::extract::{ConnectInfo, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::cookies::set_op_session_cookie;
use crate::errors::HttpError;
use crate::local_auth::LocalLoginRequest;
use crate::router::AuthHttpState;

#[derive(Debug, Deserialize)]
pub struct LoginPageQuery {
    /// The original `/oauth2/authorize` query string, percent-encoded
    /// once. After successful login we redirect to
    /// `/oauth2/authorize?<return_to>` so the code flow resumes
    /// where the user left off.
    pub return_to: Option<String>,
    /// Surfaces the most recent error so a failed POST /login can
    /// re-render the form with feedback. Plain string; we HTML-escape
    /// before rendering.
    pub error: Option<String>,
}

pub async fn login_form(Query(q): Query<LoginPageQuery>) -> Html<String> {
    Html(render(q.return_to.as_deref().unwrap_or(""), q.error.as_deref()))
}

#[derive(Debug, Deserialize)]
pub struct LoginFormBody {
    pub email: String,
    pub password: String,
    pub tenant_id: String,
    pub return_to: Option<String>,
}

pub async fn login_submit(
    State(st): State<Arc<AuthHttpState>>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    jar: CookieJar,
    axum::Form(body): axum::Form<LoginFormBody>,
) -> Result<Response, HttpError> {
    let tenant_id = body
        .tenant_id
        .parse::<uuid::Uuid>()
        .map_err(|_| HttpError(mokosh_auth_core::AuthError::InvalidRequest("tenant_id must be a UUID".into())))?;
    let req = LocalLoginRequest {
        tenant_id,
        email: body.email.clone(),
        password: body.password,
    };
    let ip = Some(addr.ip());
    let ua = headers.get(header::USER_AGENT).and_then(|v| v.to_str().ok());

    match st.local_auth.login(req, ip, ua).await {
        Ok(session) => {
            let cookie = set_op_session_cookie(
                &st.cookie_cfg,
                session.sid.clone(),
                st.provider.cfg.op_session_ttl,
            );
            // Resume the interrupted authorize flow if there was one.
            // We percent-encoded the original query string when we
            // redirected to /login, so we just stitch it back on.
            let target = match body.return_to.as_deref() {
                Some(rt) if !rt.is_empty() => format!("/oauth2/authorize?{rt}"),
                _ => "/".to_string(),
            };
            Ok((jar.add(cookie), Redirect::to(&target)).into_response())
        }
        Err(_) => {
            // Re-render with a generic error. We never tell the user
            // whether the email exists or the password was wrong: that
            // would be a username-enumeration oracle.
            let url = match body.return_to {
                Some(rt) if !rt.is_empty() => format!(
                    "/login?error=invalid&return_to={}",
                    encode_query(&rt)
                ),
                _ => "/login?error=invalid".to_string(),
            };
            Ok((StatusCode::SEE_OTHER, [(header::LOCATION, url)]).into_response())
        }
    }
}

fn encode_query(s: &str) -> String {
    urlencoding::encode(s).into_owned()
}

fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(ch),
        }
    }
    out
}

fn render(return_to: &str, error: Option<&str>) -> String {
    let return_to_e = html_escape(return_to);
    let error_html = match error {
        Some(_) => r#"<div class="err">Sign-in failed. Check your email and password.</div>"#.to_string(),
        None => String::new(),
    };
    format!(
        r#"<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Sign in - Mokosh</title>
<style>
  :root {{ color-scheme: light dark; font-family: system-ui, -apple-system, sans-serif; }}
  body {{ margin: 0; min-height: 100vh; display: grid; place-items: center; background: #f5f7fa; }}
  @media (prefers-color-scheme: dark) {{ body {{ background: #0b1220; color: #e6e9ef; }} }}
  .card {{ background: white; border-radius: 12px; padding: 2rem; width: min(28rem, 100% - 2rem); box-shadow: 0 6px 24px rgba(0,0,0,.08); }}
  @media (prefers-color-scheme: dark) {{ .card {{ background: #131c2e; box-shadow: 0 6px 24px rgba(0,0,0,.4); }} }}
  h1 {{ margin: 0 0 1.25rem; font-size: 1.25rem; }}
  label {{ display: block; font-size: .85rem; margin-bottom: .25rem; }}
  input[type=email], input[type=password], input[type=text] {{ box-sizing: border-box; width: 100%; padding: .55rem .7rem; border: 1px solid #cbd5e1; border-radius: 6px; font-size: 1rem; background: transparent; color: inherit; }}
  input:focus {{ outline: 2px solid #6366f1; outline-offset: 1px; }}
  .field {{ margin-bottom: 1rem; }}
  button {{ width: 100%; padding: .65rem; border: 0; border-radius: 6px; background: #4f46e5; color: white; font-size: 1rem; cursor: pointer; }}
  button:hover {{ background: #4338ca; }}
  .err {{ background: #fee2e2; color: #991b1b; padding: .6rem .8rem; border-radius: 6px; margin-bottom: 1rem; font-size: .9rem; }}
  @media (prefers-color-scheme: dark) {{ .err {{ background: #4c1d24; color: #fecaca; }} }}
  small {{ display: block; margin-top: 1rem; color: #64748b; font-size: .8rem; }}
</style>
</head>
<body>
  <main class="card">
    <h1>Sign in to Mokosh</h1>
    {error_html}
    <form method="post" action="/login" autocomplete="on">
      <div class="field">
        <label for="email">Email</label>
        <input id="email" name="email" type="email" required autofocus autocomplete="username"/>
      </div>
      <div class="field">
        <label for="password">Password</label>
        <input id="password" name="password" type="password" required autocomplete="current-password"/>
      </div>
      <div class="field">
        <label for="tenant_id">Tenant ID</label>
        <input id="tenant_id" name="tenant_id" type="text" required pattern="[0-9a-fA-F-]{{8,}}"
               placeholder="00000000-0000-0000-0000-000000000000"/>
      </div>
      <input type="hidden" name="return_to" value="{return_to_e}"/>
      <button type="submit">Sign in</button>
    </form>
    <small>Single-tenant deploys can pre-fill the tenant via deploy config in a later iteration.</small>
  </main>
</body></html>"#,
        error_html = error_html,
        return_to_e = return_to_e,
    )
}
