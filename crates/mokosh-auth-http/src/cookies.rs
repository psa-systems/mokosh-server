//! Cookie helpers. The OP places one cookie on the browser
//! (`mokosh_op_session`) carrying the opaque `sid` of the OP session.
//!
//! Required attributes: HttpOnly, Secure (in production), SameSite=Lax
//! (Strict would break the OAuth redirect from a relying party back to
//! the OP), `Domain` from `MOKOSH_AUTH_COOKIE_DOMAIN`, `Path=/`.

use axum_extra::extract::cookie::{Cookie, SameSite};
use chrono::Duration;
use time::OffsetDateTime;

pub const OP_SESSION_COOKIE: &str = "mokosh_op_session";

#[derive(Clone, Debug)]
pub struct CookieConfig {
    pub domain: Option<String>,
    pub secure: bool,
}

pub fn set_op_session_cookie<'a>(cfg: &CookieConfig, sid: String, ttl: Duration) -> Cookie<'a> {
    let mut c = Cookie::new(OP_SESSION_COOKIE, sid);
    c.set_http_only(true);
    c.set_secure(cfg.secure);
    c.set_same_site(SameSite::Lax);
    c.set_path("/");
    if let Some(d) = cfg.domain.clone() {
        c.set_domain(d);
    }
    let expires = OffsetDateTime::now_utc() + time::Duration::seconds(ttl.num_seconds());
    c.set_expires(expires);
    c
}

pub fn clear_op_session_cookie<'a>(cfg: &CookieConfig) -> Cookie<'a> {
    let mut c = Cookie::new(OP_SESSION_COOKIE, "");
    c.set_http_only(true);
    c.set_secure(cfg.secure);
    c.set_same_site(SameSite::Lax);
    c.set_path("/");
    if let Some(d) = cfg.domain.clone() {
        c.set_domain(d);
    }
    // Past expiry deletes the cookie.
    c.set_expires(OffsetDateTime::UNIX_EPOCH);
    c
}
