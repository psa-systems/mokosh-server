//! End-to-end mail flow tests driven via mailpit's HTTP API.
//!
//! Prerequisites (matches `docs/mokosh-smtp/08-testing.md`):
//!   - `just dev-sso` is up (server, postgres, mailpit, Traefik routing).
//!   - The bootstrap admin user (`ADMIN_EMAIL` / `ADMIN_PASSWORD` from
//!     mokosh-server's `.env`) exists.
//!   - `just register-client` has run so a public OAuth client is present
//!     for issuing Bearer tokens via the password grant in /v1/auth/login.
//!   - For the signup test only: `MOKOSH_PUBLIC_SIGNUP_ENABLED=true` is
//!     set on the server (PSA-hub default is `false`).
//!
//! Marked `#[ignore]` because they require the live stack and external
//! state. Run with:
//!
//! ```text
//! MOKOSH_E2E_CLIENT_ID=<uuid> cargo test -p mokosh-auth \
//!   --test mailpit_integration -- --ignored --nocapture --test-threads=1
//! ```
//!
//! `--test-threads=1` because all three tests share a single mailpit
//! inbox and reset it before each run.

use reqwest::StatusCode;
use serde_json::{json, Value};
use std::time::{Duration, Instant};

fn api_base() -> String {
    std::env::var("MOKOSH_E2E_API_URL").unwrap_or_else(|_| {
        let user = std::env::var("USER").unwrap_or_else(|_| "a contributor".into());
        format!("https://{user}-mokosh-api.a8n.run")
    })
}

fn mailpit_base() -> String {
    std::env::var("MOKOSH_E2E_MAILPIT_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8025".into())
}

fn admin_email() -> String {
    std::env::var("MOKOSH_E2E_ADMIN_EMAIL").unwrap_or_else(|_| "admin@example.com".into())
}

fn admin_password() -> String {
    std::env::var("MOKOSH_E2E_ADMIN_PASSWORD").unwrap_or_else(|_| "devpassword12".into())
}

fn client_id() -> String {
    std::env::var("MOKOSH_E2E_CLIENT_ID")
        .expect("set MOKOSH_E2E_CLIENT_ID to the UUID printed by `just register-client`")
}

fn http() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .expect("build reqwest client")
}

async fn reset_mailpit(c: &reqwest::Client) {
    let url = format!("{}/api/v1/messages", mailpit_base());
    let res = c.delete(&url).send().await.expect("DELETE mailpit");
    assert!(
        res.status().is_success(),
        "mailpit DELETE failed: {}",
        res.status()
    );
}

/// Poll mailpit until at least one message exists addressed to `to_email`,
/// or panic after a few seconds. Returns the full message JSON (with body).
async fn wait_for_email(c: &reqwest::Client, to_email: &str) -> Value {
    let deadline = Instant::now() + Duration::from_secs(10);
    let list_url = format!("{}/api/v1/messages", mailpit_base());
    loop {
        let list: Value = c
            .get(&list_url)
            .send()
            .await
            .expect("GET mailpit messages")
            .json()
            .await
            .expect("parse mailpit list");
        let messages = list["messages"].as_array().cloned().unwrap_or_default();
        for m in messages {
            let matches_to = m["To"]
                .as_array()
                .map(|to| {
                    to.iter()
                        .any(|t| t["Address"].as_str() == Some(to_email))
                })
                .unwrap_or(false);
            if matches_to {
                let id = m["ID"].as_str().expect("message id");
                let full_url = format!("{}/api/v1/message/{}", mailpit_base(), id);
                return c
                    .get(&full_url)
                    .send()
                    .await
                    .expect("GET full message")
                    .json()
                    .await
                    .expect("parse full message");
            }
        }
        if Instant::now() > deadline {
            panic!("no mail for {to_email} after 10s; mailpit list: {list}");
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// Pull the first http(s) URL out of an email body. The text part is
/// enough; the HTML part contains the same link.
fn extract_link(body: &str) -> String {
    let start = body
        .find("http://")
        .or_else(|| body.find("https://"))
        .expect("no link in body");
    let tail = &body[start..];
    let end = tail
        .find(|c: char| c.is_whitespace() || c == '"' || c == '<' || c == ')')
        .unwrap_or(tail.len());
    tail[..end].to_string()
}

/// Last URL path segment. The accept/preview/complete endpoints all
/// take the raw token as `{token}`, and our links end with the token,
/// so this is enough.
fn token_from_link(link: &str) -> String {
    link.rsplit('/').next().expect("link has /").to_string()
}

async fn login_bearer(c: &reqwest::Client, email: &str, password: &str) -> String {
    let url = format!("{}/v1/auth/login", api_base());
    let res = c
        .post(&url)
        .json(&json!({
            "email": email,
            "password": password,
            "client_id": client_id(),
        }))
        .send()
        .await
        .expect("POST /v1/auth/login");
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "login failed: {}",
        res.text().await.unwrap_or_default()
    );
    let body: Value = res.json().await.expect("parse login json");
    body["tokens"]["access_token"]
        .as_str()
        .expect("login response missing tokens.access_token (did you pass client_id?)")
        .to_string()
}

fn rand_local_part() -> String {
    let n = uuid::Uuid::new_v4().to_string();
    n.chars().take(12).collect()
}

#[tokio::test]
#[ignore = "requires `just dev-sso` and MOKOSH_E2E_CLIENT_ID"]
async fn invite_round_trip_via_mailpit() {
    let c = http();
    reset_mailpit(&c).await;

    let bearer = login_bearer(&c, &admin_email(), &admin_password()).await;
    let invitee_email = format!("invitee-{}@test.local", rand_local_part());

    let issue_res = c
        .post(format!("{}/v1/auth/invites", api_base()))
        .bearer_auth(&bearer)
        .json(&json!({ "email": invitee_email, "role": "member" }))
        .send()
        .await
        .expect("POST /v1/auth/invites");
    assert!(
        issue_res.status().is_success(),
        "invite issue: {} {}",
        issue_res.status(),
        issue_res.text().await.unwrap_or_default()
    );

    let msg = wait_for_email(&c, &invitee_email).await;
    let text = msg["Text"].as_str().expect("Text part present");
    let link = extract_link(text);
    let token = token_from_link(&link);
    assert!(
        link.contains("/invite/"),
        "expected /invite/ in link, got {link}"
    );

    // Preview (token-gated read).
    let preview = c
        .get(format!("{}/v1/auth/invites/by-token/{}", api_base(), token))
        .send()
        .await
        .expect("GET invite preview");
    assert_eq!(preview.status(), StatusCode::OK, "invite preview");
    let preview_body: Value = preview.json().await.expect("preview json");
    assert_eq!(preview_body["email"].as_str(), Some(invitee_email.as_str()));

    // Accept.
    let new_password = "Aa!secret-invite-12";
    let accept = c
        .post(format!(
            "{}/v1/auth/invites/by-token/{}/accept",
            api_base(),
            token
        ))
        .json(&json!({ "password": new_password }))
        .send()
        .await
        .expect("POST accept");
    assert_eq!(
        accept.status(),
        StatusCode::OK,
        "invite accept: {}",
        accept.text().await.unwrap_or_default()
    );

    // Brand-new user can log in.
    let login = c
        .post(format!("{}/v1/auth/login", api_base()))
        .json(&json!({ "email": invitee_email, "password": new_password }))
        .send()
        .await
        .expect("POST invitee login");
    assert_eq!(login.status(), StatusCode::OK, "invitee login");
}

#[tokio::test]
#[ignore = "requires `just dev-sso` with MOKOSH_PUBLIC_SIGNUP_ENABLED=true and MOKOSH_E2E_CLIENT_ID"]
async fn signup_round_trip_via_mailpit() {
    let c = http();
    reset_mailpit(&c).await;

    let new_email = format!("fresh-{}@test.local", rand_local_part());

    let start = c
        .post(format!("{}/v1/auth/signup", api_base()))
        .json(&json!({ "email": new_email }))
        .send()
        .await
        .expect("POST /v1/auth/signup");
    match start.status() {
        StatusCode::OK => {}
        StatusCode::NOT_FOUND => {
            // signup_disabled - the server is running PSA-hub config.
            // Skip without failing so this same test file is usable on
            // both deployments.
            eprintln!("signup disabled on server; skipping");
            return;
        }
        s => panic!(
            "signup start: {s} {}",
            start.text().await.unwrap_or_default()
        ),
    }

    let msg = wait_for_email(&c, &new_email).await;
    let text = msg["Text"].as_str().expect("Text part");
    let link = extract_link(text);
    let token = token_from_link(&link);
    assert!(
        link.contains("/signup/"),
        "expected /signup/ in link, got {link}"
    );

    let preview = c
        .get(format!("{}/v1/auth/signup/by-token/{}", api_base(), token))
        .send()
        .await
        .expect("GET signup preview");
    assert_eq!(preview.status(), StatusCode::OK, "signup preview");
    let preview_body: Value = preview.json().await.expect("preview json");
    assert_eq!(preview_body["email"].as_str(), Some(new_email.as_str()));

    let password = "Aa!signup-pass-12";
    let complete = c
        .post(format!(
            "{}/v1/auth/signup/by-token/{}/complete",
            api_base(),
            token
        ))
        .json(&json!({
            "password": password,
            "first_name": "Fresh",
            "last_name": "Tester",
        }))
        .send()
        .await
        .expect("POST signup complete");
    assert_eq!(
        complete.status(),
        StatusCode::OK,
        "signup complete: {}",
        complete.text().await.unwrap_or_default()
    );

    let login = c
        .post(format!("{}/v1/auth/login", api_base()))
        .json(&json!({ "email": new_email, "password": password }))
        .send()
        .await
        .expect("POST new-user login");
    assert_eq!(login.status(), StatusCode::OK, "new-user login");
}

#[tokio::test]
#[ignore = "requires `just dev-sso` and MOKOSH_E2E_CLIENT_ID"]
async fn password_reset_round_trip_via_mailpit() {
    let c = http();
    reset_mailpit(&c).await;

    // Pre-create a user via invite + accept so we know the starting
    // password. Reusing the bootstrap admin would couple this test to
    // whatever ad-hoc password rotations have happened to it.
    let bearer = login_bearer(&c, &admin_email(), &admin_password()).await;
    let target_email = format!("pwreset-{}@test.local", rand_local_part());
    let issue = c
        .post(format!("{}/v1/auth/invites", api_base()))
        .bearer_auth(&bearer)
        .json(&json!({ "email": target_email, "role": "member" }))
        .send()
        .await
        .expect("POST invite");
    assert!(issue.status().is_success(), "invite seed: {}", issue.status());
    let invite_msg = wait_for_email(&c, &target_email).await;
    let invite_link = extract_link(invite_msg["Text"].as_str().expect("Text"));
    let invite_token = token_from_link(&invite_link);
    let starting_password = "Aa!starting-pass-12";
    let accept = c
        .post(format!(
            "{}/v1/auth/invites/by-token/{}/accept",
            api_base(),
            invite_token
        ))
        .json(&json!({ "password": starting_password }))
        .send()
        .await
        .expect("POST accept");
    assert_eq!(accept.status(), StatusCode::OK, "invite accept seed");

    // Confirm starting password works before we rotate it.
    let pre_login = c
        .post(format!("{}/v1/auth/login", api_base()))
        .json(&json!({
            "email": target_email,
            "password": starting_password,
            "client_id": client_id(),
        }))
        .send()
        .await
        .expect("POST pre-reset login");
    assert_eq!(pre_login.status(), StatusCode::OK, "starting login");
    let user_bearer: String = pre_login
        .json::<Value>()
        .await
        .expect("pre-reset login json")["tokens"]["access_token"]
        .as_str()
        .expect("tokens.access_token")
        .to_string();

    // The seed flow generated an invite mail. Clear so the reset mail
    // is the only thing in mailpit when we poll next.
    reset_mailpit(&c).await;

    let start = c
        .post(format!("{}/v1/auth/password-reset", api_base()))
        .json(&json!({ "email": target_email }))
        .send()
        .await
        .expect("POST password-reset");
    assert_eq!(
        start.status(),
        StatusCode::OK,
        "reset start: {}",
        start.text().await.unwrap_or_default()
    );

    let msg = wait_for_email(&c, &target_email).await;
    let link = extract_link(msg["Text"].as_str().expect("Text"));
    let token = token_from_link(&link);
    assert!(
        link.contains("/reset-password/"),
        "expected /reset-password/ in link, got {link}"
    );

    let preview = c
        .get(format!(
            "{}/v1/auth/password-reset/by-token/{}",
            api_base(),
            token
        ))
        .send()
        .await
        .expect("GET preview");
    assert_eq!(preview.status(), StatusCode::OK, "reset preview");

    let new_password = "Aa!reset-pass-99";
    let complete = c
        .post(format!(
            "{}/v1/auth/password-reset/by-token/{}/complete",
            api_base(),
            token
        ))
        .json(&json!({
            "password": new_password,
            "password_confirmation": new_password,
        }))
        .send()
        .await
        .expect("POST reset complete");
    assert_eq!(
        complete.status(),
        StatusCode::OK,
        "reset complete: {}",
        complete.text().await.unwrap_or_default()
    );

    // Boot-everywhere: every session the user had before the reset is
    // now revoked. The access-token JWT itself is stateless so it still
    // extracts to the user, but `list_active_for_user` filters on
    // `revoked_at IS NULL` and so returns zero rows. Check this BEFORE
    // we log in with the new password, otherwise the fresh login would
    // create a new active session and the list would be 1.
    let sessions = c
        .get(format!("{}/v1/auth/sessions", api_base()))
        .bearer_auth(&user_bearer)
        .send()
        .await
        .expect("GET sessions with old bearer");
    assert_eq!(sessions.status(), StatusCode::OK, "old bearer JWT still verifies");
    let sessions_body: Value = sessions.json().await.expect("sessions json");
    let count = sessions_body["sessions"]
        .as_array()
        .map(|a| a.len())
        .unwrap_or_else(|| sessions_body.as_array().map(|a| a.len()).unwrap_or(0));
    assert_eq!(count, 0, "all prior sessions must be revoked; got {sessions_body}");

    // Old password no longer works.
    let old_login = c
        .post(format!("{}/v1/auth/login", api_base()))
        .json(&json!({ "email": target_email, "password": starting_password }))
        .send()
        .await
        .expect("POST old-pw login");
    assert_eq!(
        old_login.status(),
        StatusCode::UNAUTHORIZED,
        "old password should be rejected"
    );

    // New password works.
    let new_login = c
        .post(format!("{}/v1/auth/login", api_base()))
        .json(&json!({ "email": target_email, "password": new_password }))
        .send()
        .await
        .expect("POST new-pw login");
    assert_eq!(new_login.status(), StatusCode::OK, "new password should log in");
}
