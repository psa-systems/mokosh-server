//! MAPPS-1101: the Microsoft Graph implementation of
//! [`ContactSyncProvider`].
//!
//! One endpoint, two forms, both reads:
//!
//! * `GET /v1.0/me/contacts/delta`, paged. On the first call the response
//!   carries `@odata.nextLink` across pages and a terminal `@odata.deltaLink`
//!   on the last page. On a subsequent call the stored `@odata.deltaLink` is
//!   re-sent (as a `$deltatoken` query) and the response carries only the
//!   contacts that changed since. Reference:
//!   <https://learn.microsoft.com/en-us/graph/api/contact-delta>
//! * `GET /v1.0/me/contactFolders`, for the folder picker and its counts.
//!   Microsoft Graph has no `labels`; `contactFolders` is the equivalent
//!   grouping and PSA-70 E's "which groups to import" selection re-uses the
//!   same shape with "folder" as the user-facing word. Reference:
//!   <https://learn.microsoft.com/en-us/graph/api/user-list-contactfolders>
//!
//! # The $select is the mapping table
//!
//! [`CONTACT_FIELDS`] asks Graph for exactly what [`crate::modules::contact_sync::mapping`]
//! stores or filters on, and no more. Photos, addresses and birthdays are
//! dropped by the mapping, so they are not requested either: data this
//! integration never reads is data it cannot leak. Changing this set means
//! retiring every live delta token minted with the previous one, so it moves
//! with the mapping and not with any ad-hoc convenience.
//!
//! # Failure shapes
//!
//! * A stale delta token (Graph answers `410 Gone` with `syncStateNotFound`
//!   or a `400 BadRequest` naming an invalid token) is not an error: the
//!   client reads everything again and says so in `was_full_resync`
//!   (PSA-70 I).
//! * `429` and `503` are retried with exponential backoff and full jitter,
//!   honouring `Retry-After`; still refused after
//!   [`RetryPolicy::max_attempts`], it is [`SourceError::Throttled`], never
//!   a failure (PSA-70 I).
//! * `401` and a `403` that is not a rate limit is
//!   [`SourceError::Unauthorized`]: the grant or its scope is gone and a
//!   human has to reconnect.
//! * Every other failure is described in this codebase's words. A response
//!   body is never echoed into an error, because Graph's error bodies can
//!   echo request parameters and the connection's `last_error` is shown in
//!   the UI.
//!
//! # One-way, at the permission level
//!
//! The OAuth scope this integration asks for is `Contacts.Read`, matching
//! Google's `contacts.readonly`: Mokosh cannot alter someone's address book
//! even by mistake. The write-scoped shape is a different trait, not an
//! extra method here.

use std::time::Duration;

use async_trait::async_trait;
use rand::Rng;
use serde::de::DeserializeOwned;
use serde::Deserialize;

use super::provider::{
    ContactSyncProvider, SourceChanges, SourceContact, SourceEmail, SourceError, SourceGroup,
    SourcePhone, SourceResult,
};

/// The Graph v1.0 origin. Fixed rather than configured, and not screened by
/// `utils::net::guard_outbound_url`: no tenant can edit it (PMS-805's
/// exemption for a known provider base). A test hands the client a local
/// stub through [`MicrosoftContactsProvider::with_base_url`].
pub const GRAPH_API_BASE: &str = "https://graph.microsoft.com";

/// The scope Mokosh asks for on the Entra consent screen. Read-only against
/// the signed-in user's contacts. Changing this changes what the client can
/// read, and widens the attack surface; keep it one scope.
pub const OAUTH_SCOPE: &str = "Contacts.Read offline_access";

/// The $select mask carried on every list and delta call. Also carried on the
/// stored delta token's URL, so a widened mask invalidates every live token.
pub const CONTACT_FIELDS: &str =
    "id,givenName,surname,displayName,emailAddresses,homePhones,businessPhones,\
     mobilePhone,companyName,jobTitle,department,categories";

/// How many records per page. 100 is the documented default upper bound for
/// Graph; some endpoints accept 999 but delta's own cap is lower. Encoded in
/// [`DELTA_PATH`] as a literal; `pub` so a reader finds the number here
/// rather than parsing the baked-in query string.
pub const PAGE_SIZE: u32 = 100;

/// A ceiling on pages per read. A million contacts is well past any MSP
/// address book, so reaching it means the server is handing back a nextLink
/// that never ends, and the read stops rather than looping forever.
const MAX_PAGES: usize = 1000;

/// How hard to retry a throttled or unavailable response. Shape mirrors
/// Google's [`crate::modules::contact_sync::google::RetryPolicy`] so a tenant
/// does not see materially different throttling behaviour between the two
/// providers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Requests in total, the first included.
    pub max_attempts: u32,
    pub base: Duration,
    pub cap: Duration,
}

impl RetryPolicy {
    pub const DEFAULT: Self = Self {
        max_attempts: 5,
        base: Duration::from_millis(500),
        cap: Duration::from_secs(30),
    };

    /// Delay for `attempt` (1-indexed), honouring the server's own
    /// `Retry-After` when it offered one.
    fn delay(&self, attempt: u32, retry_after: Option<Duration>) -> Duration {
        if let Some(hint) = retry_after {
            return hint.min(self.cap);
        }
        let base_ms = self.base.as_millis() as u64;
        let cap_ms = self.cap.as_millis() as u64;
        let exp = base_ms.saturating_mul(1u64 << attempt.min(10).saturating_sub(1));
        let capped = exp.min(cap_ms);
        let jitter = rand::rng().random_range(0..=capped);
        Duration::from_millis(jitter)
    }
}

/// Built per sync: the access token lasts an hour and is never stored
/// (PMS-1212), so the provider does not outlive the run that refreshed it.
pub struct MicrosoftContactsProvider {
    http: reqwest::Client,
    base_url: String,
    access_token: String,
    retry: RetryPolicy,
}

impl MicrosoftContactsProvider {
    pub fn new(http: reqwest::Client, access_token: String) -> Self {
        Self::with_base_url(http, access_token, GRAPH_API_BASE, RetryPolicy::DEFAULT)
    }

    pub fn with_base_url(
        http: reqwest::Client,
        access_token: String,
        base_url: &str,
        retry: RetryPolicy,
    ) -> Self {
        Self {
            http,
            base_url: base_url.trim_end_matches('/').to_string(),
            access_token,
            retry,
        }
    }

    /// One GET, retried per [`RetryPolicy`]. `Ok(None)` is the stale delta
    /// token, the one refusal the caller recovers from.
    ///
    /// `url_or_path` may be either a path relative to `base_url` (first call)
    /// or an absolute URL (an `@odata.nextLink` / `@odata.deltaLink` the
    /// server minted). An absolute URL skips the base entirely and is sent
    /// verbatim, which is what Graph's nextLink / deltaLink mechanics
    /// require: the URL carries the state the server threaded into it.
    async fn get<T: DeserializeOwned>(&self, url_or_path: &str) -> SourceResult<Option<T>> {
        let url = if url_or_path.starts_with("http://") || url_or_path.starts_with("https://") {
            url_or_path.to_string()
        } else {
            format!("{}{url_or_path}", self.base_url)
        };
        let mut attempt = 0;
        loop {
            attempt += 1;
            let last = attempt >= self.retry.max_attempts;
            let sent = self
                .http
                .get(&url)
                .bearer_auth(&self.access_token)
                .send()
                .await;
            let response = match sent {
                Ok(response) => response,
                Err(e) if last => {
                    tracing::warn!(error = %e, "Microsoft Graph unreachable after {attempt} attempts");
                    return Err(SourceError::Failed(
                        "Microsoft Graph could not be reached.".to_string(),
                    ));
                }
                Err(_) => {
                    tokio::time::sleep(self.retry.delay(attempt, None)).await;
                    continue;
                }
            };

            let status = response.status().as_u16();
            let retry_after = response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.trim().parse::<u64>().ok())
                .map(Duration::from_secs);
            if (200..300).contains(&status) {
                return response.json::<T>().await.map(Some).map_err(|e| {
                    tracing::warn!(error = %e, url, "Microsoft Graph answered an unreadable body");
                    SourceError::Failed(
                        "Microsoft Graph answered with a response this version cannot read."
                            .to_string(),
                    )
                });
            }

            // Only reason tokens are read out of the body, never kept.
            let body = response.text().await.unwrap_or_default();
            let stale_token = body.contains("syncStateNotFound")
                || body.contains("syncStateInvalid")
                || body.contains("resyncRequired");
            let rate_limited =
                body.contains("TooManyRequests") || body.contains("ApplicationThrottled");
            match status {
                410 => return Ok(None),
                400 if stale_token => return Ok(None),
                401 => return Err(SourceError::Unauthorized),
                403 if !rate_limited => return Err(SourceError::Unauthorized),
                429 | 503 if last => return Err(SourceError::Throttled),
                500..=599 if last => {
                    return Err(SourceError::Failed(format!(
                        "Microsoft Graph answered {status} after {attempt} attempts."
                    )))
                }
                429 | 500..=599 => {
                    tokio::time::sleep(self.retry.delay(attempt, retry_after)).await;
                }
                _ => {
                    return Err(SourceError::Failed(format!(
                        "Microsoft Graph refused the request ({status})."
                    )))
                }
            }
        }
    }

    /// Every page of one read. `Ok(None)` when the delta token was refused
    /// as stale. On a resend the caller passes the stored `@odata.deltaLink`
    /// URL verbatim; on a first (full) read the caller passes
    /// [`DELTA_PATH`].
    async fn read_all(&self, start_url: &str) -> SourceResult<Option<SourceChanges>> {
        let mut changes = SourceChanges::default();
        let mut url = start_url.to_string();
        for _ in 0..MAX_PAGES {
            let Some(page) = self.get::<DeltaPage>(&url).await? else {
                return Ok(None);
            };
            changes.contacts.extend(page.value.into_iter().map(Contact::into_source));
            match (page.next_link, page.delta_link) {
                (Some(next), _) if !next.is_empty() => {
                    url = next;
                }
                (_, Some(delta)) if !delta.is_empty() => {
                    changes.next_sync_token = Some(delta);
                    return Ok(Some(changes));
                }
                _ => {
                    // Neither link set: the last page said neither "more"
                    // nor "resume from here", which means the server did
                    // not mint a cursor for us. Treat as a full read with
                    // no cursor; the next sync will do a fresh full read.
                    return Ok(Some(changes));
                }
            }
        }
        Err(SourceError::Failed(
            "Microsoft Graph kept returning pages past any plausible address book.".to_string(),
        ))
    }
}

/// The relative URL a first (full) delta read starts at. The `$select` is
/// baked in; the server echoes it onto the deltaLink it mints, so the stored
/// cursor already carries the mask and a subsequent read does not have to
/// repeat it.
const DELTA_PATH: &str = concat!(
    "/v1.0/me/contacts/delta?$select=",
    "id,givenName,surname,displayName,emailAddresses,homePhones,businessPhones,",
    "mobilePhone,companyName,jobTitle,department,categories",
    "&$top=100"
);

/// The folders endpoint. Not paginated for most tenants (folder count is
/// small); the client still follows nextLink if the server sends one.
const FOLDERS_PATH: &str = "/v1.0/me/contactFolders?$select=id,displayName";

#[async_trait]
impl ContactSyncProvider for MicrosoftContactsProvider {
    fn id(&self) -> &'static str {
        "microsoft"
    }

    async fn list_groups(&self) -> SourceResult<Vec<SourceGroup>> {
        let mut groups = Vec::new();
        let mut url = FOLDERS_PATH.to_string();
        for _ in 0..MAX_PAGES {
            let page = self.get::<FoldersPage>(&url).await?.ok_or_else(|| {
                SourceError::Failed("Microsoft Graph refused the folder list.".to_string())
            })?;
            groups.extend(page.value.into_iter().map(Folder::into_source));
            match page.next_link.filter(|t| !t.is_empty()) {
                Some(next) => url = next,
                None => return Ok(groups),
            }
        }
        Err(SourceError::Failed(
            "Microsoft Graph kept returning folder pages.".to_string(),
        ))
    }

    async fn changes_since(&self, sync_token: Option<&str>) -> SourceResult<SourceChanges> {
        let start = sync_token.unwrap_or(DELTA_PATH);
        if let Some(changes) = self.read_all(start).await? {
            return Ok(changes);
        }
        if sync_token.is_none() {
            // Nothing was sent to have expired; treating this as a resync
            // would loop.
            return Err(SourceError::Failed(
                "Microsoft Graph refused a full read as a stale delta token.".to_string(),
            ));
        }
        tracing::info!(
            "Microsoft Graph delta token expired; reading the whole address book"
        );
        let mut changes = self.read_all(DELTA_PATH).await?.ok_or_else(|| {
            SourceError::Failed(
                "Microsoft Graph refused a full read as a stale delta token.".to_string(),
            )
        })?;
        changes.was_full_resync = true;
        Ok(changes)
    }
}

// ----------------------------------------------------------------------------
// Wire shapes. Graph omits a field a contact has no value for rather than
// sending `null`, so every collection defaults to empty.
// ----------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
struct DeltaPage {
    #[serde(default)]
    value: Vec<Contact>,
    #[serde(default, rename = "@odata.nextLink")]
    next_link: Option<String>,
    #[serde(default, rename = "@odata.deltaLink")]
    delta_link: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct FoldersPage {
    #[serde(default)]
    value: Vec<Folder>,
    #[serde(default, rename = "@odata.nextLink")]
    next_link: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Folder {
    id: String,
    #[serde(default, rename = "displayName")]
    display_name: Option<String>,
}

impl Folder {
    fn into_source(self) -> SourceGroup {
        let name = self.display_name.unwrap_or_else(|| self.id.clone());
        SourceGroup {
            id: self.id,
            name,
            member_count: None,
        }
    }
}

#[derive(Debug, Deserialize)]
struct Contact {
    id: String,
    #[serde(default, rename = "@odata.etag")]
    etag: Option<String>,
    #[serde(default, rename = "displayName")]
    display_name: Option<String>,
    #[serde(default, rename = "givenName")]
    given_name: Option<String>,
    #[serde(default)]
    surname: Option<String>,
    #[serde(default, rename = "emailAddresses")]
    email_addresses: Vec<EmailAddress>,
    #[serde(default, rename = "homePhones")]
    home_phones: Vec<String>,
    #[serde(default, rename = "businessPhones")]
    business_phones: Vec<String>,
    #[serde(default, rename = "mobilePhone")]
    mobile_phone: Option<String>,
    #[serde(default, rename = "companyName")]
    company_name: Option<String>,
    #[serde(default, rename = "jobTitle")]
    job_title: Option<String>,
    #[serde(default)]
    department: Option<String>,
    #[serde(default)]
    categories: Vec<String>,
    /// Graph marks a contact Mokosh had seen but is now gone with an
    /// `@removed` object. The one shape in the wild is `{reason: "deleted"}`.
    #[serde(default, rename = "@removed")]
    removed: Option<Removed>,
}

#[derive(Debug, Default, Deserialize)]
struct Removed {
    #[serde(default)]
    #[allow(dead_code)]
    reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct EmailAddress {
    #[serde(default)]
    address: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    name: Option<String>,
}

fn non_empty(value: Option<String>) -> Option<String> {
    value.filter(|v| !v.trim().is_empty())
}

impl Contact {
    fn into_source(self) -> SourceContact {
        // Graph's own order; the first address is treated as primary by
        // the mapping layer. Microsoft does not mark one as primary the
        // way Google does.
        let emails: Vec<SourceEmail> = self
            .email_addresses
            .into_iter()
            .filter_map(|e| {
                Some(SourceEmail {
                    address: non_empty(e.address)?,
                    label: None,
                })
            })
            .collect();

        // Phone numbers are typed by field name in Graph, not by a label
        // on each entry. Mobile first, then business, then home: that is
        // the "primary first" ordering most contacts expect.
        let mut phones: Vec<SourcePhone> = Vec::new();
        if let Some(mobile) = non_empty(self.mobile_phone) {
            phones.push(SourcePhone {
                number: mobile,
                canonical: None,
                label: Some("mobile".to_string()),
                is_primary: true,
            });
        }
        for business in self.business_phones.into_iter().filter_map(|p| non_empty(Some(p))) {
            phones.push(SourcePhone {
                number: business,
                canonical: None,
                label: Some("work".to_string()),
                is_primary: false,
            });
        }
        for home in self.home_phones.into_iter().filter_map(|p| non_empty(Some(p))) {
            phones.push(SourcePhone {
                number: home,
                canonical: None,
                label: Some("home".to_string()),
                is_primary: false,
            });
        }

        SourceContact {
            external_id: self.id,
            etag: self.etag,
            display_name: non_empty(self.display_name),
            given_name: non_empty(self.given_name),
            family_name: non_empty(self.surname),
            emails,
            phones,
            organization: non_empty(self.company_name),
            title: non_empty(self.job_title),
            department: non_empty(self.department),
            group_ids: self.categories,
            note: None,
            photo: None,
            dropped_properties: vec![],
            deleted: self.removed.is_some(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    use axum::extract::State;
    use axum::http::{HeaderMap, StatusCode, Uri};
    use axum::response::{IntoResponse, Response};

    use super::*;

    type Seen = (String, Option<String>);

    #[derive(Clone, Default)]
    struct Stub {
        script: Arc<Mutex<VecDeque<(u16, String)>>>,
        seen: Arc<Mutex<Vec<Seen>>>,
    }

    async fn answer(State(stub): State<Stub>, uri: Uri, headers: HeaderMap) -> Response {
        stub.seen.lock().unwrap().push((
            uri.to_string(),
            headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string),
        ));
        let (status, body) = stub
            .script
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or((599, "script exhausted".into()));
        (
            StatusCode::from_u16(status).unwrap(),
            [("content-type", "application/json")],
            body,
        )
            .into_response()
    }

    async fn serve(script: Vec<(u16, &str)>) -> (Stub, MicrosoftContactsProvider) {
        let stub = Stub::default();
        stub.script
            .lock()
            .unwrap()
            .extend(script.into_iter().map(|(s, b)| (s, b.to_string())));
        let app = axum::Router::new()
            .fallback(answer)
            .with_state(stub.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let provider = MicrosoftContactsProvider::with_base_url(
            reqwest::Client::new(),
            "access-token".into(),
            &base,
            RetryPolicy {
                max_attempts: 3,
                base: Duration::ZERO,
                cap: Duration::ZERO,
            },
        );
        (stub, provider)
    }

    const ADA: &str = r#"{
        "id": "AAMk-ada", "@odata.etag": "W/\"e1\"",
        "displayName": "Ada Lovelace",
        "givenName": "Ada", "surname": "Lovelace",
        "emailAddresses": [
            {"address": "ada@work.example", "name": "Ada Lovelace"},
            {"address": "ada@home.example", "name": "Ada"}
        ],
        "mobilePhone": "+14155551234",
        "businessPhones": ["+14155550000"],
        "homePhones": ["+14155559999"],
        "companyName": "Acme Ltd",
        "jobTitle": "Analyst",
        "department": "Engines",
        "categories": ["Clients", "VIP"]
    }"#;

    #[tokio::test]
    async fn a_full_read_follows_every_page_and_keeps_the_last_cursor() {
        // Scripted bodies carry absolute URLs the client follows verbatim,
        // so they must point at the stub's own listener.
        let (stub, provider) = serve(vec![]).await;
        let next_link = format!(
            "{}/v1.0/me/contacts/delta?$skiptoken=p2",
            provider.base_url
        );
        let delta_link = format!(
            "{}/v1.0/me/contacts/delta?$deltatoken=sync-1",
            provider.base_url
        );
        let page1 = format!(
            r#"{{"value": [{ADA}], "@odata.nextLink": "{next_link}"}}"#
        );
        let page2 = format!(
            r#"{{"value": [{{"id": "contact-2", "@odata.etag": "W/\"e2\""}}], "@odata.deltaLink": "{delta_link}"}}"#
        );
        stub.script.lock().unwrap().extend([(200, page1), (200, page2)]);

        let changes = provider.changes_since(None).await.expect("read");
        assert_eq!(changes.contacts.len(), 2);
        assert_eq!(changes.next_sync_token.as_deref(), Some(delta_link.as_str()));
        assert!(!changes.was_full_resync);

        let seen = stub.seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 2, "two GETs: initial + nextLink");
        assert!(seen[0].0.contains("$select="), "first call asks the field mask");
        assert!(
            seen[1].0.contains("$skiptoken=p2"),
            "second call followed the nextLink verbatim: {}",
            seen[1].0
        );
        assert_eq!(seen[0].1.as_deref(), Some("Bearer access-token"));
    }

    #[tokio::test]
    async fn a_stale_delta_token_is_recovered_with_a_full_resync() {
        // First call: Graph refuses the stored deltaLink as stale.
        // Resync call (through DELTA_PATH): a one-page full read terminates
        // with a new deltaLink. The stored cursor is an absolute URL in
        // practice; the stub answers every path, so point it at the stub.
        let (stub, provider) = serve(vec![
            (
                410,
                r#"{"error":{"code":"syncStateNotFound","message":"gone"}}"#,
            ),
            (
                200,
                r#"{"value": [], "@odata.deltaLink": "WILL_BE_FILLED"}"#,
            ),
        ])
        .await;
        let fresh_delta = format!(
            "{}/v1.0/me/contacts/delta?$deltatoken=sync-2",
            provider.base_url
        );
        let resync_body = format!(
            r#"{{"value": [], "@odata.deltaLink": "{fresh_delta}"}}"#
        );
        stub.script.lock().unwrap().clear();
        stub.script.lock().unwrap().extend([
            (410, r#"{"error":{"code":"syncStateNotFound"}}"#.to_string()),
            (200, resync_body),
        ]);

        let stale_cursor = format!(
            "{}/v1.0/me/contacts/delta?$deltatoken=stale",
            provider.base_url
        );
        let changes = provider
            .changes_since(Some(&stale_cursor))
            .await
            .expect("resync");
        assert!(changes.was_full_resync, "flagged for the mapping layer");
        assert_eq!(changes.contacts.len(), 0);
        assert_eq!(changes.next_sync_token.as_deref(), Some(fresh_delta.as_str()));
    }

    #[tokio::test]
    async fn a_401_is_unauthorized_not_throttled() {
        let (_stub, provider) = serve(vec![(401, "{}")]).await;
        let err = provider.changes_since(None).await.unwrap_err();
        assert!(matches!(err, SourceError::Unauthorized));
    }

    #[tokio::test]
    async fn a_persistent_429_reads_as_throttled_not_failed() {
        let (_stub, provider) = serve(vec![
            (429, r#"{"error":{"code":"TooManyRequests"}}"#),
            (429, r#"{"error":{"code":"TooManyRequests"}}"#),
            (429, r#"{"error":{"code":"TooManyRequests"}}"#),
        ])
        .await;
        let err = provider.changes_since(None).await.unwrap_err();
        assert!(matches!(err, SourceError::Throttled));
    }

    #[tokio::test]
    async fn a_full_read_with_no_cursor_terminates_cleanly() {
        // The server did not mint a deltaLink (one page, no next, no delta).
        let (_stub, provider) =
            serve(vec![(200, r#"{"value": [{"id": "x"}]}"#)]).await;
        let changes = provider.changes_since(None).await.expect("read");
        assert_eq!(changes.contacts.len(), 1);
        assert_eq!(changes.next_sync_token, None, "next sync is a full read");
    }

    #[tokio::test]
    async fn a_contact_maps_mobile_before_business_before_home() {
        let (_stub, provider) =
            serve(vec![(200, &format!(r#"{{"value": [{ADA}]}}"#))]).await;
        let changes = provider.changes_since(None).await.expect("read");
        let ada = &changes.contacts[0];
        assert_eq!(ada.display_name.as_deref(), Some("Ada Lovelace"));
        assert_eq!(ada.given_name.as_deref(), Some("Ada"));
        assert_eq!(ada.family_name.as_deref(), Some("Lovelace"));
        assert_eq!(ada.emails.len(), 2);
        assert_eq!(ada.emails[0].address, "ada@work.example");
        assert_eq!(ada.phones.len(), 3);
        assert_eq!(ada.phones[0].label.as_deref(), Some("mobile"));
        assert!(ada.phones[0].is_primary);
        assert_eq!(ada.phones[1].label.as_deref(), Some("work"));
        assert_eq!(ada.phones[2].label.as_deref(), Some("home"));
        assert_eq!(ada.organization.as_deref(), Some("Acme Ltd"));
        assert_eq!(ada.title.as_deref(), Some("Analyst"));
        assert_eq!(ada.department.as_deref(), Some("Engines"));
        assert_eq!(ada.group_ids, vec!["Clients", "VIP"]);
        assert!(!ada.deleted);
    }

    #[tokio::test]
    async fn an_removed_contact_is_marked_deleted() {
        let body = r#"{"value": [{"id": "gone", "@removed": {"reason": "deleted"}}]}"#;
        let (_stub, provider) = serve(vec![(200, body)]).await;
        let changes = provider.changes_since(None).await.expect("read");
        assert_eq!(changes.contacts.len(), 1);
        assert!(changes.contacts[0].deleted);
    }

    #[tokio::test]
    async fn list_groups_reads_folders_and_maps_them() {
        let body = r#"{"value": [
            {"id": "folder-a", "displayName": "Clients"},
            {"id": "folder-b", "displayName": "VIP"}
        ]}"#;
        let (_stub, provider) = serve(vec![(200, body)]).await;
        let groups = provider.list_groups().await.expect("groups");
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].id, "folder-a");
        assert_eq!(groups[0].name, "Clients");
        assert!(groups[0].member_count.is_none(), "Graph does not report counts here");
    }

    #[tokio::test]
    async fn the_provider_id_matches_the_connection_column_value() {
        let provider = MicrosoftContactsProvider::new(reqwest::Client::new(), "t".into());
        assert_eq!(provider.id(), "microsoft");
    }
}
