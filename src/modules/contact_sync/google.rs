//! PMS-1213 (PSA-70 phase 3): the Google People API implementation of
//! [`ContactSyncProvider`].
//!
//! Two endpoints and nothing else, both reads:
//!
//! * `GET /v1/people/me/connections`, paged, with `requestSyncToken=true` so
//!   the last page carries the cursor the next sync sends back. Reference:
//!   <https://developers.google.com/people/api/rest/v1/people.connections/list>
//! * `GET /v1/contactGroups`, for the label picker and its counts. Reference:
//!   <https://developers.google.com/people/api/rest/v1/contactGroups/list>
//!
//! # The field mask is the mapping table
//!
//! [`PERSON_FIELDS`] asks for exactly what `mapping` stores or filters on, and
//! no more. Photos, addresses and birthdays are dropped by the mapping, so
//! they are not requested either: data this integration never reads is data
//! it cannot leak.
//!
//! # Failure shapes
//!
//! * An expired sync token (reason `EXPIRED_SYNC_TOKEN`, answered as `410` or
//!   as `400 FAILED_PRECONDITION`) is not an error: the client reads
//!   everything again and says so in `was_full_resync` (PSA-70 I).
//! * `429`, `503` and a `403` whose reason is a rate limit are retried with
//!   exponential backoff and full jitter, honouring `Retry-After`; still
//!   refused after [`RetryPolicy::max_attempts`], it is
//!   [`SourceError::Throttled`], never a failure (PSA-70 I).
//! * `401`, and a `403` that is not a rate limit, is
//!   [`SourceError::Unauthorized`]: the grant or its scope is gone and a human
//!   has to reconnect.
//! * Every other failure is described in this codebase's words. A response
//!   body is never echoed into an error, because Google's error bodies can
//!   repeat request parameters and the connection's `last_error` is shown in
//!   the UI.

use std::time::Duration;

use async_trait::async_trait;
use rand::Rng;
use serde::de::DeserializeOwned;
use serde::Deserialize;

use super::provider::{
    ContactSyncProvider, SourceChanges, SourceContact, SourceEmail, SourceError, SourceGroup,
    SourcePhone, SourceResult,
};

/// The People API origin. Fixed rather than configured, and not screened by
/// `utils::net::guard_outbound_url`: no tenant can edit it (PMS-805's
/// exemption for the Stripe API base). A test hands the client a local stub
/// through [`GoogleContactsProvider::with_base_url`].
pub const PEOPLE_API_BASE: &str = "https://people.googleapis.com";

/// What each person is read with. Changing this changes what Mokosh holds, so
/// it moves with the table in `mapping`, and a sync token minted with one mask
/// must be redeemed with the same one (the API refuses otherwise).
pub const PERSON_FIELDS: &str =
    "names,emailAddresses,phoneNumbers,organizations,memberships,metadata";

/// The most a page can hold.
const PAGE_SIZE: &str = "1000";

/// A ceiling on pages per read. A million contacts is far past any MSP's
/// address book, so reaching it means the API is handing back a page token
/// that never ends, and the read stops rather than looping forever.
const MAX_PAGES: usize = 1000;

/// The system groups worth offering beside a person's own labels. The rest
/// (`all`, `blocked`, `chatBuddies`, and the retired `friends` / `family` /
/// `coworkers`) either select everything or select nothing useful.
const OFFERED_SYSTEM_GROUPS: &[&str] = &["contactGroups/myContacts", "contactGroups/starred"];

/// How hard to retry a throttled or unavailable response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Requests in total, the first included.
    pub max_attempts: u32,
    pub base: Duration,
    pub cap: Duration,
}

impl RetryPolicy {
    /// Five attempts over at most about a minute: long enough to ride out a
    /// per-minute quota window, short enough that a sync never holds a worker
    /// for longer than one interval.
    pub const DEFAULT: Self = Self {
        max_attempts: 5,
        base: Duration::from_secs(1),
        cap: Duration::from_secs(32),
    };

    /// The wait before retry number `attempt` (1-based): full jitter over an
    /// exponential ceiling, so many tenants throttled at once do not retry in
    /// lockstep. A `Retry-After` is a floor, still bounded by the cap so a
    /// hostile or mistaken header cannot park a worker.
    pub fn delay(&self, attempt: u32, retry_after: Option<Duration>) -> Duration {
        let exponent = attempt.saturating_sub(1).min(20);
        let ceiling = self.base.saturating_mul(1u32 << exponent).min(self.cap);
        let jittered = Duration::from_millis(
            rand::rng().random_range(0..=u64::try_from(ceiling.as_millis()).unwrap_or(u64::MAX)),
        );
        match retry_after {
            Some(floor) => jittered.max(floor).min(self.cap),
            None => jittered,
        }
    }
}

/// A tenant's Google Contacts, read with one access token.
///
/// Built per sync: the access token lasts an hour and is never stored
/// (PMS-1212), so the provider does not outlive the run that refreshed it.
pub struct GoogleContactsProvider {
    http: reqwest::Client,
    base_url: String,
    access_token: String,
    retry: RetryPolicy,
}

impl GoogleContactsProvider {
    pub fn new(http: reqwest::Client, access_token: String) -> Self {
        Self::with_base_url(http, access_token, PEOPLE_API_BASE, RetryPolicy::DEFAULT)
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

    /// One GET, retried per [`RetryPolicy`]. `Ok(None)` is the expired sync
    /// token, the one refusal the caller recovers from.
    async fn get<T: DeserializeOwned>(
        &self,
        path: &str,
        query: &[(&str, &str)],
    ) -> SourceResult<Option<T>> {
        let url = format!("{}{path}", self.base_url);
        let mut attempt = 0;
        loop {
            attempt += 1;
            let last = attempt >= self.retry.max_attempts;
            let sent = self
                .http
                .get(&url)
                .bearer_auth(&self.access_token)
                .query(query)
                .send()
                .await;
            let response = match sent {
                Ok(response) => response,
                Err(e) if last => {
                    tracing::warn!(error = %e, "Google Contacts unreachable after {attempt} attempts");
                    return Err(SourceError::Failed(
                        "Google Contacts could not be reached.".to_string(),
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
                    tracing::warn!(error = %e, path, "Google Contacts answered an unreadable body");
                    SourceError::Failed(
                        "Google Contacts answered with a response this version cannot read."
                            .to_string(),
                    )
                });
            }

            // Only the reason tokens are read out of the body, never kept.
            let body = response.text().await.unwrap_or_default();
            let expired = body.contains("EXPIRED_SYNC_TOKEN");
            let rate_limited = body.contains("RATE_LIMIT_EXCEEDED")
                || body.contains("rateLimitExceeded")
                || body.contains("RESOURCE_EXHAUSTED");
            match status {
                410 => return Ok(None),
                400 if expired => return Ok(None),
                401 => return Err(SourceError::Unauthorized),
                403 if !rate_limited => return Err(SourceError::Unauthorized),
                403 | 429 | 503 if last => return Err(SourceError::Throttled),
                500..=599 if last => {
                    return Err(SourceError::Failed(format!(
                        "Google Contacts answered {status} after {attempt} attempts."
                    )))
                }
                403 | 429 | 500..=599 => {
                    tokio::time::sleep(self.retry.delay(attempt, retry_after)).await;
                }
                _ => {
                    return Err(SourceError::Failed(format!(
                        "Google Contacts refused the request ({status})."
                    )))
                }
            }
        }
    }

    /// Every page of one read. `Ok(None)` when the token was refused as
    /// expired.
    async fn read_all(&self, sync_token: Option<&str>) -> SourceResult<Option<SourceChanges>> {
        let mut changes = SourceChanges::default();
        let mut page_token: Option<String> = None;
        for _ in 0..MAX_PAGES {
            // The same parameters on every page: the API refuses a page or
            // sync token redeemed with a different request.
            let mut query = vec![
                ("personFields", PERSON_FIELDS),
                ("pageSize", PAGE_SIZE),
                ("requestSyncToken", "true"),
            ];
            if let Some(token) = sync_token {
                query.push(("syncToken", token));
            }
            if let Some(token) = page_token.as_deref() {
                query.push(("pageToken", token));
            }
            let Some(page) = self
                .get::<ConnectionsPage>("/v1/people/me/connections", &query)
                .await?
            else {
                return Ok(None);
            };
            changes
                .contacts
                .extend(page.connections.into_iter().map(Person::into_source));
            match page.next_page_token.filter(|t| !t.is_empty()) {
                Some(next) => page_token = Some(next),
                None => {
                    changes.next_sync_token = page.next_sync_token;
                    return Ok(Some(changes));
                }
            }
        }
        Err(SourceError::Failed(
            "Google Contacts kept returning pages past any plausible address book.".to_string(),
        ))
    }
}

#[async_trait]
impl ContactSyncProvider for GoogleContactsProvider {
    fn id(&self) -> &'static str {
        "google"
    }

    async fn list_groups(&self) -> SourceResult<Vec<SourceGroup>> {
        let mut groups = Vec::new();
        let mut page_token: Option<String> = None;
        for _ in 0..MAX_PAGES {
            let mut query = vec![
                ("pageSize", PAGE_SIZE),
                ("groupFields", "name,groupType,memberCount"),
            ];
            if let Some(token) = page_token.as_deref() {
                query.push(("pageToken", token));
            }
            let page = self
                .get::<GroupsPage>("/v1/contactGroups", &query)
                .await?
                .ok_or_else(|| {
                    SourceError::Failed("Google Contacts refused the label list.".to_string())
                })?;
            groups.extend(page.contact_groups.into_iter().filter_map(Group::offered));
            match page.next_page_token.filter(|t| !t.is_empty()) {
                Some(next) => page_token = Some(next),
                None => return Ok(groups),
            }
        }
        Err(SourceError::Failed(
            "Google Contacts kept returning label pages.".to_string(),
        ))
    }

    async fn changes_since(&self, sync_token: Option<&str>) -> SourceResult<SourceChanges> {
        if let Some(changes) = self.read_all(sync_token).await? {
            return Ok(changes);
        }
        if sync_token.is_none() {
            // Nothing was sent to have expired; treating this as a resync
            // would loop.
            return Err(SourceError::Failed(
                "Google Contacts refused a full read as an expired sync token.".to_string(),
            ));
        }
        tracing::info!("Google Contacts sync token expired; reading the whole address book");
        let mut changes = self.read_all(None).await?.ok_or_else(|| {
            SourceError::Failed(
                "Google Contacts refused a full read as an expired sync token.".to_string(),
            )
        })?;
        changes.was_full_resync = true;
        Ok(changes)
    }
}

// ----------------------------------------------------------------------------
// Wire shapes. Every collection defaults to empty: the API omits a field a
// person has no value for rather than sending `[]`.
// ----------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConnectionsPage {
    #[serde(default)]
    connections: Vec<Person>,
    next_page_token: Option<String>,
    next_sync_token: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FieldMetadata {
    #[serde(default)]
    primary: bool,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PersonMetadata {
    #[serde(default)]
    deleted: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Person {
    resource_name: String,
    etag: Option<String>,
    #[serde(default)]
    metadata: PersonMetadata,
    #[serde(default)]
    names: Vec<Name>,
    #[serde(default)]
    email_addresses: Vec<EmailAddress>,
    #[serde(default)]
    phone_numbers: Vec<PhoneNumber>,
    #[serde(default)]
    organizations: Vec<Organization>,
    #[serde(default)]
    memberships: Vec<Membership>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Name {
    display_name: Option<String>,
    given_name: Option<String>,
    family_name: Option<String>,
    #[serde(default)]
    metadata: FieldMetadata,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EmailAddress {
    value: Option<String>,
    /// `home`, `work`, `other` or the user's own label. Inside the
    /// `emailAddresses` field already requested, so reading it does not
    /// change the mask.
    #[serde(rename = "type")]
    kind: Option<String>,
    #[serde(default)]
    metadata: FieldMetadata,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PhoneNumber {
    value: Option<String>,
    canonical_form: Option<String>,
    #[serde(rename = "type")]
    kind: Option<String>,
    #[serde(default)]
    metadata: FieldMetadata,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Organization {
    name: Option<String>,
    title: Option<String>,
    department: Option<String>,
    #[serde(default)]
    metadata: FieldMetadata,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Membership {
    contact_group_membership: Option<ContactGroupMembership>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ContactGroupMembership {
    contact_group_resource_name: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GroupsPage {
    #[serde(default)]
    contact_groups: Vec<Group>,
    next_page_token: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Group {
    resource_name: String,
    name: Option<String>,
    formatted_name: Option<String>,
    group_type: Option<String>,
    member_count: Option<u32>,
}

impl Group {
    fn offered(self) -> Option<SourceGroup> {
        let own_label = self.group_type.as_deref() == Some("USER_CONTACT_GROUP");
        if !own_label && !OFFERED_SYSTEM_GROUPS.contains(&self.resource_name.as_str()) {
            return None;
        }
        let name = self
            .formatted_name
            .or(self.name)
            .unwrap_or_else(|| self.resource_name.clone());
        Some(SourceGroup {
            id: self.resource_name,
            name,
            member_count: self.member_count,
        })
    }
}

/// The source's primary entry first, then the rest in the source's order.
fn primary_first<T>(mut items: Vec<T>, is_primary: impl Fn(&T) -> bool) -> Vec<T> {
    if let Some(at) = items.iter().position(&is_primary) {
        let primary = items.remove(at);
        items.insert(0, primary);
    }
    items
}

fn non_empty(value: Option<String>) -> Option<String> {
    value.filter(|v| !v.trim().is_empty())
}

impl Person {
    fn into_source(self) -> SourceContact {
        let name = primary_first(self.names, |n| n.metadata.primary)
            .into_iter()
            .next();
        let organization = primary_first(self.organizations, |o| o.metadata.primary)
            .into_iter()
            .next();
        let (display_name, given_name, family_name) = match name {
            Some(n) => (
                non_empty(n.display_name),
                non_empty(n.given_name),
                non_empty(n.family_name),
            ),
            None => (None, None, None),
        };
        let (org_name, title, department) = match organization {
            Some(o) => (
                non_empty(o.name),
                non_empty(o.title),
                non_empty(o.department),
            ),
            None => (None, None, None),
        };
        SourceContact {
            external_id: self.resource_name,
            etag: self.etag,
            display_name,
            given_name,
            family_name,
            emails: primary_first(self.email_addresses, |e| e.metadata.primary)
                .into_iter()
                .filter_map(|e| {
                    Some(SourceEmail {
                        address: non_empty(e.value)?,
                        label: non_empty(e.kind).map(|k| k.to_lowercase()),
                    })
                })
                .collect(),
            phones: self
                .phone_numbers
                .into_iter()
                .filter_map(|p| {
                    Some(SourcePhone {
                        number: non_empty(p.value)?,
                        canonical: non_empty(p.canonical_form),
                        label: non_empty(p.kind).map(|k| k.to_lowercase()),
                        is_primary: p.metadata.primary,
                    })
                })
                .collect(),
            organization: org_name,
            title,
            department,
            group_ids: self
                .memberships
                .into_iter()
                .filter_map(|m| m.contact_group_membership?.contact_group_resource_name)
                .collect(),
            note: None,
            photo: None,
            dropped_properties: vec![],
            deleted: self.metadata.deleted,
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

    /// A request the stub received: its path and query, and its
    /// `Authorization` header.
    type Seen = (String, Option<String>);

    /// A scripted People API: answers in order, records what it was asked.
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

    async fn serve(script: Vec<(u16, &str)>) -> (Stub, GoogleContactsProvider) {
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
        let provider = GoogleContactsProvider::with_base_url(
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
        "resourceName": "people/c1", "etag": "e1",
        "names": [
            {"displayName": "Countess", "metadata": {}},
            {"displayName": "Ada Lovelace", "givenName": "Ada", "familyName": "Lovelace", "metadata": {"primary": true}}
        ],
        "emailAddresses": [
            {"value": "ada@home.example", "type": "Home"},
            {"value": "ada@work.example", "type": "Billing desk", "metadata": {"primary": true}}
        ],
        "phoneNumbers": [{"value": "(415) 555-1234", "canonicalForm": "+14155551234", "type": "workFax"}],
        "organizations": [{"name": "Acme Ltd", "title": "Analyst", "department": "Engines", "metadata": {"primary": true}}],
        "memberships": [
            {"contactGroupMembership": {"contactGroupId": "abc", "contactGroupResourceName": "contactGroups/abc"}},
            {"domainMembership": {"inViewerDomain": true}}
        ]
    }"#;

    /// Pages are followed with the same mask and the sync token requested, and
    /// the cursor comes off the last page only.
    #[tokio::test]
    async fn a_full_read_follows_every_page_and_keeps_the_last_cursor() {
        let page1 = format!(r#"{{"connections": [{ADA}], "nextPageToken": "p2"}}"#);
        let page2 = r#"{"connections": [{"resourceName": "people/c2", "etag": "e2"}], "nextSyncToken": "sync-1"}"#;
        let (stub, provider) = serve(vec![(200, &page1), (200, page2)]).await;

        let changes = provider.changes_since(None).await.expect("read");
        assert_eq!(changes.contacts.len(), 2);
        assert_eq!(changes.next_sync_token.as_deref(), Some("sync-1"));
        assert!(!changes.was_full_resync);

        let seen = stub.seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 2);
        for (uri, auth) in &seen {
            assert!(uri.starts_with("/v1/people/me/connections?"), "{uri}");
            assert!(uri.contains("requestSyncToken=true"), "{uri}");
            assert!(uri.contains("personFields=names%2CemailAddresses"), "{uri}");
            assert!(
                !uri.replace("requestSyncToken", "").contains("syncToken"),
                "a full read sends no cursor: {uri}"
            );
            assert_eq!(auth.as_deref(), Some("Bearer access-token"));
        }
        assert!(seen[1].0.contains("pageToken=p2"), "{}", seen[1].0);
    }

    /// The wire record becomes a source contact with primaries first.
    #[tokio::test]
    async fn a_person_is_read_primary_first() {
        let body = format!(r#"{{"connections": [{ADA}], "nextSyncToken": "s"}}"#);
        let (_stub, provider) = serve(vec![(200, &body)]).await;
        let contact = provider
            .changes_since(None)
            .await
            .unwrap()
            .contacts
            .remove(0);
        assert_eq!(contact.external_id, "people/c1");
        assert_eq!(contact.given_name.as_deref(), Some("Ada"));
        assert_eq!(contact.display_name.as_deref(), Some("Ada Lovelace"));
        let addresses: Vec<&str> = contact.emails.iter().map(|e| e.address.as_str()).collect();
        assert_eq!(addresses, vec!["ada@work.example", "ada@home.example"]);
        // PMS-1288: a user's own label rides along, lowercased like a phone's.
        assert_eq!(contact.emails[0].label.as_deref(), Some("billing desk"));
        assert_eq!(contact.emails[1].label.as_deref(), Some("home"));
        assert_eq!(contact.phones[0].canonical.as_deref(), Some("+14155551234"));
        assert_eq!(contact.phones[0].label.as_deref(), Some("workfax"));
        assert_eq!(contact.organization.as_deref(), Some("Acme Ltd"));
        assert_eq!(contact.department.as_deref(), Some("Engines"));
        assert_eq!(contact.group_ids, vec!["contactGroups/abc"]);
        assert!(!contact.deleted);
    }

    #[tokio::test]
    async fn a_deleted_person_in_a_delta_is_marked_deleted() {
        let body = r#"{"connections": [{"resourceName": "people/c9", "etag": "x", "metadata": {"deleted": true}}], "nextSyncToken": "s2"}"#;
        let (stub, provider) = serve(vec![(200, body)]).await;
        let changes = provider.changes_since(Some("s1")).await.unwrap();
        assert!(changes.contacts[0].deleted);
        assert!(stub.seen.lock().unwrap()[0].0.contains("syncToken=s1"));
    }

    /// Both answers Google gives an aged-out cursor fall back to a full read,
    /// and the result says it is one.
    #[tokio::test]
    async fn an_expired_sync_token_resyncs_rather_than_failing() {
        for refusal in [
            (410, r#"{"error": {"code": 410, "status": "GONE"}}"#),
            (
                400,
                r#"{"error": {"code": 400, "status": "FAILED_PRECONDITION", "details": [{"reason": "EXPIRED_SYNC_TOKEN"}]}}"#,
            ),
        ] {
            let full = r#"{"connections": [{"resourceName": "people/c1", "etag": "e"}], "nextSyncToken": "fresh"}"#;
            let (stub, provider) = serve(vec![refusal, (200, full)]).await;
            let changes = provider.changes_since(Some("stale")).await.expect("resync");
            assert!(changes.was_full_resync, "{refusal:?}");
            assert_eq!(changes.next_sync_token.as_deref(), Some("fresh"));
            let seen = stub.seen.lock().unwrap().clone();
            assert!(seen[0].0.contains("syncToken=stale"));
            assert!(
                !seen[1].0.contains("syncToken=stale"),
                "the resync must not resend the dead cursor"
            );
        }
    }

    /// A 400 that is not about the cursor is a failure, not a resync: a
    /// malformed request resynced forever is a loop.
    #[tokio::test]
    async fn an_unrelated_bad_request_is_not_a_resync() {
        let (_stub, provider) =
            serve(vec![(400, r#"{"error": {"status": "INVALID_ARGUMENT"}}"#)]).await;
        let err = provider.changes_since(Some("s")).await.unwrap_err();
        assert!(matches!(err, SourceError::Failed(_)), "{err:?}");
    }

    #[tokio::test]
    async fn a_rate_limit_is_retried_then_succeeds() {
        let ok = r#"{"connections": [], "nextSyncToken": "s"}"#;
        let (stub, provider) = serve(vec![(429, "{}"), (503, "{}"), (200, ok)]).await;
        let changes = provider
            .changes_since(None)
            .await
            .expect("third attempt succeeds");
        assert_eq!(changes.next_sync_token.as_deref(), Some("s"));
        assert_eq!(stub.seen.lock().unwrap().len(), 3);
    }

    /// Still limited after every attempt: throttled, never failed.
    #[tokio::test]
    async fn a_rate_limit_that_persists_is_throttled_not_failed() {
        let (stub, provider) = serve(vec![(429, "{}"), (429, "{}"), (429, "{}")]).await;
        assert_eq!(
            provider.changes_since(None).await.unwrap_err(),
            SourceError::Throttled
        );
        assert_eq!(
            stub.seen.lock().unwrap().len(),
            3,
            "exactly max_attempts requests"
        );

        let quota = r#"{"error": {"status": "PERMISSION_DENIED", "details": [{"reason": "RATE_LIMIT_EXCEEDED"}]}}"#;
        let (_stub, provider) = serve(vec![(403, quota), (403, quota), (403, quota)]).await;
        assert_eq!(
            provider.list_groups().await.unwrap_err(),
            SourceError::Throttled
        );
    }

    #[tokio::test]
    async fn a_refused_credential_asks_for_a_reconnect() {
        let (stub, provider) = serve(vec![(401, "{}")]).await;
        assert_eq!(
            provider.changes_since(None).await.unwrap_err(),
            SourceError::Unauthorized
        );
        assert_eq!(stub.seen.lock().unwrap().len(), 1, "a 401 is not retried");

        let (_stub, provider) =
            serve(vec![(403, r#"{"error": {"status": "PERMISSION_DENIED"}}"#)]).await;
        assert_eq!(
            provider.list_groups().await.unwrap_err(),
            SourceError::Unauthorized
        );
    }

    /// The provider's body never reaches the error, which reaches the UI.
    #[tokio::test]
    async fn an_error_never_echoes_the_response_body() {
        let body = r#"{"error": {"message": "secret-request-echo"}}"#;
        let (_stub, provider) = serve(vec![(500, body), (500, body), (500, body)]).await;
        let err = provider.changes_since(None).await.unwrap_err();
        assert!(matches!(err, SourceError::Failed(_)));
        assert!(!err.to_string().contains("secret-request-echo"), "{err}");
    }

    /// A person's own labels and the two useful system groups are offered;
    /// the rest are not.
    #[tokio::test]
    async fn the_label_list_offers_own_labels_and_useful_system_groups() {
        let page = r#"{"contactGroups": [
            {"resourceName": "contactGroups/abc", "name": "Clients", "formattedName": "Clients", "groupType": "USER_CONTACT_GROUP", "memberCount": 40},
            {"resourceName": "contactGroups/myContacts", "name": "myContacts", "formattedName": "My Contacts", "groupType": "SYSTEM_CONTACT_GROUP", "memberCount": 2000},
            {"resourceName": "contactGroups/blocked", "name": "blocked", "groupType": "SYSTEM_CONTACT_GROUP"},
            {"resourceName": "contactGroups/all", "name": "all", "groupType": "SYSTEM_CONTACT_GROUP"}
        ]}"#;
        let (stub, provider) = serve(vec![(200, page)]).await;
        let groups = provider.list_groups().await.expect("groups");
        assert_eq!(
            groups,
            vec![
                SourceGroup {
                    id: "contactGroups/abc".into(),
                    name: "Clients".into(),
                    member_count: Some(40)
                },
                SourceGroup {
                    id: "contactGroups/myContacts".into(),
                    name: "My Contacts".into(),
                    member_count: Some(2000)
                },
            ]
        );
        assert!(stub.seen.lock().unwrap()[0]
            .0
            .starts_with("/v1/contactGroups?"));
    }

    #[test]
    fn the_backoff_is_bounded_and_honours_retry_after() {
        let policy = RetryPolicy {
            max_attempts: 5,
            base: Duration::from_secs(1),
            cap: Duration::from_secs(8),
        };
        for attempt in 1..=10 {
            let d = policy.delay(attempt, None);
            let ceiling = Duration::from_secs(1u64 << (attempt - 1).min(3));
            assert!(d <= ceiling, "attempt {attempt}: {d:?} over {ceiling:?}");
        }
        assert_eq!(
            policy.delay(1, Some(Duration::from_secs(5))),
            Duration::from_secs(5)
        );
        assert_eq!(
            policy.delay(1, Some(Duration::from_secs(3600))),
            Duration::from_secs(8),
            "the cap bounds Retry-After"
        );
    }

    /// The request mask covers what the mapping reads, and nothing the mapping
    /// drops.
    #[test]
    fn the_field_mask_is_the_mapping_table() {
        for needed in [
            "names",
            "emailAddresses",
            "phoneNumbers",
            "organizations",
            "memberships",
            "metadata",
        ] {
            assert!(
                PERSON_FIELDS.split(',').any(|f| f == needed),
                "{needed} missing"
            );
        }
        for dropped in ["photos", "addresses", "birthdays", "biographies"] {
            assert!(
                !PERSON_FIELDS.split(',').any(|f| f == dropped),
                "{dropped} is requested but dropped"
            );
        }
    }
}
