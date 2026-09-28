//! PMS-1341: the CardDAV half of contact sync, for iCloud.
//!
//! Apple publishes no OAuth scope for contacts, so an iCloud connection is an
//! Apple ID and an app-specific password over CardDAV (RFC 6352) against
//! `contacts.icloud.com`. That is genuinely a different protocol from Google's
//! People API rather than a different credential for the same one, which is why
//! this module exists at all; what comes OUT of it is the same
//! [`SourceContact`](super::provider::SourceContact) every other source
//! produces, because a CardDAV payload is vCard and the vCard reader is already
//! the one canonical parser (PMS-1288).
//!
//! # The shape of the protocol, and what this reads of it
//!
//! Three requests find the address book, because a CardDAV client may not assume
//! a URL layout:
//!
//! 1. `PROPFIND` `/` for `current-user-principal`, which is who the credential
//!    signs in as.
//! 2. `PROPFIND` that principal for `addressbook-home-set`, the collection its
//!    address books live under.
//! 3. `PROPFIND` the home set at depth 1 for the collections whose
//!    `resourcetype` includes `addressbook`.
//!
//! Then the contacts: `REPORT addressbook-query` returns every card with its
//! `getetag` and its `address-data` in one response, which is the whole address
//! book, and `REPORT sync-collection` (RFC 6578) returns what changed since a
//! sync token. iCloud supports both.
//!
//! # Parsing is pure, I/O is thin
//!
//! Every function that understands XML takes `&str` and returns data, and the
//! only thing that touches the network is [`CardDavClient`]'s three request
//! helpers. That split is what makes this testable without Apple: the fixtures
//! in `tests/fixtures/carddav/` are real-shaped `multistatus` bodies, and the
//! parser tests below read them directly. It is the same bargain the S3 provider
//! made with its SigV4 signer (PMS-958), for the same reason: a protocol
//! implementation nobody can test offline is one nobody changes with confidence.
//!
//! # What this refuses to guess
//!
//! A 401 is reported as its own thing, because it is the one failure an admin can
//! act on: an app-specific password is revoked from the Apple ID's own settings
//! page and Apple gives no warning here, so "the password was rejected" and "the
//! server is unreachable" must not arrive as the same message (PMS-1341's
//! acceptance criterion, and the shape PMS-1181 settled for a payment gateway).

use std::collections::BTreeMap;

use quick_xml::events::Event;
use quick_xml::Reader;

use super::provider::{SourceError, SourceResult};

/// The iCloud CardDAV entry point. Overridable so a test can point the client at
/// a local server, and so a self-hosted CardDAV (Fastmail, Nextcloud) is a
/// configuration change rather than a second implementation.
pub const ICLOUD_BASE_URL: &str = "https://contacts.icloud.com";

/// One `<D:response>` worth of what this client reads: where the resource is,
/// what version it is at, and its card when the response carried one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DavResource {
    /// The resource's path, as the server wrote it.
    pub href: String,
    /// `getetag`, with the quotes the header form carries stripped.
    pub etag: Option<String>,
    /// `address-data`: the vCard itself, when the request asked for it.
    pub card: Option<String>,
    /// The `resourcetype` element names, lowercased and without a namespace
    /// prefix, so `addressbook` and `collection` are comparable.
    pub resource_types: Vec<String>,
    /// A per-resource status, present on a sync report's removals (`404`).
    pub status: Option<String>,
    /// The values of the properties this module looks up by name, so one parser
    /// serves `current-user-principal`, `addressbook-home-set` and
    /// `displayname` without a variant each.
    pub properties: BTreeMap<String, String>,
}

impl DavResource {
    /// Whether this response describes an address book collection.
    pub fn is_addressbook(&self) -> bool {
        self.resource_types.iter().any(|t| t == "addressbook")
    }

    /// Whether the server said this resource is gone, which on a sync report is
    /// how a deletion arrives.
    pub fn is_gone(&self) -> bool {
        self.status
            .as_deref()
            .is_some_and(|status| status.contains(" 404"))
    }
}

/// A parsed `multistatus`: its responses, plus the sync token when the server
/// returned one (a sync report answers with the token to use next time).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MultiStatus {
    pub resources: Vec<DavResource>,
    pub sync_token: Option<String>,
}

/// Strip a namespace prefix and lowercase, so `D:href`, `d:href` and `href` are
/// one name. CardDAV servers disagree about prefixes and a client that matched on
/// `D:` alone would work against exactly the servers it was written against.
fn local_name(raw: &[u8]) -> String {
    let name = String::from_utf8_lossy(raw);
    name.rsplit(':').next().unwrap_or(&name).to_lowercase()
}

/// Parse a `multistatus` body.
///
/// Deliberately not a document model: the reader walks events and keeps the few
/// elements this module needs, so an unknown property is skipped rather than
/// being a parse failure. A CardDAV server is free to return more than was asked
/// for, and iCloud does.
pub fn parse_multistatus(xml: &str) -> SourceResult<MultiStatus> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut out = MultiStatus::default();
    let mut current: Option<DavResource> = None;
    // The element whose text we are collecting, and the text so far.
    let mut path: Vec<String> = Vec::new();
    let mut text = String::new();
    let mut in_resource_type = false;
    // PMS-1341: an empty result is the dangerous answer here, so the parser has
    // to know it read a whole `multistatus` and not merely reach the end of
    // something. `changes_since` reports a full read as the WHOLE address book
    // (`lists_everything`), and the sync engine treats a linked contact absent
    // from a full read as deleted in the source - so a truncated body, or an HTML
    // error page where XML was expected, would tombstone every contact the
    // connection has ever imported. quick-xml stops at EOF without complaining,
    // which is why both of these are tracked by hand.
    let mut depth: i32 = 0;
    let mut saw_multistatus = false;

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let name = local_name(e.name().as_ref());
                depth += 1;
                match name.as_str() {
                    "multistatus" => saw_multistatus = true,
                    "response" => current = Some(DavResource::default()),
                    "resourcetype" => in_resource_type = true,
                    _ => {}
                }
                path.push(name);
                text.clear();
            }
            Ok(Event::Empty(e)) => {
                // `<D:addressbook/>` inside `resourcetype` is the common shape.
                let name = local_name(e.name().as_ref());
                if in_resource_type {
                    if let Some(resource) = current.as_mut() {
                        resource.resource_types.push(name);
                    }
                }
            }
            Ok(Event::Text(e)) => {
                text.push_str(&e.unescape().unwrap_or_default());
            }
            Ok(Event::CData(e)) => {
                text.push_str(&String::from_utf8_lossy(e.as_ref()));
            }
            Ok(Event::End(e)) => {
                let name = local_name(e.name().as_ref());
                depth -= 1;
                let value = std::mem::take(&mut text);
                match name.as_str() {
                    "resourcetype" => in_resource_type = false,
                    "response" => {
                        if let Some(resource) = current.take() {
                            out.resources.push(resource);
                        }
                    }
                    "sync-token" if value.trim().is_empty() => {}
                    "sync-token" => match current.as_mut() {
                        // Inside a `<response>` it is a PROPERTY of that
                        // collection, which is how a PROPFIND asking for
                        // `D:sync-token` answers, and what
                        // [`CardDavClient::sync_token`] falls back to. Reading
                        // this arm as collection-level only used to drop it,
                        // which left that fallback unreachable and a full read
                        // with no token to sync from next time.
                        Some(resource) => {
                            resource
                                .properties
                                .entry("sync-token".to_string())
                                .or_insert_with(|| value.trim().to_string());
                        }
                        // The multistatus' own token, which a sync report carries
                        // after the last response.
                        None => out.sync_token = Some(value.trim().to_string()),
                    },
                    "href" => {
                        if let Some(resource) = current.as_mut() {
                            // A `<D:href>` inside a property (a home set, a
                            // principal) is that property's value, not the
                            // response's own href, which comes first.
                            if resource.href.is_empty() {
                                resource.href = value.trim().to_string();
                            } else if let Some(parent) = parent_property(&path) {
                                resource
                                    .properties
                                    .entry(parent)
                                    .or_insert_with(|| value.trim().to_string());
                            }
                        }
                    }
                    "getetag" => {
                        if let Some(resource) = current.as_mut() {
                            resource.etag = Some(value.trim().trim_matches('"').to_string());
                        }
                    }
                    "address-data" => {
                        if let Some(resource) = current.as_mut() {
                            resource.card = Some(value);
                        }
                    }
                    "status" => {
                        if let Some(resource) = current.as_mut() {
                            // The first status wins: a `<propstat>` 200 follows
                            // the response-level 404 on a removal, and it is the
                            // removal that matters.
                            if resource.status.is_none() {
                                resource.status = Some(value.trim().to_string());
                            }
                        }
                    }
                    other => {
                        if let Some(resource) = current.as_mut() {
                            if !value.trim().is_empty() {
                                resource
                                    .properties
                                    .entry(other.to_string())
                                    .or_insert_with(|| value.trim().to_string());
                            }
                        }
                    }
                }
                path.pop();
            }
            Ok(Event::Eof) => {
                if !saw_multistatus {
                    // Not XML this module understands. The case that matters is
                    // a server answering with an HTML error page: parsed as
                    // events it yields no responses, which would otherwise read
                    // as "the address book is empty".
                    return Err(SourceError::Failed(
                        "The contact server's response was not a CardDAV multistatus document."
                            .to_string(),
                    ));
                }
                if depth != 0 {
                    return Err(SourceError::Failed(
                        "The contact server's CardDAV response ended mid-document, so it cannot be \
                         read as the whole address book."
                            .to_string(),
                    ));
                }
                break;
            }
            Err(e) => {
                // `Failed` rather than a new variant: its doc says "anything
                // else, in this codebase's own words", and the two variants that
                // carry meaning for the caller are already spoken for - a 401 is
                // `Unauthorized`, which the run records as `reconnect_required`,
                // and a 429 is `Throttled`. An unreadable body is neither.
                return Err(SourceError::Failed(format!(
                    "The contact server's response could not be read as CardDAV XML: {e}"
                )));
            }
            _ => {}
        }
    }
    Ok(out)
}

/// The property element a nested `href` belongs to: the name one level above it,
/// skipping the DAV wrappers that carry no meaning of their own.
fn parent_property(path: &[String]) -> Option<String> {
    path.iter()
        .rev()
        .skip(1)
        .find(|name| {
            !matches!(
                name.as_str(),
                "href" | "prop" | "propstat" | "response" | "multistatus"
            )
        })
        .cloned()
}

/// The first response that carries `property` as a nested href, which is how
/// `current-user-principal` and `addressbook-home-set` both answer.
pub fn href_property(status: &MultiStatus, property: &str) -> Option<String> {
    status
        .resources
        .iter()
        .find_map(|r| r.properties.get(property).cloned())
}

/// The marker a stale-sync-token failure carries, so the provider can tell that
/// one refusal from every other `Failed` without a variant of its own.
///
/// RFC 6578 says a server that will not honour a token answers `403` with a
/// `DAV:valid-sync-token` precondition; some servers use `507`
/// (`number-of-matches-within-limits`) when the delta is too large to express.
/// Both mean the same thing to a caller: ask for everything instead.
const STALE_TOKEN: &str = "sync token is no longer valid";

/// Whether a `Failed` message is the stale-token refusal.
pub fn is_stale_token(message: &str) -> bool {
    message.contains(STALE_TOKEN)
}

/// What a delta read answered: the changed cards, what left the book, and the
/// token for next time.
#[derive(Debug, Clone, Default)]
pub struct CardDelta {
    pub cards: Vec<String>,
    /// The hrefs RFC 6578 reported as gone (a `404` response inside the
    /// multistatus). Hrefs and not ids: a sync report names the RESOURCE, and
    /// the `UID` a contact link is keyed on lives in the card that is no longer
    /// there to read. Carried rather than dropped so the caller can tell a delta
    /// that only added or edited from one it cannot express, which is what
    /// [`super::icloud::ICloudProvider::changes_since`] turns into a full read.
    pub removed: Vec<String>,
    pub next_sync_token: Option<String>,
}

/// A CardDAV client for one account.
///
/// Holds the credential rather than taking it per call, because every request in
/// a run carries the same Basic header and a client that took it per call would
/// invite one request being made without it.
pub struct CardDavClient {
    http: reqwest::Client,
    base_url: String,
    apple_id: String,
    app_password: String,
}

impl CardDavClient {
    pub fn new(
        http: reqwest::Client,
        base_url: impl Into<String>,
        apple_id: impl Into<String>,
        app_password: impl Into<String>,
    ) -> Self {
        Self {
            http,
            base_url: base_url.into().trim_end_matches('/').to_string(),
            apple_id: apple_id.into(),
            app_password: app_password.into(),
        }
    }

    /// An absolute URL for a path the server gave us. A DAV href is a path, and
    /// pasting it onto the base is the only join that is correct for both the
    /// absolute hrefs iCloud returns and a relative one another server might.
    fn url(&self, href: &str) -> String {
        if href.starts_with("http://") || href.starts_with("https://") {
            href.to_string()
        } else {
            format!("{}/{}", self.base_url, href.trim_start_matches('/'))
        }
    }

    /// One DAV request, with the credential, the depth and the body, classified
    /// by status into the three outcomes a caller can act on.
    async fn dav(
        &self,
        method: &str,
        href: &str,
        depth: &str,
        body: &'static str,
    ) -> SourceResult<String> {
        let method = reqwest::Method::from_bytes(method.as_bytes())
            .map_err(|e| SourceError::Failed(format!("bad DAV method: {e}")))?;
        let response = self
            .http
            .request(method, self.url(href))
            .basic_auth(&self.apple_id, Some(&self.app_password))
            .header("Depth", depth)
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/xml; charset=utf-8",
            )
            .body(body)
            .send()
            .await
            .map_err(|e| {
                // The provider's own words never reach a user here (the
                // `SourceError` rule); what is kept is whether we got an answer.
                SourceError::Failed(format!(
                    "The contact server could not be reached: {}",
                    if e.is_timeout() {
                        "it timed out"
                    } else {
                        "the connection failed"
                    }
                ))
            })?;

        let status = response.status();
        if status == reqwest::StatusCode::UNAUTHORIZED
            || status == reqwest::StatusCode::FORBIDDEN && !self.looks_like_stale_token(&response)
        {
            // The one state a person can act on: an app-specific password is
            // revoked from the Apple ID's own settings and Apple gives no notice
            // here, so this must not read as a broken integration.
            return Err(SourceError::Unauthorized);
        }
        // 429 by number rather than `StatusCode::TOO_MANY_REQUESTS`, the way
        // `google::request` spells it: `check-rate-limit-helper` (PMS-773) fails
        // any file under `src/` that names that constant, because its job is to
        // stop a second hand-rolled 429 RESPONSE, and what this reads is
        // somebody else's status code. Do not tidy it back into the constant.
        if status.as_u16() == 429 || status.is_server_error() {
            return Err(SourceError::Throttled);
        }
        if status.as_u16() == 507 || status == reqwest::StatusCode::FORBIDDEN {
            return Err(SourceError::Failed(format!(
                "The {STALE_TOKEN}, so the next read is a full one."
            )));
        }
        if !status.is_success() && status.as_u16() != 207 {
            return Err(SourceError::Failed(format!(
                "The contact server refused the request with status {}.",
                status.as_u16()
            )));
        }
        response.text().await.map_err(|_| {
            SourceError::Failed("The contact server's response could not be read.".to_string())
        })
    }

    /// Whether a 403 is the stale-token precondition rather than a refusal of the
    /// credential. Read from the headers alone, because the body has not been
    /// consumed yet and a 403 that IS a credential problem must not be retried as
    /// a full read.
    fn looks_like_stale_token(&self, response: &reqwest::Response) -> bool {
        response
            .headers()
            .get("DAV")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|dav| dav.contains("addressbook"))
    }

    /// Discovery: the principal, its address-book home, and the first collection
    /// under it whose `resourcetype` says addressbook.
    pub async fn address_book(&self) -> SourceResult<String> {
        const PRINCIPAL_BODY: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<D:propfind xmlns:D="DAV:"><D:prop><D:current-user-principal/></D:prop></D:propfind>"#;
        const HOME_BODY: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<D:propfind xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav"><D:prop><C:addressbook-home-set/></D:prop></D:propfind>"#;
        const BOOKS_BODY: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<D:propfind xmlns:D="DAV:"><D:prop><D:resourcetype/><D:displayname/></D:prop></D:propfind>"#;

        let principal = parse_multistatus(&self.dav("PROPFIND", "/", "0", PRINCIPAL_BODY).await?)?;
        let principal = href_property(&principal, "current-user-principal").ok_or_else(|| {
            SourceError::Failed(
                "The contact server did not say which account this credential belongs to."
                    .to_string(),
            )
        })?;

        let home = parse_multistatus(&self.dav("PROPFIND", &principal, "0", HOME_BODY).await?)?;
        let home = href_property(&home, "addressbook-home-set").ok_or_else(|| {
            SourceError::Failed(
                "The contact server did not say where this account's contacts live.".to_string(),
            )
        })?;

        let books = parse_multistatus(&self.dav("PROPFIND", &home, "1", BOOKS_BODY).await?)?;
        books
            .resources
            .into_iter()
            .find(|r| r.is_addressbook())
            .map(|r| r.href)
            .ok_or_else(|| {
                SourceError::Failed(
                    "This account has no contacts address book to read.".to_string(),
                )
            })
    }

    /// Every card in the book, with its `address-data`.
    pub async fn all_cards(&self, book: &str) -> SourceResult<Vec<String>> {
        const QUERY: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<C:addressbook-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav">
  <D:prop><D:getetag/><C:address-data/></D:prop>
</C:addressbook-query>"#;
        let parsed = parse_multistatus(&self.dav("REPORT", book, "1", QUERY).await?)?;
        Ok(parsed
            .resources
            .into_iter()
            .filter_map(|r| r.card)
            .collect())
    }

    /// The book's current sync token, for the next delta.
    pub async fn sync_token(&self, book: &str) -> SourceResult<Option<String>> {
        const BODY: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<D:propfind xmlns:D="DAV:"><D:prop><D:sync-token/></D:prop></D:propfind>"#;
        let parsed = parse_multistatus(&self.dav("PROPFIND", book, "0", BODY).await?)?;
        Ok(parsed.sync_token.or_else(|| {
            parsed
                .resources
                .first()
                .and_then(|r| r.properties.get("sync-token").cloned())
        }))
    }

    /// What changed since `token`: the cards that were added or edited, and
    /// separately the hrefs that are gone, which arrive as `404` responses
    /// inside the same multistatus (RFC 6578 section 3.2).
    pub async fn changed_cards(&self, book: &str, token: &str) -> SourceResult<CardDelta> {
        // The token goes in the body, so it cannot be built from a static string;
        // `dav` takes `&'static str` to keep every request body a literal, so the
        // sync report has its own request here.
        let body = format!(
            r#"<?xml version="1.0" encoding="utf-8"?>
<D:sync-collection xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav">
  <D:sync-token>{}</D:sync-token>
  <D:sync-level>1</D:sync-level>
  <D:prop><D:getetag/><C:address-data/></D:prop>
</D:sync-collection>"#,
            xml_text(token)
        );
        let response = self
            .http
            .request(
                reqwest::Method::from_bytes(b"REPORT").expect("REPORT is a method"),
                self.url(book),
            )
            .basic_auth(&self.apple_id, Some(&self.app_password))
            .header("Depth", "1")
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/xml; charset=utf-8",
            )
            .body(body)
            .send()
            .await
            .map_err(|_| {
                SourceError::Failed("The contact server could not be reached.".to_string())
            })?;
        let status = response.status();
        if status == reqwest::StatusCode::UNAUTHORIZED {
            return Err(SourceError::Unauthorized);
        }
        // 429 by number, for the reason `dav` above states.
        if status.as_u16() == 429 || status.is_server_error() {
            return Err(SourceError::Throttled);
        }
        if status == reqwest::StatusCode::FORBIDDEN || status.as_u16() == 507 {
            return Err(SourceError::Failed(format!(
                "The {STALE_TOKEN}, so the next read is a full one."
            )));
        }
        let text = response.text().await.map_err(|_| {
            SourceError::Failed("The contact server's response could not be read.".to_string())
        })?;
        let parsed = parse_multistatus(&text)?;
        Ok(CardDelta {
            cards: parsed
                .resources
                .iter()
                .filter(|r| !r.is_gone())
                .filter_map(|r| r.card.clone())
                .collect(),
            removed: parsed
                .resources
                .iter()
                .filter(|r| r.is_gone())
                .map(|r| r.href.clone())
                .collect(),
            next_sync_token: parsed.sync_token,
        })
    }
}

/// Escape the five XML text characters. A sync token is opaque server data that
/// goes back into a request body, so it is escaped rather than trusted, even
/// though iCloud's are base64: a token is not ours to assume the shape of.
fn xml_text(raw: &str) -> String {
    raw.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRINCIPAL: &str = include_str!("../../../tests/fixtures/carddav/principal.xml");
    const HOME_SET: &str = include_str!("../../../tests/fixtures/carddav/home_set.xml");
    const BOOKS: &str = include_str!("../../../tests/fixtures/carddav/addressbooks.xml");
    const CARDS: &str = include_str!("../../../tests/fixtures/carddav/cards.xml");
    const SYNC: &str = include_str!("../../../tests/fixtures/carddav/sync_report.xml");

    /// Discovery step 1: who the credential is.
    #[test]
    fn the_principal_comes_out_of_the_first_propfind() {
        let parsed = parse_multistatus(PRINCIPAL).expect("parses");
        assert_eq!(
            href_property(&parsed, "current-user-principal").as_deref(),
            Some("/1234567890/principal/")
        );
    }

    /// Step 2: where its address books live.
    #[test]
    fn the_home_set_comes_out_of_the_second() {
        let parsed = parse_multistatus(HOME_SET).expect("parses");
        assert_eq!(
            href_property(&parsed, "addressbook-home-set").as_deref(),
            Some("/1234567890/carddavhome/")
        );
    }

    /// Step 3: which collections are address books. The home set also contains
    /// collections that are not (iCloud returns the home itself), so the
    /// `resourcetype` test is what picks the book rather than its position.
    #[test]
    fn only_the_addressbook_collections_are_address_books() {
        let parsed = parse_multistatus(BOOKS).expect("parses");
        let books: Vec<&str> = parsed
            .resources
            .iter()
            .filter(|r| r.is_addressbook())
            .map(|r| r.href.as_str())
            .collect();
        assert_eq!(books, vec!["/1234567890/carddavhome/card/"]);
        assert!(
            parsed.resources.len() > books.len(),
            "the fixture carries a non-addressbook collection too, or it is not testing the filter"
        );
    }

    /// The cards themselves, with their etags, and the vCard body intact
    /// including the folded lines a naive reader would mangle.
    #[test]
    fn a_query_report_yields_each_card_with_its_etag() {
        let parsed = parse_multistatus(CARDS).expect("parses");
        assert_eq!(parsed.resources.len(), 3);
        let first = &parsed.resources[0];
        assert_eq!(first.href, "/1234567890/carddavhome/card/ada.vcf");
        assert_eq!(first.etag.as_deref(), Some("C=1234@example.com"));
        let card = first.card.as_deref().expect("a card body");
        assert!(card.contains("BEGIN:VCARD"), "{card}");
        assert!(card.contains("FN:Ada Lovelace"), "{card}");
        // The group card is in the same response, because to iCloud it is just
        // another card; the provider is what tells them apart.
        let group = parsed.resources[2].card.as_deref().expect("group card");
        assert!(group.contains("X-ADDRESSBOOKSERVER-KIND:group"), "{group}");
    }

    /// A sync report carries the token to use next time, and reports a deletion
    /// as a response whose status is 404 rather than as an absence.
    #[test]
    fn a_sync_report_carries_its_token_and_its_removals() {
        let parsed = parse_multistatus(SYNC).expect("parses");
        assert_eq!(
            parsed.sync_token.as_deref(),
            Some("HwoQEgwAAAh4WEt3aAAAAAAYAhgAIhUIxNvJ9Y2AgAIQxNvJ9Y2AgAIYASgA")
        );
        let gone: Vec<&str> = parsed
            .resources
            .iter()
            .filter(|r| r.is_gone())
            .map(|r| r.href.as_str())
            .collect();
        assert_eq!(gone, vec!["/1234567890/carddavhome/card/removed.vcf"]);
        let changed: Vec<&str> = parsed
            .resources
            .iter()
            .filter(|r| !r.is_gone())
            .map(|r| r.href.as_str())
            .collect();
        assert_eq!(changed, vec!["/1234567890/carddavhome/card/ada.vcf"]);
    }

    /// A PROPFIND for `D:sync-token` answers with the token INSIDE the response,
    /// as a property of the collection, where a sync report puts it after the
    /// last response. Both are the book's token, so both have to be readable or
    /// a full read finishes with nothing to sync from next time.
    #[test]
    fn a_token_inside_a_response_is_that_collections_token() {
        let parsed = parse_multistatus(BOOKS).expect("parses");
        let book = parsed
            .resources
            .iter()
            .find(|r| r.is_addressbook())
            .expect("the address book");
        assert_eq!(
            book.properties.get("sync-token").map(String::as_str),
            Some("HwoQEgwAAAh4WEt3aAAAAAAYAhgAIhUIxNvJ9Y2AgAIQxNvJ9Y2AgAIYASgA")
        );
        assert!(
            parsed.sync_token.is_none(),
            "a property is not the multistatus' own token"
        );
    }

    /// A namespace prefix is not part of an element's meaning. iCloud answers
    /// with `D:` today and a self-hosted CardDAV may answer with `d:` or none;
    /// matching on the prefix would work against exactly the server it was
    /// written against.
    #[test]
    fn the_namespace_prefix_does_not_matter() {
        let lowercase = PRINCIPAL.replace("D:", "d:");
        let parsed = parse_multistatus(&lowercase).expect("parses");
        assert_eq!(
            href_property(&parsed, "current-user-principal").as_deref(),
            Some("/1234567890/principal/")
        );
    }

    /// Malformed XML is an error naming itself, not a panic and not an empty
    /// result that reads as "the address book is empty".
    ///
    /// This is the most consequential test in the file. A full read is reported
    /// as the WHOLE address book, and the sync engine treats a linked contact
    /// absent from a full read as deleted in the source, so a body that parses to
    /// zero responses would tombstone every contact the connection ever
    /// imported. quick-xml reaches EOF on a truncated document without
    /// complaining, which is exactly how that would have shipped.
    #[test]
    fn a_truncated_body_is_an_error_rather_than_an_empty_address_book() {
        let err = parse_multistatus("<D:multistatus><D:response><D:href>/x/")
            .expect_err("a truncated body cannot parse");
        assert!(
            matches!(err, SourceError::Failed(_)),
            "unexpected error: {err:?}"
        );
        assert!(
            err.to_string().contains("CardDAV"),
            "the message should name what could not be read: {err}"
        );
    }

    /// The same hazard by another route: a server that answers an expired
    /// session or a proxy error with HTML. It parses as events, yields no
    /// responses, and must not read as an empty address book either.
    #[test]
    fn an_html_error_page_is_not_an_empty_address_book() {
        let err = parse_multistatus(
            "<html><head><title>401 Unauthorized</title></head><body>Denied</body></html>",
        )
        .expect_err("HTML is not a multistatus");
        assert!(
            err.to_string().contains("multistatus"),
            "the message should say what was expected: {err}"
        );
    }
}
