//! PMS-1341: iCloud Contacts, over CardDAV.
//!
//! The protocol is [`super::carddav`] and the payload parser is
//! [`super::vcard`], both of which exist already; this module is the
//! [`ContactSyncProvider`] on top of them, so the schema, the matching, the
//! review queue and the sync worker take iCloud without a change (the reason
//! PMS-1211 built that seam).
//!
//! # Groups are cards here
//!
//! Google has a groups endpoint. iCloud has one address book, and what a person
//! calls a group in Contacts.app is another vCard inside it, with
//! `X-ADDRESSBOOKSERVER-KIND:group` and one `X-ADDRESSBOOKSERVER-MEMBER` per
//! member holding that member's `UID`. So [`Self::list_groups`] reads the whole
//! book, keeps the group cards, and counts their members; membership is resolved
//! by `UID` rather than by anything positional, and a member id matching no card
//! is simply not counted rather than guessed at.
//!
//! `UNGROUPED_ID` is offered beside them, exactly as the `.vcf` import offers it
//! (PMS-1290), because an Apple address book routinely holds contacts in no group
//! at all and a selection that could not reach them would make half a directory
//! unimportable.
//!
//! # One full read, reused
//!
//! `list_groups` and a full `changes_since` both need every card, so the read is
//! one `addressbook-query` REPORT either way. A delta sync uses
//! `sync-collection` instead and asks for the changed cards only.
//!
//! # What the credential is
//!
//! An Apple ID and an app-specific password, sent as HTTP Basic. Apple publishes
//! no OAuth scope for contacts, so there is no token to refresh and no consent
//! screen: the credential is valid until the person revokes it from their Apple
//! ID settings, and Apple gives no notice here when they do. A 401 is therefore
//! the one failure an admin can act on, and it is reported as
//! [`SourceError::Unauthorized`] so the run records `reconnect_required` and the
//! settings card says so, rather than as a generic failure.

use async_trait::async_trait;

use super::carddav::{self, CardDavClient};
use super::provider::{
    ContactSyncProvider, SourceChanges, SourceContact, SourceError, SourceGroup, SourceResult,
    UNGROUPED_ID,
};
use super::vcard::{self, GroupCard};

/// The provider discriminator, matching `contact_sync_connections.provider`.
pub const ICLOUD: &str = "icloud";

/// Read one iCloud account's contacts.
pub struct ICloudProvider {
    client: CardDavClient,
}

impl ICloudProvider {
    /// An Apple ID and an app-specific password against a CardDAV base URL.
    pub fn new(client: CardDavClient) -> Self {
        Self { client }
    }

    /// Every card in the account's address book, parsed once.
    ///
    /// Returns the contacts and the group cards separately, because iCloud does
    /// not distinguish them on the wire: both are cards in the same collection,
    /// and only the parsed `KIND` tells them apart.
    async fn read_book(&self) -> SourceResult<(Vec<SourceContact>, Vec<GroupCard>)> {
        let book = self.client.address_book().await?;
        let cards = self.client.all_cards(&book).await?;
        Ok(parse_cards(&cards))
    }
}

/// Parse a CardDAV response's cards into contacts and group cards.
///
/// Pure, so the fixtures drive it: the vCard reader is the one canonical parser
/// (PMS-1288) and it already recognises Apple's group cards, so this is the
/// per-card loop and nothing else. A card that fails to parse is skipped rather
/// than failing the read, which is the `.vcf` import's rule too: one malformed
/// card in an address book of two thousand must not stop the sync.
pub fn parse_cards(cards: &[String]) -> (Vec<SourceContact>, Vec<GroupCard>) {
    let mut contacts = Vec::new();
    let mut groups = Vec::new();
    for card in cards {
        let Ok(file) = vcard::read_vcards(card.as_bytes(), vcard::Limits::DEFAULT) else {
            continue;
        };
        contacts.extend(file.contacts);
        groups.extend(file.group_cards_read);
    }
    (contacts, groups)
}

/// The selectable groups: each group card that names itself, plus Ungrouped.
///
/// A group's count is its members that are actually in the book, so the preview
/// counts what an import would bring rather than what the card claims: an Apple
/// group card keeps a member line for a contact deleted from another device until
/// something rewrites the group.
pub fn groups_from(contacts: &[SourceContact], group_cards: &[GroupCard]) -> Vec<SourceGroup> {
    let known: std::collections::HashSet<&str> =
        contacts.iter().map(|c| c.external_id.as_str()).collect();
    let mut groups: Vec<SourceGroup> = group_cards
        .iter()
        .filter_map(|card| {
            let id = card.id.clone()?;
            let name = card.name.clone().unwrap_or_else(|| "Untitled group".into());
            let members = card
                .member_ids
                .iter()
                .filter(|member| known.contains(member.as_str()))
                .count();
            Some(SourceGroup {
                id,
                name,
                member_count: Some(members as u32),
            })
        })
        .collect();
    groups.sort_by_key(|g| g.name.to_lowercase());

    let grouped: std::collections::HashSet<&str> = group_cards
        .iter()
        .flat_map(|card| card.member_ids.iter().map(String::as_str))
        .collect();
    let ungrouped = contacts
        .iter()
        .filter(|c| !grouped.contains(c.external_id.as_str()))
        .count();
    groups.push(SourceGroup {
        id: UNGROUPED_ID.to_string(),
        name: "Ungrouped".to_string(),
        member_count: Some(ungrouped as u32),
    });
    groups
}

/// Stamp each contact with the groups it belongs to.
///
/// iCloud carries membership on the GROUP card, not on the member, so a contact
/// arrives from the wire with no `group_ids` at all and the selection would match
/// nothing. This is the pass that fills them in, and it is the reason the option
/// chosen for PMS-1341 costs one extra walk over the cards.
pub fn apply_membership(contacts: &mut [SourceContact], group_cards: &[GroupCard]) {
    for card in group_cards {
        let Some(group_id) = card.id.as_deref() else {
            continue;
        };
        for contact in contacts.iter_mut() {
            if card.member_ids.iter().any(|m| m == &contact.external_id)
                && !contact.group_ids.iter().any(|g| g == group_id)
            {
                contact.group_ids.push(group_id.to_string());
            }
        }
    }
}

#[async_trait]
impl ContactSyncProvider for ICloudProvider {
    fn id(&self) -> &'static str {
        ICLOUD
    }

    async fn list_groups(&self) -> SourceResult<Vec<SourceGroup>> {
        let (contacts, group_cards) = self.read_book().await?;
        Ok(groups_from(&contacts, &group_cards))
    }

    async fn changes_since(&self, sync_token: Option<&str>) -> SourceResult<SourceChanges> {
        let book = self.client.address_book().await?;
        if let Some(token) = sync_token {
            match self.client.changed_cards(&book, token).await {
                // Nothing left the book, so the delta is the whole story.
                Ok(delta) if delta.removed.is_empty() => {
                    let (mut contacts, group_cards) = parse_cards(&delta.cards);
                    apply_membership(&mut contacts, &group_cards);
                    return Ok(SourceChanges {
                        contacts,
                        next_sync_token: delta.next_sync_token,
                        was_full_resync: false,
                    });
                }
                // A removal names an href and nothing else, and a contact link
                // is keyed on the card's `UID`, which is in the card that is no
                // longer there to read; iCloud's `<uid>.vcf` filename is a
                // convention, not a promise, so deriving the id from the href
                // would tombstone by guess. Falling through to a FULL read
                // instead reuses the reconciliation the engine already trusts:
                // `lists_everything` is true here, so absence from a full read
                // IS deletion in the source. The cost is one whole-book read in
                // the run that first sees a deletion, which is the cheap half of
                // the trade against a contact that stays linked forever.
                Ok(delta) => {
                    tracing::info!(
                        removed = delta.removed.len(),
                        "an iCloud delta reported removals, so this run reads the whole address book"
                    );
                }
                // A token iCloud no longer honours is not an error: the caller
                // would otherwise stop syncing after a quiet week (the rule the
                // trait states, and Google's `410 EXPIRED_SYNC_TOKEN` shape).
                // Anything else is, because a full read after a real failure
                // would be a full read the caller trusts as the whole book.
                Err(SourceError::Failed(message)) if carddav::is_stale_token(&message) => {}
                Err(other) => return Err(other),
            }
        }
        let cards = self.client.all_cards(&book).await?;
        let token = self.client.sync_token(&book).await.ok().flatten();
        let (mut contacts, group_cards) = parse_cards(&cards);
        apply_membership(&mut contacts, &group_cards);
        Ok(SourceChanges {
            contacts,
            next_sync_token: token,
            was_full_resync: sync_token.is_some(),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    use axum::extract::State;
    use axum::http::{HeaderMap, Method, StatusCode, Uri};
    use axum::response::{IntoResponse, Response};

    use super::*;
    use crate::modules::contact_sync::carddav::parse_multistatus;

    const CARDS: &str = include_str!("../../../tests/fixtures/carddav/cards.xml");
    const PRINCIPAL: &str = include_str!("../../../tests/fixtures/carddav/principal.xml");
    const HOME_SET: &str = include_str!("../../../tests/fixtures/carddav/home_set.xml");
    const ADDRESSBOOKS: &str = include_str!("../../../tests/fixtures/carddav/addressbooks.xml");
    const SYNC_REPORT: &str = include_str!("../../../tests/fixtures/carddav/sync_report.xml");
    const SYNC_EDIT_ONLY: &str =
        include_str!("../../../tests/fixtures/carddav/sync_report_edit_only.xml");
    const BOOK_TOKEN: &str = include_str!("../../../tests/fixtures/carddav/book_token.xml");

    fn cards_from_fixture() -> Vec<String> {
        parse_multistatus(CARDS)
            .expect("the fixture parses")
            .resources
            .into_iter()
            .filter_map(|r| r.card)
            .collect()
    }

    /// The shared mapping path: the cards come out as `SourceContact`s through
    /// the same vCard reader the `.vcf` import uses, with the fields PMS-1288's
    /// table promises.
    #[test]
    fn the_cards_come_through_the_shared_vcard_reader() {
        let (contacts, groups) = parse_cards(&cards_from_fixture());
        assert_eq!(contacts.len(), 2, "two people and one group card");
        assert_eq!(groups.len(), 1);

        let ada = contacts
            .iter()
            .find(|c| c.display_name.as_deref() == Some("Ada Lovelace"))
            .expect("Ada is in the book");
        assert_eq!(
            ada.external_id, "AAAA1111-2222-3333-4444-555566667777",
            "the vCard UID is the external id"
        );
        assert_eq!(ada.given_name.as_deref(), Some("Ada"));
        assert_eq!(ada.family_name.as_deref(), Some("Lovelace"));
        assert_eq!(ada.organization.as_deref(), Some("Analytical Engines Ltd"));
        assert_eq!(ada.title.as_deref(), Some("Chief Programmer"));
        assert_eq!(
            ada.emails.first().map(|e| e.address.as_str()),
            Some("ada@analytical.example"),
            "the pref address comes first, which is what the primary-email rule reads"
        );
        assert_eq!(ada.phones.len(), 2, "both numbers, typed");
        assert!(
            ada.note.as_deref().is_some_and(|n| n.contains("symposium")),
            "the folded NOTE is unfolded by the reader: {:?}",
            ada.note
        );
    }

    /// The group card is a group, not a contact, and its name and members come
    /// out of it.
    #[test]
    fn a_group_card_is_a_group_and_not_a_contact() {
        let (contacts, groups) = parse_cards(&cards_from_fixture());
        assert!(
            !contacts
                .iter()
                .any(|c| c.display_name.as_deref() == Some("Clients")),
            "the group must not arrive as a person"
        );
        let group = groups.first().expect("the group card");
        assert_eq!(group.name.as_deref(), Some("Clients"));
        assert_eq!(
            group.id.as_deref(),
            Some("GGGG1111-2222-3333-4444-555566667777")
        );
        assert_eq!(group.member_ids.len(), 2, "both member lines are kept");
    }

    /// The selectable list: the group, and Ungrouped for the contact in none.
    ///
    /// The count is members actually in the book. The fixture's group names two
    /// members and only one of them is a card, which is the ordinary state of an
    /// Apple group card after a contact is deleted on another device, and the
    /// preview must not promise the import will bring the other.
    #[test]
    fn the_groups_offered_are_the_cards_groups_plus_ungrouped() {
        let (contacts, group_cards) = parse_cards(&cards_from_fixture());
        let groups = groups_from(&contacts, &group_cards);
        assert_eq!(groups.len(), 2, "{groups:?}");
        assert_eq!(groups[0].name, "Clients");
        assert_eq!(
            groups[0].member_count,
            Some(1),
            "only the member that is actually a card in this book"
        );
        assert_eq!(groups[1].id, UNGROUPED_ID);
        assert_eq!(
            groups[1].member_count,
            Some(1),
            "Charles is in no group, so Ungrouped is how he can be selected"
        );
    }

    /// Membership reaches the contacts, because the selection matches on the
    /// contact's own `group_ids` and iCloud carries membership on the group card.
    #[test]
    fn membership_is_stamped_onto_the_members() {
        let (mut contacts, group_cards) = parse_cards(&cards_from_fixture());
        assert!(
            contacts.iter().all(|c| c.group_ids.is_empty()),
            "a card arrives off the wire with no membership of its own"
        );
        apply_membership(&mut contacts, &group_cards);

        let ada = contacts
            .iter()
            .find(|c| c.external_id == "AAAA1111-2222-3333-4444-555566667777")
            .expect("Ada");
        assert_eq!(
            ada.group_ids,
            vec!["GGGG1111-2222-3333-4444-555566667777".to_string()],
            "Ada is in Clients"
        );
        let charles = contacts
            .iter()
            .find(|c| c.external_id == "BBBB1111-2222-3333-4444-555566667777")
            .expect("Charles");
        assert!(
            charles.group_ids.is_empty(),
            "Charles is in no group, and must not inherit one"
        );
    }

    /// Applying membership twice does not double it: a delta sync re-reads group
    /// cards it has seen, and a contact in one group must not end up listed twice
    /// in it.
    #[test]
    fn membership_does_not_accumulate_on_a_second_pass() {
        let (mut contacts, group_cards) = parse_cards(&cards_from_fixture());
        apply_membership(&mut contacts, &group_cards);
        apply_membership(&mut contacts, &group_cards);
        let ada = contacts
            .iter()
            .find(|c| c.external_id == "AAAA1111-2222-3333-4444-555566667777")
            .expect("Ada");
        assert_eq!(ada.group_ids.len(), 1, "{:?}", ada.group_ids);
    }

    /// A malformed card is skipped rather than failing the whole read. One bad
    /// card in an address book of two thousand must not stop the sync, which is
    /// the `.vcf` import's rule as well.
    #[test]
    fn one_unreadable_card_does_not_lose_the_book() {
        let mut cards = cards_from_fixture();
        cards.insert(0, "this is not a vCard at all".to_string());
        let (contacts, _groups) = parse_cards(&cards);
        assert_eq!(contacts.len(), 2, "the two real contacts still arrive");
    }

    /// A request the stub received: the method, the path, and whether the
    /// credential rode along.
    type Seen = (String, String, Option<String>);

    /// A scripted CardDAV server: answers `207 Multi-Status` in order and records
    /// what it was asked. Ordered rather than routed, because what is under test
    /// is the SEQUENCE - discovery, then the report the provider chose - and a
    /// router would answer a request the provider should never have made.
    #[derive(Clone, Default)]
    struct Stub {
        script: Arc<Mutex<VecDeque<String>>>,
        seen: Arc<Mutex<Vec<Seen>>>,
    }

    async fn answer(
        State(stub): State<Stub>,
        method: Method,
        uri: Uri,
        headers: HeaderMap,
    ) -> Response {
        stub.seen.lock().unwrap().push((
            method.to_string(),
            uri.path().to_string(),
            headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string),
        ));
        match stub.script.lock().unwrap().pop_front() {
            Some(body) => (
                StatusCode::from_u16(207).expect("207 is a status"),
                [("content-type", "application/xml; charset=utf-8")],
                body,
            )
                .into_response(),
            None => (StatusCode::INTERNAL_SERVER_ERROR, "script exhausted").into_response(),
        }
    }

    async fn serve(script: Vec<&str>) -> (Stub, ICloudProvider) {
        let stub = Stub::default();
        stub.script
            .lock()
            .unwrap()
            .extend(script.into_iter().map(str::to_string));
        let app = axum::Router::new()
            .fallback(answer)
            .with_state(stub.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let provider = ICloudProvider::new(CardDavClient::new(
            reqwest::Client::new(),
            base,
            "ada@icloud.example",
            "abcd-efgh-ijkl-mnop",
        ));
        (stub, provider)
    }

    /// The discovery ladder is three PROPFINDs and every request carries the
    /// app-specific password: CardDAV has no session, so a request made without
    /// the Basic header is a request iCloud answers with a 401 nobody can place.
    #[tokio::test]
    async fn every_request_carries_the_app_specific_password() {
        let (stub, provider) = serve(vec![PRINCIPAL, HOME_SET, ADDRESSBOOKS, CARDS]).await;
        provider.list_groups().await.expect("the book reads");
        let seen = stub.seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 4, "{seen:?}");
        assert!(
            seen.iter()
                .all(|(_, _, auth)| auth.as_deref().is_some_and(|a| a.starts_with("Basic "))),
            "{seen:?}"
        );
        assert_eq!(
            seen.iter().map(|(m, _, _)| m.as_str()).collect::<Vec<_>>(),
            vec!["PROPFIND", "PROPFIND", "PROPFIND", "REPORT"],
            "discovery, then the query report"
        );
    }

    /// A delta that only added or edited stays a delta: the run reads the changed
    /// cards, keeps the server's new token, and does not claim to have read the
    /// whole book.
    #[tokio::test]
    async fn a_delta_that_removed_nothing_stays_a_delta() {
        let (stub, provider) = serve(vec![PRINCIPAL, HOME_SET, ADDRESSBOOKS, SYNC_EDIT_ONLY]).await;
        let changes = provider
            .changes_since(Some("an-earlier-token"))
            .await
            .expect("the delta reads");
        assert!(!changes.was_full_resync, "nothing needed a full read");
        assert_eq!(changes.contacts.len(), 1, "the one changed card");
        assert!(
            changes
                .next_sync_token
                .as_deref()
                .is_some_and(|t| t.ends_with("gC")),
            "the token from the sync report: {:?}",
            changes.next_sync_token
        );
        assert_eq!(
            stub.seen.lock().unwrap().len(),
            4,
            "discovery plus the one sync report"
        );
    }

    /// A delta that reported a removal reads the whole book instead, and says so,
    /// because that is the only read whose absences the engine reconciles
    /// (`lists_everything`). A removal names an href and a contact link is keyed
    /// on the card's `UID`, which is in the card that is gone.
    #[tokio::test]
    async fn a_removal_turns_the_delta_into_a_full_read() {
        let (stub, provider) = serve(vec![
            PRINCIPAL,
            HOME_SET,
            ADDRESSBOOKS,
            SYNC_REPORT,
            CARDS,
            BOOK_TOKEN,
        ])
        .await;
        let changes = provider
            .changes_since(Some("an-earlier-token"))
            .await
            .expect("the read succeeds");
        assert!(
            changes.was_full_resync,
            "the engine only reconciles deletions against a read that says it is the whole book"
        );
        assert_eq!(changes.contacts.len(), 2, "every person in the book");
        let ada = changes
            .contacts
            .iter()
            .find(|c| c.external_id == "AAAA1111-2222-3333-4444-555566667777")
            .expect("Ada");
        assert_eq!(
            ada.group_ids,
            vec!["GGGG1111-2222-3333-4444-555566667777".to_string()],
            "membership is stamped on the full read too, not only on the delta"
        );
        assert!(
            changes
                .next_sync_token
                .as_deref()
                .is_some_and(|t| t.ends_with("gB")),
            "the book's own token, read after the cards: {:?}",
            changes.next_sync_token
        );
        let seen = stub.seen.lock().unwrap().clone();
        assert_eq!(
            seen.iter().map(|(m, _, _)| m.as_str()).collect::<Vec<_>>(),
            vec!["PROPFIND", "PROPFIND", "PROPFIND", "REPORT", "REPORT", "PROPFIND"],
            "the sync report, then the whole-book query, then the token"
        );
    }
}
