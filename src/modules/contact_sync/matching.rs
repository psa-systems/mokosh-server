//! PMS-1213 (PSA-70 D): whether an incoming record is somebody Mokosh already
//! holds.
//!
//! A pure decision over match keys ([`super::normalize`]), so every rule is
//! tested without a database. The tiers, in order:
//!
//! 1. **Email, unique**: exactly one Mokosh contact shares a normalized email
//!    with the record, and no other record from this connection is linked to
//!    it. Linked automatically, because an address is the one identifier two
//!    different people do not share.
//! 2. **Email, ambiguous**: more than one Mokosh contact shares the address
//!    (plus-addressing folds `jo+work@` and `jo+home@` together), or the one
//!    that does is already linked to a different record. Queued: an exact
//!    match that could be either of two people is a question, not an answer.
//! 3. **Phone**, or **name and company together**: queued for review, never
//!    merged. A shared switchboard number or two people called Sam at one
//!    company is ordinary.
//! 4. **Nothing**: a new contact.
//!
//! A name ALONE is never a match at any tier, not even a queued one: two
//! people with the same name at no stated company are strangers, and a queue
//! full of them teaches a reviewer to click through it.

use std::collections::BTreeMap;

use uuid::Uuid;

use super::normalize::{email_key, name_key, phone_key};

/// Why a pair was put in front of a human. The strings are the
/// `contact_sync_candidates.match_reason` values (migrations 220 and 227).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MatchReason {
    EmailAmbiguous,
    Phone,
    NameCompany,
}

impl MatchReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::EmailAmbiguous => "email_ambiguous",
            Self::Phone => "phone",
            Self::NameCompany => "name_company",
        }
    }
}

/// A Mokosh contact as the matcher sees it: keys, never raw values.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LocalContact {
    pub contact_id: Uuid,
    pub email_keys: Vec<String>,
    pub phone_keys: Vec<String>,
    pub name_key: Option<String>,
    /// The linked companies' names and the freeform company name, as keys.
    pub company_keys: Vec<String>,
    /// Already linked to a record from THIS connection.
    pub linked: bool,
}

impl LocalContact {
    /// Build the keys from stored values.
    pub fn from_values<'a>(
        contact_id: Uuid,
        email: Option<&str>,
        phones: impl IntoIterator<Item = &'a str>,
        full_name: &str,
        company_names: impl IntoIterator<Item = &'a str>,
        linked: bool,
    ) -> Self {
        Self {
            contact_id,
            email_keys: email.and_then(email_key).into_iter().collect(),
            phone_keys: phones.into_iter().filter_map(phone_key).collect(),
            name_key: name_key(full_name),
            company_keys: company_names.into_iter().filter_map(name_key).collect(),
            linked,
        }
    }
}

/// The incoming record's keys.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IncomingKeys {
    pub email_keys: Vec<String>,
    pub phone_keys: Vec<String>,
    pub name_key: Option<String>,
    pub company_key: Option<String>,
}

impl IncomingKeys {
    /// Every email the source holds is compared, not only the primary one the
    /// import keeps: a Mokosh contact holding somebody's secondary address is
    /// still that person.
    pub fn from_values<'a>(
        emails: impl IntoIterator<Item = &'a str>,
        phones: impl IntoIterator<Item = &'a str>,
        full_name: &str,
        company: Option<&str>,
    ) -> Self {
        let mut email_keys: Vec<String> = emails.into_iter().filter_map(email_key).collect();
        email_keys.dedup();
        let mut phone_keys: Vec<String> = phones.into_iter().filter_map(phone_key).collect();
        phone_keys.dedup();
        Self {
            email_keys,
            phone_keys,
            name_key: name_key(full_name),
            company_key: company.and_then(name_key),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchDecision {
    /// Link to this contact without asking.
    Link(Uuid),
    /// Ask a human about each pair, in contact-id order.
    Review(Vec<(Uuid, MatchReason)>),
    /// Nobody Mokosh holds; import as new.
    Create,
}

pub fn decide(incoming: &IncomingKeys, locals: &[LocalContact]) -> MatchDecision {
    let by_email: Vec<&LocalContact> = locals
        .iter()
        .filter(|l| l.email_keys.iter().any(|k| incoming.email_keys.contains(k)))
        .collect();
    if let [only] = by_email.as_slice() {
        if !only.linked {
            return MatchDecision::Link(only.contact_id);
        }
    }

    // One reason per contact, the strongest: a pair is one row in the queue.
    let mut pairs: BTreeMap<Uuid, MatchReason> = BTreeMap::new();
    let mut propose = |id: Uuid, reason: MatchReason| {
        pairs
            .entry(id)
            .and_modify(|r| *r = (*r).min(reason))
            .or_insert(reason);
    };
    for local in &by_email {
        propose(local.contact_id, MatchReason::EmailAmbiguous);
    }
    for local in locals {
        if local
            .phone_keys
            .iter()
            .any(|k| incoming.phone_keys.contains(k))
        {
            propose(local.contact_id, MatchReason::Phone);
        }
        let same_name = incoming.name_key.is_some() && local.name_key == incoming.name_key;
        let same_company = incoming
            .company_key
            .as_ref()
            .is_some_and(|c| local.company_keys.contains(c));
        if same_name && same_company {
            propose(local.contact_id, MatchReason::NameCompany);
        }
    }

    if pairs.is_empty() {
        MatchDecision::Create
    } else {
        MatchDecision::Review(pairs.into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    fn local(
        n: u128,
        email: Option<&str>,
        phones: &[&str],
        name: &str,
        companies: &[&str],
    ) -> LocalContact {
        LocalContact::from_values(
            id(n),
            email,
            phones.iter().copied(),
            name,
            companies.iter().copied(),
            false,
        )
    }

    fn incoming(
        emails: &[&str],
        phones: &[&str],
        name: &str,
        company: Option<&str>,
    ) -> IncomingKeys {
        IncomingKeys::from_values(
            emails.iter().copied(),
            phones.iter().copied(),
            name,
            company,
        )
    }

    #[test]
    fn a_unique_normalized_email_links_automatically() {
        let locals = [
            local(1, Some("Ada@Acme.example"), &[], "Ada Lovelace", &[]),
            local(2, Some("grace@acme.example"), &[], "Grace Hopper", &[]),
        ];
        let decision = decide(
            &incoming(&["  ada+crm@acme.example "], &[], "A. Lovelace", None),
            &locals,
        );
        assert_eq!(decision, MatchDecision::Link(id(1)));
    }

    /// Any of the source's addresses counts, not only the primary.
    #[test]
    fn a_secondary_source_address_still_links() {
        let locals = [local(1, Some("ada@home.example"), &[], "Ada", &[])];
        let decision = decide(
            &incoming(&["ada@work.example", "ada@home.example"], &[], "Ada", None),
            &locals,
        );
        assert_eq!(decision, MatchDecision::Link(id(1)));
    }

    /// Two Mokosh contacts behind one normalized address: a question.
    #[test]
    fn an_address_two_contacts_share_is_queued_not_guessed() {
        let locals = [
            local(1, Some("jo+work@acme.example"), &[], "Jo Smith", &[]),
            local(2, Some("jo+home@acme.example"), &[], "Jo Smith", &[]),
        ];
        let decision = decide(
            &incoming(&["jo@acme.example"], &[], "Jo Smith", None),
            &locals,
        );
        assert_eq!(
            decision,
            MatchDecision::Review(vec![
                (id(1), MatchReason::EmailAmbiguous),
                (id(2), MatchReason::EmailAmbiguous)
            ])
        );
    }

    /// The one contact an address matches is already another record's: two
    /// Google entries for one person is for a human to untangle.
    #[test]
    fn an_email_match_already_linked_elsewhere_is_queued() {
        let mut taken = local(1, Some("ada@acme.example"), &[], "Ada", &[]);
        taken.linked = true;
        let decision = decide(&incoming(&["ada@acme.example"], &[], "Ada", None), &[taken]);
        assert_eq!(
            decision,
            MatchDecision::Review(vec![(id(1), MatchReason::EmailAmbiguous)])
        );
    }

    #[test]
    fn a_phone_match_is_queued_never_linked() {
        let locals = [local(1, None, &["+1 (415) 555-1234"], "Front Desk", &[])];
        let decision = decide(
            &incoming(&[], &["+14155551234"], "Ada Lovelace", None),
            &locals,
        );
        assert_eq!(
            decision,
            MatchDecision::Review(vec![(id(1), MatchReason::Phone)])
        );
    }

    #[test]
    fn name_and_company_together_are_queued() {
        let locals = [local(1, None, &[], "ada  LOVELACE", &["Acme Ltd"])];
        let decision = decide(
            &incoming(&[], &[], "Ada Lovelace", Some("acme ltd")),
            &locals,
        );
        assert_eq!(
            decision,
            MatchDecision::Review(vec![(id(1), MatchReason::NameCompany)])
        );
    }

    /// The rule the epic states twice: never on name alone.
    #[test]
    fn a_name_alone_is_never_a_match() {
        let locals = [local(1, None, &[], "Ada Lovelace", &["Acme Ltd"])];
        assert_eq!(
            decide(&incoming(&[], &[], "Ada Lovelace", None), &locals),
            MatchDecision::Create
        );
        assert_eq!(
            decide(
                &incoming(&[], &[], "Ada Lovelace", Some("Other Co")),
                &locals
            ),
            MatchDecision::Create
        );
    }

    /// A contact that matches on several grounds is one pair with the
    /// strongest reason.
    #[test]
    fn one_pair_per_contact_with_the_strongest_reason() {
        let locals = [local(1, None, &["4155551234"], "Ada Lovelace", &["Acme"])];
        let decision = decide(
            &incoming(&[], &["4155551234"], "Ada Lovelace", Some("Acme")),
            &locals,
        );
        assert_eq!(
            decision,
            MatchDecision::Review(vec![(id(1), MatchReason::Phone)])
        );
    }

    #[test]
    fn no_overlap_creates() {
        let locals = [local(
            1,
            Some("grace@acme.example"),
            &["4155550000"],
            "Grace Hopper",
            &["Navy"],
        )];
        assert_eq!(
            decide(
                &incoming(
                    &["ada@acme.example"],
                    &["4155551234"],
                    "Ada Lovelace",
                    Some("Acme")
                ),
                &locals
            ),
            MatchDecision::Create
        );
    }

    /// Match keys are never stored: the reasons are the migration's values.
    #[test]
    fn the_reasons_are_the_column_values() {
        const MIGRATION: &str = include_str!("../../../migrations/227_contact_sync_matching.sql");
        for reason in [
            MatchReason::EmailAmbiguous,
            MatchReason::Phone,
            MatchReason::NameCompany,
        ] {
            assert!(
                MIGRATION.contains(&format!("'{}'", reason.as_str())),
                "{reason:?} missing from migration 227"
            );
        }
    }
}
