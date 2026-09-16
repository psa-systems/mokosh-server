//! PMS-1213 (PSA-70 F): a source contact, as Mokosh can hold it.
//!
//! # The mapping table
//!
//! | Google People field | Mokosh field | Policy |
//! |---|---|---|
//! | `names[].givenName` | `first_name` | Primary name. |
//! | `names[].familyName` | `last_name` | Primary name. Empty for a single-name person. |
//! | `names[].displayName` | `first_name` | Only when there is no given or family name: a single-name or display-only record keeps its whole name rather than being split by a guess. |
//! | `emailAddresses[]` | `email` | **Primary email wins** (PSA-70, decided): the one Google marks primary, else the first. Every other address is DROPPED and counted in [`MappedContact::dropped`]. |
//! | `phoneNumbers[]` | `contact_phones` | All kept, typed: `mobile`, `work`, `home`, `*Fax` to `fax`, anything else to `other`. Stored as Google's E.164 `canonicalForm` when present, else the formatting-stripped `value`; a number that is neither valid E.164 nor plain digits is DROPPED rather than failing the contact. |
//! | `organizations[].name` | `company_name` | Free text only. NEVER a `companies` row (PSA-70 G); a matching company is a suggestion for a human. |
//! | `organizations[].title` | `title` | |
//! | `organizations[].department` | `department` | |
//! | `memberships[]` | (none) | Read for the opt-in group filter (PSA-70 E), not stored. |
//!
//! # Dropped, explicitly
//!
//! [`DROPPED_FIELDS`] lists every People field with no Mokosh home. Photos are
//! among them in v1: referencing Google's image URL would make every staff
//! browser that opens a contact fetch from a third party, and fetching a copy
//! is storage and a retention question the epic did not settle.
//!
//! # A record with no name at all
//!
//! Mokosh requires a first name. A contact with no given, family or display
//! name takes its organisation name, else its primary email, else the literal
//! `(no name)`, so it can still be imported and found - and the placeholder is
//! visible, which is the point: a silently invented name would read as a
//! real one.

use super::provider::SourceContact;

/// People fields that have no home in Mokosh and are never imported.
///
/// Stated as data so the list is the documentation, and so a UI can show a
/// person what an import leaves behind instead of leaving them to discover it.
pub const DROPPED_FIELDS: &[&str] = &[
    "additional email addresses (only the primary is kept)",
    "addresses",
    "birthdays",
    "biographies",
    "calendarUrls",
    "clientData",
    "coverPhotos",
    "events",
    "externalIds",
    "fileAses",
    "genders",
    "imClients",
    "interests",
    "locales",
    "locations",
    "miscKeywords",
    "nicknames",
    "occupations",
    "photos",
    "relations",
    "sipAddresses",
    "skills",
    "urls",
    "userDefined",
];

/// Mokosh's closed phone types, as `contact_phones.phone_type` stores them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MappedPhoneType {
    Mobile,
    Work,
    Home,
    Fax,
    Other,
}

impl MappedPhoneType {
    pub fn from_label(label: Option<&str>) -> Self {
        match label.map(str::to_lowercase).as_deref() {
            Some("mobile") => Self::Mobile,
            Some("work") => Self::Work,
            Some("home") => Self::Home,
            Some(l) if l.ends_with("fax") => Self::Fax,
            _ => Self::Other,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Mobile => "mobile",
            Self::Work => "work",
            Self::Home => "home",
            Self::Fax => "fax",
            Self::Other => "other",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappedPhone {
    pub number: String,
    pub phone_type: MappedPhoneType,
    pub is_primary: bool,
}

/// A source contact collapsed onto Mokosh's model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappedContact {
    pub first_name: String,
    pub last_name: String,
    pub email: Option<String>,
    pub phones: Vec<MappedPhone>,
    pub company_name: Option<String>,
    pub title: Option<String>,
    pub department: Option<String>,
    /// What this particular record lost in the collapse, beyond the fields
    /// no record keeps: additional emails and unstorable phone numbers.
    pub dropped: Vec<String>,
}

/// Column widths from migration 004, so a mapped value always fits.
const NAME_MAX: usize = 100;
const EMAIL_MAX: usize = 255;
const COMPANY_NAME_MAX: usize = 255;
const TITLE_MAX: usize = 100;
const PHONE_MAX: usize = 50;

/// Trim, and cut at a character boundary so a multi-byte name is never split
/// mid-character.
fn fit(value: Option<&str>, max: usize) -> Option<String> {
    let trimmed = value?.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.chars().take(max).collect())
}

/// Whether a number is one Mokosh will store: the same rule
/// `mokosh_types::contacts` validates a phone with - an optional `+`, then 2
/// to 15 digits, the first of them 1 to 9. Pinned against that validator by a
/// test rather than trusted to agree.
pub fn storable_phone(raw: &str) -> Option<String> {
    let stripped: String = raw
        .chars()
        .filter(|c| !matches!(c, ' ' | '\t' | '\u{00A0}' | '-' | '(' | ')' | '.'))
        .collect();
    let digits = stripped.strip_prefix('+').unwrap_or(&stripped);
    let valid = (2..=15).contains(&digits.len())
        && digits.bytes().all(|b| b.is_ascii_digit())
        && digits
            .as_bytes()
            .first()
            .is_some_and(|b| (b'1'..=b'9').contains(b));
    (valid && stripped.len() <= PHONE_MAX).then_some(stripped)
}

pub fn map_contact(source: &SourceContact) -> MappedContact {
    let mut dropped = Vec::new();

    let given = fit(source.given_name.as_deref(), NAME_MAX);
    let family = fit(source.family_name.as_deref(), NAME_MAX);
    let (first_name, last_name) = match (given, family) {
        (Some(g), f) => (g, f.unwrap_or_default()),
        (None, Some(f)) => (f, String::new()),
        (None, None) => {
            let fallback = fit(source.display_name.as_deref(), NAME_MAX)
                .or_else(|| fit(source.organization.as_deref(), NAME_MAX))
                .or_else(|| fit(source.emails.first().map(String::as_str), NAME_MAX))
                .unwrap_or_else(|| "(no name)".to_string());
            (fallback, String::new())
        }
    };

    let email = fit(source.emails.first().map(String::as_str), EMAIL_MAX);
    if source.emails.len() > 1 {
        dropped.push(format!(
            "{} additional email address(es)",
            source.emails.len() - 1
        ));
    }

    let mut phones: Vec<MappedPhone> = Vec::new();
    for phone in &source.phones {
        let storable = phone
            .canonical
            .as_deref()
            .and_then(storable_phone)
            .or_else(|| storable_phone(&phone.number));
        match storable {
            Some(number) if !phones.iter().any(|p| p.number == number) => {
                phones.push(MappedPhone {
                    number,
                    phone_type: MappedPhoneType::from_label(phone.label.as_deref()),
                    is_primary: phone.is_primary,
                })
            }
            // The same number twice under two labels is one number.
            Some(_) => {}
            None => dropped.push(format!("unstorable phone number {:?}", phone.number)),
        }
    }
    // Exactly one primary, or the `contact_phones` one-primary index refuses
    // the write: the source's own primary, else the first number.
    if !phones.is_empty() {
        let primary_at = phones.iter().position(|p| p.is_primary).unwrap_or(0);
        for (i, phone) in phones.iter_mut().enumerate() {
            phone.is_primary = i == primary_at;
        }
    }

    MappedContact {
        first_name,
        last_name,
        email,
        phones,
        company_name: fit(source.organization.as_deref(), COMPANY_NAME_MAX),
        title: fit(source.title.as_deref(), TITLE_MAX),
        department: fit(source.department.as_deref(), TITLE_MAX),
        dropped,
    }
}

#[cfg(test)]
mod tests {
    use super::super::provider::SourcePhone;
    use super::*;

    fn source() -> SourceContact {
        SourceContact {
            external_id: "people/c1".into(),
            etag: Some("etag-1".into()),
            display_name: None,
            given_name: None,
            family_name: None,
            emails: vec![],
            phones: vec![],
            organization: None,
            title: None,
            department: None,
            group_ids: vec![],
            photo_url: None,
            deleted: false,
        }
    }

    fn phone(number: &str, canonical: Option<&str>, label: &str, primary: bool) -> SourcePhone {
        SourcePhone {
            number: number.into(),
            canonical: canonical.map(Into::into),
            label: Some(label.into()),
            is_primary: primary,
        }
    }

    /// The decided policy: primary email wins, the rest are dropped and said
    /// to be.
    #[test]
    fn the_primary_email_wins_and_the_rest_are_counted_as_dropped() {
        let mut s = source();
        s.given_name = Some("Ada".into());
        s.emails = vec![
            "ada@work.example".into(),
            "ada@home.example".into(),
            "a@x.example".into(),
        ];
        let m = map_contact(&s);
        assert_eq!(m.email.as_deref(), Some("ada@work.example"));
        assert!(
            m.dropped.iter().any(|d| d.contains("2 additional email")),
            "{:?}",
            m.dropped
        );
    }

    /// Several phones all survive, typed, with exactly one primary.
    #[test]
    fn every_phone_is_kept_typed_with_one_primary() {
        let mut s = source();
        s.given_name = Some("Ada".into());
        s.phones = vec![
            phone("(415) 555-1234", Some("+14155551234"), "work", false),
            phone("415 555 9999", None, "mobile", true),
            phone("+1 415 555 0000", None, "workFax", false),
            phone("+1 415 555 1234", None, "home", false),
        ];
        let m = map_contact(&s);
        assert_eq!(
            m.phones.len(),
            3,
            "the duplicate of the work number collapses: {:?}",
            m.phones
        );
        assert_eq!(
            m.phones[0].number, "+14155551234",
            "the canonical form is preferred"
        );
        assert_eq!(m.phones[0].phone_type, MappedPhoneType::Work);
        assert_eq!(m.phones[1].phone_type, MappedPhoneType::Mobile);
        assert_eq!(m.phones[2].phone_type, MappedPhoneType::Fax);
        assert_eq!(m.phones.iter().filter(|p| p.is_primary).count(), 1);
        assert!(m.phones[1].is_primary, "the source's own primary is kept");
    }

    /// A national number with no canonical form and a leading zero cannot be
    /// stored, so it is dropped and said to be - never a failed contact.
    #[test]
    fn an_unstorable_number_is_dropped_not_fatal() {
        let mut s = source();
        s.given_name = Some("Ada".into());
        s.phones = vec![phone("0412 345 678", None, "mobile", true)];
        let m = map_contact(&s);
        assert!(m.phones.is_empty());
        assert!(
            m.dropped.iter().any(|d| d.contains("unstorable phone")),
            "{:?}",
            m.dropped
        );
    }

    /// A single-name person keeps their whole name, rather than having one
    /// guessed apart.
    #[test]
    fn a_single_name_is_kept_whole() {
        let mut s = source();
        s.display_name = Some("Björk".into());
        let m = map_contact(&s);
        assert_eq!((m.first_name.as_str(), m.last_name.as_str()), ("Björk", ""));

        let mut s = source();
        s.given_name = Some("Prince".into());
        let m = map_contact(&s);
        assert_eq!(
            (m.first_name.as_str(), m.last_name.as_str()),
            ("Prince", "")
        );
    }

    #[test]
    fn a_non_latin_name_is_kept_exactly() {
        let mut s = source();
        s.given_name = Some("小龙".into());
        s.family_name = Some("李".into());
        let m = map_contact(&s);
        assert_eq!(
            (m.first_name.as_str(), m.last_name.as_str()),
            ("小龙", "李")
        );
    }

    /// No name at all falls back visibly, never to an invented person.
    #[test]
    fn a_nameless_record_falls_back_visibly() {
        let mut s = source();
        s.organization = Some("Acme Ltd".into());
        assert_eq!(map_contact(&s).first_name, "Acme Ltd");

        let mut s = source();
        s.emails = vec!["billing@acme.example".into()];
        assert_eq!(map_contact(&s).first_name, "billing@acme.example");

        assert_eq!(map_contact(&source()).first_name, "(no name)");
    }

    #[test]
    fn a_contact_with_no_email_maps_to_none() {
        let mut s = source();
        s.given_name = Some("Ada".into());
        assert_eq!(map_contact(&s).email, None);
    }

    /// A long multi-byte value is cut at a character boundary and fits its
    /// column.
    #[test]
    fn values_fit_their_columns_without_splitting_a_character() {
        let mut s = source();
        s.given_name = Some("é".repeat(150));
        let m = map_contact(&s);
        assert_eq!(m.first_name.chars().count(), NAME_MAX);
    }

    /// The organisation is free text on the contact, never a company id.
    #[test]
    fn the_organisation_is_free_text() {
        let mut s = source();
        s.given_name = Some("Ada".into());
        s.organization = Some("  Acme Ltd ".into());
        assert_eq!(map_contact(&s).company_name.as_deref(), Some("Acme Ltd"));
    }

    /// `storable_phone` agrees with the validator Mokosh stores phones under.
    /// The two are separate code, so they are compared rather than trusted.
    #[test]
    fn storable_phone_agrees_with_the_contact_validator() {
        use validator::Validate;
        for raw in [
            "+14155551234",
            "4155551234",
            "0412345678",
            "+0412",
            "12",
            "+1 (415) 555-1234",
            "abc",
        ] {
            let input: mokosh_types::contacts::ContactPhoneInput =
                serde_json::from_value(serde_json::json!({ "number": raw })).expect("parse");
            let accepted_by_validator = input.validate().is_ok() && input.number.is_some();
            assert_eq!(
                storable_phone(raw).is_some(),
                accepted_by_validator,
                "{raw:?}: storable_phone and the contact validator disagree"
            );
        }
    }
}
