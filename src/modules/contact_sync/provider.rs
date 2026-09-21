//! PMS-1211 (PSA-70 phase 1): the seam an external contact directory is read
//! through.
//!
//! ONE interface with ONE implementation, the `RmmProvider` shape (PMS-966),
//! not a plugin system. It exists because Microsoft 365 contacts (PSA-11) is
//! the next provider and the schema, the matching, the review queue and the
//! sync worker should not have to change to take it. Everything provider-
//! specific - the field mask, the pagination, the sync-token semantics - lives
//! behind here; everything above it works in [`SourceContact`].
//!
//! # One canonical contact model (PMS-1288)
//!
//! [`SourceContact`] is the ONE shape every source normalizes into, and it is
//! shaped after vCard (RFC 6350) because that is the contact standard the
//! other sources approximate: Google's People API through `google`, an
//! uploaded `.vcf` file, and later CardDAV (whose payload IS vCard) and
//! Microsoft 365. There is then exactly one canonical-to-Mokosh mapping
//! (`mapping::map_contact`) and one matching and review pipeline (`matching`,
//! `sync`), so a rule decided once - primary email wins, phones typed, an
//! organisation is a suggestion and never a company - holds for every source
//! without a second copy that could drift.
//!
//! | vCard property | Field | Google People field |
//! |---|---|---|
//! | `UID` (else the provider's own id) | [`SourceContact::external_id`] | `resourceName` |
//! | `REV`, a DAV `getetag`, or a content hash | [`SourceContact::etag`] | `etag` |
//! | `FN` | [`SourceContact::display_name`] | `names[].displayName` |
//! | `N` (given; family) | [`SourceContact::given_name`], [`SourceContact::family_name`] | `names[].givenName`, `familyName` |
//! | `EMAIL` | [`SourceContact::emails`] | `emailAddresses[]` |
//! | `TEL` | [`SourceContact::phones`] | `phoneNumbers[]` |
//! | `ORG` (first unit; second unit) | [`SourceContact::organization`], [`SourceContact::department`] | `organizations[].name`, `department` |
//! | `TITLE` | [`SourceContact::title`] | `organizations[].title` |
//! | `CATEGORIES` | [`SourceContact::group_ids`] | `memberships[]` |
//! | `NOTE` | [`SourceContact::note`] | not read: `biographies` is outside the field mask |
//! | `PHOTO` | [`SourceContact::photo`] | not read: `photos` is outside the field mask |
//! | `ADR`, `BDAY`, `URL`, and the rest | [`SourceContact::dropped_properties`] | outside the field mask |
//!
//! Google's `biographies` stays outside the mask on purpose. A sync token is
//! only redeemable with the mask that minted it, so widening the mask would
//! put every live connection's stored token in front of a refusal the client
//! does not classify as an expiry.
//!
//! # One-way, at the permission level
//!
//! There is no write method on this trait, and there will not be one. The
//! OAuth scope this integration requests is `contacts.readonly` (PMS-1212), so
//! Mokosh cannot alter somebody's address book even by mistake. A future
//! provider that needs write access is a different trait and a different
//! consent screen, not an extra method here.

use async_trait::async_trait;

use crate::utils::error::AppError;

/// The provider discriminators this build can read, as
/// `contact_sync_connections.provider` stores them.
///
/// The narrow, honest list, the way `billing::provider::SUPPORTED` is: the
/// column's CHECK and this constant are two statements of the same fact, and a
/// connection naming anything else cannot be built.
pub const SUPPORTED: &[&str] = &["google"];

/// Whether [`build`] can produce a provider for this discriminator.
pub fn is_supported(provider: &str) -> bool {
    SUPPORTED.contains(&provider)
}

/// One contact group or label, for the opt-in selection (PSA-70 E).
///
/// `member_count` is what the preview counts against, so a person choosing
/// "Clients" knows they are importing 40 records and not 2,000.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceGroup {
    /// The provider's own id for the group.
    pub id: String,
    pub name: String,
    pub member_count: Option<u32>,
}

/// One typed phone number as the source holds it.
///
/// Typed because Mokosh's `contact_phones` is typed (migration 108), so the
/// type survives the import instead of every number landing as `other`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourcePhone {
    pub number: String,
    /// The source's own E.164 rendering, when it could work one out. Google
    /// supplies `canonicalForm` for numbers whose country it can infer, which
    /// is exactly the case a national-format `value` cannot be stored from.
    pub canonical: Option<String>,
    /// The source's own label, lowercased. Mapped onto Mokosh's closed set by
    /// the mapping layer, which is where an unrecognised label becomes
    /// `other`.
    pub label: Option<String>,
    pub is_primary: bool,
}

/// One email address as the source holds it.
///
/// The address and its label only: which address is primary is carried by
/// ORDER, primary first, because that is what every source can say and the
/// mapping's "primary email wins" rule reads the first entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceEmail {
    pub address: String,
    /// The source's own label, lowercased: a vCard `TYPE=`, an Apple
    /// `X-ABLabel` such as `billing desk`, or Google's `type`. Carried so a
    /// future `contact_emails` table has it; today only the primary address is
    /// kept and its label is not stored.
    pub label: Option<String>,
}

impl From<&str> for SourceEmail {
    fn from(address: &str) -> Self {
        Self {
            address: address.to_string(),
            label: None,
        }
    }
}

impl From<String> for SourceEmail {
    fn from(address: String) -> Self {
        Self {
            address,
            label: None,
        }
    }
}

/// A contact's photo, as a source can describe one.
///
/// Neither variant carries bytes Mokosh keeps, and neither is ever fetched:
/// photos are dropped (PSA-70 F), and a URI a `.vcf` names can point anywhere,
/// so dereferencing it server-side is an SSRF vector (PMS-805). The variant is
/// kept so the preview can say a photo was left behind, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourcePhoto {
    /// A link to the image. Stored as text at most, never requested.
    Uri(String),
    /// Image bytes embedded in the record (a vCard base64 `PHOTO`), already
    /// decoded by the reader and measured; the bytes themselves are not kept.
    Inline {
        media_type: Option<String>,
        byte_len: usize,
    },
}

/// One contact as the source holds it, before any Mokosh policy is applied.
///
/// Deliberately close to the wire and deliberately lossless about what arrived:
/// the single-valued collapse (PSA-70 F, primary email wins) happens in the
/// mapping layer, so the record here still carries what was dropped and a
/// future `contact_emails` table would need no change to this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceContact {
    /// The provider's id. For Google this is the People API `resourceName`,
    /// e.g. `people/c12345`, stored verbatim and never parsed for meaning.
    pub external_id: String,
    /// The provider's version. An unchanged etag is the cheapest possible
    /// "nothing to do", which is half of idempotency (PSA-70 I).
    pub etag: Option<String>,
    /// The source's own display name. Kept because a single-name record
    /// ("Prince", "Björk") has no family name to split into, and guessing one
    /// is how an import mangles a person's name.
    pub display_name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    /// Every email the source holds, in the source's order, primary first.
    /// The collapse to one is the mapping layer's, not this layer's.
    pub emails: Vec<SourceEmail>,
    pub phones: Vec<SourcePhone>,
    /// The source's organisation name. FREE TEXT, and never a company id:
    /// turning it into a `companies` row is a suggestion for a human to
    /// confirm (PSA-70 G), because auto-creating from arbitrary strings fills
    /// a CRM with garbage somebody then has to clean up by hand.
    pub organization: Option<String>,
    pub title: Option<String>,
    pub department: Option<String>,
    /// The groups this contact belongs to, as provider group ids. The opt-in
    /// selection (PSA-70 E) is checked against these.
    pub group_ids: Vec<String>,
    /// Free text about the person (vCard `NOTE`). Untrusted like every
    /// other field: the mapping passes it through the same invisible-character
    /// rule as a request body before it is stored.
    pub note: Option<String>,
    /// The photo the source described, if any. Never fetched; see
    /// [`SourcePhoto`].
    pub photo: Option<SourcePhoto>,
    /// Properties this record carried that have no home in Mokosh, by their
    /// source name (`ADR`, `BDAY`, ...), so the preview can say what an import
    /// leaves behind. A provider that never requests such fields (Google's
    /// mask) leaves it empty and lists them statically instead.
    pub dropped_properties: Vec<String>,
    /// The source says this record is gone. Surfaced, never acted on as a
    /// delete (PSA-70 I).
    pub deleted: bool,
}

/// What one read of the source returned.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SourceChanges {
    pub contacts: Vec<SourceContact>,
    /// The cursor to hand back next time. Absent means the next sync is a full
    /// one.
    pub next_sync_token: Option<String>,
    /// The provider refused the cursor we sent and this is a full snapshot
    /// rather than a delta. Google answers `410 EXPIRED_SYNC_TOKEN`; the
    /// caller must treat the result as the whole truth rather than as changes
    /// (PSA-70 I), which is why it is a flag on the result and not an error.
    pub was_full_resync: bool,
}

/// Why a read of the source failed, by the outcome it means for the
/// connection (PSA-70 J).
///
/// Typed rather than an `AppError` because the three cases are three
/// different `sync_status` values and a caller must not have to read a
/// message to tell them apart: a rate limit is the provider asking us to wait
/// and must never read as a broken integration, and a refused credential is
/// the one state where a human has something to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceError {
    /// Still rate limited or unavailable after the client's own backoff.
    /// Recorded as `throttled`, never `failed`.
    Throttled,
    /// The provider refused the credential. Recorded as `reconnect_required`.
    Unauthorized,
    /// Anything else, in this codebase's own words. Never the provider's
    /// response body, which can echo what was sent.
    Failed(String),
}

impl std::fmt::Display for SourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Throttled => {
                f.write_str("The contact provider is rate limiting this connection.")
            }
            Self::Unauthorized => {
                f.write_str("The contact provider refused this connection's credential.")
            }
            Self::Failed(reason) => f.write_str(reason),
        }
    }
}

impl From<SourceError> for AppError {
    fn from(error: SourceError) -> Self {
        AppError::Integration(error.to_string())
    }
}

pub type SourceResult<T> = Result<T, SourceError>;

/// Read one tenant's contacts from one external directory.
///
/// Read-only by construction: see the module doc.
#[async_trait]
pub trait ContactSyncProvider: Send + Sync {
    /// Matches `contact_sync_connections.provider`.
    fn id(&self) -> &'static str;

    /// The groups an admin can opt into, with counts for the preview.
    async fn list_groups(&self) -> SourceResult<Vec<SourceGroup>>;

    /// Contacts changed since `sync_token`, or everything when it is `None`.
    ///
    /// An expired token is NOT an error: the implementation falls back to a
    /// full read and says so in [`SourceChanges::was_full_resync`]. A sync
    /// that fails because a cursor aged out is a sync that stops working after
    /// a week of quiet.
    ///
    /// A full read is all or nothing. The caller treats absence from a full
    /// read as deletion in the source, so an implementation that returns the
    /// pages it managed to fetch before an error would tombstone every contact
    /// on the pages it did not.
    async fn changes_since(&self, sync_token: Option<&str>) -> SourceResult<SourceChanges>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The migration's CHECK and [`SUPPORTED`] are two statements of one fact,
    /// in two files that no compiler relates. A provider added to the column
    /// and not here is a connection row nothing can read; added here and not
    /// to the column, it is a row that cannot be written. Both have shipped in
    /// this codebase before (PMS-966), so the guard reads the migration.
    #[test]
    fn the_supported_list_matches_the_migration_check() {
        const MIGRATION: &str = include_str!("../../../migrations/220_contact_sync.sql");
        let check = MIGRATION
            .split("provider VARCHAR(32) NOT NULL CHECK (provider IN (")
            .nth(1)
            .and_then(|rest| rest.split("))").next())
            .expect("the connection table CHECKs its provider column");
        let allowed: Vec<String> = check
            .split(',')
            .map(|v| v.trim().trim_matches('\'').to_string())
            .filter(|v| !v.is_empty())
            .collect();
        let mut expected: Vec<String> = SUPPORTED.iter().map(|p| p.to_string()).collect();
        expected.sort();
        let mut allowed_sorted = allowed.clone();
        allowed_sorted.sort();
        assert_eq!(
            allowed_sorted, expected,
            "the migration allows {allowed:?} but this build serves {SUPPORTED:?}"
        );
    }

    /// Nothing outside the list is servable, so a stored row naming one cannot
    /// be silently skipped.
    #[test]
    fn an_unknown_provider_is_not_supported() {
        for unknown in ["microsoft", "icloud", "", "Google"] {
            assert!(!is_supported(unknown), "{unknown:?} must not be supported");
        }
    }
}
