//! PMS-1524: which tenant-wide switch a contact-sync provider answers to.
//!
//! Each provider has its own key - `integrations/google_contacts_enabled`
//! (PSA-70 K), `integrations/icloud_contacts_enabled` (PMS-1341),
//! `integrations/microsoft_contacts_enabled` (PMS-1512) - because an MSP that
//! turns one integration off has not turned the others off.
//!
//! The SELECTION between those keys was written twice and about to be written a
//! third time. [`super::service::ContactSyncService::assert_enabled`] picks the
//! key when a sync is REQUESTED and had all three; [`super::runs`] picks it
//! again before a queued run is EXECUTED, was updated by PMS-1341 for iCloud and
//! not by PMS-1512 for Microsoft 365, and sent every Microsoft run to Google's
//! key. So an MSP who turned Microsoft 365 off kept syncing from it, and one who
//! turned Google off had their Microsoft runs cancelled with a message naming
//! Microsoft.
//!
//! One function, so the next provider's key is added in one place and a caller
//! cannot inherit another provider's answer by falling through an `else`.
//!
//! Unset is enabled, which each reader decides for its own key: an MSP who has
//! never opened the setting has not turned the integration off.

use crate::db::Database;
use crate::modules::auth::TenantId;
use crate::modules::settings::{
    read_google_contacts_enabled, read_icloud_contacts_enabled, read_microsoft_contacts_enabled,
};
use crate::utils::error::{AppError, AppResult};

use super::icloud::ICLOUD;
use super::service::{GOOGLE, MICROSOFT};

/// Whether this tenant has `provider`'s contact sync switched on.
///
/// Exhaustive over the three providers that have a switch rather than
/// defaulting, because the default WAS the defect: `vcard` has no tenant-wide
/// switch (an uploaded file is one import, gated by the upload), and a provider
/// name this build does not know is a caller bug, not a reason to answer for
/// Google.
pub async fn contacts_enabled(
    db: &Database,
    tenant_id: TenantId,
    provider: &str,
) -> AppResult<bool> {
    match provider {
        GOOGLE => read_google_contacts_enabled(db, tenant_id).await,
        ICLOUD => read_icloud_contacts_enabled(db, tenant_id).await,
        MICROSOFT => read_microsoft_contacts_enabled(db, tenant_id).await,
        other => Err(AppError::Internal(format!(
            "{other} has no contact-sync switch, so nothing can be read for it"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The three providers with a switch are exactly the three the shared
    /// routes accept (`ProviderQuery::resolve`), and `vcard` is not one of
    /// them.
    ///
    /// A pure check on the names, because the branch that reads the database is
    /// covered by the suite. What this pins is the thing that broke: a fourth
    /// provider added to the routes without a key here must not quietly read
    /// Google's.
    #[test]
    fn every_provider_with_a_switch_is_named_and_vcard_is_not() {
        let named = [GOOGLE, ICLOUD, MICROSOFT];
        let mut unique = named.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), named.len(), "two providers share a name");
        assert!(
            !named.contains(&super::super::file_import::VCARD),
            "an uploaded file is gated by its upload, not by a tenant-wide switch"
        );
    }
}
