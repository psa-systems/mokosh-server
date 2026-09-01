//! PMS-911: the MSP's identity on a document a client receives, and the copy of
//! it an invoice keeps.
//!
//! An invoice carries the identity of the MSP that issued it, not the
//! platform's. Those values live in `tenants.branding`, which is a live
//! document an operator edits, so resolving them when the PDF is rendered would
//! mean an invoice sent last quarter reprints under this quarter's name,
//! address and tax number. That contradicts the rule PMS-953 established: once
//! an invoice is frozen the customer holds a copy of it, and the only
//! correction is a credit note.
//!
//! So the values are copied onto the invoice at the moment it freezes and read
//! back from there afterwards.
//!
//! ## When the copy is taken
//!
//! At the first transition to `sent`, in the same transaction that stamps
//! `sent_at`. Not at "issue time", because an invoice has no `issued` status:
//! `InvoiceStatus::is_frozen` starts at `sent` and `issued` belongs to credit
//! notes. And not in the post-commit `just_sent` hook beside it, which is
//! best-effort by design so a Pay Now mail failure cannot undo a status change:
//! hanging the snapshot there would let an invoice freeze carrying no identity
//! at all, which is the one state this module exists to prevent.
//!
//! ## Why the logo is bytes and not a URL
//!
//! The live logo is stored under one key per tenant and overwritten on replace,
//! so a snapshot holding its address would re-render with whatever mark is
//! current: replacing a logo would silently change every invoice already sent.
//! The snapshot therefore copies the bytes to a content-addressed object
//! (`ObjectKind::BrandingLogo`) and holds the digest. One object is shared by
//! every invoice sent while that logo was current, so this costs one copy per
//! distinct logo rather than one per invoice.
//!
//! ## Resolved, not read field by field
//!
//! [`resolve`] takes a tenant row and produces the whole identity, including
//! the fallbacks. Everything downstream reads a resolved value, which is what
//! keeps this working if the branding a document should carry ever stops being
//! the tenant's own: a per-company override resolver would replace this
//! function and change nothing about what a snapshot holds or how it is read.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use mokosh_types::tenants::TenantBranding;

use crate::modules::tenants::logo::TenantLogoStore;
use crate::storage::{LocalStore, ObjectKey, ObjectStore};
use crate::utils::error::AppResult;

/// The issuing MSP, as a document shows it.
///
/// Every field optional: an MSP that has filled nothing in still gets a valid
/// invoice with its tenant name on it, which is an explicit acceptance
/// criterion rather than a convenience.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Issuer {
    /// The registered entity, falling back to the trading name and then to the
    /// tenant's own name, so this is never empty on a resolved value.
    pub name: String,
    /// The trading name, when it differs from [`Self::name`] and is worth
    /// showing beside it.
    pub trading_name: Option<String>,
    pub postal_address: Option<String>,
    pub tax_id: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub website: Option<String>,
    /// A digest of the logo's bytes, naming a `BrandingLogo` object. Present
    /// only on a snapshot: [`resolve`] does not copy anything.
    pub logo_digest: Option<String>,
    pub logo_mime: Option<String>,
}

/// Compose the identity a document should show for this tenant, right now.
///
/// The fallback chain is the acceptance criterion about an MSP with nothing
/// filled in: `legal_name`, then `company_name`, then the tenant's own name.
pub fn resolve(tenant_name: &str, branding: &TenantBranding) -> Issuer {
    let legal = clean(branding.legal_name.as_deref());
    let trading = clean(branding.company_name.as_deref());
    let name = legal
        .clone()
        .or_else(|| trading.clone())
        .unwrap_or_else(|| tenant_name.to_string());
    Issuer {
        // Only worth a second line when it says something the first does not.
        trading_name: trading.filter(|t| *t != name),
        name,
        postal_address: clean(branding.postal_address.as_deref()),
        tax_id: clean(branding.tax_id.as_deref()),
        email: clean(branding.support_email.as_deref()),
        phone: clean(branding.support_phone.as_deref()),
        website: clean(branding.website.as_deref()),
        logo_digest: None,
        logo_mime: clean(branding.logo_mime.as_deref()),
    }
}

/// Freeze the identity, copying the logo so it cannot change underneath.
///
/// The object write happens before the caller's transaction commits. A rollback
/// therefore leaves the copy behind, which is deduplicated litter rather than a
/// problem: it is content-addressed, so the next successful snapshot of the
/// same logo writes the same key and the row that references it is the only
/// thing that decides whether it is reachable.
///
/// A logo that cannot be read is not fatal. The snapshot keeps every text value
/// and drops the mark, which is the same trade the renderer makes for an image
/// that will not decode: withholding an invoice over its decoration is worse
/// than sending one without it.
pub async fn freeze(
    tenant_id: Uuid,
    tenant_name: &str,
    branding: &TenantBranding,
    logos: &TenantLogoStore,
) -> Issuer {
    let mut issuer = resolve(tenant_name, branding);
    let Some(mime) = issuer.logo_mime.clone() else {
        return issuer;
    };
    match copy_logo(tenant_id, &mime, logos).await {
        Ok(digest) => issuer.logo_digest = Some(digest),
        Err(e) => {
            tracing::warn!(
                tenant_id = %tenant_id,
                error = %e,
                "PMS-911: could not freeze the logo; the invoice keeps its text identity"
            );
            issuer.logo_mime = None;
        }
    }
    issuer
}

async fn copy_logo(tenant_id: Uuid, mime: &str, logos: &TenantLogoStore) -> AppResult<String> {
    let bytes = logos.read(tenant_id, mime).await?;
    let digest = hex(&<Sha256 as Digest>::digest(&bytes));
    let store = LocalStore::from_env();
    let key = ObjectKey::branding_logo(tenant_id, &digest);
    // Idempotent by construction: the same bytes give the same key, so a second
    // invoice sent under the same logo rewrites the identical object rather
    // than adding one.
    store.put(&key, &bytes).await?;
    Ok(digest)
}

/// Read back a frozen logo. `None` for an invoice whose snapshot carries none,
/// and for one whose copy has gone missing, because a document without its mark
/// is still the document.
pub async fn logo_bytes(tenant_id: Uuid, issuer: &Issuer) -> Option<Vec<u8>> {
    let digest = issuer.logo_digest.as_deref()?;
    let store = LocalStore::from_env();
    store
        .read(&ObjectKey::branding_logo(tenant_id, digest))
        .await
        .ok()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn clean(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn branding() -> TenantBranding {
        TenantBranding {
            company_name: Some("Acme IT".into()),
            legal_name: Some("Acme IT Services Pty Ltd".into()),
            postal_address: Some("12 Example St\nSydney NSW 2000".into()),
            tax_id: Some("ABN 12 345 678 901".into()),
            support_email: Some("billing@acme.example".into()),
            support_phone: Some("555-0100".into()),
            website: Some("https://acme.example".into()),
            ..Default::default()
        }
    }

    /// An invoice carries the registered entity, with the trading name beside
    /// it when the two differ.
    #[test]
    fn the_legal_name_is_what_an_invoice_leads_with() {
        let issuer = resolve("acme", &branding());
        assert_eq!(issuer.name, "Acme IT Services Pty Ltd");
        assert_eq!(issuer.trading_name.as_deref(), Some("Acme IT"));
    }

    /// And an MSP trading under its registered name does not get it printed
    /// twice.
    #[test]
    fn a_trading_name_that_says_nothing_new_is_dropped() {
        let mut b = branding();
        b.legal_name = Some("Acme IT".into());
        assert_eq!(resolve("acme", &b).trading_name, None);
    }

    /// The acceptance criterion about an MSP that has filled nothing in: it
    /// still gets an identity, so it still gets a valid invoice.
    #[test]
    fn an_empty_record_still_names_the_issuer() {
        let issuer = resolve("Acme IT", &TenantBranding::default());
        assert_eq!(issuer.name, "Acme IT");
        assert_eq!(issuer.trading_name, None);
        assert_eq!(issuer.logo_digest, None);
        assert_eq!(issuer.tax_id, None);
    }

    /// Blank is unset. An operator who clears a field in a UI that sends `""`
    /// must not get an empty line printed on an invoice.
    #[test]
    fn a_blank_value_is_not_a_value() {
        let mut b = branding();
        b.tax_id = Some("   ".into());
        b.legal_name = Some("".into());
        let issuer = resolve("acme", &b);
        assert_eq!(issuer.tax_id, None);
        assert_eq!(
            issuer.name, "Acme IT",
            "a blank legal name falls through to the trading name"
        );
    }

    /// `resolve` copies nothing. Only `freeze` touches storage, which is what
    /// lets the live-branding render path stay free of side effects.
    #[test]
    fn resolving_never_produces_a_digest() {
        let mut b = branding();
        b.logo_mime = Some("image/png".into());
        let issuer = resolve("acme", &b);
        assert_eq!(issuer.logo_digest, None);
        assert_eq!(issuer.logo_mime.as_deref(), Some("image/png"));
    }
}
