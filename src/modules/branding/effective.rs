//! MAPPS-617 (mokosh-branding prompt 001): tenant + Company brand merge.
//!
//! The contact portal paints an `EffectiveBranding` for a given
//! (tenant, company) tuple. The rule is a per-field
//! `company.field.or(tenant.field)` fold: every non-`None` Company key
//! wins over the tenant key. Missing on both sides stays `None`, and
//! the SPA supplies the coded fallback (a "no logo" placeholder, the
//! wordmark "Mokosh Platform", the default color scheme).
//!
//! The resolver is a pure function so the plumbing can unit-test it
//! without a DB, and so the sqlx service methods that hand it (tenant,
//! company) tuples stay free of merge policy. Callers are the
//! contact-portal `/host` handler (MAPPS-617 changes) and the three
//! contact-auth endpoints (`login`, `refresh`, `me`) that fold
//! `EffectiveBranding` into their existing response bodies.

use mokosh_types::contacts::CompanyBranding;
use mokosh_types::tenants::{EffectiveBranding, TenantBranding};

/// Merge a tenant's default brand with a Company's override brand.
///
/// Every non-`None` Company field wins over the tenant field. A field
/// that is `None` on both sides stays `None` in the result.
///
/// Pure; no I/O.
pub fn effective_branding(tenant: &TenantBranding, company: &CompanyBranding) -> EffectiveBranding {
    EffectiveBranding {
        logo_url: company.logo_url.clone().or_else(|| tenant.logo_url.clone()),
        logo_mime: company
            .logo_mime
            .clone()
            .or_else(|| tenant.logo_mime.clone()),
        favicon_url: company
            .favicon_url
            .clone()
            .or_else(|| tenant.favicon_url.clone()),
        favicon_mime: company
            .favicon_mime
            .clone()
            .or_else(|| tenant.favicon_mime.clone()),
        primary_color: company
            .primary_color
            .clone()
            .or_else(|| tenant.primary_color.clone()),
        secondary_color: company
            .secondary_color
            .clone()
            .or_else(|| tenant.secondary_color.clone()),
        background_color: company
            .background_color
            .clone()
            .or_else(|| tenant.background_color.clone()),
        background_url: company
            .background_url
            .clone()
            .or_else(|| tenant.background_url.clone()),
        background_mime: company
            .background_mime
            .clone()
            .or_else(|| tenant.background_mime.clone()),
        display_name: company
            .display_name
            .clone()
            .or_else(|| tenant.display_name.clone()),
        company_name: company
            .company_name
            .clone()
            .or_else(|| tenant.company_name.clone()),
        support_email: company
            .support_email
            .clone()
            .or_else(|| tenant.support_email.clone()),
        support_phone: company
            .support_phone
            .clone()
            .or_else(|| tenant.support_phone.clone()),
        support_contact_name: company
            .support_contact_name
            .clone()
            .or_else(|| tenant.support_contact_name.clone()),
        portal_domain: company
            .portal_domain
            .clone()
            .or_else(|| tenant.portal_domain.clone()),
    }
}

/// MAPPS-807: the brand a CUSTOMER is shown, which always names the MSP.
///
/// [`effective_branding`] carries a name only when somebody typed one into the
/// optional `display_name` / `company_name` fields, and the client falls back
/// to the vendor's product name when both are absent. So the portal sign-in
/// page read "Mokosh Platform" under the MSP's own logo, and the "not shared
/// with you" screen and the read-only profile said "your provider", while every
/// email the same MSP sent said "Niceguy IT": `OrgIdentity::name()` uses the
/// organization's own name, `tenants.name`, which onboarding requires.
///
/// This fills `company_name` with that name when neither side set a name, so
/// the portal names the MSP exactly as its emails do. A configured
/// `display_name` or `company_name`, on the company or the tenant, still wins.
///
/// Only for what a customer sees. The brand editor keeps [`effective_branding`]
/// for its preview, because a synthesized name there would read as a value
/// somebody configured.
pub fn customer_branding(
    tenant: &TenantBranding,
    company: &CompanyBranding,
    organization_name: &str,
) -> EffectiveBranding {
    let mut brand = effective_branding(tenant, company);
    let named = |v: &Option<String>| v.as_deref().is_some_and(|s| !s.trim().is_empty());
    if !named(&brand.display_name) && !named(&brand.company_name) {
        let organization_name = organization_name.trim();
        if !organization_name.is_empty() {
            brand.company_name = Some(organization_name.to_string());
        }
    }
    brand
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tenant_full() -> TenantBranding {
        TenantBranding {
            logo_url: Some("t/logo.png".into()),
            logo_mime: Some("image/png".into()),
            favicon_url: Some("t/fav.png".into()),
            favicon_mime: Some("image/png".into()),
            primary_color: Some("#111111".into()),
            secondary_color: Some("#222222".into()),
            background_color: Some("#333333".into()),
            background_url: Some("t/bg.png".into()),
            background_mime: Some("image/png".into()),
            display_name: Some("Acme MSP".into()),
            company_name: Some("Acme".into()),
            support_email: Some("help@acme.example".into()),
            support_phone: Some("+15555550100".into()),
            support_contact_name: Some("Alice".into()),
            portal_domain: Some("portal.acme.example".into()),
            ..Default::default()
        }
    }

    fn company_full() -> CompanyBranding {
        CompanyBranding {
            logo_url: Some("c/logo.png".into()),
            logo_mime: Some("image/webp".into()),
            favicon_url: Some("c/fav.png".into()),
            favicon_mime: Some("image/webp".into()),
            primary_color: Some("#aaaaaa".into()),
            secondary_color: Some("#bbbbbb".into()),
            background_color: Some("#cccccc".into()),
            background_url: Some("c/bg.png".into()),
            background_mime: Some("image/webp".into()),
            display_name: Some("Widgets Inc portal".into()),
            company_name: Some("Widgets Inc".into()),
            support_email: Some("it@widgets.example".into()),
            support_phone: Some("+15555550200".into()),
            support_contact_name: Some("Bob".into()),
            portal_domain: Some("portal.widgets.example".into()),
        }
    }

    #[test]
    fn tenant_only_wins_when_company_empty() {
        let out = effective_branding(&tenant_full(), &CompanyBranding::default());
        assert_eq!(out.logo_url.as_deref(), Some("t/logo.png"));
        assert_eq!(out.primary_color.as_deref(), Some("#111111"));
        assert_eq!(out.display_name.as_deref(), Some("Acme MSP"));
        assert_eq!(out.support_email.as_deref(), Some("help@acme.example"));
    }

    #[test]
    fn company_only_wins_when_tenant_empty() {
        let out = effective_branding(&TenantBranding::default(), &company_full());
        assert_eq!(out.logo_url.as_deref(), Some("c/logo.png"));
        assert_eq!(out.primary_color.as_deref(), Some("#aaaaaa"));
        assert_eq!(out.display_name.as_deref(), Some("Widgets Inc portal"));
        assert_eq!(out.support_email.as_deref(), Some("it@widgets.example"));
    }

    #[test]
    fn company_full_wins_over_tenant_full_field_by_field() {
        let out = effective_branding(&tenant_full(), &company_full());
        // Every field is the Company value, not the tenant value.
        assert_eq!(out.logo_url.as_deref(), Some("c/logo.png"));
        assert_eq!(out.logo_mime.as_deref(), Some("image/webp"));
        assert_eq!(out.favicon_url.as_deref(), Some("c/fav.png"));
        assert_eq!(out.primary_color.as_deref(), Some("#aaaaaa"));
        assert_eq!(out.secondary_color.as_deref(), Some("#bbbbbb"));
        assert_eq!(out.background_color.as_deref(), Some("#cccccc"));
        assert_eq!(out.background_url.as_deref(), Some("c/bg.png"));
        assert_eq!(out.display_name.as_deref(), Some("Widgets Inc portal"));
        assert_eq!(out.company_name.as_deref(), Some("Widgets Inc"));
        assert_eq!(out.support_email.as_deref(), Some("it@widgets.example"));
        assert_eq!(out.support_phone.as_deref(), Some("+15555550200"));
        assert_eq!(out.support_contact_name.as_deref(), Some("Bob"));
        assert_eq!(out.portal_domain.as_deref(), Some("portal.widgets.example"));
    }

    #[test]
    fn neither_side_leaves_every_field_none() {
        let out = effective_branding(&TenantBranding::default(), &CompanyBranding::default());
        assert_eq!(out, EffectiveBranding::default());
    }

    #[test]
    fn single_field_override_leaves_others_from_tenant() {
        let co = CompanyBranding {
            primary_color: Some("#deadbeef".into()),
            ..CompanyBranding::default()
        };
        let out = effective_branding(&tenant_full(), &co);
        // Overridden field wins.
        assert_eq!(out.primary_color.as_deref(), Some("#deadbeef"));
        // Every other field still comes from the tenant.
        assert_eq!(out.logo_url.as_deref(), Some("t/logo.png"));
        assert_eq!(out.secondary_color.as_deref(), Some("#222222"));
        assert_eq!(out.display_name.as_deref(), Some("Acme MSP"));
        assert_eq!(out.support_email.as_deref(), Some("help@acme.example"));
    }

    /// PMS-1197: `EffectiveBranding` is the merge of `TenantBranding` and
    /// `CompanyBranding`, and both are written through
    /// `validate_branding_patch` / `validate_company_branding_patch`
    /// (`crate::modules::tenants::branding`). A field read here that table
    /// has never validated is a key a third branding surface could write
    /// unchecked and have it show up in what a client is shown, which is
    /// exactly the regression this issue closes.
    #[test]
    fn every_field_effective_branding_reads_is_a_known_branding_key() {
        use crate::modules::tenants::branding::KNOWN_KEYS;
        let fields = [
            "logo_url",
            "logo_mime",
            "favicon_url",
            "favicon_mime",
            "primary_color",
            "secondary_color",
            "background_color",
            "background_url",
            "background_mime",
            "display_name",
            "company_name",
            "support_email",
            "support_phone",
            "support_contact_name",
            "portal_domain",
        ];
        for field in fields {
            assert!(
                KNOWN_KEYS.contains(&field),
                "EffectiveBranding reads `{field}` but it is not in validate_branding_patch's KNOWN_KEYS"
            );
        }
    }

    /// MAPPS-807: with no name configured anywhere, a customer sees the
    /// organization's name - the one its emails already use - rather than
    /// nothing, which the client rendered as the vendor's product name.
    #[test]
    fn a_customer_sees_the_organization_name_when_none_is_configured() {
        let out = customer_branding(
            &TenantBranding::default(),
            &CompanyBranding::default(),
            "Niceguy IT",
        );
        assert_eq!(out.company_name.as_deref(), Some("Niceguy IT"));
        assert_eq!(out.display_name, None, "display_name is not invented");
    }

    /// A name somebody configured always wins, on either side and in either
    /// field.
    #[test]
    fn a_configured_name_is_never_overridden() {
        let tenant = TenantBranding {
            display_name: Some("Niceguy Support".into()),
            ..TenantBranding::default()
        };
        let out = customer_branding(&tenant, &CompanyBranding::default(), "Niceguy IT");
        assert_eq!(out.display_name.as_deref(), Some("Niceguy Support"));
        assert_eq!(out.company_name, None);

        let company = CompanyBranding {
            company_name: Some("Acme Portal".into()),
            ..CompanyBranding::default()
        };
        let out = customer_branding(&TenantBranding::default(), &company, "Niceguy IT");
        assert_eq!(out.company_name.as_deref(), Some("Acme Portal"));
    }

    /// A blank configured name is no name, so it is filled; a blank
    /// organization name fills nothing rather than a blank.
    #[test]
    fn blanks_are_treated_as_absent() {
        let tenant = TenantBranding {
            display_name: Some("   ".into()),
            ..TenantBranding::default()
        };
        let out = customer_branding(&tenant, &CompanyBranding::default(), "Niceguy IT");
        assert_eq!(out.company_name.as_deref(), Some("Niceguy IT"));

        let out = customer_branding(
            &TenantBranding::default(),
            &CompanyBranding::default(),
            "  ",
        );
        assert_eq!(out.company_name, None);
    }

    /// Everything else about the brand is exactly the plain resolver's.
    #[test]
    fn nothing_but_the_name_changes() {
        let plain = effective_branding(&tenant_full(), &company_full());
        let customer = customer_branding(&tenant_full(), &company_full(), "Niceguy IT");
        assert_eq!(plain, customer, "a fully configured brand is untouched");
    }
}
