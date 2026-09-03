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
}
