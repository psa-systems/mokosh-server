//! mokosh-contact-login prompt 002: portal capability names.
//!
//! Contact roles hold an array of these (as TEXT[] in
//! `portal_roles.capabilities`); the contact session JWT carries the
//! union in its `caps` claim; every gated route + UI element checks
//! membership against the union. `ALL_CAPABILITIES` is the canonical
//! set the MSP admin's role editor exposes as checkboxes (prompt 007)
//! and `PortalRoleService::create_role` validates against - unknown
//! capability strings fail-closed at create-time so the DB never
//! carries garbage that would silently disable a permission check.
//!
//! Naming convention: `<domain>:<action>`. `<domain>` matches the
//! mokosh-workspace tab it gates (tickets, invoices, quotes,
//! contracts, assets, projects, kb, forms, notifications, settings,
//! contacts). `<action>` is `read`, `write`, `comment`, `pay`,
//! `accept`, `submit`, `manage_own`, `invite_sub_user`,
//! `manage_sub_user` - the surface of things a contact can request
//! from the mokosh workspace. Never grants `companies:*` or
//! `contacts:create`: those stay staff-only by construction.

/// See tickets in the mokosh workspace scoped to the contact's own Company.
pub const TICKETS_READ: &str = "tickets:read";
/// Open a new ticket. Server sets `created_by_contact_id` on the row.
pub const TICKETS_WRITE: &str = "tickets:write";
/// Post a public comment on an existing ticket. Cannot post internal notes.
pub const TICKETS_COMMENT: &str = "tickets:comment";

/// View invoices scoped to the contact's own Company.
pub const INVOICES_READ: &str = "invoices:read";
/// Trigger a payment checkout (Stripe / Paddle) for an outstanding invoice.
pub const INVOICES_PAY: &str = "invoices:pay";

/// View quotes scoped to the contact's own Company.
pub const QUOTES_READ: &str = "quotes:read";
/// Accept or decline a quote on behalf of the Company.
pub const QUOTES_ACCEPT: &str = "quotes:accept";

/// View contracts scoped to the contact's own Company.
pub const CONTRACTS_READ: &str = "contracts:read";
/// View assets (CIs) scoped to the contact's own Company.
pub const ASSETS_READ: &str = "assets:read";
/// View projects scoped to the contact's own Company.
pub const PROJECTS_READ: &str = "projects:read";
/// Read published Knowledge Base articles visible to the Company.
pub const KB_READ: &str = "kb:read";
/// Submit an MSP-published request form.
pub const FORMS_SUBMIT: &str = "forms:submit";
/// Read notifications addressed to the contact.
pub const NOTIFICATIONS_READ: &str = "notifications:read";
/// Edit own profile + password + MFA + own sessions.
pub const SETTINGS_MANAGE_OWN: &str = "settings:manage_own";

/// Invite a colleague at the same Company (creates a contact + fires
/// the portal setup email). Contact-plane only; never grants
/// `contacts:create` for cross-Company contacts.
pub const CONTACTS_INVITE_SUB_USER: &str = "contacts:invite_sub_user";
/// Manage (assign roles / resend invites / deactivate) sub-user
/// contacts at the same Company. Cannot grant a capability the caller
/// does not themselves hold (server enforces the subset check in
/// prompt 008).
pub const CONTACTS_MANAGE_SUB_USER: &str = "contacts:manage_sub_user";

/// Canonical list of every capability the server + SPA recognise.
/// `PortalRoleService::create_role` validates that every string in a
/// submitted `capabilities` array appears here (fail-closed on
/// unknowns); the role editor UI (prompt 007) renders one checkbox
/// per entry.
///
/// Order matches the mokosh-workspace sidebar grouping so the checkbox
/// picker's default layout reads naturally.
pub const ALL_CAPABILITIES: &[&str] = &[
    TICKETS_READ,
    TICKETS_WRITE,
    TICKETS_COMMENT,
    INVOICES_READ,
    INVOICES_PAY,
    QUOTES_READ,
    QUOTES_ACCEPT,
    CONTRACTS_READ,
    ASSETS_READ,
    PROJECTS_READ,
    KB_READ,
    FORMS_SUBMIT,
    NOTIFICATIONS_READ,
    SETTINGS_MANAGE_OWN,
    CONTACTS_INVITE_SUB_USER,
    CONTACTS_MANAGE_SUB_USER,
];

/// Predicate for validating a role's capability set at write time.
/// Returns `Ok(())` when every entry in `caps` appears in
/// [`ALL_CAPABILITIES`]; returns the first offending value otherwise.
pub fn validate_capabilities(caps: &[String]) -> Result<(), String> {
    for cap in caps {
        if !ALL_CAPABILITIES.iter().any(|k| k == cap) {
            return Err(cap.clone());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_appear_in_all_capabilities() {
        for cap in [
            TICKETS_READ,
            TICKETS_WRITE,
            TICKETS_COMMENT,
            INVOICES_READ,
            INVOICES_PAY,
            QUOTES_READ,
            QUOTES_ACCEPT,
            CONTRACTS_READ,
            ASSETS_READ,
            PROJECTS_READ,
            KB_READ,
            FORMS_SUBMIT,
            NOTIFICATIONS_READ,
            SETTINGS_MANAGE_OWN,
            CONTACTS_INVITE_SUB_USER,
            CONTACTS_MANAGE_SUB_USER,
        ] {
            assert!(
                ALL_CAPABILITIES.contains(&cap),
                "capability {cap} is missing from ALL_CAPABILITIES"
            );
        }
    }

    #[test]
    fn validate_accepts_known() {
        let caps = vec![TICKETS_READ.to_string(), INVOICES_PAY.to_string()];
        assert!(validate_capabilities(&caps).is_ok());
    }

    #[test]
    fn validate_rejects_unknown() {
        let caps = vec![TICKETS_READ.to_string(), "billing:full_access".to_string()];
        assert_eq!(
            validate_capabilities(&caps).err().as_deref(),
            Some("billing:full_access")
        );
    }

    #[test]
    fn validate_accepts_empty() {
        assert!(validate_capabilities(&[]).is_ok());
    }

    #[test]
    fn all_capabilities_match_seed_migration() {
        // The migration 142 seed hardcodes the built-in role capability
        // sets as SQL string literals; keep this test as a canary that
        // every capability referenced by the seed also exists in the
        // Rust enum. If someone extends the seed with a new capability
        // string and forgets to add it here, the SPA will not gate on
        // it and this test does not catch that specific mistake - but
        // a mismatch in the other direction (Rust drops one the seed
        // still references) shows up as an unrenderable role in the UI.
        let seed_billing = &[
            "invoices:read",
            "invoices:pay",
            "quotes:read",
            "quotes:accept",
            "notifications:read",
            "settings:manage_own",
        ];
        let seed_support = &[
            "tickets:read",
            "tickets:write",
            "tickets:comment",
            "kb:read",
            "notifications:read",
            "settings:manage_own",
        ];
        let seed_readonly = &[
            "tickets:read",
            "invoices:read",
            "quotes:read",
            "contracts:read",
            "assets:read",
            "projects:read",
            "kb:read",
            "notifications:read",
        ];
        let all_seeds: &[&[&str]] = &[seed_billing, seed_support, seed_readonly];
        for seed in all_seeds {
            for cap in *seed {
                assert!(
                    ALL_CAPABILITIES.iter().any(|k| k == cap),
                    "seed migration 142 references `{cap}` but it is missing from ALL_CAPABILITIES"
                );
            }
        }
    }
}
